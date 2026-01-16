//! Output context and mode detection for CLI applications.
//!
//! Provides automatic detection of output capabilities and preferences,
//! including color support, TTY detection, unicode compatibility, and
//! adaptive colors for light/dark terminal backgrounds.

use super::adaptive::{
    detect_background, detect_color_level, detect_hyperlink_support, AdaptiveColor, Background,
    ColorLevel,
};
use super::style::Style;
use super::writer::OutputWriter;
use colored::Color;
use serde::Serialize;
use std::env;

/// Output mode determining how content is formatted and displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputMode {
    /// Colored output with unicode symbols and progress indicators.
    #[default]
    Human,
    /// Plain text without colors or animations, ASCII fallback.
    Plain,
    /// Machine-readable JSON output to stdout.
    Json,
    /// Minimal output - errors only.
    Quiet,
}

/// Verbosity level (orthogonal to output mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verbosity {
    /// Only show errors.
    Quiet,
    /// Standard output level.
    #[default]
    Normal,
    /// Additional debug information.
    Verbose,
}

/// Terminal capabilities detected at runtime.
#[derive(Debug, Clone, Copy)]
pub struct TerminalCaps {
    /// Terminal width in columns.
    pub width: u16,
    /// Terminal height in rows.
    pub height: u16,
    /// Whether colors are supported.
    pub supports_color: bool,
    /// Whether unicode is supported.
    pub supports_unicode: bool,
    /// Level of color support (16, 256, or true color).
    pub color_level: ColorLevel,
    /// Whether the terminal supports hyperlinks (OSC 8).
    pub supports_hyperlinks: bool,
    /// Terminal background (light or dark).
    pub background: Background,
}

impl Default for TerminalCaps {
    fn default() -> Self {
        Self {
            width: 80,
            height: 24,
            supports_color: false,
            supports_unicode: false,
            color_level: ColorLevel::default(),
            supports_hyperlinks: false,
            background: Background::default(),
        }
    }
}

impl TerminalCaps {
    /// Detect terminal capabilities from the environment.
    pub fn detect() -> Self {
        let (width, height) = terminal_size::terminal_size()
            .map(|(w, h)| (w.0, h.0))
            .unwrap_or((80, 24));

        let supports_color = Self::detect_color_support();
        let supports_unicode = Self::detect_unicode_support();
        let color_level = detect_color_level();
        let supports_hyperlinks = detect_hyperlink_support();
        let background = detect_background();

        Self {
            width,
            height,
            supports_color,
            supports_unicode,
            color_level,
            supports_hyperlinks,
            background,
        }
    }

    /// Check if the terminal supports colors.
    fn detect_color_support() -> bool {
        // Check TERM environment variable
        if let Ok(term) = env::var("TERM") {
            if term == "dumb" {
                return false;
            }
        }

        // NO_COLOR disables colors (https://no-color.org/)
        if env::var("NO_COLOR").is_ok() {
            return false;
        }

        // CLICOLOR_FORCE enables colors
        if env::var("CLICOLOR_FORCE").is_ok() {
            return true;
        }

        // Default to checking if stdout is a TTY
        is_terminal::is_terminal(&std::io::stdout())
    }

    /// Check if the terminal supports unicode.
    fn detect_unicode_support() -> bool {
        // Check LANG or LC_ALL for UTF-8
        for var in &["LC_ALL", "LC_CTYPE", "LANG"] {
            if let Ok(val) = env::var(var) {
                let val_lower = val.to_lowercase();
                if val_lower.contains("utf-8") || val_lower.contains("utf8") {
                    return true;
                }
            }
        }

        // Check for Windows Terminal (supports unicode)
        if env::var("WT_SESSION").is_ok() {
            return true;
        }

        // Default to ASCII on plain Windows cmd.exe
        #[cfg(windows)]
        {
            // Windows Terminal sets WT_SESSION, ConEmu sets ConEmuANSI
            if env::var("ConEmuANSI").is_ok() {
                return true;
            }
            return false;
        }

        #[cfg(not(windows))]
        {
            // Unix-like systems generally support unicode
            true
        }
    }
}

/// Configuration for creating an OutputContext.
#[derive(Debug, Clone, Default)]
pub struct OutputConfig {
    /// Force a specific output mode (overrides auto-detection).
    pub force_mode: Option<OutputMode>,
    /// Color preference from CLI flag.
    pub color: ColorChoice,
    /// JSON output requested.
    pub json: bool,
    /// Verbose flag.
    pub verbose: bool,
    /// Quiet flag.
    pub quiet: bool,
}

/// Color preference from CLI flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorChoice {
    /// Auto-detect based on terminal.
    #[default]
    Auto,
    /// Always use colors.
    Always,
    /// Never use colors.
    Never,
}

impl ColorChoice {
    /// Parse from CLI string argument.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "always" | "yes" | "true" => Self::Always,
            "never" | "no" | "false" => Self::Never,
            _ => Self::Auto,
        }
    }
}

/// Central output context that manages all output operations.
#[derive(Debug)]
pub struct OutputContext {
    /// Current output mode.
    mode: OutputMode,
    /// Verbosity level.
    verbosity: Verbosity,
    /// Terminal capabilities.
    caps: TerminalCaps,
    /// Styling configuration.
    style: Style,
    /// Thread-safe stdout writer.
    stdout: OutputWriter,
    /// Thread-safe stderr writer.
    stderr: OutputWriter,
}

impl OutputContext {
    /// Create a new output context with the given configuration.
    pub fn new(config: OutputConfig) -> Self {
        let stdout = OutputWriter::stdout();
        let stderr = OutputWriter::stderr();
        Self::with_writers(config, stdout, stderr)
    }

    /// Create an output context with custom writers (for testing).
    pub fn with_writers(config: OutputConfig, stdout: OutputWriter, stderr: OutputWriter) -> Self {
        let caps = TerminalCaps::detect();
        let mode = Self::detect_mode(&config, &stdout, &caps);
        let verbosity = Self::detect_verbosity(&config);

        // Determine color and unicode support
        let colors_enabled = match config.color {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => mode == OutputMode::Human && caps.supports_color,
        };
        let supports_unicode = caps.supports_unicode;

        let style = Style::new(colors_enabled, supports_unicode);

        Self {
            mode,
            verbosity,
            caps,
            style,
            stdout,
            stderr,
        }
    }

    /// Detect output mode based on configuration and environment.
    ///
    /// Priority order:
    /// 1. `--json` flag → Json mode
    /// 2. `--quiet` / `-q` flag → Quiet mode
    /// 3. `--no-color` / `--color=never` flag → Plain mode
    /// 4. `--color=always` flag → Human mode (force colors)
    /// 5. `NO_COLOR` env var → Plain mode
    /// 6. `CLICOLOR_FORCE` env var → Human mode
    /// 7. `TERM=dumb` → Plain mode
    /// 8. stdout not TTY → Plain mode for stdout
    /// 9. Otherwise → Human mode
    fn detect_mode(config: &OutputConfig, stdout: &OutputWriter, caps: &TerminalCaps) -> OutputMode {
        // 1. Force mode if specified
        if let Some(mode) = config.force_mode {
            return mode;
        }

        // 2. --json flag
        if config.json {
            return OutputMode::Json;
        }

        // 3. --quiet flag
        if config.quiet {
            return OutputMode::Quiet;
        }

        // 4. --color=never
        if config.color == ColorChoice::Never {
            return OutputMode::Plain;
        }

        // 5. --color=always
        if config.color == ColorChoice::Always {
            return OutputMode::Human;
        }

        // 6. NO_COLOR env var
        if env::var("NO_COLOR").is_ok() {
            return OutputMode::Plain;
        }

        // 7. CLICOLOR_FORCE env var
        if env::var("CLICOLOR_FORCE").is_ok() {
            return OutputMode::Human;
        }

        // 8. TERM=dumb
        if env::var("TERM").is_ok_and(|t| t == "dumb") {
            return OutputMode::Plain;
        }

        // 9. Check if stdout is a TTY
        if !stdout.is_tty() {
            return OutputMode::Plain;
        }

        // 10. Check terminal color support
        if !caps.supports_color {
            return OutputMode::Plain;
        }

        // Default to human mode
        OutputMode::Human
    }

    /// Detect verbosity level from configuration.
    fn detect_verbosity(config: &OutputConfig) -> Verbosity {
        if config.quiet {
            Verbosity::Quiet
        } else if config.verbose {
            Verbosity::Verbose
        } else {
            Verbosity::Normal
        }
    }

    /// Get the current output mode.
    pub fn mode(&self) -> OutputMode {
        self.mode
    }

    /// Get the current verbosity level.
    pub fn verbosity(&self) -> Verbosity {
        self.verbosity
    }

    /// Check if stdout is a TTY.
    pub fn is_tty(&self) -> bool {
        self.stdout.is_tty()
    }

    /// Check if JSON output mode is active.
    pub fn is_json(&self) -> bool {
        self.mode == OutputMode::Json
    }

    /// Check if quiet mode is active.
    pub fn is_quiet(&self) -> bool {
        self.mode == OutputMode::Quiet || self.verbosity == Verbosity::Quiet
    }

    /// Check if verbose mode is active.
    pub fn is_verbose(&self) -> bool {
        self.verbosity == Verbosity::Verbose
    }

    /// Get terminal width.
    pub fn terminal_width(&self) -> u16 {
        self.caps.width
    }

    /// Get the style configuration.
    pub fn style(&self) -> &Style {
        &self.style
    }

    // --- Adaptive color support ---

    /// Check if the terminal has a light background.
    pub fn is_light_background(&self) -> bool {
        self.caps.background == Background::Light
    }

    /// Check if the terminal has a dark background.
    pub fn is_dark_background(&self) -> bool {
        self.caps.background == Background::Dark
    }

    /// Get the terminal's background type.
    pub fn background(&self) -> Background {
        self.caps.background
    }

    /// Get the terminal's color level.
    ///
    /// If plain mode is active, returns `ColorLevel::None` regardless of
    /// actual terminal capabilities.
    pub fn color_level(&self) -> ColorLevel {
        if self.mode == OutputMode::Plain {
            ColorLevel::None
        } else {
            self.caps.color_level
        }
    }

    /// Check if the terminal supports hyperlinks (OSC 8).
    pub fn supports_hyperlinks(&self) -> bool {
        self.mode == OutputMode::Human && self.caps.supports_hyperlinks
    }

    /// Resolve an adaptive color for the current terminal background.
    pub fn resolve_color(&self, adaptive: &AdaptiveColor) -> Color {
        adaptive.resolve(self.caps.background)
    }

    // --- Status messages (to stderr in Human/Plain, suppressed in Quiet) ---

    /// Print a success message to stderr.
    pub fn success(&self, msg: &str) {
        if self.is_quiet() || self.is_json() {
            return;
        }
        self.stderr.write_line(&self.style.format_success(msg));
    }

    /// Print an error message to stderr.
    pub fn error(&self, msg: &str) {
        // Errors always show (except in JSON mode)
        if self.is_json() {
            return;
        }
        self.stderr.write_line(&self.style.format_error(msg));
    }

    /// Print a warning message to stderr.
    pub fn warning(&self, msg: &str) {
        if self.is_quiet() || self.is_json() {
            return;
        }
        self.stderr.write_line(&self.style.format_warning(msg));
    }

    /// Print an info message to stderr.
    pub fn info(&self, msg: &str) {
        if self.is_quiet() || self.is_json() {
            return;
        }
        self.stderr.write_line(&self.style.format_info(msg));
    }

    /// Print a debug message to stderr (only in verbose mode).
    pub fn debug(&self, msg: &str) {
        if !self.is_verbose() || self.is_json() {
            return;
        }
        self.stderr
            .write_line(&format!("[DEBUG] {}", self.style.muted(msg)));
    }

    // --- Structured output (to stdout) ---

    /// Print raw text to stdout.
    pub fn print(&self, msg: &str) {
        if self.is_json() {
            return;
        }
        self.stdout.write_line(msg);
    }

    /// Print a section header.
    pub fn header(&self, title: &str) {
        if self.is_json() {
            return;
        }
        self.stdout.write_line(&self.style.format_header(title));
    }

    /// Print a key-value pair with alignment.
    pub fn key_value(&self, key: &str, value: &str) {
        if self.is_json() {
            return;
        }
        self.stdout
            .write_line(&self.style.format_key_value(key, value, 16));
    }

    /// Print a key-value pair with custom key width.
    pub fn key_value_width(&self, key: &str, value: &str, width: usize) {
        if self.is_json() {
            return;
        }
        self.stdout
            .write_line(&self.style.format_key_value(key, value, width));
    }

    /// Print a simple table.
    pub fn table(&self, headers: &[&str], rows: &[Vec<String>]) {
        if self.is_json() {
            return;
        }

        // Calculate column widths
        let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                if i < widths.len() {
                    widths[i] = widths[i].max(cell.len());
                }
            }
        }

        // Print header
        let header_line: Vec<String> = headers
            .iter()
            .zip(widths.iter())
            .map(|(h, w)| format!("{:width$}", h, width = *w))
            .collect();
        self.stdout
            .write_line(&self.style.highlight(&header_line.join("  ")).to_string());

        // Print separator
        let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
        self.stdout.write_line(&sep.join("  "));

        // Print rows
        for row in rows {
            let row_line: Vec<String> = row
                .iter()
                .zip(widths.iter())
                .map(|(cell, w)| format!("{:width$}", cell, width = *w))
                .collect();
            self.stdout.write_line(&row_line.join("  "));
        }
    }

    // --- JSON output ---

    /// Output JSON (only in JSON mode).
    pub fn json<T: Serialize>(&self, value: &T) -> serde_json::Result<()> {
        if !self.is_json() {
            return Ok(());
        }
        let json = serde_json::to_string_pretty(value)?;
        self.stdout.write_line(&json);
        Ok(())
    }

    /// Output compact JSON (only in JSON mode).
    pub fn json_compact<T: Serialize>(&self, value: &T) -> serde_json::Result<()> {
        if !self.is_json() {
            return Ok(());
        }
        let json = serde_json::to_string(value)?;
        self.stdout.write_line(&json);
        Ok(())
    }

    /// Flush all output streams.
    pub fn flush(&self) {
        self.stdout.flush();
        self.stderr.flush();
    }
}

/// Create a default output context for typical CLI usage.
pub fn default_context() -> OutputContext {
    OutputContext::new(OutputConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::writer::SharedOutputBuffer;

    fn make_test_context(config: OutputConfig) -> (OutputContext, SharedOutputBuffer, SharedOutputBuffer) {
        let stdout_buf = SharedOutputBuffer::new();
        let stderr_buf = SharedOutputBuffer::new();
        let stdout = stdout_buf.as_writer(true);
        let stderr = stderr_buf.as_writer(true);
        let ctx = OutputContext::with_writers(config, stdout, stderr);
        (ctx, stdout_buf, stderr_buf)
    }

    #[test]
    fn test_output_mode_default() {
        let mode = OutputMode::default();
        assert_eq!(mode, OutputMode::Human);
    }

    #[test]
    fn test_verbosity_default() {
        let v = Verbosity::default();
        assert_eq!(v, Verbosity::Normal);
    }

    #[test]
    fn test_color_choice_parse() {
        assert_eq!(ColorChoice::parse("always"), ColorChoice::Always);
        assert_eq!(ColorChoice::parse("never"), ColorChoice::Never);
        assert_eq!(ColorChoice::parse("auto"), ColorChoice::Auto);
        assert_eq!(ColorChoice::parse("invalid"), ColorChoice::Auto);
    }

    #[test]
    fn test_json_mode_json_output() {
        let config = OutputConfig {
            json: true,
            ..Default::default()
        };
        let (ctx, stdout_buf, _) = make_test_context(config);

        assert!(ctx.is_json());

        #[derive(Serialize)]
        struct TestData {
            value: i32,
        }
        ctx.json(&TestData { value: 42 }).unwrap();

        let output = stdout_buf.to_string_lossy();
        assert!(output.contains("42"));
        assert!(output.contains("value"));
    }

    #[test]
    fn test_json_mode_suppresses_human_output() {
        let config = OutputConfig {
            json: true,
            ..Default::default()
        };
        let (ctx, stdout_buf, stderr_buf) = make_test_context(config);

        ctx.header("Test");
        ctx.print("Should not appear");
        ctx.success("Also should not appear");

        assert!(stdout_buf.to_string_lossy().is_empty());
        assert!(stderr_buf.to_string_lossy().is_empty());
    }

    #[test]
    fn test_quiet_mode_suppresses_info() {
        let config = OutputConfig {
            quiet: true,
            ..Default::default()
        };
        let (ctx, _, stderr_buf) = make_test_context(config);

        ctx.info("Should not appear");
        ctx.success("Also hidden");

        assert!(stderr_buf.to_string_lossy().is_empty());
    }

    #[test]
    fn test_error_always_shows() {
        let config = OutputConfig {
            quiet: true,
            ..Default::default()
        };
        let (ctx, _, stderr_buf) = make_test_context(config);

        ctx.error("This should appear");

        let output = stderr_buf.to_string_lossy();
        assert!(output.contains("This should appear"));
    }

    #[test]
    fn test_verbose_debug_messages() {
        let config = OutputConfig {
            verbose: true,
            ..Default::default()
        };
        let (ctx, _, stderr_buf) = make_test_context(config);

        ctx.debug("Debug info");

        let output = stderr_buf.to_string_lossy();
        assert!(output.contains("Debug info"));
    }

    #[test]
    fn test_non_verbose_hides_debug() {
        let config = OutputConfig::default();
        let (ctx, _, stderr_buf) = make_test_context(config);

        ctx.debug("Should not appear");

        assert!(stderr_buf.to_string_lossy().is_empty());
    }

    #[test]
    fn test_table_output() {
        let config = OutputConfig::default();
        let (ctx, stdout_buf, _) = make_test_context(config);

        ctx.table(
            &["Name", "Status"],
            &[
                vec!["worker-1".to_string(), "healthy".to_string()],
                vec!["worker-2".to_string(), "degraded".to_string()],
            ],
        );

        let output = stdout_buf.to_string_lossy();
        assert!(output.contains("Name"));
        assert!(output.contains("Status"));
        assert!(output.contains("worker-1"));
        assert!(output.contains("healthy"));
    }

    #[test]
    fn test_terminal_caps_defaults() {
        let caps = TerminalCaps::default();
        assert_eq!(caps.width, 80);
        assert_eq!(caps.height, 24);
        assert!(!caps.supports_color);
        assert!(!caps.supports_unicode);
        assert_eq!(caps.color_level, ColorLevel::Ansi16);
        assert!(!caps.supports_hyperlinks);
        assert_eq!(caps.background, Background::Dark);
    }

    #[test]
    fn test_context_background_methods() {
        let config = OutputConfig::default();
        let (ctx, _, _) = make_test_context(config);

        // Default background is dark
        let bg = ctx.background();
        // Either light or dark is valid, just ensure the methods are consistent
        if bg == Background::Light {
            assert!(ctx.is_light_background());
            assert!(!ctx.is_dark_background());
        } else {
            assert!(!ctx.is_light_background());
            assert!(ctx.is_dark_background());
        }
    }

    #[test]
    fn test_context_color_level() {
        let config = OutputConfig::default();
        let (ctx, _, _) = make_test_context(config);

        // Color level should be a valid level
        let level = ctx.color_level();
        assert!(
            level == ColorLevel::None
                || level == ColorLevel::Ansi16
                || level == ColorLevel::Ansi256
                || level == ColorLevel::TrueColor
        );
    }

    #[test]
    fn test_context_color_level_plain_mode() {
        let config = OutputConfig {
            force_mode: Some(OutputMode::Plain),
            ..Default::default()
        };
        let (ctx, _, _) = make_test_context(config);

        // Plain mode should return None color level regardless of terminal
        assert_eq!(ctx.color_level(), ColorLevel::None);
    }

    #[test]
    fn test_context_resolve_color() {
        use crate::ui::adaptive::palette;

        let config = OutputConfig::default();
        let (ctx, _, _) = make_test_context(config);

        // Resolve should return a valid color
        let color = ctx.resolve_color(&palette::SUCCESS);
        // Just verify we get a color (the exact value depends on background)
        let _ = color;
    }

    #[test]
    fn test_context_supports_hyperlinks_human_mode() {
        let config = OutputConfig {
            force_mode: Some(OutputMode::Human),
            ..Default::default()
        };
        let (ctx, _, _) = make_test_context(config);

        // Result depends on environment, just verify it doesn't panic
        let _ = ctx.supports_hyperlinks();
    }

    #[test]
    fn test_context_supports_hyperlinks_plain_mode() {
        let config = OutputConfig {
            force_mode: Some(OutputMode::Plain),
            ..Default::default()
        };
        let (ctx, _, _) = make_test_context(config);

        // Plain mode should never support hyperlinks
        assert!(!ctx.supports_hyperlinks());
    }
}
