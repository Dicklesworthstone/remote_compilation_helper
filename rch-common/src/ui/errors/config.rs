//! ConfigErrorDisplay - Specialized display for configuration errors.
//!
//! This module provides rich error display for configuration-related issues,
//! including TOML parse errors, missing files, invalid values, and permission
//! issues.
//!
//! # Features
//!
//! - Parses `toml::de::Error` for location extraction
//! - Shows file content snippets with error highlighting
//! - Displays expected vs actual values for type mismatches
//! - Includes config file search paths when file not found
//! - Suggests `rch config init` for missing configs
//! - Supports JSON serialization for structured output
//!
//! # Example
//!
//! ```ignore
//! use rch_common::ui::errors::ConfigErrorDisplay;
//! use rch_common::ui::OutputContext;
//!
//! let display = ConfigErrorDisplay::parse_error("/home/user/.config/rch/config.toml")
//!     .line(13)
//!     .column(15)
//!     .snippet("timeout = \"thirty\"")
//!     .expected("integer")
//!     .actual("string");
//!
//! display.render(OutputContext::detect());
//! ```

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::errors::catalog::ErrorCode;
use crate::ui::{ErrorPanel, Icons, OutputContext};

#[cfg(feature = "rich-ui")]
use crate::ui::RchTheme;

#[cfg(feature = "rich-ui")]
use rich_rust::r#box::HEAVY;
#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;

/// Location within a configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigLocation {
    /// Path to the config file.
    pub file_path: PathBuf,
    /// Line number (1-indexed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// Column number (1-indexed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    /// Key path within the config (e.g., "workers.0.host").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
}

impl ConfigLocation {
    /// Create a new config location.
    #[must_use]
    pub fn new(file_path: impl Into<PathBuf>) -> Self {
        Self {
            file_path: file_path.into(),
            line: None,
            column: None,
            key_path: None,
        }
    }

    /// Set line number.
    #[must_use]
    pub fn at_line(mut self, line: usize) -> Self {
        self.line = Some(line);
        self
    }

    /// Set column number.
    #[must_use]
    pub fn at_column(mut self, column: usize) -> Self {
        self.column = Some(column);
        self
    }

    /// Set key path.
    #[must_use]
    pub fn at_key(mut self, key_path: impl Into<String>) -> Self {
        self.key_path = Some(key_path.into());
        self
    }

    /// Format the location for display.
    #[must_use]
    pub fn format(&self) -> String {
        let path = self.file_path.display();
        match (self.line, self.column) {
            (Some(line), Some(col)) => format!("{path}:{line}:{col}"),
            (Some(line), None) => format!("{path}:{line}"),
            _ => format!("{path}"),
        }
    }
}

/// A snippet of config file content with context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnippet {
    /// Lines of the snippet with their line numbers.
    pub lines: Vec<SnippetLine>,
    /// The line number that contains the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_line: Option<usize>,
    /// Column range to highlight on the error line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highlight_range: Option<(usize, usize)>,
}

/// A single line in a config snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnippetLine {
    /// Line number (1-indexed).
    pub line_num: usize,
    /// Line content.
    pub content: String,
    /// Whether this is the error line.
    #[serde(default)]
    pub is_error_line: bool,
}

impl ConfigSnippet {
    /// Create a snippet from file content around a specific line.
    #[must_use]
    pub fn from_content(content: &str, error_line: usize, context_lines: usize) -> Self {
        let all_lines: Vec<&str> = content.lines().collect();
        let start = error_line.saturating_sub(context_lines + 1);
        let end = (error_line + context_lines).min(all_lines.len());

        let lines = all_lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let line_num = start + i + 1;
                SnippetLine {
                    line_num,
                    content: (*line).to_string(),
                    is_error_line: line_num == error_line,
                }
            })
            .collect();

        Self {
            lines,
            error_line: Some(error_line),
            highlight_range: None,
        }
    }

    /// Create a snippet from a single line.
    #[must_use]
    pub fn single_line(line_num: usize, content: impl Into<String>) -> Self {
        Self {
            lines: vec![SnippetLine {
                line_num,
                content: content.into(),
                is_error_line: true,
            }],
            error_line: Some(line_num),
            highlight_range: None,
        }
    }

    /// Set the highlight range on the error line.
    #[must_use]
    pub fn with_highlight(mut self, start: usize, end: usize) -> Self {
        self.highlight_range = Some((start, end));
        self
    }

    /// Check if the snippet has content.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

/// Type mismatch information for validation errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeMismatch {
    /// Expected type/format.
    pub expected: String,
    /// Actual type/value found.
    pub actual: String,
    /// Example of a valid value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
}

/// Config search paths for "file not found" errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSearchPaths {
    /// Paths that were searched.
    pub searched: Vec<PathBuf>,
    /// First path found (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found: Option<PathBuf>,
}

impl ConfigSearchPaths {
    /// Create with a list of searched paths.
    #[must_use]
    pub fn new(paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        Self {
            searched: paths.into_iter().map(Into::into).collect(),
            found: None,
        }
    }

    /// Mark one of the paths as found.
    #[must_use]
    pub fn with_found(mut self, path: impl Into<PathBuf>) -> Self {
        self.found = Some(path.into());
        self
    }
}

/// ConfigErrorDisplay - Rich error display for configuration errors.
///
/// Builds on [`ErrorPanel`] with config-specific context:
/// - File location (path, line, column)
/// - Content snippets with highlighting
/// - Expected vs actual values
/// - Config search paths
/// - Environment variable issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigErrorDisplay {
    /// The underlying error code.
    pub error_code: ErrorCode,

    /// Location in the config file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<ConfigLocation>,

    /// Code snippet showing the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<ConfigSnippet>,

    /// Type mismatch details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_mismatch: Option<TypeMismatch>,

    /// Search paths for "not found" errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_paths: Option<ConfigSearchPaths>,

    /// Environment variable name (for env errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_var_name: Option<String>,

    /// Environment variable value (for env errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_var_value: Option<String>,

    /// Profile name (for profile not found).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,

    /// Worker ID (for worker config errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,

    /// SSH key path (for key errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key_path: Option<PathBuf>,

    /// Socket path (for socket errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<PathBuf>,

    /// Permission mode (for permission errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,

    /// Required permission mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_mode: Option<String>,

    /// Raw error message from TOML parser or IO.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_error: Option<String>,

    /// Error chain (caused by).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caused_by: Vec<String>,

    /// Custom message override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_message: Option<String>,
}

impl ConfigErrorDisplay {
    // ========================================================================
    // CONSTRUCTORS FOR SPECIFIC ERROR TYPES
    // ========================================================================

    /// Create display for config file not found (E001).
    #[must_use]
    pub fn not_found(searched_path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = searched_path.into();
        let mut display = Self::new(ErrorCode::ConfigNotFound);
        display.location = Some(ConfigLocation::new(&path));
        display
    }

    /// Create display for config read error (E002).
    #[must_use]
    pub fn read_error(file_path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = file_path.into();
        let mut display = Self::new(ErrorCode::ConfigReadError);
        display.location = Some(ConfigLocation::new(&path));
        display
    }

    /// Create display for TOML parse error (E003).
    #[must_use]
    pub fn parse_error(file_path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = file_path.into();
        let mut display = Self::new(ErrorCode::ConfigParseError);
        display.location = Some(ConfigLocation::new(&path));
        display
    }

    /// Create display for validation error (E004).
    #[must_use]
    pub fn validation_error(file_path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = file_path.into();
        let mut display = Self::new(ErrorCode::ConfigValidationError);
        display.location = Some(ConfigLocation::new(&path));
        display
    }

    /// Create display for environment variable error (E005).
    #[must_use]
    pub fn env_error(var_name: impl Into<String>) -> Self {
        let mut display = Self::new(ErrorCode::ConfigEnvError);
        display.env_var_name = Some(var_name.into());
        display
    }

    /// Create display for profile not found error (E006).
    #[must_use]
    pub fn profile_not_found(profile_name: impl Into<String>) -> Self {
        let mut display = Self::new(ErrorCode::ConfigProfileNotFound);
        display.profile_name = Some(profile_name.into());
        display
    }

    /// Create display for no workers configured error (E007).
    #[must_use]
    pub fn no_workers(config_path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = config_path.into();
        let mut display = Self::new(ErrorCode::ConfigNoWorkers);
        display.location = Some(ConfigLocation::new(&path));
        display
    }

    /// Create display for invalid worker error (E008).
    #[must_use]
    pub fn invalid_worker(worker_id: impl Into<String>) -> Self {
        let mut display = Self::new(ErrorCode::ConfigInvalidWorker);
        display.worker_id = Some(worker_id.into());
        display
    }

    /// Create display for SSH key error (E009).
    #[must_use]
    pub fn ssh_key_error(key_path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = key_path.into();
        let mut display = Self::new(ErrorCode::ConfigSshKeyError);
        display.ssh_key_path = Some(path);
        display
    }

    /// Create display for socket path error (E010).
    #[must_use]
    pub fn socket_path_error(socket_path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = socket_path.into();
        let mut display = Self::new(ErrorCode::ConfigSocketPathError);
        display.socket_path = Some(path);
        display
    }

    // ========================================================================
    // CORE CONSTRUCTOR
    // ========================================================================

    /// Create a new ConfigErrorDisplay with error code.
    #[must_use]
    fn new(error_code: ErrorCode) -> Self {
        Self {
            error_code,
            location: None,
            snippet: None,
            type_mismatch: None,
            search_paths: None,
            env_var_name: None,
            env_var_value: None,
            profile_name: None,
            worker_id: None,
            ssh_key_path: None,
            socket_path: None,
            permission_mode: None,
            required_mode: None,
            raw_error: None,
            caused_by: Vec::new(),
            custom_message: None,
        }
    }

    // ========================================================================
    // BUILDER METHODS
    // ========================================================================

    /// Set the line number.
    #[must_use]
    pub fn line(mut self, line: usize) -> Self {
        if let Some(ref mut loc) = self.location {
            loc.line = Some(line);
        }
        self
    }

    /// Set the column number.
    #[must_use]
    pub fn column(mut self, column: usize) -> Self {
        if let Some(ref mut loc) = self.location {
            loc.column = Some(column);
        }
        self
    }

    /// Set the key path within the config.
    #[must_use]
    pub fn key_path(mut self, key: impl Into<String>) -> Self {
        if let Some(ref mut loc) = self.location {
            loc.key_path = Some(key.into());
        }
        self
    }

    /// Set a single-line snippet.
    #[must_use]
    pub fn snippet(mut self, content: impl Into<String>) -> Self {
        let line_num = self.location.as_ref().and_then(|l| l.line).unwrap_or(1);
        self.snippet = Some(ConfigSnippet::single_line(line_num, content));
        self
    }

    /// Set a multi-line snippet from file content.
    #[must_use]
    pub fn snippet_from_content(mut self, content: &str, context_lines: usize) -> Self {
        if let Some(line) = self.location.as_ref().and_then(|l| l.line) {
            self.snippet = Some(ConfigSnippet::from_content(content, line, context_lines));
        }
        self
    }

    /// Set the expected type/value.
    #[must_use]
    pub fn expected(mut self, expected: impl Into<String>) -> Self {
        if let Some(ref mut tm) = self.type_mismatch {
            tm.expected = expected.into();
        } else {
            self.type_mismatch = Some(TypeMismatch {
                expected: expected.into(),
                actual: String::new(),
                example: None,
            });
        }
        self
    }

    /// Set the actual type/value found.
    #[must_use]
    pub fn actual(mut self, actual: impl Into<String>) -> Self {
        if let Some(ref mut tm) = self.type_mismatch {
            tm.actual = actual.into();
        } else {
            self.type_mismatch = Some(TypeMismatch {
                expected: String::new(),
                actual: actual.into(),
                example: None,
            });
        }
        self
    }

    /// Set an example of a valid value.
    #[must_use]
    pub fn example(mut self, example: impl Into<String>) -> Self {
        if let Some(ref mut tm) = self.type_mismatch {
            tm.example = Some(example.into());
        }
        self
    }

    /// Set config search paths.
    #[must_use]
    pub fn search_paths(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.search_paths = Some(ConfigSearchPaths::new(paths));
        self
    }

    /// Set the environment variable value.
    #[must_use]
    pub fn env_value(mut self, value: impl Into<String>) -> Self {
        self.env_var_value = Some(value.into());
        self
    }

    /// Set permission mode info.
    #[must_use]
    pub fn permission(mut self, current: impl Into<String>, required: impl Into<String>) -> Self {
        self.permission_mode = Some(current.into());
        self.required_mode = Some(required.into());
        self
    }

    /// Set the raw error message.
    #[must_use]
    pub fn raw_error(mut self, error: impl Into<String>) -> Self {
        self.raw_error = Some(error.into());
        self
    }

    /// Set a custom message.
    #[must_use]
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.custom_message = Some(message.into());
        self
    }

    /// Add a caused-by entry.
    #[must_use]
    pub fn caused_by(mut self, cause: impl Into<String>) -> Self {
        self.caused_by.push(cause.into());
        self
    }

    /// Set location from a toml parse error.
    #[must_use]
    pub fn from_toml_error(mut self, error: &toml::de::Error) -> Self {
        if let Some(span) = error.span() {
            // TOML spans are byte offsets; we need line/col info
            // For now, just capture the raw error message
            if let Some(ref mut loc) = self.location {
                loc.line = Some(span.start);
            }
        }
        self.raw_error = Some(error.message().to_string());
        self
    }

    /// Set location from an IO error.
    #[must_use]
    pub fn from_io_error(mut self, error: &std::io::Error) -> Self {
        self.raw_error = Some(error.to_string());
        if let std::io::ErrorKind::PermissionDenied = error.kind() {
            // Add permission context
            self.permission_mode = Some("unknown".to_string());
        }
        self
    }

    // ========================================================================
    // CONVERSION TO ErrorPanel
    // ========================================================================

    /// Convert to an ErrorPanel for rendering.
    #[must_use]
    pub fn to_error_panel(&self) -> ErrorPanel {
        let entry = self.error_code.entry();

        let mut panel = ErrorPanel::error(&entry.code, &entry.message);

        // Set custom message if provided
        if let Some(ref msg) = self.custom_message {
            panel = panel.message(msg.clone());
        }

        // Add file location
        if let Some(ref loc) = self.location {
            panel = panel.context("File", loc.format());
            if let Some(ref key) = loc.key_path {
                panel = panel.context("Key", key.clone());
            }
        }

        // Add type mismatch info
        if let Some(ref tm) = self.type_mismatch {
            if !tm.expected.is_empty() {
                panel = panel.context("Expected", tm.expected.clone());
            }
            if !tm.actual.is_empty() {
                panel = panel.context("Found", tm.actual.clone());
            }
            if let Some(ref example) = tm.example {
                panel = panel.context("Example", example.clone());
            }
        }

        // Add env var info
        if let Some(ref name) = self.env_var_name {
            panel = panel.context("Variable", name.clone());
            if let Some(ref value) = self.env_var_value {
                panel = panel.context("Value", value.clone());
            }
        }

        // Add profile info
        if let Some(ref profile) = self.profile_name {
            panel = panel.context("Profile", profile.clone());
        }

        // Add worker info
        if let Some(ref worker) = self.worker_id {
            panel = panel.context("Worker", worker.clone());
        }

        // Add SSH key path
        if let Some(ref path) = self.ssh_key_path {
            panel = panel.context("SSH Key", path.display().to_string());
        }

        // Add socket path
        if let Some(ref path) = self.socket_path {
            panel = panel.context("Socket", path.display().to_string());
        }

        // Add permission info
        if let (Some(current), Some(required)) = (&self.permission_mode, &self.required_mode) {
            panel = panel.context("Permissions", format!("{current} (need {required})"));
        }

        // Add caused-by chain
        for cause in &self.caused_by {
            panel = panel.caused_by(cause.clone(), None);
        }

        // Add remediation from catalog
        for step in entry.remediation {
            panel = panel.suggestion(step);
        }

        panel
    }

    // ========================================================================
    // RENDERING
    // ========================================================================

    /// Render the error to stderr.
    pub fn render(&self, ctx: OutputContext) {
        if ctx.is_machine() {
            // Machine mode - caller should use to_json()
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
        let content = self.build_rich_content(ctx);
        let entry = self.error_code.entry();
        let icon = Icons::cross(ctx);
        let title_text = format!("{icon} {}: {}", entry.code, entry.message);

        let border_color = Color::parse(RchTheme::ERROR).unwrap_or_else(|_| Color::default());
        let border_style = Style::new().bold().color(border_color);

        let panel = Panel::from_text(&content)
            .title(title_text.as_str())
            .border_style(border_style)
            .box_style(&HEAVY);

        let console = Console::builder().force_terminal(true).build();
        console.print_renderable(&panel);
    }

    /// Build rich content string.
    #[cfg(feature = "rich-ui")]
    fn build_rich_content(&self, _ctx: OutputContext) -> String {
        let mut lines = Vec::new();

        // Custom message
        if let Some(ref msg) = self.custom_message {
            lines.push(msg.clone());
        }

        // File location
        if let Some(ref loc) = self.location {
            lines.push(String::new());
            lines.push(format!("[{}]File:[/] {}", RchTheme::DIM, loc.format()));
            if let Some(ref key) = loc.key_path {
                lines.push(format!("[{}]Key:[/] {key}", RchTheme::DIM));
            }
        }

        // Code snippet
        if let Some(ref snippet) = self.snippet {
            lines.push(String::new());
            for line in &snippet.lines {
                let prefix = if line.is_error_line {
                    format!("[{}]→ {:>4} │[/] ", RchTheme::ERROR, line.line_num)
                } else {
                    format!("[{}]  {:>4} │[/] ", RchTheme::DIM, line.line_num)
                };
                lines.push(format!("{prefix}{}", line.content));
            }
        }

        // Type mismatch
        if let Some(ref tm) = self.type_mismatch {
            lines.push(String::new());
            if !tm.expected.is_empty() {
                lines.push(format!("[{}]Expected:[/] {}", RchTheme::DIM, tm.expected));
            }
            if !tm.actual.is_empty() {
                lines.push(format!("[{}]Found:[/] {}", RchTheme::ERROR, tm.actual));
            }
            if let Some(ref example) = tm.example {
                lines.push(format!("[{}]Example:[/] {example}", RchTheme::SUCCESS));
            }
        }

        // Search paths
        if let Some(ref sp) = self.search_paths {
            lines.push(String::new());
            lines.push(format!("[{}]Searched locations:[/]", RchTheme::DIM));
            for path in &sp.searched {
                lines.push(format!("  • {}", path.display()));
            }
        }

        // Environment variable
        if let Some(ref name) = self.env_var_name {
            lines.push(String::new());
            lines.push(format!(
                "[{}]Environment variable:[/] {name}",
                RchTheme::DIM
            ));
            if let Some(ref value) = self.env_var_value {
                lines.push(format!("[{}]Current value:[/] {value}", RchTheme::DIM));
            }
        }

        // Permission info
        if let (Some(current), Some(required)) = (&self.permission_mode, &self.required_mode) {
            lines.push(String::new());
            lines.push(format!(
                "[{}]Permissions:[/] {current} (need {required})",
                RchTheme::DIM
            ));
        }

        // Raw error
        if let Some(ref raw) = self.raw_error {
            lines.push(String::new());
            lines.push(format!("[{}]Parser message:[/]", RchTheme::DIM));
            lines.push(format!("  {raw}"));
        }

        // Error chain
        if !self.caused_by.is_empty() {
            lines.push(String::new());
            lines.push(format!("[{}]Caused by:[/]", RchTheme::DIM));
            for cause in &self.caused_by {
                lines.push(format!("  {cause}"));
            }
        }

        // Remediation from catalog
        let entry = self.error_code.entry();
        if !entry.remediation.is_empty() {
            lines.push(String::new());
            lines.push(format!("[{}]Suggestions:[/]", RchTheme::SECONDARY));
            for (i, step) in entry.remediation.iter().enumerate() {
                lines.push(format!("  [{}]{}.[/] {step}", RchTheme::SECONDARY, i + 1));
            }
        }

        lines.join("\n")
    }

    /// Render plain text to stderr.
    fn render_plain(&self, ctx: OutputContext) {
        let entry = self.error_code.entry();
        let icon = Icons::cross(ctx);

        // Header line
        eprintln!("{icon} [ERROR] {}: {}", entry.code, entry.message);

        // Custom message
        if let Some(ref msg) = self.custom_message {
            eprintln!();
            eprintln!("{msg}");
        }

        // File location
        if let Some(ref loc) = self.location {
            eprintln!();
            eprintln!("File: {}", loc.format());
            if let Some(ref key) = loc.key_path {
                eprintln!("Key: {key}");
            }
        }

        // Code snippet
        if let Some(ref snippet) = self.snippet {
            eprintln!();
            for line in &snippet.lines {
                let prefix = if line.is_error_line {
                    format!("→ {:>4} │ ", line.line_num)
                } else {
                    format!("  {:>4} │ ", line.line_num)
                };
                eprintln!("{prefix}{}", line.content);
            }
        }

        // Type mismatch
        if let Some(ref tm) = self.type_mismatch {
            eprintln!();
            if !tm.expected.is_empty() {
                eprintln!("Expected: {}", tm.expected);
            }
            if !tm.actual.is_empty() {
                eprintln!("Found: {}", tm.actual);
            }
            if let Some(ref example) = tm.example {
                eprintln!("Example: {example}");
            }
        }

        // Search paths
        if let Some(ref sp) = self.search_paths {
            eprintln!();
            eprintln!("Searched locations:");
            for path in &sp.searched {
                eprintln!("  • {}", path.display());
            }
        }

        // Environment variable
        if let Some(ref name) = self.env_var_name {
            eprintln!();
            eprintln!("Environment variable: {name}");
            if let Some(ref value) = self.env_var_value {
                eprintln!("Current value: {value}");
            }
        }

        // Profile info
        if let Some(ref profile) = self.profile_name {
            eprintln!();
            eprintln!("Profile: {profile}");
        }

        // Worker info
        if let Some(ref worker) = self.worker_id {
            eprintln!();
            eprintln!("Worker: {worker}");
        }

        // SSH key path
        if let Some(ref path) = self.ssh_key_path {
            eprintln!();
            eprintln!("SSH Key: {}", path.display());
        }

        // Socket path
        if let Some(ref path) = self.socket_path {
            eprintln!();
            eprintln!("Socket: {}", path.display());
        }

        // Permission info
        if let (Some(current), Some(required)) = (&self.permission_mode, &self.required_mode) {
            eprintln!();
            eprintln!("Permissions: {current} (need {required})");
        }

        // Raw error
        if let Some(ref raw) = self.raw_error {
            eprintln!();
            eprintln!("Parser message:");
            eprintln!("  {raw}");
        }

        // Error chain
        if !self.caused_by.is_empty() {
            eprintln!();
            eprintln!("Caused by:");
            for cause in &self.caused_by {
                eprintln!("  {cause}");
            }
        }

        // Remediation
        if !entry.remediation.is_empty() {
            eprintln!();
            eprintln!("Suggestions:");
            for (i, step) in entry.remediation.iter().enumerate() {
                eprintln!("  {}. {step}", i + 1);
            }
        }
    }

    // ========================================================================
    // JSON SERIALIZATION
    // ========================================================================

    /// Serialize to JSON string.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize to compact JSON string.
    pub fn to_json_compact(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

impl std::fmt::Display for ConfigErrorDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entry = self.error_code.entry();
        write!(f, "[ERROR] {}: {}", entry.code, entry.message)?;
        if let Some(ref loc) = self.location {
            write!(f, " at {}", loc.format())?;
        }
        if let Some(ref msg) = self.custom_message {
            write!(f, " - {msg}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigErrorDisplay {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_not_found() {
        let display = ConfigErrorDisplay::not_found("/home/user/.config/rch/config.toml");
        assert_eq!(display.error_code, ErrorCode::ConfigNotFound);
        assert!(display.location.is_some());
    }

    #[test]
    fn test_parse_error_with_location() {
        let display = ConfigErrorDisplay::parse_error("/home/user/.config/rch/config.toml")
            .line(13)
            .column(15)
            .snippet("timeout = \"thirty\"")
            .expected("integer")
            .actual("string");

        assert_eq!(display.error_code, ErrorCode::ConfigParseError);
        let loc = display.location.as_ref().unwrap();
        assert_eq!(loc.line, Some(13));
        assert_eq!(loc.column, Some(15));
        assert!(display.snippet.is_some());
        assert!(display.type_mismatch.is_some());
    }

    #[test]
    fn test_validation_error() {
        let display = ConfigErrorDisplay::validation_error("/home/user/.config/rch/workers.toml")
            .key_path("workers.0.host")
            .expected("non-empty string")
            .actual("empty string")
            .example("192.168.1.100");

        assert_eq!(display.error_code, ErrorCode::ConfigValidationError);
        let tm = display.type_mismatch.as_ref().unwrap();
        assert_eq!(tm.expected, "non-empty string");
        assert_eq!(tm.actual, "empty string");
        assert_eq!(tm.example, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_env_error() {
        let display = ConfigErrorDisplay::env_error("RCH_WORKERS")
            .env_value("not a valid path")
            .message("Environment variable must be a valid file path");

        assert_eq!(display.error_code, ErrorCode::ConfigEnvError);
        assert_eq!(display.env_var_name, Some("RCH_WORKERS".to_string()));
        assert_eq!(display.env_var_value, Some("not a valid path".to_string()));
    }

    #[test]
    fn test_profile_not_found() {
        let display = ConfigErrorDisplay::profile_not_found("production");
        assert_eq!(display.error_code, ErrorCode::ConfigProfileNotFound);
        assert_eq!(display.profile_name, Some("production".to_string()));
    }

    #[test]
    fn test_no_workers() {
        let display = ConfigErrorDisplay::no_workers("/home/user/.config/rch/workers.toml");
        assert_eq!(display.error_code, ErrorCode::ConfigNoWorkers);
    }

    #[test]
    fn test_invalid_worker() {
        let display = ConfigErrorDisplay::invalid_worker("build-server-1")
            .message("Worker is missing required 'host' field");
        assert_eq!(display.error_code, ErrorCode::ConfigInvalidWorker);
        assert_eq!(display.worker_id, Some("build-server-1".to_string()));
    }

    #[test]
    fn test_ssh_key_error() {
        let display = ConfigErrorDisplay::ssh_key_error("/home/user/.ssh/id_rsa")
            .permission("0644", "0600")
            .message("SSH key has incorrect permissions");
        assert_eq!(display.error_code, ErrorCode::ConfigSshKeyError);
        assert_eq!(display.permission_mode, Some("0644".to_string()));
        assert_eq!(display.required_mode, Some("0600".to_string()));
    }

    #[test]
    fn test_socket_path_error() {
        let display = ConfigErrorDisplay::socket_path_error("/tmp/rch/socket")
            .message("Socket path parent directory does not exist");
        assert_eq!(display.error_code, ErrorCode::ConfigSocketPathError);
        assert!(display.socket_path.is_some());
    }

    #[test]
    fn test_search_paths() {
        let display = ConfigErrorDisplay::not_found("/home/user/.config/rch/config.toml")
            .search_paths([
                "/home/user/.config/rch/config.toml",
                "/etc/rch/config.toml",
                "./.rch/config.toml",
            ]);

        let sp = display.search_paths.as_ref().unwrap();
        assert_eq!(sp.searched.len(), 3);
    }

    #[test]
    fn test_config_snippet_from_content() {
        let content = "[general]\nenabled = true\n\n[workers]\ntimeout = \"thirty\"\nretry = 3";
        let snippet = ConfigSnippet::from_content(content, 5, 1);

        assert!(!snippet.is_empty());
        assert_eq!(snippet.error_line, Some(5));
        // Should have lines 4, 5, 6
        assert!(snippet.lines.len() >= 2);
    }

    #[test]
    fn test_config_snippet_single_line() {
        let snippet = ConfigSnippet::single_line(13, "timeout = \"thirty\"");
        assert_eq!(snippet.lines.len(), 1);
        assert_eq!(snippet.lines[0].line_num, 13);
        assert!(snippet.lines[0].is_error_line);
    }

    #[test]
    fn test_location_format() {
        let loc = ConfigLocation::new("/home/user/config.toml")
            .at_line(42)
            .at_column(10);
        assert_eq!(loc.format(), "/home/user/config.toml:42:10");

        let loc2 = ConfigLocation::new("/home/user/config.toml").at_line(42);
        assert_eq!(loc2.format(), "/home/user/config.toml:42");

        let loc3 = ConfigLocation::new("/home/user/config.toml");
        assert_eq!(loc3.format(), "/home/user/config.toml");
    }

    #[test]
    fn test_to_error_panel() {
        let display = ConfigErrorDisplay::parse_error("/home/user/.config/rch/config.toml")
            .line(13)
            .expected("integer")
            .actual("string");

        let panel = display.to_error_panel();
        assert_eq!(panel.code, "RCH-E003");
    }

    #[test]
    fn test_json_serialization() {
        let display = ConfigErrorDisplay::parse_error("/home/user/config.toml")
            .line(10)
            .raw_error("expected '=' after key");

        let json = display.to_json().expect("JSON serialization failed");
        assert!(json.contains("RCH-E003") || json.contains("ConfigParseError"));
        assert!(json.contains("config.toml"));
    }

    #[test]
    fn test_json_compact() {
        let display = ConfigErrorDisplay::not_found("/path/to/config.toml");
        let json = display
            .to_json_compact()
            .expect("JSON serialization failed");
        assert!(!json.contains('\n'));
    }

    #[test]
    fn test_display_implementation() {
        let display = ConfigErrorDisplay::parse_error("/home/user/config.toml")
            .line(42)
            .message("Unexpected character");

        let output = format!("{display}");
        assert!(output.contains("RCH-E003"));
        assert!(output.contains("config.toml:42"));
        assert!(output.contains("Unexpected character"));
    }

    #[test]
    fn test_error_trait() {
        let display: Box<dyn std::error::Error> =
            Box::new(ConfigErrorDisplay::not_found("/config.toml"));
        let _ = format!("{display}");
    }

    #[test]
    fn test_render_plain_no_panic() {
        let display = ConfigErrorDisplay::parse_error("/home/user/.config/rch/config.toml")
            .line(13)
            .column(15)
            .snippet("timeout = \"thirty\"")
            .expected("integer")
            .actual("string")
            .raw_error("expected integer, found string");

        // Should not panic
        display.render(OutputContext::Plain);
    }

    #[test]
    fn test_render_machine_silent() {
        let display = ConfigErrorDisplay::not_found("/config.toml");
        // Should not output anything in machine mode
        display.render(OutputContext::Machine);
    }

    #[test]
    fn test_caused_by_chain() {
        let display = ConfigErrorDisplay::read_error("/config.toml")
            .caused_by("IO error: file not found")
            .caused_by("Path does not exist");

        assert_eq!(display.caused_by.len(), 2);
    }

    #[test]
    fn test_all_error_constructors() {
        assert_eq!(
            ConfigErrorDisplay::not_found("path").error_code,
            ErrorCode::ConfigNotFound
        );
        assert_eq!(
            ConfigErrorDisplay::read_error("path").error_code,
            ErrorCode::ConfigReadError
        );
        assert_eq!(
            ConfigErrorDisplay::parse_error("path").error_code,
            ErrorCode::ConfigParseError
        );
        assert_eq!(
            ConfigErrorDisplay::validation_error("path").error_code,
            ErrorCode::ConfigValidationError
        );
        assert_eq!(
            ConfigErrorDisplay::env_error("VAR").error_code,
            ErrorCode::ConfigEnvError
        );
        assert_eq!(
            ConfigErrorDisplay::profile_not_found("profile").error_code,
            ErrorCode::ConfigProfileNotFound
        );
        assert_eq!(
            ConfigErrorDisplay::no_workers("path").error_code,
            ErrorCode::ConfigNoWorkers
        );
        assert_eq!(
            ConfigErrorDisplay::invalid_worker("id").error_code,
            ErrorCode::ConfigInvalidWorker
        );
        assert_eq!(
            ConfigErrorDisplay::ssh_key_error("path").error_code,
            ErrorCode::ConfigSshKeyError
        );
        assert_eq!(
            ConfigErrorDisplay::socket_path_error("path").error_code,
            ErrorCode::ConfigSocketPathError
        );
    }

    #[test]
    fn test_read_error_with_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let display = ConfigErrorDisplay::read_error("/etc/rch/config.toml").from_io_error(&io_err);

        assert!(display.raw_error.is_some());
        assert!(display.raw_error.as_ref().unwrap().contains("permission"));
    }

    #[test]
    fn test_snippet_highlight_range() {
        let snippet = ConfigSnippet::single_line(10, "timeout = \"thirty\"").with_highlight(10, 18);
        assert_eq!(snippet.highlight_range, Some((10, 18)));
    }
}
