//! BuildErrorDisplay - Specialized display for compilation and build errors.
//!
//! This module provides rich error display for build-related issues,
//! including compilation failures, timeouts, signal kills, and artifact errors.
//!
//! # Key Design Principle
//!
//! For compilation errors, we preserve and enhance rustc/cargo error formatting
//! rather than overriding it. RCH adds context (worker info, command, timing)
//! around the compiler output, not replacing it.
//!
//! # Features
//!
//! - Compilation errors with compiler output passthrough
//! - Build timeout with resource usage at timeout
//! - Signal kills with OOM killer detection
//! - Artifact retrieval failures with path details
//! - Worker resource state display
//! - JSON serialization for structured output
//!
//! # Example
//!
//! ```ignore
//! use rch_common::ui::errors::BuildErrorDisplay;
//! use rch_common::ui::OutputContext;
//!
//! let display = BuildErrorDisplay::build_timeout("cargo build --release")
//!     .worker("build1.internal")
//!     .duration_secs(300)
//!     .timeout_secs(300)
//!     .last_output("Compiling serde_derive v1.0.152")
//!     .cpu_usage(98.0)
//!     .memory_usage(14.2, 16.0)
//!     .load_average(8.5);
//!
//! display.render(OutputContext::detect());
//! ```

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::errors::catalog::ErrorCode;
use crate::ui::{ErrorPanel, Icons, OutputContext, RchTheme};

#[cfg(feature = "rich-ui")]
use rich_rust::r#box::HEAVY;
#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;

/// Worker resource state at the time of error.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkerResourceState {
    /// CPU usage percentage (0-100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<f64>,
    /// Memory used in GB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_used_gb: Option<f64>,
    /// Total memory in GB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_total_gb: Option<f64>,
    /// System load average (1 minute).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_average: Option<f64>,
    /// Disk usage percentage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_percent: Option<f64>,
}

impl WorkerResourceState {
    /// Check if any resource data is available.
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.cpu_percent.is_some()
            || self.memory_used_gb.is_some()
            || self.load_average.is_some()
            || self.disk_percent.is_some()
    }

    /// Format for display.
    #[must_use]
    pub fn format_line(&self) -> String {
        let mut parts = Vec::new();

        if let Some(cpu) = self.cpu_percent {
            parts.push(format!("CPU: {cpu:.0}%"));
        }

        if let (Some(used), Some(total)) = (self.memory_used_gb, self.memory_total_gb) {
            parts.push(format!("Memory: {used:.1}/{total:.1} GB"));
        } else if let Some(used) = self.memory_used_gb {
            parts.push(format!("Memory: {used:.1} GB"));
        }

        if let Some(load) = self.load_average {
            parts.push(format!("Load: {load:.1}"));
        }

        if let Some(disk) = self.disk_percent {
            parts.push(format!("Disk: {disk:.0}%"));
        }

        parts.join(" │ ")
    }
}

/// Signal information for killed builds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalInfo {
    /// Signal number (e.g., 9 for SIGKILL, 15 for SIGTERM).
    pub signal_number: i32,
    /// Signal name (e.g., "SIGKILL", "SIGTERM").
    pub signal_name: String,
    /// Whether this was likely an OOM kill.
    pub likely_oom: bool,
    /// Additional details about the kill.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl SignalInfo {
    /// Create from a signal number.
    #[must_use]
    pub fn from_signal(signal: i32) -> Self {
        let signal_name = match signal {
            1 => "SIGHUP",
            2 => "SIGINT",
            3 => "SIGQUIT",
            6 => "SIGABRT",
            9 => "SIGKILL",
            11 => "SIGSEGV",
            13 => "SIGPIPE",
            14 => "SIGALRM",
            15 => "SIGTERM",
            _ => "UNKNOWN",
        };

        // SIGKILL is the most common OOM signal
        let likely_oom = signal == 9;

        Self {
            signal_number: signal,
            signal_name: signal_name.to_string(),
            likely_oom,
            details: None,
        }
    }

    /// Create from an exit code (128 + signal).
    #[must_use]
    pub fn from_exit_code(exit_code: i32) -> Option<Self> {
        if exit_code > 128 && exit_code <= 128 + 64 {
            Some(Self::from_signal(exit_code - 128))
        } else {
            None
        }
    }

    /// Mark as OOM kill with details.
    #[must_use]
    pub fn with_oom_details(mut self, details: impl Into<String>) -> Self {
        self.likely_oom = true;
        self.details = Some(details.into());
        self
    }
}

/// BuildErrorDisplay - Rich error display for build/compilation errors.
///
/// Builds on [`ErrorPanel`] with build-specific context:
/// - Command that was executed
/// - Worker and timing information
/// - Compiler output passthrough
/// - Resource usage at error time
/// - Signal/kill information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildErrorDisplay {
    /// The underlying error code.
    pub error_code: ErrorCode,

    /// Build command that was executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// Worker where build ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_name: Option<String>,

    /// Build duration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<Duration>,

    /// Configured timeout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<Duration>,

    /// Last line(s) of build output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_output: Option<String>,

    /// Full compiler output (for passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_output: Option<String>,

    /// Worker resource state at error time.
    #[serde(default, skip_serializing_if = "is_default_resources")]
    pub resources: WorkerResourceState,

    /// Signal information for killed builds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_info: Option<SignalInfo>,

    /// Exit code from build process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    /// Artifact path (for missing artifact errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,

    /// Working directory on remote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,

    /// Toolchain being used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<String>,

    /// Whether this was a local or remote build.
    #[serde(default)]
    pub is_remote: bool,

    /// Custom message override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_message: Option<String>,

    /// Error chain (caused by).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caused_by: Vec<String>,
}

fn is_default_resources(r: &WorkerResourceState) -> bool {
    !r.has_data()
}

impl BuildErrorDisplay {
    // ========================================================================
    // CONSTRUCTORS FOR SPECIFIC ERROR TYPES
    // ========================================================================

    /// Create display for compilation failure (E300).
    #[must_use]
    pub fn compilation_failed(command: impl Into<String>) -> Self {
        Self::new(ErrorCode::BuildCompilationFailed).command(command)
    }

    /// Create display for unknown build command (E301).
    #[must_use]
    pub fn unknown_command(command: impl Into<String>) -> Self {
        Self::new(ErrorCode::BuildUnknownCommand).command(command)
    }

    /// Create display for build killed by signal (E302).
    #[must_use]
    pub fn killed_by_signal(signal: i32) -> Self {
        let signal_info = SignalInfo::from_signal(signal);
        let mut display = Self::new(ErrorCode::BuildKilledBySignal);
        display.signal_info = Some(signal_info);
        display
    }

    /// Create display for build killed by signal from exit code.
    #[must_use]
    pub fn killed_from_exit_code(exit_code: i32) -> Self {
        if let Some(signal_info) = SignalInfo::from_exit_code(exit_code) {
            let mut display = Self::new(ErrorCode::BuildKilledBySignal);
            display.signal_info = Some(signal_info);
            display.exit_code = Some(exit_code);
            display
        } else {
            let mut display = Self::new(ErrorCode::BuildCompilationFailed);
            display.exit_code = Some(exit_code);
            display
        }
    }

    /// Create display for build timeout (E303).
    #[must_use]
    pub fn build_timeout(command: impl Into<String>) -> Self {
        Self::new(ErrorCode::BuildTimeout).command(command)
    }

    /// Create display for build output capture error (E304).
    #[must_use]
    pub fn output_error() -> Self {
        Self::new(ErrorCode::BuildOutputError)
    }

    /// Create display for working directory error (E305).
    #[must_use]
    pub fn workdir_error(workdir: impl Into<String>) -> Self {
        let mut display = Self::new(ErrorCode::BuildWorkdirError);
        display.workdir = Some(workdir.into());
        display
    }

    /// Create display for toolchain error (E306).
    #[must_use]
    pub fn toolchain_error(toolchain: impl Into<String>) -> Self {
        let mut display = Self::new(ErrorCode::BuildToolchainError);
        display.toolchain = Some(toolchain.into());
        display
    }

    /// Create display for environment setup error (E307).
    #[must_use]
    pub fn env_error() -> Self {
        Self::new(ErrorCode::BuildEnvError)
    }

    /// Create display for incremental build corruption (E308).
    #[must_use]
    pub fn incremental_error() -> Self {
        Self::new(ErrorCode::BuildIncrementalError)
    }

    /// Create display for missing artifact (E309).
    #[must_use]
    pub fn artifact_missing(artifact_path: impl Into<String>) -> Self {
        let mut display = Self::new(ErrorCode::BuildArtifactMissing);
        display.artifact_path = Some(artifact_path.into());
        display
    }

    // ========================================================================
    // CORE CONSTRUCTOR
    // ========================================================================

    /// Create a new BuildErrorDisplay with error code.
    #[must_use]
    fn new(error_code: ErrorCode) -> Self {
        Self {
            error_code,
            command: None,
            worker_name: None,
            duration: None,
            timeout: None,
            last_output: None,
            compiler_output: None,
            resources: WorkerResourceState::default(),
            signal_info: None,
            exit_code: None,
            artifact_path: None,
            workdir: None,
            toolchain: None,
            is_remote: true,
            custom_message: None,
            caused_by: Vec::new(),
        }
    }

    // ========================================================================
    // BUILDER METHODS
    // ========================================================================

    /// Set the build command.
    #[must_use]
    pub fn command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Set the worker name.
    #[must_use]
    pub fn worker(mut self, worker: impl Into<String>) -> Self {
        self.worker_name = Some(worker.into());
        self
    }

    /// Set the build duration.
    #[must_use]
    pub fn duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    /// Set the build duration in seconds.
    #[must_use]
    pub fn duration_secs(self, secs: u64) -> Self {
        self.duration(Duration::from_secs(secs))
    }

    /// Set the configured timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the configured timeout in seconds.
    #[must_use]
    pub fn timeout_secs(self, secs: u64) -> Self {
        self.timeout(Duration::from_secs(secs))
    }

    /// Set the last line(s) of build output.
    #[must_use]
    pub fn last_output(mut self, output: impl Into<String>) -> Self {
        self.last_output = Some(output.into());
        self
    }

    /// Set the full compiler output for passthrough.
    #[must_use]
    pub fn compiler_output(mut self, output: impl Into<String>) -> Self {
        self.compiler_output = Some(output.into());
        self
    }

    /// Set CPU usage percentage.
    #[must_use]
    pub fn cpu_usage(mut self, percent: f64) -> Self {
        self.resources.cpu_percent = Some(percent);
        self
    }

    /// Set memory usage.
    #[must_use]
    pub fn memory_usage(mut self, used_gb: f64, total_gb: f64) -> Self {
        self.resources.memory_used_gb = Some(used_gb);
        self.resources.memory_total_gb = Some(total_gb);
        self
    }

    /// Set load average.
    #[must_use]
    pub fn load_average(mut self, load: f64) -> Self {
        self.resources.load_average = Some(load);
        self
    }

    /// Set disk usage percentage.
    #[must_use]
    pub fn disk_usage(mut self, percent: f64) -> Self {
        self.resources.disk_percent = Some(percent);
        self
    }

    /// Set the exit code.
    #[must_use]
    pub fn exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }

    /// Mark as local build (not remote).
    #[must_use]
    pub fn local(mut self) -> Self {
        self.is_remote = false;
        self
    }

    /// Set working directory.
    #[must_use]
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.workdir = Some(path.into());
        self
    }

    /// Set toolchain.
    #[must_use]
    pub fn toolchain(mut self, tc: impl Into<String>) -> Self {
        self.toolchain = Some(tc.into());
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

    /// Mark as OOM kill.
    #[must_use]
    pub fn mark_oom(mut self, details: impl Into<String>) -> Self {
        if let Some(ref mut info) = self.signal_info {
            info.likely_oom = true;
            info.details = Some(details.into());
        } else {
            self.signal_info = Some(SignalInfo::from_signal(9).with_oom_details(details));
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

        // Add command
        if let Some(ref cmd) = self.command {
            panel = panel.context("Command", cmd.clone());
        }

        // Add worker info
        if let Some(ref worker) = self.worker_name {
            let location = if self.is_remote { "remote" } else { "local" };
            panel = panel.context("Worker", format!("{worker} ({location})"));
        }

        // Add timing
        if let (Some(dur), Some(timeout)) = (self.duration, self.timeout) {
            panel = panel.context(
                "Duration",
                format!("{}s (timeout: {}s)", dur.as_secs(), timeout.as_secs()),
            );
        } else if let Some(dur) = self.duration {
            panel = panel.context("Duration", format!("{}s", dur.as_secs()));
        }

        // Add exit code
        if let Some(code) = self.exit_code {
            panel = panel.context("Exit code", code.to_string());
        }

        // Add signal info
        if let Some(ref sig) = self.signal_info {
            let sig_text = if sig.likely_oom {
                format!(
                    "{} (signal {}) - likely OOM",
                    sig.signal_name, sig.signal_number
                )
            } else {
                format!("{} (signal {})", sig.signal_name, sig.signal_number)
            };
            panel = panel.context("Signal", sig_text);
        }

        // Add toolchain
        if let Some(ref tc) = self.toolchain {
            panel = panel.context("Toolchain", tc.clone());
        }

        // Add workdir
        if let Some(ref wd) = self.workdir {
            panel = panel.context("Working directory", wd.clone());
        }

        // Add artifact path
        if let Some(ref path) = self.artifact_path {
            panel = panel.context("Artifact path", path.clone());
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
    ///
    /// For compilation errors, this preserves and enhances rustc/cargo output
    /// rather than replacing it.
    pub fn render(&self, ctx: OutputContext) {
        if ctx.is_machine() {
            // Machine mode - caller should use to_json()
            return;
        }

        // If we have compiler output, render it with RCH header/footer
        if let Some(ref compiler_output) = self.compiler_output {
            self.render_with_compiler_output(ctx, compiler_output);
            return;
        }

        #[cfg(feature = "rich-ui")]
        if ctx.supports_rich() {
            self.render_rich(ctx);
            return;
        }

        self.render_plain(ctx);
    }

    /// Render with compiler output passthrough.
    fn render_with_compiler_output(&self, ctx: OutputContext, compiler_output: &str) {
        let entry = self.error_code.entry();
        let icon = Icons::cross(ctx);

        // Header with RCH context
        eprintln!();
        eprintln!(
            "{icon} [RCH] Build failed on {}",
            self.worker_name.as_deref().unwrap_or("remote")
        );

        if let Some(ref cmd) = self.command {
            eprintln!("    Command: {cmd}");
        }
        if let Some(dur) = self.duration {
            eprintln!("    Duration: {}s", dur.as_secs());
        }
        eprintln!();

        // Pass through compiler output unchanged
        eprint!("{compiler_output}");

        // Footer with suggestions
        eprintln!();
        eprintln!("{icon} {} - {}", entry.code, entry.message);

        if self.resources.has_data() {
            eprintln!("    Worker state: {}", self.resources.format_line());
        }

        if !entry.remediation.is_empty() {
            eprintln!();
            eprintln!("Suggestions:");
            for (i, step) in entry.remediation.iter().enumerate() {
                eprintln!("  {}. {step}", i + 1);
            }
        }
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

        // Custom or signal message
        if let Some(ref msg) = self.custom_message {
            lines.push(msg.clone());
        } else if let Some(ref sig) = self.signal_info {
            if sig.likely_oom {
                lines.push(format!(
                    "Build process was killed by {} - likely out of memory",
                    sig.signal_name
                ));
            } else {
                lines.push(format!("Build process was killed by {}", sig.signal_name));
            }
        }

        // Command
        if let Some(ref cmd) = self.command {
            lines.push(String::new());
            lines.push(format!("[{}]Command:[/] {cmd}", RchTheme::DIM));
        }

        // Worker and timing
        if let Some(ref worker) = self.worker_name {
            let location = if self.is_remote { "remote" } else { "local" };
            lines.push(format!(
                "[{}]Worker:[/] {worker} ({location})",
                RchTheme::DIM
            ));
        }

        if let (Some(dur), Some(timeout)) = (self.duration, self.timeout) {
            lines.push(format!(
                "[{}]Duration:[/] {}s (timeout: {}s)",
                RchTheme::DIM,
                dur.as_secs(),
                timeout.as_secs()
            ));
        } else if let Some(dur) = self.duration {
            lines.push(format!(
                "[{}]Duration:[/] {}s",
                RchTheme::DIM,
                dur.as_secs()
            ));
        }

        // Last output
        if let Some(ref output) = self.last_output {
            lines.push(String::new());
            lines.push(format!("[{}]Last output:[/]", RchTheme::DIM));
            lines.push(format!("  {output}"));
        }

        // Worker resources
        if self.resources.has_data() {
            lines.push(String::new());
            lines.push(format!("[{}]Worker state at error:[/]", RchTheme::DIM));
            lines.push(format!("  {}", self.resources.format_line()));
        }

        // Signal details
        if let Some(ref sig) = self.signal_info
            && let Some(ref details) = sig.details
        {
            lines.push(String::new());
            lines.push(format!("[{}]Signal details:[/]", RchTheme::DIM));
            lines.push(format!("  {details}"));
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

        // Custom or signal message
        if let Some(ref msg) = self.custom_message {
            eprintln!();
            eprintln!("{msg}");
        } else if let Some(ref sig) = self.signal_info {
            eprintln!();
            if sig.likely_oom {
                eprintln!(
                    "Build process was killed by {} (signal {}) - likely out of memory",
                    sig.signal_name, sig.signal_number
                );
            } else {
                eprintln!(
                    "Build process was killed by {} (signal {})",
                    sig.signal_name, sig.signal_number
                );
            }
        }

        // Command
        if let Some(ref cmd) = self.command {
            eprintln!();
            eprintln!("Command: {cmd}");
        }

        // Worker and timing
        if let Some(ref worker) = self.worker_name {
            let location = if self.is_remote { "remote" } else { "local" };
            eprintln!("Worker: {worker} ({location})");
        }

        if let (Some(dur), Some(timeout)) = (self.duration, self.timeout) {
            eprintln!(
                "Duration: {}s (timeout: {}s)",
                dur.as_secs(),
                timeout.as_secs()
            );
        } else if let Some(dur) = self.duration {
            eprintln!("Duration: {}s", dur.as_secs());
        }

        // Exit code
        if let Some(code) = self.exit_code {
            eprintln!("Exit code: {code}");
        }

        // Toolchain and workdir
        if let Some(ref tc) = self.toolchain {
            eprintln!("Toolchain: {tc}");
        }
        if let Some(ref wd) = self.workdir {
            eprintln!("Working directory: {wd}");
        }
        if let Some(ref path) = self.artifact_path {
            eprintln!("Artifact path: {path}");
        }

        // Last output
        if let Some(ref output) = self.last_output {
            eprintln!();
            eprintln!("Last output:");
            eprintln!("  {output}");
        }

        // Worker resources
        if self.resources.has_data() {
            eprintln!();
            eprintln!("Worker state at error:");
            eprintln!("  {}", self.resources.format_line());
        }

        // Signal details
        if let Some(ref sig) = self.signal_info
            && let Some(ref details) = sig.details
        {
            eprintln!();
            eprintln!("Signal details: {details}");
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

impl std::fmt::Display for BuildErrorDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entry = self.error_code.entry();
        write!(f, "[ERROR] {}: {}", entry.code, entry.message)?;
        if let Some(ref msg) = self.custom_message {
            write!(f, " - {msg}")?;
        }
        Ok(())
    }
}

impl std::error::Error for BuildErrorDisplay {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compilation_failed_creation() {
        let display = BuildErrorDisplay::compilation_failed("cargo build");
        assert_eq!(display.error_code, ErrorCode::BuildCompilationFailed);
        assert_eq!(display.command, Some("cargo build".to_string()));
    }

    #[test]
    fn test_build_timeout_creation() {
        let display = BuildErrorDisplay::build_timeout("cargo build --release")
            .worker("build1")
            .duration_secs(300)
            .timeout_secs(300);

        assert_eq!(display.error_code, ErrorCode::BuildTimeout);
        assert_eq!(display.command, Some("cargo build --release".to_string()));
        assert_eq!(display.worker_name, Some("build1".to_string()));
        assert_eq!(display.duration, Some(Duration::from_secs(300)));
        assert_eq!(display.timeout, Some(Duration::from_secs(300)));
    }

    #[test]
    fn test_killed_by_signal() {
        let display = BuildErrorDisplay::killed_by_signal(9);
        assert_eq!(display.error_code, ErrorCode::BuildKilledBySignal);
        assert!(display.signal_info.is_some());

        let sig = display.signal_info.unwrap();
        assert_eq!(sig.signal_number, 9);
        assert_eq!(sig.signal_name, "SIGKILL");
        assert!(sig.likely_oom);
    }

    #[test]
    fn test_killed_from_exit_code() {
        // Exit code 137 = 128 + 9 (SIGKILL)
        let display = BuildErrorDisplay::killed_from_exit_code(137);
        assert_eq!(display.error_code, ErrorCode::BuildKilledBySignal);
        assert_eq!(display.exit_code, Some(137));

        let sig = display.signal_info.unwrap();
        assert_eq!(sig.signal_number, 9);
    }

    #[test]
    fn test_killed_from_regular_exit_code() {
        // Regular exit code (not signal-based)
        let display = BuildErrorDisplay::killed_from_exit_code(1);
        assert_eq!(display.error_code, ErrorCode::BuildCompilationFailed);
        assert!(display.signal_info.is_none());
    }

    #[test]
    fn test_worker_resources() {
        let display = BuildErrorDisplay::build_timeout("cargo build")
            .cpu_usage(98.0)
            .memory_usage(14.2, 16.0)
            .load_average(8.5)
            .disk_usage(75.0);

        assert!(display.resources.has_data());
        assert_eq!(display.resources.cpu_percent, Some(98.0));
        assert_eq!(display.resources.memory_used_gb, Some(14.2));
        assert_eq!(display.resources.memory_total_gb, Some(16.0));
        assert_eq!(display.resources.load_average, Some(8.5));
        assert_eq!(display.resources.disk_percent, Some(75.0));
    }

    #[test]
    fn test_resource_format_line() {
        let resources = WorkerResourceState {
            cpu_percent: Some(98.0),
            memory_used_gb: Some(14.2),
            memory_total_gb: Some(16.0),
            load_average: Some(8.5),
            ..Default::default()
        };

        let line = resources.format_line();
        assert!(line.contains("CPU: 98%"));
        assert!(line.contains("Memory: 14.2/16.0 GB"));
        assert!(line.contains("Load: 8.5"));
    }

    #[test]
    fn test_artifact_missing() {
        let display = BuildErrorDisplay::artifact_missing("target/release/myapp");
        assert_eq!(display.error_code, ErrorCode::BuildArtifactMissing);
        assert_eq!(
            display.artifact_path,
            Some("target/release/myapp".to_string())
        );
    }

    #[test]
    fn test_toolchain_error() {
        let display = BuildErrorDisplay::toolchain_error("nightly-2024-01-15");
        assert_eq!(display.error_code, ErrorCode::BuildToolchainError);
        assert_eq!(display.toolchain, Some("nightly-2024-01-15".to_string()));
    }

    #[test]
    fn test_workdir_error() {
        let display = BuildErrorDisplay::workdir_error("/tmp/rch/project");
        assert_eq!(display.error_code, ErrorCode::BuildWorkdirError);
        assert_eq!(display.workdir, Some("/tmp/rch/project".to_string()));
    }

    #[test]
    fn test_builder_chain() {
        let display = BuildErrorDisplay::compilation_failed("cargo test")
            .worker("build2")
            .duration_secs(45)
            .exit_code(101)
            .last_output("test result: FAILED. 3 passed; 2 failed;")
            .caused_by("Test assertion failed")
            .message("Tests failed on remote worker");

        assert_eq!(display.worker_name, Some("build2".to_string()));
        assert_eq!(display.duration, Some(Duration::from_secs(45)));
        assert_eq!(display.exit_code, Some(101));
        assert!(display.last_output.is_some());
        assert_eq!(display.caused_by.len(), 1);
        assert!(display.custom_message.is_some());
    }

    #[test]
    fn test_local_build() {
        let display = BuildErrorDisplay::compilation_failed("cargo build").local();
        assert!(!display.is_remote);
    }

    #[test]
    fn test_mark_oom() {
        let display = BuildErrorDisplay::killed_by_signal(9)
            .mark_oom("OOM killer triggered at 15.9GB memory usage");

        let sig = display.signal_info.unwrap();
        assert!(sig.likely_oom);
        assert!(sig.details.is_some());
        assert!(sig.details.unwrap().contains("OOM killer"));
    }

    #[test]
    fn test_to_error_panel() {
        let display = BuildErrorDisplay::build_timeout("cargo build --release")
            .worker("build1")
            .duration_secs(300)
            .timeout_secs(300);

        let panel = display.to_error_panel();
        assert_eq!(panel.code, "RCH-E303");
    }

    #[test]
    fn test_json_serialization() {
        let display = BuildErrorDisplay::build_timeout("cargo build")
            .worker("build1")
            .cpu_usage(95.0);

        let json = display.to_json().expect("JSON serialization failed");
        assert!(json.contains("cargo build"));
        assert!(json.contains("build1"));
        assert!(json.contains("95"));
    }

    #[test]
    fn test_json_compact() {
        let display = BuildErrorDisplay::compilation_failed("cargo test");
        let json = display
            .to_json_compact()
            .expect("JSON serialization failed");
        assert!(!json.contains('\n'));
    }

    #[test]
    fn test_display_implementation() {
        let display =
            BuildErrorDisplay::build_timeout("cargo build").message("Custom timeout message");

        let output = format!("{display}");
        assert!(output.contains("RCH-E303"));
        assert!(output.contains("Custom timeout message"));
    }

    #[test]
    fn test_render_plain_no_panic() {
        let display = BuildErrorDisplay::build_timeout("cargo build --release")
            .worker("build1")
            .duration_secs(300)
            .timeout_secs(300)
            .last_output("Compiling serde_derive v1.0.152")
            .cpu_usage(98.0)
            .memory_usage(14.2, 16.0);

        // Should not panic
        display.render(OutputContext::Plain);
    }

    #[test]
    fn test_render_machine_silent() {
        let display = BuildErrorDisplay::compilation_failed("cargo build");
        // Should not output anything in machine mode
        display.render(OutputContext::Machine);
    }

    #[test]
    fn test_signal_info_from_exit_code_invalid() {
        // Too low
        assert!(SignalInfo::from_exit_code(128).is_none());
        // Too high
        assert!(SignalInfo::from_exit_code(200).is_none());
        // Valid range
        assert!(SignalInfo::from_exit_code(137).is_some()); // 128 + 9
        assert!(SignalInfo::from_exit_code(143).is_some()); // 128 + 15
    }

    #[test]
    fn test_all_error_constructors() {
        assert_eq!(
            BuildErrorDisplay::compilation_failed("cmd").error_code,
            ErrorCode::BuildCompilationFailed
        );
        assert_eq!(
            BuildErrorDisplay::unknown_command("cmd").error_code,
            ErrorCode::BuildUnknownCommand
        );
        assert_eq!(
            BuildErrorDisplay::killed_by_signal(9).error_code,
            ErrorCode::BuildKilledBySignal
        );
        assert_eq!(
            BuildErrorDisplay::build_timeout("cmd").error_code,
            ErrorCode::BuildTimeout
        );
        assert_eq!(
            BuildErrorDisplay::output_error().error_code,
            ErrorCode::BuildOutputError
        );
        assert_eq!(
            BuildErrorDisplay::workdir_error("path").error_code,
            ErrorCode::BuildWorkdirError
        );
        assert_eq!(
            BuildErrorDisplay::toolchain_error("nightly").error_code,
            ErrorCode::BuildToolchainError
        );
        assert_eq!(
            BuildErrorDisplay::env_error().error_code,
            ErrorCode::BuildEnvError
        );
        assert_eq!(
            BuildErrorDisplay::incremental_error().error_code,
            ErrorCode::BuildIncrementalError
        );
        assert_eq!(
            BuildErrorDisplay::artifact_missing("path").error_code,
            ErrorCode::BuildArtifactMissing
        );
    }

    #[test]
    fn test_error_trait() {
        let display: Box<dyn std::error::Error> =
            Box::new(BuildErrorDisplay::compilation_failed("cargo build"));
        let _ = format!("{display}");
    }

    #[test]
    fn test_empty_resources() {
        let resources = WorkerResourceState::default();
        assert!(!resources.has_data());
        assert!(resources.format_line().is_empty());
    }

    #[test]
    fn test_partial_resources() {
        let resources = WorkerResourceState {
            cpu_percent: Some(50.0),
            ..Default::default()
        };
        assert!(resources.has_data());

        let line = resources.format_line();
        assert!(line.contains("CPU: 50%"));
        assert!(!line.contains("Memory"));
    }

    #[test]
    fn test_compiler_output_passthrough() {
        let display = BuildErrorDisplay::compilation_failed("cargo build")
            .worker("build1")
            .compiler_output("error[E0308]: mismatched types\n  --> src/main.rs:5:5");

        assert!(display.compiler_output.is_some());
    }
}
