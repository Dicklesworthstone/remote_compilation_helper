//! E2E Test Logging Library
//!
//! Provides comprehensive logging infrastructure for end-to-end tests.
//!
//! - Real-time console output (human-readable)
//! - Per-test JSONL log files under `target/test-logs/` (machine-readable)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, File};
use std::io::{BufWriter, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Find the workspace root by walking up from a path until we find a Cargo.toml
/// that contains `[workspace]` or has a `target/` subdirectory with actual builds.
fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    // Handle case where start is a file (e.g., manifest path)
    if current.is_file() {
        current = current.parent()?.to_path_buf();
    }

    // First pass: look for workspace root marker
    let mut candidate = current.clone();
    loop {
        let cargo_toml = candidate.join("Cargo.toml");
        if cargo_toml.exists() {
            // Check if this is the workspace root by looking for [workspace]
            if let Ok(contents) = std::fs::read_to_string(&cargo_toml)
                && contents.contains("[workspace]")
            {
                return Some(candidate);
            }
            // Also check if target/debug or target/release exists (indicates build root)
            let target = candidate.join("target");
            if target.join("debug").exists() || target.join("release").exists() {
                return Some(candidate);
            }
        }
        // Move up one level
        match candidate.parent() {
            Some(parent) if parent != candidate => candidate = parent.to_path_buf(),
            _ => break,
        }
    }

    // Fallback: walk up and find first directory with target/
    loop {
        if current.join("target").exists() {
            return Some(current);
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent.to_path_buf(),
            _ => break,
        }
    }

    // Last resort: just use the start directory
    start.parent().map(|p| p.to_path_buf())
}

/// Log severity levels for E2E tests
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Very fine-grained diagnostic information
    Trace,
    /// Detailed diagnostic information
    Debug,
    /// Normal operational information
    Info,
    /// Potential issues that don't prevent operation
    Warn,
    /// Errors that may cause test failure
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        };
        write!(f, "{s}")
    }
}

impl LogLevel {
    /// Returns the ANSI color code for this log level
    pub fn color_code(&self) -> &'static str {
        match self {
            LogLevel::Trace => "\x1b[90m", // Gray
            LogLevel::Debug => "\x1b[36m", // Cyan
            LogLevel::Info => "\x1b[32m",  // Green
            LogLevel::Warn => "\x1b[33m",  // Yellow
            LogLevel::Error => "\x1b[31m", // Red
        }
    }
}

/// Source of a log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    /// Log from the test harness itself
    Harness,
    /// Stdout from a spawned process
    ProcessStdout { name: String, pid: u32 },
    /// Stderr from a spawned process
    ProcessStderr { name: String, pid: u32 },
    /// Log from the daemon process
    Daemon,
    /// Log from a worker process
    Worker { id: String },
    /// Log from the hook process
    Hook,
    /// Custom source
    Custom(String),
}

impl fmt::Display for LogSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogSource::Harness => write!(f, "harness"),
            LogSource::ProcessStdout { name, pid } => write!(f, "{name}:{pid}:stdout"),
            LogSource::ProcessStderr { name, pid } => write!(f, "{name}:{pid}:stderr"),
            LogSource::Daemon => write!(f, "daemon"),
            LogSource::Worker { id } => write!(f, "worker:{id}"),
            LogSource::Hook => write!(f, "hook"),
            LogSource::Custom(s) => write!(f, "{s}"),
        }
    }
}

/// A single log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp when the log was created
    pub timestamp: DateTime<Utc>,
    /// Elapsed time since test start
    pub elapsed_ms: u64,
    /// Severity level
    pub level: LogLevel,
    /// Source of the log
    pub source: LogSource,
    /// Log message
    pub message: String,
    /// Optional context key-value pairs
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<(String, String)>,
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:>6}ms] [{:<5}] [{}] {}",
            self.elapsed_ms, self.level, self.source, self.message
        )?;
        if !self.context.is_empty() {
            write!(f, " {{")?;
            for (i, (k, v)) in self.context.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{k}={v}")?;
            }
            write!(f, "}}")?;
        }
        Ok(())
    }
}

impl LogEntry {
    /// Format the log entry with ANSI colors
    pub fn format_colored(&self) -> String {
        let reset = "\x1b[0m";
        let color = self.level.color_code();
        let dim = "\x1b[2m";

        let ctx = if self.context.is_empty() {
            String::new()
        } else {
            let pairs: Vec<_> = self
                .context
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            format!(" {dim}{{{}}}{reset}", pairs.join(", "))
        };

        format!(
            "{dim}[{:>6}ms]{reset} {color}[{:<5}]{reset} {dim}[{}]{reset} {}{ctx}",
            self.elapsed_ms, self.level, self.source, self.message
        )
    }
}

/// Stable schema version for reliability phase events.
pub const RELIABILITY_EVENT_SCHEMA_VERSION: &str = "1.0.0";

/// Reliability test phase used for lifecycle-oriented logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReliabilityPhase {
    Setup,
    Execute,
    Verify,
    Cleanup,
}

impl fmt::Display for ReliabilityPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self {
            Self::Setup => "setup",
            Self::Execute => "execute",
            Self::Verify => "verify",
            Self::Cleanup => "cleanup",
        };
        write!(f, "{phase}")
    }
}

/// Context payload attached to each reliability phase event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliabilityContext {
    pub worker_id: Option<String>,
    pub repo_set: Vec<String>,
    pub pressure_state: Option<String>,
    pub triage_actions: Vec<String>,
    pub decision_code: String,
    pub fallback_reason: Option<String>,
}

impl ReliabilityContext {
    /// Build a context with required decision code and no optional fields.
    pub fn decision_only(decision_code: impl Into<String>) -> Self {
        Self {
            worker_id: None,
            repo_set: Vec::new(),
            pressure_state: None,
            triage_actions: Vec::new(),
            decision_code: decision_code.into(),
            fallback_reason: None,
        }
    }
}

/// Machine-readable reliability phase event schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilityPhaseEvent {
    pub schema_version: String,
    pub timestamp: DateTime<Utc>,
    pub elapsed_ms: u64,
    pub level: LogLevel,
    pub phase: ReliabilityPhase,
    pub scenario_id: String,
    pub message: String,
    pub context: ReliabilityContext,
    pub artifact_paths: Vec<String>,
}

/// Input contract for emitting reliability phase events.
#[derive(Debug, Clone)]
pub struct ReliabilityEventInput {
    pub level: LogLevel,
    pub phase: ReliabilityPhase,
    pub scenario_id: String,
    pub message: String,
    pub context: ReliabilityContext,
    pub artifact_paths: Vec<String>,
}

impl ReliabilityEventInput {
    /// Convenience constructor for phase+scenario+decision-only events.
    pub fn with_decision(
        phase: ReliabilityPhase,
        scenario_id: impl Into<String>,
        message: impl Into<String>,
        decision_code: impl Into<String>,
    ) -> Self {
        Self {
            level: LogLevel::Info,
            phase,
            scenario_id: scenario_id.into(),
            message: message.into(),
            context: ReliabilityContext::decision_only(decision_code),
            artifact_paths: Vec::new(),
        }
    }
}

/// Configuration for the test logger
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    /// Minimum log level to capture
    pub min_level: LogLevel,
    /// Whether to print logs to stdout in real-time
    pub print_realtime: bool,
    /// Whether to use ANSI colors when printing
    pub use_colors: bool,
    /// Maximum number of entries to keep in memory (0 = unlimited)
    pub max_entries: usize,
    /// Directory for persisting logs
    pub log_dir: Option<PathBuf>,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            min_level: LogLevel::Debug,
            print_realtime: true,
            use_colors: true,
            max_entries: 10_000,
            log_dir: None,
        }
    }
}

/// Thread-safe test logger that captures logs during E2E tests
#[derive(Clone)]
pub struct TestLogger {
    config: Arc<RwLock<LoggerConfig>>,
    entries: Arc<Mutex<VecDeque<LogEntry>>>,
    start_time: Instant,
    test_name: Arc<String>,
    file_writer: Arc<Mutex<Option<BufWriter<File>>>>,
    reliability_writer: Arc<Mutex<Option<BufWriter<File>>>>,
    reliability_log_path: Arc<Option<PathBuf>>,
    artifact_root: Arc<Option<PathBuf>>,
}

impl TestLogger {
    /// Create a new test logger with the given configuration
    pub fn new(test_name: &str, config: LoggerConfig) -> Self {
        let mut file_writer = None;
        let mut reliability_writer = None;
        let mut reliability_log_path = None;
        let mut artifact_root = None;

        if let Some(ref dir) = config.log_dir
            && fs::create_dir_all(dir).is_ok()
        {
            let sanitized_test_name = test_name.replace("::", "_").replace(' ', "_");
            let timestamp = Utc::now().format("%Y%m%d_%H%M%S");

            let log_path = dir.join(format!("{sanitized_test_name}_{timestamp}.jsonl"));
            match File::create(&log_path) {
                Ok(file) => file_writer = Some(BufWriter::new(file)),
                Err(error) => {
                    eprintln!(
                        "Warning: Failed to create log file {}: {error}",
                        log_path.display()
                    );
                }
            }

            let reliability_path = dir.join(format!(
                "reliability_{sanitized_test_name}_{timestamp}.jsonl"
            ));
            match File::create(&reliability_path) {
                Ok(file) => {
                    reliability_writer = Some(BufWriter::new(file));
                    reliability_log_path = Some(reliability_path);
                }
                Err(error) => {
                    eprintln!(
                        "Warning: Failed to create reliability log file {}: {error}",
                        reliability_path.display()
                    );
                }
            }

            let artifacts_dir = dir.join("artifacts");
            if fs::create_dir_all(&artifacts_dir).is_ok() {
                artifact_root = Some(artifacts_dir);
            }
        }

        Self {
            config: Arc::new(RwLock::new(config)),
            entries: Arc::new(Mutex::new(VecDeque::new())),
            start_time: Instant::now(),
            test_name: Arc::new(test_name.to_string()),
            file_writer: Arc::new(Mutex::new(file_writer)),
            reliability_writer: Arc::new(Mutex::new(reliability_writer)),
            reliability_log_path: Arc::new(reliability_log_path),
            artifact_root: Arc::new(artifact_root),
        }
    }

    /// Create a logger with default configuration
    pub fn default_for_test(test_name: &str) -> Self {
        Self::new(test_name, LoggerConfig::default())
    }

    /// Get the test name
    pub fn test_name(&self) -> &str {
        &self.test_name
    }

    /// Get elapsed time since logger creation
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Log an entry with the given level and source
    pub fn log(&self, level: LogLevel, source: LogSource, message: impl Into<String>) {
        self.log_with_context(level, source, message, Vec::new());
    }

    /// Log an entry with context key-value pairs
    pub fn log_with_context(
        &self,
        level: LogLevel,
        source: LogSource,
        message: impl Into<String>,
        context: Vec<(String, String)>,
    ) {
        let config = self.config.read().unwrap();
        if level < config.min_level {
            return;
        }

        let entry = LogEntry {
            timestamp: Utc::now(),
            elapsed_ms: self.start_time.elapsed().as_millis() as u64,
            level,
            source,
            message: message.into(),
            context,
        };

        // Print to stdout if configured
        if config.print_realtime {
            if config.use_colors {
                println!("{}", entry.format_colored());
            } else {
                println!("{entry}");
            }
        }

        // Write JSONL to file if configured
        if let Ok(mut writer) = self.file_writer.lock()
            && let Some(ref mut w) = *writer
            && let Ok(json) = serde_json::to_string(&entry)
        {
            let _ = writeln!(w, "{json}");
            let _ = w.flush();
        }

        // Store in memory
        let mut entries = self.entries.lock().unwrap();
        entries.push_back(entry);
        if config.max_entries > 0 && entries.len() > config.max_entries {
            entries.pop_front();
        }
    }

    /// Returns the reliability JSONL path if reliability logging is enabled.
    pub fn reliability_log_path(&self) -> Option<&Path> {
        self.reliability_log_path.as_deref()
    }

    /// Emit a structured reliability event using the stable schema contract.
    pub fn log_reliability_event(&self, input: ReliabilityEventInput) -> ReliabilityPhaseEvent {
        let event = ReliabilityPhaseEvent {
            schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
            timestamp: Utc::now(),
            elapsed_ms: self.start_time.elapsed().as_millis() as u64,
            level: input.level,
            phase: input.phase,
            scenario_id: input.scenario_id,
            message: input.message,
            context: input.context,
            artifact_paths: input.artifact_paths,
        };

        let mut log_context = vec![
            ("schema_version".to_string(), event.schema_version.clone()),
            ("phase".to_string(), event.phase.to_string()),
            ("scenario_id".to_string(), event.scenario_id.clone()),
            (
                "decision_code".to_string(),
                event.context.decision_code.clone(),
            ),
        ];
        if let Some(worker_id) = event.context.worker_id.as_ref() {
            log_context.push(("worker_id".to_string(), worker_id.clone()));
        }
        if !event.context.repo_set.is_empty() {
            log_context.push(("repo_set".to_string(), event.context.repo_set.join(",")));
        }
        if let Some(pressure_state) = event.context.pressure_state.as_ref() {
            log_context.push(("pressure_state".to_string(), pressure_state.clone()));
        }
        if !event.context.triage_actions.is_empty() {
            log_context.push((
                "triage_actions".to_string(),
                event.context.triage_actions.join(","),
            ));
        }
        if let Some(fallback_reason) = event.context.fallback_reason.as_ref() {
            log_context.push(("fallback_reason".to_string(), fallback_reason.clone()));
        }
        if !event.artifact_paths.is_empty() {
            log_context.push(("artifact_paths".to_string(), event.artifact_paths.join(",")));
        }

        self.log_with_context(
            event.level,
            LogSource::Harness,
            format!("[{}] {}", event.phase, event.message),
            log_context,
        );

        if let Ok(mut writer_guard) = self.reliability_writer.lock()
            && let Some(ref mut writer) = *writer_guard
            && let Ok(serialized) = serde_json::to_string(&event)
        {
            let _ = writeln!(writer, "{serialized}");
            let _ = writer.flush();
        }

        event
    }

    /// Persist a text artifact for replay/postmortem analysis.
    pub fn capture_artifact_text(
        &self,
        scenario_id: &str,
        artifact_name: &str,
        content: &str,
    ) -> std::io::Result<PathBuf> {
        let Some(artifact_root) = self.artifact_root.as_deref() else {
            return Err(std::io::Error::other(
                "artifact capture requires logger log_dir to be configured",
            ));
        };

        let scenario_dir = artifact_root.join(Self::sanitize_artifact_component(scenario_id));
        fs::create_dir_all(&scenario_dir)?;
        let artifact_path = scenario_dir.join(format!(
            "{}.txt",
            Self::sanitize_artifact_component(artifact_name)
        ));
        fs::write(&artifact_path, content)?;
        Ok(artifact_path)
    }

    /// Persist a JSON artifact for replay/postmortem analysis.
    pub fn capture_artifact_json<T: Serialize>(
        &self,
        scenario_id: &str,
        artifact_name: &str,
        value: &T,
    ) -> std::io::Result<PathBuf> {
        let serialized = serde_json::to_string_pretty(value).map_err(|error| {
            std::io::Error::other(format!("failed to serialize artifact json: {error}"))
        })?;
        let Some(artifact_root) = self.artifact_root.as_deref() else {
            return Err(std::io::Error::other(
                "artifact capture requires logger log_dir to be configured",
            ));
        };

        let scenario_dir = artifact_root.join(Self::sanitize_artifact_component(scenario_id));
        fs::create_dir_all(&scenario_dir)?;
        let artifact_path = scenario_dir.join(format!(
            "{}.json",
            Self::sanitize_artifact_component(artifact_name)
        ));
        fs::write(&artifact_path, serialized)?;
        Ok(artifact_path)
    }

    fn sanitize_artifact_component(raw: &str) -> String {
        let mut cleaned = String::with_capacity(raw.len());
        for ch in raw.chars() {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                cleaned.push(ch);
            } else {
                cleaned.push('_');
            }
        }
        if cleaned.is_empty() {
            "artifact".to_string()
        } else {
            cleaned
        }
    }

    /// Log a trace message from the harness
    pub fn trace(&self, message: impl Into<String>) {
        self.log(LogLevel::Trace, LogSource::Harness, message);
    }

    /// Log a debug message from the harness
    pub fn debug(&self, message: impl Into<String>) {
        self.log(LogLevel::Debug, LogSource::Harness, message);
    }

    /// Log an info message from the harness
    pub fn info(&self, message: impl Into<String>) {
        self.log(LogLevel::Info, LogSource::Harness, message);
    }

    /// Log a warning message from the harness
    pub fn warn(&self, message: impl Into<String>) {
        self.log(LogLevel::Warn, LogSource::Harness, message);
    }

    /// Log an error message from the harness
    pub fn error(&self, message: impl Into<String>) {
        self.log(LogLevel::Error, LogSource::Harness, message);
    }

    /// Log process stdout
    pub fn log_stdout(&self, process_name: &str, pid: u32, message: impl Into<String>) {
        self.log(
            LogLevel::Debug,
            LogSource::ProcessStdout {
                name: process_name.to_string(),
                pid,
            },
            message,
        );
    }

    /// Log process stderr
    pub fn log_stderr(&self, process_name: &str, pid: u32, message: impl Into<String>) {
        self.log(
            LogLevel::Warn,
            LogSource::ProcessStderr {
                name: process_name.to_string(),
                pid,
            },
            message,
        );
    }

    /// Log a daemon message
    pub fn log_daemon(&self, level: LogLevel, message: impl Into<String>) {
        self.log(level, LogSource::Daemon, message);
    }

    /// Log a worker message
    pub fn log_worker(&self, worker_id: &str, level: LogLevel, message: impl Into<String>) {
        self.log(
            level,
            LogSource::Worker {
                id: worker_id.to_string(),
            },
            message,
        );
    }

    /// Log a hook message
    pub fn log_hook(&self, level: LogLevel, message: impl Into<String>) {
        self.log(level, LogSource::Hook, message);
    }

    /// Get all log entries
    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries.lock().unwrap().iter().cloned().collect()
    }

    /// Get entries filtered by level
    pub fn entries_by_level(&self, min_level: LogLevel) -> Vec<LogEntry> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.level >= min_level)
            .cloned()
            .collect()
    }

    /// Get entries filtered by source
    pub fn entries_by_source(&self, source_prefix: &str) -> Vec<LogEntry> {
        let prefix = source_prefix.to_lowercase();
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.source.to_string().to_lowercase().starts_with(&prefix))
            .cloned()
            .collect()
    }

    /// Search entries by message content
    pub fn search(&self, pattern: &str) -> Vec<LogEntry> {
        let pattern_lower = pattern.to_lowercase();
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.message.to_lowercase().contains(&pattern_lower))
            .cloned()
            .collect()
    }

    /// Check if any errors were logged
    pub fn has_errors(&self) -> bool {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.level == LogLevel::Error)
    }

    /// Get error count
    pub fn error_count(&self) -> usize {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.level == LogLevel::Error)
            .count()
    }

    /// Get warning count
    pub fn warn_count(&self) -> usize {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.level == LogLevel::Warn)
            .count()
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }

    /// Export logs to JSON
    pub fn export_json(&self) -> String {
        let entries = self.entries();
        serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
    }

    /// Export logs to a JSON file
    pub fn export_json_to_file(&self, path: &Path) -> std::io::Result<()> {
        let json = self.export_json();
        fs::write(path, json)
    }

    /// Generate a test summary
    pub fn summary(&self) -> TestLogSummary {
        let entries = self.entries.lock().unwrap();
        let mut summary = TestLogSummary {
            test_name: self.test_name.to_string(),
            total_entries: entries.len(),
            duration_ms: self.elapsed().as_millis() as u64,
            counts_by_level: [
                (LogLevel::Trace, 0),
                (LogLevel::Debug, 0),
                (LogLevel::Info, 0),
                (LogLevel::Warn, 0),
                (LogLevel::Error, 0),
            ]
            .into_iter()
            .collect(),
            first_error: None,
            last_error: None,
        };

        for entry in entries.iter() {
            *summary.counts_by_level.entry(entry.level).or_insert(0) += 1;
            if entry.level == LogLevel::Error {
                if summary.first_error.is_none() {
                    summary.first_error = Some(entry.message.clone());
                }
                summary.last_error = Some(entry.message.clone());
            }
        }

        summary
    }

    /// Print a formatted summary to stdout
    pub fn print_summary(&self) {
        let summary = self.summary();
        println!("\n{}", "=".repeat(60));
        println!("Test Log Summary: {}", summary.test_name);
        println!("{}", "=".repeat(60));
        println!("Duration: {}ms", summary.duration_ms);
        println!("Total entries: {}", summary.total_entries);
        println!(
            "  TRACE: {}",
            summary.counts_by_level.get(&LogLevel::Trace).unwrap_or(&0)
        );
        println!(
            "  DEBUG: {}",
            summary.counts_by_level.get(&LogLevel::Debug).unwrap_or(&0)
        );
        println!(
            "  INFO:  {}",
            summary.counts_by_level.get(&LogLevel::Info).unwrap_or(&0)
        );
        println!(
            "  WARN:  {}",
            summary.counts_by_level.get(&LogLevel::Warn).unwrap_or(&0)
        );
        println!(
            "  ERROR: {}",
            summary.counts_by_level.get(&LogLevel::Error).unwrap_or(&0)
        );
        if let Some(ref err) = summary.first_error {
            println!("First error: {err}");
        }
        if let Some(ref err) = summary.last_error
            && summary.first_error.as_ref() != Some(err)
        {
            println!("Last error: {err}");
        }
        println!("{}", "=".repeat(60));
    }
}

/// Summary of test logs
#[derive(Debug, Clone, Serialize)]
pub struct TestLogSummary {
    pub test_name: String,
    pub total_entries: usize,
    pub duration_ms: u64,
    pub counts_by_level: std::collections::HashMap<LogLevel, usize>,
    pub first_error: Option<String>,
    pub last_error: Option<String>,
}

/// Builder for creating a TestLogger with custom configuration
pub struct TestLoggerBuilder {
    test_name: String,
    config: LoggerConfig,
}

impl TestLoggerBuilder {
    /// Create a new builder for the given test name.
    ///
    /// By default, logs are written to `target/test-logs/` relative to the
    /// workspace root (auto-detected via CARGO_MANIFEST_DIR) as JSONL (one
    /// JSON object per line).
    pub fn new(test_name: &str) -> Self {
        // Auto-set log directory for standardized JSONL output
        let config = LoggerConfig {
            log_dir: Self::auto_detect_log_dir(),
            ..Default::default()
        };
        Self {
            test_name: test_name.to_string(),
            config,
        }
    }

    /// Auto-detect the log directory based on cargo workspace.
    /// Returns `target/test-logs/` relative to workspace root.
    fn auto_detect_log_dir() -> Option<PathBuf> {
        // Try CARGO_MANIFEST_DIR first (set during cargo test)
        if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
            let manifest_path = PathBuf::from(&manifest_dir);
            // Walk up to find workspace root (has target/ directory)
            let workspace_root = find_workspace_root(&manifest_path)?;
            let log_dir = workspace_root.join("target").join("test-logs");
            // Create directory if it doesn't exist
            let _ = fs::create_dir_all(&log_dir);
            return Some(log_dir);
        }
        // Fallback: try current directory
        if let Ok(cwd) = std::env::current_dir() {
            let log_dir = cwd.join("target").join("test-logs");
            if log_dir.parent().map(|p| p.exists()).unwrap_or(false) {
                let _ = fs::create_dir_all(&log_dir);
                return Some(log_dir);
            }
        }
        None
    }

    /// Set the minimum log level
    pub fn min_level(mut self, level: LogLevel) -> Self {
        self.config.min_level = level;
        self
    }

    /// Enable or disable real-time printing
    pub fn print_realtime(mut self, enabled: bool) -> Self {
        self.config.print_realtime = enabled;
        self
    }

    /// Enable or disable ANSI colors
    pub fn use_colors(mut self, enabled: bool) -> Self {
        self.config.use_colors = enabled;
        self
    }

    /// Set the maximum number of entries to keep in memory
    pub fn max_entries(mut self, max: usize) -> Self {
        self.config.max_entries = max;
        self
    }

    /// Set the log directory for file persistence
    pub fn log_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config.log_dir = Some(dir.into());
        self
    }

    /// Build the TestLogger
    pub fn build(self) -> TestLogger {
        TestLogger::new(&self.test_name, self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_levels_order() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_logger_basic() {
        let logger = TestLoggerBuilder::new("test_basic")
            .print_realtime(false)
            .build();

        logger.info("Test message");
        logger.warn("Warning message");
        logger.error("Error message");

        assert_eq!(logger.entries().len(), 3);
        assert!(logger.has_errors());
        assert_eq!(logger.error_count(), 1);
        assert_eq!(logger.warn_count(), 1);
    }

    #[test]
    fn test_logger_filtering() {
        let logger = TestLoggerBuilder::new("test_filtering")
            .print_realtime(false)
            .min_level(LogLevel::Info)
            .build();

        logger.trace("Trace message");
        logger.debug("Debug message");
        logger.info("Info message");

        // Only info should be captured (trace and debug filtered out)
        assert_eq!(logger.entries().len(), 1);
    }

    #[test]
    fn test_logger_search() {
        let logger = TestLoggerBuilder::new("test_search")
            .print_realtime(false)
            .build();

        logger.info("Starting daemon");
        logger.info("Daemon ready");
        logger.info("Worker connected");

        let daemon_logs = logger.search("daemon");
        assert_eq!(daemon_logs.len(), 2);
    }

    #[test]
    fn test_logger_context() {
        let logger = TestLoggerBuilder::new("test_context")
            .print_realtime(false)
            .build();

        logger.log_with_context(
            LogLevel::Info,
            LogSource::Harness,
            "Worker selected",
            vec![
                ("worker_id".to_string(), "css".to_string()),
                ("slots".to_string(), "4".to_string()),
            ],
        );

        let entries = logger.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].context.len(), 2);
    }

    #[test]
    fn test_logger_max_entries() {
        let logger = TestLoggerBuilder::new("test_max_entries")
            .print_realtime(false)
            .max_entries(5)
            .build();

        for i in 0..10 {
            logger.info(format!("Message {i}"));
        }

        let entries = logger.entries();
        assert_eq!(entries.len(), 5);
        // Should keep the most recent entries
        assert!(entries[0].message.contains("5"));
        assert!(entries[4].message.contains("9"));
    }

    #[test]
    fn test_logger_summary() {
        let logger = TestLoggerBuilder::new("test_summary")
            .print_realtime(false)
            .build();

        logger.debug("Debug 1");
        logger.debug("Debug 2");
        logger.info("Info 1");
        logger.warn("Warn 1");
        logger.error("First error");
        logger.error("Last error");

        let summary = logger.summary();
        assert_eq!(summary.test_name, "test_summary");
        assert_eq!(summary.total_entries, 6);
        assert_eq!(summary.counts_by_level.get(&LogLevel::Debug), Some(&2));
        assert_eq!(summary.counts_by_level.get(&LogLevel::Error), Some(&2));
        assert_eq!(summary.first_error, Some("First error".to_string()));
        assert_eq!(summary.last_error, Some("Last error".to_string()));
    }

    #[test]
    fn test_log_entry_display() {
        let entry = LogEntry {
            timestamp: Utc::now(),
            elapsed_ms: 123,
            level: LogLevel::Info,
            source: LogSource::Harness,
            message: "Test message".to_string(),
            context: vec![("key".to_string(), "value".to_string())],
        };

        let s = entry.to_string();
        assert!(s.contains("123ms"));
        assert!(s.contains("INFO"));
        assert!(s.contains("harness"));
        assert!(s.contains("Test message"));
        assert!(s.contains("key=value"));
    }

    #[test]
    fn test_auto_detect_log_dir() {
        // Verify auto-detection finds a log directory
        let log_dir = TestLoggerBuilder::auto_detect_log_dir();
        eprintln!("Auto-detected log_dir: {:?}", log_dir);

        // Should find something when running in cargo test context
        if std::env::var("CARGO_MANIFEST_DIR").is_ok() {
            assert!(
                log_dir.is_some(),
                "Should auto-detect log_dir with CARGO_MANIFEST_DIR set"
            );
            let dir = log_dir.unwrap();
            eprintln!("Log directory: {}", dir.display());
            assert!(dir.ends_with("test-logs"), "Should end with test-logs");
        }
    }

    #[test]
    fn test_logger_writes_to_file() {
        // Create logger with explicit temp directory
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let temp_dir_path = temp_dir.path();

        let logger = TestLoggerBuilder::new("test_file_write")
            .log_dir(temp_dir_path)
            .print_realtime(false)
            .build();

        logger.info("Test file write message");
        logger.warn("Another message");

        // Drop logger to flush file
        drop(logger);

        // Check for log file
        let entries: Vec<_> = fs::read_dir(temp_dir_path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("test_file_write")
            })
            .collect();

        assert!(
            !entries.is_empty(),
            "Should have created a log file in {:?}",
            temp_dir_path
        );

        // Read and verify contents
        let log_path = &entries[0].path();
        let contents = fs::read_to_string(log_path).expect("Should read log file");
        assert!(
            contents.contains("Test file write message"),
            "Log should contain message"
        );
    }

    #[test]
    fn test_reliability_event_schema_contract() {
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let logger = TestLoggerBuilder::new("test_reliability_schema")
            .log_dir(temp_dir.path())
            .print_realtime(false)
            .build();

        let event = logger.log_reliability_event(ReliabilityEventInput {
            level: LogLevel::Info,
            phase: ReliabilityPhase::Execute,
            scenario_id: "scenario-path-deps".to_string(),
            message: "remote execution complete".to_string(),
            context: ReliabilityContext {
                worker_id: Some("worker-a".to_string()),
                repo_set: vec!["/data/projects/repo-a".to_string()],
                pressure_state: Some("disk:normal,memory:normal".to_string()),
                triage_actions: vec!["none".to_string()],
                decision_code: "REMOTE_OK".to_string(),
                fallback_reason: None,
            },
            artifact_paths: vec!["/tmp/a.json".to_string()],
        });

        assert_eq!(event.schema_version, RELIABILITY_EVENT_SCHEMA_VERSION);
        assert_eq!(event.phase, ReliabilityPhase::Execute);
        assert_eq!(event.scenario_id, "scenario-path-deps");
        assert_eq!(event.context.decision_code, "REMOTE_OK");

        let reliability_path = logger
            .reliability_log_path()
            .expect("reliability log path should exist")
            .to_path_buf();
        let reliability_contents =
            fs::read_to_string(&reliability_path).expect("should read reliability log");
        let first_line = reliability_contents
            .lines()
            .next()
            .expect("reliability log should contain one event");
        let parsed: ReliabilityPhaseEvent =
            serde_json::from_str(first_line).expect("reliability event should parse");
        assert_eq!(parsed.schema_version, RELIABILITY_EVENT_SCHEMA_VERSION);
        assert_eq!(parsed.phase, ReliabilityPhase::Execute);
        assert_eq!(parsed.context.worker_id, Some("worker-a".to_string()));
        assert_eq!(parsed.context.repo_set, vec!["/data/projects/repo-a"]);
    }

    #[test]
    fn test_reliability_event_parser_compatibility() {
        let json = r#"{
            "schema_version":"1.0.0",
            "timestamp":"2026-02-16T00:00:00Z",
            "elapsed_ms":42,
            "level":"info",
            "phase":"verify",
            "scenario_id":"scenario-x",
            "message":"verify finished",
            "context":{
                "worker_id":"worker-1",
                "repo_set":["/data/projects/repo-x","/dp/repo-y"],
                "pressure_state":"disk:high",
                "triage_actions":["trim-cache","kill-stuck-procs"],
                "decision_code":"VERIFY_OK",
                "fallback_reason":null
            },
            "artifact_paths":["/tmp/trace.json"]
        }"#;

        let event: ReliabilityPhaseEvent =
            serde_json::from_str(json).expect("contract payload should deserialize");
        assert_eq!(event.schema_version, "1.0.0");
        assert_eq!(event.phase, ReliabilityPhase::Verify);
        assert_eq!(event.context.decision_code, "VERIFY_OK");
        assert_eq!(event.context.triage_actions.len(), 2);
    }

    #[test]
    fn test_reliability_artifact_capture_text_and_json() {
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let logger = TestLoggerBuilder::new("test_reliability_artifacts")
            .log_dir(temp_dir.path())
            .print_realtime(false)
            .build();

        let text_path = logger
            .capture_artifact_text("scenario-alpha", "stdout_capture", "hello world")
            .expect("text artifact capture should succeed");
        assert!(text_path.exists());
        let text_contents = fs::read_to_string(&text_path).expect("read text artifact");
        assert_eq!(text_contents, "hello world");

        let json_path = logger
            .capture_artifact_json(
                "scenario-alpha",
                "command_trace",
                &serde_json::json!({ "cmd": "cargo test", "exit_code": 0 }),
            )
            .expect("json artifact capture should succeed");
        assert!(json_path.exists());
        let json_contents = fs::read_to_string(&json_path).expect("read json artifact");
        assert!(json_contents.contains("\"cmd\""));
        assert!(json_contents.contains("\"cargo test\""));
    }
}
