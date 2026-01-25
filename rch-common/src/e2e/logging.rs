//! E2E Test Logging Library
//!
//! Provides comprehensive logging infrastructure for end-to-end tests.
//! Captures detailed logs including process output, timing, and structured data.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, File};
use std::io::{BufWriter, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

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
}

impl TestLogger {
    /// Create a new test logger with the given configuration
    pub fn new(test_name: &str, config: LoggerConfig) -> Self {
        let file_writer = if let Some(ref dir) = config.log_dir {
            if fs::create_dir_all(dir).is_ok() {
                let filename = format!(
                    "{}_{}.log",
                    test_name.replace("::", "_").replace(" ", "_"),
                    Utc::now().format("%Y%m%d_%H%M%S")
                );
                let path = dir.join(filename);
                match File::create(&path) {
                    Ok(f) => Some(BufWriter::new(f)),
                    Err(e) => {
                        eprintln!("Warning: Failed to create log file {}: {e}", path.display());
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        Self {
            config: Arc::new(RwLock::new(config)),
            entries: Arc::new(Mutex::new(VecDeque::new())),
            start_time: Instant::now(),
            test_name: Arc::new(test_name.to_string()),
            file_writer: Arc::new(Mutex::new(file_writer)),
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

        // Write to file if configured
        if let Ok(mut writer) = self.file_writer.lock() {
            if let Some(ref mut w) = *writer {
                let _ = writeln!(w, "{entry}");
                let _ = w.flush();
            }
        }

        // Store in memory
        let mut entries = self.entries.lock().unwrap();
        entries.push_back(entry);
        if config.max_entries > 0 && entries.len() > config.max_entries {
            entries.pop_front();
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
        if let Some(ref err) = summary.last_error {
            if summary.first_error.as_ref() != Some(err) {
                println!("Last error: {err}");
            }
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
    /// Create a new builder for the given test name
    pub fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            config: LoggerConfig::default(),
        }
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

        logger.log_with_context(LogLevel::Info, LogSource::Harness, "Worker selected", vec![
            ("worker_id".to_string(), "css".to_string()),
            ("slots".to_string(), "4".to_string()),
        ]);

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
}
