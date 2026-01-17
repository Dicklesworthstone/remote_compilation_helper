//! Structured logging initialization for RCH components.
//!
//! Provides a shared logging configuration and initialization routine for
//! binaries (rch, rchd, rch-wkr) and libraries that need consistent output.

use anyhow::Result;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use tracing::Subscriber;
use tracing_subscriber::{
    EnvFilter, fmt,
    fmt::writer::{BoxMakeWriter, MakeWriterExt},
    util::SubscriberInitExt,
};

/// Logging output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-friendly, pretty-printed logs.
    Pretty,
    /// JSON-formatted logs for machine parsing.
    Json,
    /// Compact single-line logs.
    Compact,
}

impl LogFormat {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "pretty" => Some(Self::Pretty),
            "json" => Some(Self::Json),
            "compact" => Some(Self::Compact),
            _ => None,
        }
    }
}

/// Configuration for logging initialization.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Base log level (trace, debug, info, warn, error, off).
    pub level: String,
    /// Output format.
    pub format: LogFormat,
    /// Optional file path for rotating logs.
    pub file_path: Option<PathBuf>,
    /// Per-target log level overrides.
    pub targets: BTreeMap<String, String>,
    /// Include target in log output.
    pub with_target: bool,
    /// Include thread IDs in log output.
    pub with_thread_ids: bool,
    /// Include file and line number in log output.
    pub with_file_line: bool,
    /// Write console logs to stderr instead of stdout.
    pub use_stderr: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Pretty,
            file_path: None,
            targets: BTreeMap::new(),
            with_target: true,
            with_thread_ids: true,
            with_file_line: true,
            use_stderr: false,
        }
    }
}

impl LogConfig {
    /// Build a logging configuration from environment variables.
    ///
    /// Supported environment variables:
    /// - RCH_LOG_LEVEL
    /// - RCH_LOG_FORMAT (pretty|json|compact)
    /// - RCH_LOG_FILE (path to rotating log file)
    /// - RCH_LOG_TARGETS (comma-separated target=level list)
    pub fn from_env(default_level: &str) -> Self {
        let mut config = Self {
            level: std::env::var("RCH_LOG_LEVEL").unwrap_or_else(|_| default_level.to_string()),
            ..Self::default()
        };

        if let Ok(format) = std::env::var("RCH_LOG_FORMAT") {
            if let Some(parsed) = LogFormat::parse(&format) {
                config.format = parsed;
            }
        }

        if let Ok(path) = std::env::var("RCH_LOG_FILE") {
            if !path.trim().is_empty() {
                config.file_path = Some(PathBuf::from(path));
            }
        }

        if let Ok(targets) = std::env::var("RCH_LOG_TARGETS") {
            config.targets = parse_target_overrides(&targets);
        }

        config
    }

    /// Override the base log level.
    pub fn with_level(mut self, level: impl Into<String>) -> Self {
        self.level = level.into();
        self
    }

    /// Write console logs to stderr.
    pub fn with_stderr(mut self) -> Self {
        self.use_stderr = true;
        self
    }

    /// Build the effective EnvFilter, honoring RUST_LOG if set.
    pub fn env_filter(&self) -> EnvFilter {
        if std::env::var_os("RUST_LOG").is_some() {
            return EnvFilter::from_default_env();
        }

        let mut filter = self.level.clone();
        for (target, level) in &self.targets {
            filter.push_str(&format!(",{}={}", target, level));
        }
        EnvFilter::new(filter)
    }
}

/// Guards required to keep background logging workers alive.
pub struct LoggingGuards {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Initialize tracing-based logging for the current process.
///
/// Returns guards that must be kept alive for the duration of the program
/// (particularly when file logging is enabled).
pub fn init_logging(config: &LogConfig) -> Result<LoggingGuards> {
    match config.format {
        LogFormat::Pretty => init_with_format(config, LogFormat::Pretty),
        LogFormat::Json => init_with_format(config, LogFormat::Json),
        LogFormat::Compact => init_with_format(config, LogFormat::Compact),
    }
}

fn build_writer(
    config: &LogConfig,
) -> Result<(
    BoxMakeWriter,
    Option<tracing_appender::non_blocking::WorkerGuard>,
)> {
    let base_writer = if config.use_stderr {
        BoxMakeWriter::new(std::io::stderr)
    } else {
        BoxMakeWriter::new(std::io::stdout)
    };

    if let Some(path) = config.file_path.as_ref() {
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file_name = path.file_name().unwrap_or_else(|| OsStr::new("rch.log"));
        let appender = tracing_appender::rolling::daily(dir, file_name);
        let (non_blocking, guard) = tracing_appender::non_blocking(appender);
        let writer = BoxMakeWriter::new(base_writer.and(non_blocking));
        Ok((writer, Some(guard)))
    } else {
        Ok((base_writer, None))
    }
}

fn init_with_format(config: &LogConfig, format: LogFormat) -> Result<LoggingGuards> {
    let filter = config.env_filter();
    let (writer, file_guard) = build_writer(config)?;
    let ansi = file_guard.is_none();

    match format {
        LogFormat::Pretty => {
            let subscriber = fmt::Subscriber::builder()
                .with_writer(writer)
                .with_target(config.with_target)
                .with_thread_ids(config.with_thread_ids)
                .with_file(config.with_file_line)
                .with_line_number(config.with_file_line)
                .with_env_filter(filter)
                .with_ansi(ansi)
                .pretty()
                .finish();
            finish_subscriber(subscriber, file_guard)
        }
        LogFormat::Json => {
            let subscriber = fmt::Subscriber::builder()
                .with_writer(writer)
                .with_target(config.with_target)
                .with_thread_ids(config.with_thread_ids)
                .with_file(config.with_file_line)
                .with_line_number(config.with_file_line)
                .with_env_filter(filter)
                .with_ansi(false)
                .json()
                .finish();
            finish_subscriber(subscriber, file_guard)
        }
        LogFormat::Compact => {
            let subscriber = fmt::Subscriber::builder()
                .with_writer(writer)
                .with_target(config.with_target)
                .with_thread_ids(config.with_thread_ids)
                .with_file(config.with_file_line)
                .with_line_number(config.with_file_line)
                .with_env_filter(filter)
                .with_ansi(ansi)
                .compact()
                .finish();
            finish_subscriber(subscriber, file_guard)
        }
    }
}

fn finish_subscriber<S>(
    subscriber: S,
    file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
) -> Result<LoggingGuards>
where
    S: Subscriber + Send + Sync + 'static,
{
    if let Err(err) = subscriber.try_init() {
        if err.to_string().contains("already initialized") {
            return Ok(LoggingGuards {
                _file_guard: file_guard,
            });
        }
        return Err(err.into());
    }

    Ok(LoggingGuards {
        _file_guard: file_guard,
    })
}

fn parse_target_overrides(value: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for entry in value.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((target, level)) = entry.split_once('=') else {
            continue;
        };
        let target = target.trim();
        let level = level.trim().to_lowercase();
        if target.is_empty() || !is_valid_level(&level) {
            continue;
        }
        map.insert(target.to_string(), level);
    }
    map
}

fn is_valid_level(level: &str) -> bool {
    matches!(level, "trace" | "debug" | "info" | "warn" | "error" | "off")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_targets() {
        let targets = parse_target_overrides("rchd::workers=debug,hyper=warn,invalid");
        assert_eq!(targets.get("rchd::workers"), Some(&"debug".to_string()));
        assert_eq!(targets.get("hyper"), Some(&"warn".to_string()));
        assert!(!targets.contains_key("invalid"));
    }

    #[test]
    fn test_env_filter_builds_overrides() {
        let mut config = LogConfig {
            level: "info".to_string(),
            ..LogConfig::default()
        };
        config
            .targets
            .insert("rchd::api".to_string(), "debug".to_string());
        let filter = config.env_filter();
        let filter_str = format!("{filter}");
        assert!(filter_str.contains("info"));
        assert!(filter_str.contains("rchd::api=debug"));
    }
}
