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

        if let Ok(format) = std::env::var("RCH_LOG_FORMAT")
            && let Some(parsed) = LogFormat::parse(&format)
        {
            config.format = parsed;
        }

        if let Ok(path) = std::env::var("RCH_LOG_FILE")
            && !path.trim().is_empty()
        {
            config.file_path = Some(PathBuf::from(path));
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
        if std::env::var_os("RUST_LOG").is_some()
            && let Ok(filter) = EnvFilter::try_from_default_env()
        {
            return filter;
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
        // Retention cap for daily-rotated logs. The bare `rolling::daily`
        // helper keeps every file forever, which is how a file-logging
        // setup would silently fill the disk. Default to a week; allow
        // operators to override via env without touching the public
        // LogConfig struct (which would be a SemVer break since it has
        // no #[non_exhaustive] attribute).
        let max_files = std::env::var("RCH_LOG_MAX_FILES")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(7);
        let appender = tracing_appender::rolling::Builder::new()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix(file_name.to_string_lossy().into_owned())
            .max_log_files(max_files)
            .build(dir)
            .map_err(|e| anyhow::anyhow!("failed to build rolling log appender: {e}"))?;
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
    fn test_parse_targets_trims_and_filters_invalid_levels() {
        let targets = parse_target_overrides(" rchd::api = DEBUG ,hyper=verbose,=warn,missing");
        assert_eq!(targets.get("rchd::api"), Some(&"debug".to_string()));
        assert!(!targets.contains_key("hyper"));
        assert!(!targets.contains_key(""));
        assert!(!targets.contains_key("missing"));
    }

    #[test]
    fn test_log_format_parse() {
        assert_eq!(LogFormat::parse("pretty"), Some(LogFormat::Pretty));
        assert_eq!(LogFormat::parse("JSON"), Some(LogFormat::Json));
        assert_eq!(LogFormat::parse("Compact"), Some(LogFormat::Compact));
        assert_eq!(LogFormat::parse("invalid"), None);
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

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert_eq!(config.level, "info");
        assert_eq!(config.format, LogFormat::Pretty);
        assert!(config.file_path.is_none());
        assert!(config.targets.is_empty());
        assert!(config.with_target);
        assert!(config.with_thread_ids);
        assert!(config.with_file_line);
        assert!(!config.use_stderr);
    }

    #[test]
    fn test_log_config_with_level() {
        let config = LogConfig::default().with_level("debug");
        assert_eq!(config.level, "debug");
    }

    #[test]
    fn test_log_config_with_level_owned_string() {
        let config = LogConfig::default().with_level(String::from("trace"));
        assert_eq!(config.level, "trace");
    }

    #[test]
    fn test_log_config_with_stderr() {
        let config = LogConfig::default().with_stderr();
        assert!(config.use_stderr);
    }

    #[test]
    fn test_log_config_chained_builders() {
        let config = LogConfig::default().with_level("warn").with_stderr();
        assert_eq!(config.level, "warn");
        assert!(config.use_stderr);
    }

    #[test]
    fn test_log_format_equality() {
        assert_eq!(LogFormat::Pretty, LogFormat::Pretty);
        assert_eq!(LogFormat::Json, LogFormat::Json);
        assert_eq!(LogFormat::Compact, LogFormat::Compact);
        assert_ne!(LogFormat::Pretty, LogFormat::Json);
        assert_ne!(LogFormat::Json, LogFormat::Compact);
    }

    #[test]
    fn test_log_format_copy() {
        let format = LogFormat::Json;
        let copy = format; // Copy trait
        assert_eq!(format, copy);
    }

    #[test]
    fn test_log_format_clone() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<LogFormat>();
    }

    #[test]
    fn test_log_format_debug() {
        let format = LogFormat::Pretty;
        let debug = format!("{:?}", format);
        assert!(debug.contains("Pretty"));
    }

    #[test]
    fn test_log_format_parse_whitespace() {
        assert_eq!(LogFormat::parse("  pretty  "), Some(LogFormat::Pretty));
        assert_eq!(LogFormat::parse("\tjson\t"), Some(LogFormat::Json));
        assert_eq!(LogFormat::parse(" compact "), Some(LogFormat::Compact));
    }

    #[test]
    fn test_log_format_parse_mixed_case() {
        assert_eq!(LogFormat::parse("PRETTY"), Some(LogFormat::Pretty));
        assert_eq!(LogFormat::parse("JsOn"), Some(LogFormat::Json));
        assert_eq!(LogFormat::parse("cOmPaCt"), Some(LogFormat::Compact));
    }

    #[test]
    fn test_log_format_parse_empty() {
        assert_eq!(LogFormat::parse(""), None);
        assert_eq!(LogFormat::parse("   "), None);
    }

    #[test]
    fn test_is_valid_level_all_valid() {
        assert!(is_valid_level("trace"));
        assert!(is_valid_level("debug"));
        assert!(is_valid_level("info"));
        assert!(is_valid_level("warn"));
        assert!(is_valid_level("error"));
        assert!(is_valid_level("off"));
    }

    #[test]
    fn test_is_valid_level_invalid() {
        assert!(!is_valid_level(""));
        assert!(!is_valid_level("DEBUG")); // Case sensitive
        assert!(!is_valid_level("warning"));
        assert!(!is_valid_level("fatal"));
        assert!(!is_valid_level("verbose"));
    }

    #[test]
    fn test_parse_target_overrides_empty() {
        let targets = parse_target_overrides("");
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_target_overrides_whitespace_only() {
        let targets = parse_target_overrides("   ,  ,  ");
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_target_overrides_single_entry() {
        let targets = parse_target_overrides("my_crate=debug");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets.get("my_crate"), Some(&"debug".to_string()));
    }

    #[test]
    fn test_parse_target_overrides_multiple_entries() {
        let targets = parse_target_overrides("a=trace,b=debug,c=info,d=warn,e=error,f=off");
        assert_eq!(targets.len(), 6);
        assert_eq!(targets.get("a"), Some(&"trace".to_string()));
        assert_eq!(targets.get("b"), Some(&"debug".to_string()));
        assert_eq!(targets.get("c"), Some(&"info".to_string()));
        assert_eq!(targets.get("d"), Some(&"warn".to_string()));
        assert_eq!(targets.get("e"), Some(&"error".to_string()));
        assert_eq!(targets.get("f"), Some(&"off".to_string()));
    }

    #[test]
    fn test_parse_target_overrides_empty_target() {
        let targets = parse_target_overrides("=debug");
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_target_overrides_no_equals() {
        let targets = parse_target_overrides("nodebug");
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_target_overrides_duplicate_target() {
        // Later entry should win (BTreeMap behavior)
        let targets = parse_target_overrides("crate=debug,crate=warn");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets.get("crate"), Some(&"warn".to_string()));
    }

    #[test]
    fn test_log_config_clone() {
        let mut config = LogConfig {
            level: "debug".to_string(),
            format: LogFormat::Json,
            file_path: Some(PathBuf::from("/tmp/test.log")),
            ..LogConfig::default()
        };
        config.targets.insert("a".to_string(), "trace".to_string());

        let cloned = config.clone();
        assert_eq!(config.level, cloned.level);
        assert_eq!(config.format, cloned.format);
        assert_eq!(config.file_path, cloned.file_path);
        assert_eq!(config.targets, cloned.targets);
    }

    #[test]
    fn test_log_config_debug() {
        let config = LogConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("LogConfig"));
        assert!(debug.contains("info"));
    }

    #[test]
    fn test_env_filter_no_targets() {
        let config = LogConfig {
            level: "warn".to_string(),
            ..LogConfig::default()
        };
        let filter = config.env_filter();
        let filter_str = format!("{filter}");
        assert!(filter_str.contains("warn"));
    }

    #[test]
    fn test_env_filter_multiple_targets() {
        let mut config = LogConfig {
            level: "error".to_string(),
            ..LogConfig::default()
        };
        config
            .targets
            .insert("mod_a".to_string(), "debug".to_string());
        config
            .targets
            .insert("mod_b".to_string(), "trace".to_string());
        let filter = config.env_filter();
        let filter_str = format!("{filter}");
        assert!(filter_str.contains("error"));
        assert!(filter_str.contains("mod_a=debug"));
        assert!(filter_str.contains("mod_b=trace"));
    }
}
