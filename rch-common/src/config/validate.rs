//! Configuration validation on startup.
//!
//! Validates all configuration values on startup and reports warnings/errors.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration warning or error detected during validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigWarning {
    /// The environment variable or config key involved.
    pub var: String,
    /// Human-readable description of the issue.
    pub message: String,
    /// Severity level.
    pub severity: Severity,
}

impl ConfigWarning {
    /// Create a new warning.
    pub fn warning(var: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            var: var.into(),
            message: message.into(),
            severity: Severity::Warning,
        }
    }

    /// Create a new error.
    pub fn error(var: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            var: var.into(),
            message: message.into(),
            severity: Severity::Error,
        }
    }

    /// Create a new info message.
    pub fn info(var: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            var: var.into(),
            message: message.into(),
            severity: Severity::Info,
        }
    }
}

impl std::fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.var, self.message)
    }
}

/// Severity level for configuration warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational message.
    Info,
    /// Warning that may cause issues.
    Warning,
    /// Error that will likely cause failures.
    Error,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARN"),
            Severity::Error => write!(f, "ERROR"),
        }
    }
}

/// Configuration values to validate.
#[derive(Debug, Clone, Default)]
pub struct ConfigToValidate {
    /// Daemon socket timeout in milliseconds.
    pub daemon_timeout_ms: Option<u64>,
    /// Zstd compression level (1-22).
    pub zstd_level: Option<i32>,
    /// SSH key path.
    pub ssh_key_path: Option<PathBuf>,
    /// Whether mock SSH is enabled.
    pub mock_ssh: bool,
    /// Whether test mode is enabled.
    pub test_mode: bool,
    /// Circuit breaker failure threshold.
    pub circuit_failure_threshold: Option<u32>,
    /// Circuit breaker reset timeout in seconds.
    pub circuit_reset_timeout_sec: Option<u64>,
    /// Log level.
    pub log_level: Option<String>,
}

/// Validate all configuration on startup.
///
/// Returns a list of warnings and errors. Errors should generally
/// prevent the application from starting.
pub fn validate_config(config: &ConfigToValidate) -> Vec<ConfigWarning> {
    let mut warnings = Vec::new();

    // Validate daemon timeout
    if let Some(timeout_ms) = config.daemon_timeout_ms {
        if timeout_ms < 100 {
            warnings.push(ConfigWarning::warning(
                "RCH_DAEMON_TIMEOUT_MS",
                "Timeout less than 100ms may cause premature failures",
            ));
        }
        if timeout_ms > 60000 {
            warnings.push(ConfigWarning::warning(
                "RCH_DAEMON_TIMEOUT_MS",
                "Timeout greater than 60s may cause unresponsive behavior",
            ));
        }
    }

    // Validate zstd compression level
    if let Some(level) = config.zstd_level {
        if level > 19 {
            warnings.push(ConfigWarning::warning(
                "RCH_TRANSFER_ZSTD_LEVEL",
                "Zstd level > 19 uses excessive CPU for minimal gain",
            ));
        }
        if level < 1 {
            warnings.push(ConfigWarning::warning(
                "RCH_TRANSFER_ZSTD_LEVEL",
                "Zstd level < 1 is invalid, using default",
            ));
        }
    }

    // Validate SSH key path
    if let Some(ref key_path) = config.ssh_key_path
        && !config.mock_ssh
        && !key_path.exists()
    {
        warnings.push(ConfigWarning::error(
            "RCH_SSH_KEY",
            format!("SSH key not found: {:?}", key_path),
        ));
    }

    // Validate mock SSH usage
    if config.mock_ssh && !config.test_mode {
        warnings.push(ConfigWarning::warning(
            "RCH_MOCK_SSH",
            "Mock SSH enabled outside test mode - builds won't actually compile remotely",
        ));
    }

    // Validate circuit breaker settings
    if let Some(threshold) = config.circuit_failure_threshold {
        if threshold == 0 {
            warnings.push(ConfigWarning::warning(
                "RCH_CIRCUIT_FAILURE_THRESHOLD",
                "Threshold of 0 means circuit will never open",
            ));
        }
        if threshold > 100 {
            warnings.push(ConfigWarning::warning(
                "RCH_CIRCUIT_FAILURE_THRESHOLD",
                "Very high threshold may delay failure detection",
            ));
        }
    }

    if let Some(timeout_sec) = config.circuit_reset_timeout_sec {
        if timeout_sec < 5 {
            warnings.push(ConfigWarning::warning(
                "RCH_CIRCUIT_RESET_TIMEOUT_SEC",
                "Reset timeout < 5s may cause rapid circuit state changes",
            ));
        }
        if timeout_sec > 600 {
            warnings.push(ConfigWarning::warning(
                "RCH_CIRCUIT_RESET_TIMEOUT_SEC",
                "Reset timeout > 10 minutes may delay recovery",
            ));
        }
    }

    // Validate log level
    if let Some(ref level) = config.log_level {
        let valid_levels = ["trace", "debug", "info", "warn", "error", "off"];
        if !valid_levels.contains(&level.to_lowercase().as_str()) {
            warnings.push(ConfigWarning::error(
                "RCH_LOG_LEVEL",
                format!(
                    "Invalid log level '{}', expected one of: {:?}",
                    level, valid_levels
                ),
            ));
        }
    }

    warnings
}

/// Check if there are any errors in the warnings list.
pub fn has_errors(warnings: &[ConfigWarning]) -> bool {
    warnings
        .iter()
        .any(|w| matches!(w.severity, Severity::Error))
}

/// Filter warnings by severity.
pub fn filter_by_severity(warnings: &[ConfigWarning], severity: Severity) -> Vec<&ConfigWarning> {
    warnings.iter().filter(|w| w.severity == severity).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_low_timeout() {
        let config = ConfigToValidate {
            daemon_timeout_ms: Some(50),
            ..Default::default()
        };
        let warnings = validate_config(&config);
        assert!(warnings.iter().any(|w| w.var == "RCH_DAEMON_TIMEOUT_MS"));
    }

    #[test]
    fn test_validate_high_zstd_level() {
        let config = ConfigToValidate {
            zstd_level: Some(20),
            ..Default::default()
        };
        let warnings = validate_config(&config);
        assert!(warnings.iter().any(|w| w.var == "RCH_TRANSFER_ZSTD_LEVEL"));
    }

    #[test]
    fn test_validate_mock_ssh_without_test_mode() {
        let config = ConfigToValidate {
            mock_ssh: true,
            test_mode: false,
            ..Default::default()
        };
        let warnings = validate_config(&config);
        assert!(warnings.iter().any(|w| w.var == "RCH_MOCK_SSH"));
    }

    #[test]
    fn test_validate_mock_ssh_with_test_mode() {
        let config = ConfigToValidate {
            mock_ssh: true,
            test_mode: true,
            ..Default::default()
        };
        let warnings = validate_config(&config);
        assert!(!warnings.iter().any(|w| w.var == "RCH_MOCK_SSH"));
    }

    #[test]
    fn test_validate_missing_ssh_key() {
        let config = ConfigToValidate {
            ssh_key_path: Some(PathBuf::from("/nonexistent/path/key")),
            mock_ssh: false,
            ..Default::default()
        };
        let warnings = validate_config(&config);
        assert!(
            warnings
                .iter()
                .any(|w| w.var == "RCH_SSH_KEY" && matches!(w.severity, Severity::Error))
        );
    }

    #[test]
    fn test_validate_missing_ssh_key_with_mock() {
        let config = ConfigToValidate {
            ssh_key_path: Some(PathBuf::from("/nonexistent/path/key")),
            mock_ssh: true,
            test_mode: true,
            ..Default::default()
        };
        let warnings = validate_config(&config);
        // Should NOT complain about missing key when mock SSH is enabled
        assert!(!warnings.iter().any(|w| w.var == "RCH_SSH_KEY"));
    }

    #[test]
    fn test_validate_circuit_breaker_zero_threshold() {
        let config = ConfigToValidate {
            circuit_failure_threshold: Some(0),
            ..Default::default()
        };
        let warnings = validate_config(&config);
        assert!(
            warnings
                .iter()
                .any(|w| w.var == "RCH_CIRCUIT_FAILURE_THRESHOLD")
        );
    }

    #[test]
    fn test_validate_invalid_log_level() {
        let config = ConfigToValidate {
            log_level: Some("verbose".to_string()),
            ..Default::default()
        };
        let warnings = validate_config(&config);
        assert!(
            warnings
                .iter()
                .any(|w| w.var == "RCH_LOG_LEVEL" && matches!(w.severity, Severity::Error))
        );
    }

    #[test]
    fn test_validate_valid_log_level() {
        let config = ConfigToValidate {
            log_level: Some("debug".to_string()),
            ..Default::default()
        };
        let warnings = validate_config(&config);
        assert!(!warnings.iter().any(|w| w.var == "RCH_LOG_LEVEL"));
    }

    #[test]
    fn test_has_errors() {
        let warnings = vec![
            ConfigWarning::warning("A", "warning"),
            ConfigWarning::info("B", "info"),
        ];
        assert!(!has_errors(&warnings));

        let warnings_with_error = vec![
            ConfigWarning::warning("A", "warning"),
            ConfigWarning::error("B", "error"),
        ];
        assert!(has_errors(&warnings_with_error));
    }

    #[test]
    fn test_filter_by_severity() {
        let warnings = vec![
            ConfigWarning::warning("A", "warning1"),
            ConfigWarning::error("B", "error1"),
            ConfigWarning::warning("C", "warning2"),
            ConfigWarning::info("D", "info1"),
        ];

        let errors = filter_by_severity(&warnings, Severity::Error);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].var, "B");

        let warnings_only = filter_by_severity(&warnings, Severity::Warning);
        assert_eq!(warnings_only.len(), 2);
    }
}
