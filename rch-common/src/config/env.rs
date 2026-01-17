//! Environment variable parsing with type safety.
//!
//! Provides a type-safe parser for RCH environment variables with
//! validation, error collection, and source tracking.

use super::source::{ConfigSource, Sourced};
use std::env;
use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur during environment variable parsing.
#[derive(Debug, Error)]
pub enum EnvError {
    /// Invalid value for a variable.
    #[error("Invalid value for {var}: expected {expected}, got '{value}'")]
    InvalidValue {
        var: String,
        expected: String,
        value: String,
    },

    /// Path does not exist.
    #[error("Path not found for {var}: {path}")]
    PathNotFound { var: String, path: PathBuf },

    /// Invalid duration format.
    #[error("Invalid duration for {var}: {value}")]
    InvalidDuration { var: String, value: String },

    /// Value out of valid range.
    #[error("Value out of range for {var}: {value} (valid: {min}..={max})")]
    OutOfRange {
        var: String,
        value: String,
        min: String,
        max: String,
    },

    /// Invalid log level.
    #[error("Invalid log level for {var}: {value}")]
    InvalidLogLevel { var: String, value: String },
}

/// Type-safe environment variable parser.
///
/// Collects errors during parsing so all issues can be reported at once.
pub struct EnvParser {
    prefix: &'static str,
    errors: Vec<EnvError>,
}

impl EnvParser {
    /// Create a new parser with the RCH_ prefix.
    pub fn new() -> Self {
        Self {
            prefix: "RCH_",
            errors: Vec::new(),
        }
    }

    /// Get all accumulated errors.
    pub fn errors(&self) -> &[EnvError] {
        &self.errors
    }

    /// Check if any errors occurred.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Take ownership of errors.
    pub fn take_errors(&mut self) -> Vec<EnvError> {
        std::mem::take(&mut self.errors)
    }

    /// Get the full variable name with prefix.
    fn var_name(&self, name: &str) -> String {
        format!("{}{}", self.prefix, name)
    }

    /// Get a string value with default.
    pub fn get_string(&mut self, name: &str, default: &str) -> Sourced<String> {
        let var_name = self.var_name(name);
        match env::var(&var_name) {
            Ok(value) => Sourced::from_env(value, var_name),
            Err(_) => Sourced::default_value(default.to_string()),
        }
    }

    /// Get a boolean value with default.
    ///
    /// Accepts: 1, true, yes, on (for true)
    ///          0, false, no, off, "" (for false)
    pub fn get_bool(&mut self, name: &str, default: bool) -> Sourced<bool> {
        let var_name = self.var_name(name);
        match env::var(&var_name) {
            Ok(value) => {
                let parsed = match value.to_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" => true,
                    "0" | "false" | "no" | "off" | "" => false,
                    _ => {
                        self.errors.push(EnvError::InvalidValue {
                            var: var_name.clone(),
                            expected: "boolean (true/false/1/0/yes/no)".to_string(),
                            value: value.clone(),
                        });
                        default
                    }
                };
                Sourced::from_env(parsed, var_name)
            }
            Err(_) => Sourced::default_value(default),
        }
    }

    /// Get a u32 value with default and range validation.
    pub fn get_u32_range(&mut self, name: &str, default: u32, min: u32, max: u32) -> Sourced<u32> {
        let var_name = self.var_name(name);
        match env::var(&var_name) {
            Ok(value) => match value.parse::<u32>() {
                Ok(n) if n >= min && n <= max => Sourced::from_env(n, var_name),
                Ok(n) => {
                    self.errors.push(EnvError::OutOfRange {
                        var: var_name.clone(),
                        value: n.to_string(),
                        min: min.to_string(),
                        max: max.to_string(),
                    });
                    Sourced::from_env(default, var_name)
                }
                Err(_) => {
                    self.errors.push(EnvError::InvalidValue {
                        var: var_name.clone(),
                        expected: "unsigned 32-bit integer".to_string(),
                        value,
                    });
                    Sourced::default_value(default)
                }
            },
            Err(_) => Sourced::default_value(default),
        }
    }

    /// Get a u64 value with default and range validation.
    pub fn get_u64_range(&mut self, name: &str, default: u64, min: u64, max: u64) -> Sourced<u64> {
        let var_name = self.var_name(name);
        match env::var(&var_name) {
            Ok(value) => match value.parse::<u64>() {
                Ok(n) if n >= min && n <= max => Sourced::from_env(n, var_name),
                Ok(n) => {
                    self.errors.push(EnvError::OutOfRange {
                        var: var_name.clone(),
                        value: n.to_string(),
                        min: min.to_string(),
                        max: max.to_string(),
                    });
                    Sourced::from_env(default, var_name)
                }
                Err(_) => {
                    self.errors.push(EnvError::InvalidValue {
                        var: var_name.clone(),
                        expected: "unsigned 64-bit integer".to_string(),
                        value,
                    });
                    Sourced::default_value(default)
                }
            },
            Err(_) => Sourced::default_value(default),
        }
    }

    /// Get an i32 value with default and range validation.
    pub fn get_i32_range(&mut self, name: &str, default: i32, min: i32, max: i32) -> Sourced<i32> {
        let var_name = self.var_name(name);
        match env::var(&var_name) {
            Ok(value) => match value.parse::<i32>() {
                Ok(n) if n >= min && n <= max => Sourced::from_env(n, var_name),
                Ok(n) => {
                    self.errors.push(EnvError::OutOfRange {
                        var: var_name.clone(),
                        value: n.to_string(),
                        min: min.to_string(),
                        max: max.to_string(),
                    });
                    Sourced::from_env(default, var_name)
                }
                Err(_) => {
                    self.errors.push(EnvError::InvalidValue {
                        var: var_name.clone(),
                        expected: "signed 32-bit integer".to_string(),
                        value,
                    });
                    Sourced::default_value(default)
                }
            },
            Err(_) => Sourced::default_value(default),
        }
    }

    /// Get a f64 value with default and range validation.
    pub fn get_f64_range(&mut self, name: &str, default: f64, min: f64, max: f64) -> Sourced<f64> {
        let var_name = self.var_name(name);
        match env::var(&var_name) {
            Ok(value) => match value.parse::<f64>() {
                Ok(n) if n >= min && n <= max => Sourced::from_env(n, var_name),
                Ok(n) => {
                    self.errors.push(EnvError::OutOfRange {
                        var: var_name.clone(),
                        value: n.to_string(),
                        min: min.to_string(),
                        max: max.to_string(),
                    });
                    Sourced::from_env(default, var_name)
                }
                Err(_) => {
                    self.errors.push(EnvError::InvalidValue {
                        var: var_name.clone(),
                        expected: "floating-point number".to_string(),
                        value,
                    });
                    Sourced::default_value(default)
                }
            },
            Err(_) => Sourced::default_value(default),
        }
    }

    /// Get a path value with ~ expansion.
    ///
    /// If `must_exist` is true, records an error if the path doesn't exist.
    pub fn get_path(&mut self, name: &str, default: &str, must_exist: bool) -> Sourced<PathBuf> {
        let var_name = self.var_name(name);
        let (value, source) = match env::var(&var_name) {
            Ok(v) => (v, ConfigSource::Environment),
            Err(_) => (default.to_string(), ConfigSource::Default),
        };

        // Expand ~ to home directory
        let expanded = if let Some(stripped) = value.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                home.join(stripped)
            } else {
                PathBuf::from(&value)
            }
        } else {
            PathBuf::from(&value)
        };

        if must_exist && !expanded.exists() {
            self.errors.push(EnvError::PathNotFound {
                var: var_name.clone(),
                path: expanded.clone(),
            });
        }

        if source == ConfigSource::Environment {
            Sourced::from_env(expanded, var_name)
        } else {
            Sourced::default_value(expanded)
        }
    }

    /// Get a log level value with validation.
    pub fn get_log_level(&mut self, name: &str, default: &str) -> Sourced<String> {
        let var_name = self.var_name(name);
        match env::var(&var_name) {
            Ok(value) => {
                let lower = value.to_lowercase();
                match lower.as_str() {
                    "trace" | "debug" | "info" | "warn" | "error" | "off" => {
                        Sourced::from_env(lower, var_name)
                    }
                    _ => {
                        self.errors.push(EnvError::InvalidLogLevel {
                            var: var_name.clone(),
                            value: value.clone(),
                        });
                        Sourced::from_env(default.to_string(), var_name)
                    }
                }
            }
            Err(_) => Sourced::default_value(default.to_string()),
        }
    }

    /// Get a comma-separated list of strings.
    pub fn get_string_list(&mut self, name: &str, default: Vec<String>) -> Sourced<Vec<String>> {
        let var_name = self.var_name(name);
        match env::var(&var_name) {
            Ok(value) if value.is_empty() => Sourced::from_env(Vec::new(), var_name),
            Ok(value) => {
                let items: Vec<String> = value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                Sourced::from_env(items, var_name)
            }
            Err(_) => Sourced::default_value(default),
        }
    }

    /// Get an optional string (None if not set or empty).
    pub fn get_optional_string(&mut self, name: &str) -> Sourced<Option<String>> {
        let var_name = self.var_name(name);
        match env::var(&var_name) {
            Ok(value) if value.is_empty() => Sourced::from_env(None, var_name),
            Ok(value) => Sourced::from_env(Some(value), var_name),
            Err(_) => Sourced::default_value(None),
        }
    }
}

impl Default for EnvParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use crate::config::env_test_lock;
    use std::env;

    fn cleanup_env(vars: &[&str]) {
        for var in vars {
            // SAFETY: Tests run single-threaded, no concurrent access to env vars
            unsafe { env::remove_var(var) };
        }
    }

    fn set_env(key: &str, value: &str) {
        // SAFETY: Tests run single-threaded, no concurrent access to env vars
        unsafe { env::set_var(key, value) };
    }

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        env_test_lock()
    }

    #[test]
    fn test_get_bool_true_values() {
        let _guard = env_guard();
        let vars = ["RCH_TEST_BOOL_TRUE"];
        cleanup_env(&vars);

        for val in &["1", "true", "yes", "on", "TRUE", "Yes"] {
            set_env("RCH_TEST_BOOL_TRUE", val);
            let mut parser = EnvParser::new();
            let result = parser.get_bool("TEST_BOOL_TRUE", false);
            assert!(result.value, "Expected true for '{}'", val);
            assert!(!parser.has_errors());
        }

        cleanup_env(&vars);
    }

    #[test]
    fn test_get_bool_false_values() {
        let _guard = env_guard();
        let vars = ["RCH_TEST_BOOL_FALSE"];
        cleanup_env(&vars);

        for val in &["0", "false", "no", "off", "FALSE", ""] {
            set_env("RCH_TEST_BOOL_FALSE", val);
            let mut parser = EnvParser::new();
            let result = parser.get_bool("TEST_BOOL_FALSE", true);
            assert!(!result.value, "Expected false for '{}'", val);
            assert!(!parser.has_errors());
        }

        cleanup_env(&vars);
    }

    #[test]
    fn test_get_bool_invalid_uses_default() {
        let _guard = env_guard();
        let vars = ["RCH_BAD_BOOL"];
        cleanup_env(&vars);

        set_env("RCH_BAD_BOOL", "maybe");
        let mut parser = EnvParser::new();
        let result = parser.get_bool("BAD_BOOL", false);
        assert!(!result.value);
        assert!(parser.has_errors());

        cleanup_env(&vars);
    }

    #[test]
    fn test_get_u64_range_valid() {
        let _guard = env_guard();
        let vars = ["RCH_TEST_U64"];
        cleanup_env(&vars);

        set_env("RCH_TEST_U64", "50");
        let mut parser = EnvParser::new();
        let result = parser.get_u64_range("TEST_U64", 10, 0, 100);
        assert_eq!(result.value, 50);
        assert!(!parser.has_errors());

        cleanup_env(&vars);
    }

    #[test]
    fn test_get_u64_range_out_of_range() {
        let _guard = env_guard();
        // Use unique var name to avoid race with test_get_u64_range_valid
        let vars = ["RCH_TEST_U64_OOR"];
        cleanup_env(&vars);

        set_env("RCH_TEST_U64_OOR", "200");
        let mut parser = EnvParser::new();
        let result = parser.get_u64_range("TEST_U64_OOR", 10, 0, 100);
        assert_eq!(result.value, 10); // Uses default
        assert!(parser.has_errors());

        cleanup_env(&vars);
    }

    #[test]
    fn test_get_log_level_valid() {
        let _guard = env_guard();
        let vars = ["RCH_LOG_LEVEL"];
        cleanup_env(&vars);

        for level in &["trace", "debug", "info", "warn", "error", "DEBUG", "INFO"] {
            set_env("RCH_LOG_LEVEL", level);
            let mut parser = EnvParser::new();
            let result = parser.get_log_level("LOG_LEVEL", "info");
            assert!(!parser.has_errors(), "Expected valid for '{}'", level);
            assert_eq!(result.value, level.to_lowercase());
        }

        cleanup_env(&vars);
    }

    #[test]
    fn test_get_log_level_invalid() {
        let _guard = env_guard();
        let vars = ["RCH_LOG_LEVEL"];
        cleanup_env(&vars);

        set_env("RCH_LOG_LEVEL", "verbose");
        let mut parser = EnvParser::new();
        let result = parser.get_log_level("LOG_LEVEL", "info");
        assert!(parser.has_errors());
        assert_eq!(result.value, "info"); // Default

        cleanup_env(&vars);
    }

    #[test]
    fn test_get_string_list() {
        let _guard = env_guard();
        let vars = ["RCH_TEST_LIST"];
        cleanup_env(&vars);

        set_env("RCH_TEST_LIST", "a, b, c");
        let mut parser = EnvParser::new();
        let result = parser.get_string_list("TEST_LIST", vec![]);
        assert_eq!(result.value, vec!["a", "b", "c"]);

        cleanup_env(&vars);
    }

    #[test]
    fn test_get_optional_string() {
        let _guard = env_guard();
        let vars = ["RCH_TEST_OPT"];
        cleanup_env(&vars);

        // Not set
        let mut parser = EnvParser::new();
        let result = parser.get_optional_string("TEST_OPT");
        assert!(result.value.is_none());

        // Set to empty
        set_env("RCH_TEST_OPT", "");
        let mut parser = EnvParser::new();
        let result = parser.get_optional_string("TEST_OPT");
        assert!(result.value.is_none());

        // Set to value
        set_env("RCH_TEST_OPT", "value");
        let mut parser = EnvParser::new();
        let result = parser.get_optional_string("TEST_OPT");
        assert_eq!(result.value, Some("value".to_string()));

        cleanup_env(&vars);
    }

    #[test]
    fn test_source_tracking() {
        let _guard = env_guard();
        let vars = ["RCH_TEST_SRC"];
        cleanup_env(&vars);

        // Default source
        let mut parser = EnvParser::new();
        let result = parser.get_string("TEST_SRC", "default");
        assert_eq!(result.source, ConfigSource::Default);
        assert!(result.env_var.is_none());

        // Environment source
        set_env("RCH_TEST_SRC", "from_env");
        let mut parser = EnvParser::new();
        let result = parser.get_string("TEST_SRC", "default");
        assert_eq!(result.source, ConfigSource::Environment);
        assert_eq!(result.env_var.as_deref(), Some("RCH_TEST_SRC"));

        cleanup_env(&vars);
    }
}
