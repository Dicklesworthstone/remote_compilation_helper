//! Configuration source tracking.
//!
//! Tracks where each configuration value came from for debugging.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Where a configuration value originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    /// Built-in default value.
    Default,
    /// User-level config file (~/.config/rch/config.toml).
    UserConfig,
    /// Project-level config file (.rch/config.toml).
    ProjectConfig,
    /// Loaded from .env or .rch.env file.
    DotEnv,
    /// From a profile (dev/prod/test).
    Profile,
    /// Environment variable.
    Environment,
    /// Command-line argument (highest precedence).
    CommandLine,
}

impl ConfigSource {
    /// Get the precedence level (higher = takes priority).
    pub fn precedence(&self) -> u8 {
        match self {
            ConfigSource::Default => 0,
            ConfigSource::UserConfig => 1,
            ConfigSource::ProjectConfig => 2,
            ConfigSource::DotEnv => 3,
            ConfigSource::Profile => 4,
            ConfigSource::Environment => 5,
            ConfigSource::CommandLine => 6,
        }
    }

    /// Get a human-readable name for this source.
    pub fn display_name(&self) -> &'static str {
        match self {
            ConfigSource::Default => "default",
            ConfigSource::UserConfig => "user config",
            ConfigSource::ProjectConfig => "project config",
            ConfigSource::DotEnv => ".env file",
            ConfigSource::Profile => "profile",
            ConfigSource::Environment => "environment",
            ConfigSource::CommandLine => "command line",
        }
    }
}

impl fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Detailed source for a specific configuration value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigValueSource {
    /// Built-in default value.
    Default,
    /// User-level config file (~/.config/rch/config.toml).
    UserConfig(PathBuf),
    /// Project-level config file (.rch/config.toml).
    ProjectConfig(PathBuf),
    /// Environment variable name.
    EnvVar(String),
}

impl ConfigValueSource {
    /// Render a human-friendly label for CLI output.
    pub fn label(&self) -> String {
        match self {
            ConfigValueSource::Default => "default".to_string(),
            ConfigValueSource::UserConfig(path) => {
                format!("user:{}", path.display())
            }
            ConfigValueSource::ProjectConfig(path) => {
                format!("project:{}", path.display())
            }
            ConfigValueSource::EnvVar(name) => format!("env:{}", name),
        }
    }
}

impl fmt::Display for ConfigValueSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// A configuration value with its source.
#[derive(Debug, Clone)]
pub struct Sourced<T> {
    /// The actual value.
    pub value: T,
    /// Where this value came from.
    pub source: ConfigSource,
    /// Optional environment variable name if from environment.
    pub env_var: Option<String>,
}

impl<T> Sourced<T> {
    /// Create a new sourced value.
    pub fn new(value: T, source: ConfigSource) -> Self {
        Self {
            value,
            source,
            env_var: None,
        }
    }

    /// Create a sourced value from an environment variable.
    pub fn from_env(value: T, var_name: impl Into<String>) -> Self {
        Self {
            value,
            source: ConfigSource::Environment,
            env_var: Some(var_name.into()),
        }
    }

    /// Create a default sourced value.
    pub fn default_value(value: T) -> Self {
        Self::new(value, ConfigSource::Default)
    }

    /// Map the value while preserving source.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Sourced<U> {
        Sourced {
            value: f(self.value),
            source: self.source,
            env_var: self.env_var,
        }
    }

    /// Merge with another sourced value, taking the higher precedence one.
    pub fn merge(self, other: Self) -> Self {
        if other.source.precedence() >= self.source.precedence() {
            other
        } else {
            self
        }
    }
}

impl<T: Default> Default for Sourced<T> {
    fn default() -> Self {
        Self::default_value(T::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_precedence() {
        assert!(ConfigSource::Environment.precedence() > ConfigSource::UserConfig.precedence());
        assert!(ConfigSource::CommandLine.precedence() > ConfigSource::Environment.precedence());
        assert!(ConfigSource::Default.precedence() < ConfigSource::ProjectConfig.precedence());
    }

    #[test]
    fn test_sourced_merge() {
        let default = Sourced::new(10, ConfigSource::Default);
        let env = Sourced::new(20, ConfigSource::Environment);

        let merged = default.merge(env);
        assert_eq!(merged.value, 20);
        assert_eq!(merged.source, ConfigSource::Environment);
    }

    #[test]
    fn test_sourced_map() {
        let sourced = Sourced::from_env("42".to_string(), "MY_VAR");
        let mapped = sourced.map(|s| s.parse::<i32>().unwrap());

        assert_eq!(mapped.value, 42);
        assert_eq!(mapped.source, ConfigSource::Environment);
        assert_eq!(mapped.env_var.as_deref(), Some("MY_VAR"));
    }
}
