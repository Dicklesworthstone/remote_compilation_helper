//! Configuration profiles for RCH.
//!
//! Profiles provide preset configurations for different environments:
//! - dev: Development mode with verbose logging
//! - prod: Production mode with minimal logging
//! - test: Testing mode with mock SSH enabled

use std::env;
use tracing::debug;

/// Predefined configuration profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Development mode: verbose logging, relaxed settings.
    Dev,
    /// Production mode: minimal logging, strict settings.
    Prod,
    /// Testing mode: mock SSH enabled, test fixtures.
    Test,
    /// Custom profile loaded from file.
    Custom,
}

impl Profile {
    /// Get the profile from the RCH_PROFILE environment variable.
    pub fn from_env() -> Option<Self> {
        let value = env::var("RCH_PROFILE").ok()?;
        Some(Self::from_string(&value))
    }

    /// Parse a profile from a string.
    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "dev" | "development" => Profile::Dev,
            "prod" | "production" => Profile::Prod,
            "test" | "testing" => Profile::Test,
            _ => Profile::Custom,
        }
    }

    /// Get the profile name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Profile::Dev => "dev",
            Profile::Prod => "prod",
            Profile::Test => "test",
            Profile::Custom => "custom",
        }
    }

    /// Get profile defaults as key-value pairs.
    ///
    /// Returns environment variable defaults for this profile.
    /// Only returns variables that are NOT already set in the environment.
    /// The caller is responsible for actually setting them if desired.
    pub fn get_defaults(&self) -> Vec<(&'static str, &'static str)> {
        let candidates = match self {
            Profile::Dev => {
                debug!("Getting dev profile defaults");
                vec![("RCH_LOG_LEVEL", "debug"), ("RCH_LOG_FORMAT", "pretty")]
            }
            Profile::Prod => {
                debug!("Getting prod profile defaults");
                vec![
                    ("RCH_LOG_LEVEL", "warn"),
                    ("RCH_LOG_FORMAT", "json"),
                    ("RCH_ENABLE_METRICS", "true"),
                ]
            }
            Profile::Test => {
                debug!("Getting test profile defaults");
                vec![
                    ("RCH_MOCK_SSH", "1"),
                    ("RCH_LOG_LEVEL", "debug"),
                    ("RCH_TEST_MODE", "1"),
                ]
            }
            Profile::Custom => {
                debug!("Custom profile - no automatic defaults");
                vec![]
            }
        };

        // Filter out already-set variables
        candidates
            .into_iter()
            .filter(|(key, _)| env::var(key).is_err())
            .collect()
    }

    /// Get profile-specific description.
    pub fn description(&self) -> &'static str {
        match self {
            Profile::Dev => "Development mode with verbose logging and relaxed settings",
            Profile::Prod => "Production mode with minimal logging and strict settings",
            Profile::Test => "Testing mode with mock SSH and test fixtures enabled",
            Profile::Custom => "Custom profile with user-defined settings",
        }
    }

    /// Check if this profile enables mock SSH by default.
    pub fn uses_mock_ssh(&self) -> bool {
        matches!(self, Profile::Test)
    }

    /// Check if this profile enables verbose logging by default.
    pub fn is_verbose(&self) -> bool {
        matches!(self, Profile::Dev | Profile::Test)
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    /// Helper to safely set an env var in tests.
    fn set_env(key: &str, value: &str) {
        // SAFETY: Tests run single-threaded via --test-threads=1 or use serial isolation.
        unsafe { std::env::set_var(key, value) };
    }

    /// Helper to safely remove an env var in tests.
    fn remove_env(key: &str) {
        // SAFETY: Tests run single-threaded via --test-threads=1 or use serial isolation.
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn test_profile_from_string() {
        assert_eq!(Profile::from_string("dev"), Profile::Dev);
        assert_eq!(Profile::from_string("DEV"), Profile::Dev);
        assert_eq!(Profile::from_string("development"), Profile::Dev);
        assert_eq!(Profile::from_string("prod"), Profile::Prod);
        assert_eq!(Profile::from_string("production"), Profile::Prod);
        assert_eq!(Profile::from_string("test"), Profile::Test);
        assert_eq!(Profile::from_string("testing"), Profile::Test);
        assert_eq!(Profile::from_string("unknown"), Profile::Custom);
    }

    #[test]
    fn test_profile_as_str() {
        assert_eq!(Profile::Dev.as_str(), "dev");
        assert_eq!(Profile::Prod.as_str(), "prod");
        assert_eq!(Profile::Test.as_str(), "test");
        assert_eq!(Profile::Custom.as_str(), "custom");
    }

    #[test]
    fn test_profile_uses_mock_ssh() {
        assert!(!Profile::Dev.uses_mock_ssh());
        assert!(!Profile::Prod.uses_mock_ssh());
        assert!(Profile::Test.uses_mock_ssh());
        assert!(!Profile::Custom.uses_mock_ssh());
    }

    #[test]
    fn test_profile_is_verbose() {
        assert!(Profile::Dev.is_verbose());
        assert!(!Profile::Prod.is_verbose());
        assert!(Profile::Test.is_verbose());
        assert!(!Profile::Custom.is_verbose());
    }

    #[test]
    fn test_dev_profile_defaults() {
        // Clean up any vars that might affect the test
        remove_env("RCH_LOG_LEVEL");
        remove_env("RCH_LOG_FORMAT");

        let defaults = Profile::Dev.get_defaults();

        // If variables are unset, defaults should include them; otherwise they should be omitted.
        if env::var("RCH_LOG_LEVEL").is_ok() {
            assert!(!defaults.iter().any(|(k, _)| *k == "RCH_LOG_LEVEL"));
        } else {
            assert!(
                defaults
                    .iter()
                    .any(|(k, v)| *k == "RCH_LOG_LEVEL" && *v == "debug")
            );
        }

        if env::var("RCH_LOG_FORMAT").is_ok() {
            assert!(!defaults.iter().any(|(k, _)| *k == "RCH_LOG_FORMAT"));
        } else {
            assert!(
                defaults
                    .iter()
                    .any(|(k, v)| *k == "RCH_LOG_FORMAT" && *v == "pretty")
            );
        }
    }

    #[test]
    fn test_test_profile_enables_mock() {
        // Clean up any vars that might affect the test
        remove_env("RCH_MOCK_SSH");
        remove_env("RCH_TEST_MODE");
        remove_env("RCH_LOG_LEVEL");

        let defaults = Profile::Test.get_defaults();

        // Should include mock SSH and test mode
        assert!(
            defaults
                .iter()
                .any(|(k, v)| *k == "RCH_MOCK_SSH" && *v == "1")
        );
        assert!(
            defaults
                .iter()
                .any(|(k, v)| *k == "RCH_TEST_MODE" && *v == "1")
        );
    }

    #[test]
    fn test_profile_doesnt_override() {
        // Set a value before getting defaults
        set_env("RCH_LOG_LEVEL", "error");

        let defaults = Profile::Dev.get_defaults();

        // Should NOT include RCH_LOG_LEVEL since it's already set
        assert!(!defaults.iter().any(|(k, _)| *k == "RCH_LOG_LEVEL"));
        // But should include RCH_LOG_FORMAT which isn't set
        assert!(
            defaults
                .iter()
                .any(|(k, v)| *k == "RCH_LOG_FORMAT" && *v == "pretty")
        );

        // Clean up
        remove_env("RCH_LOG_LEVEL");
    }
}
