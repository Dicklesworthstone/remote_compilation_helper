//! Utility functions that build on top of workspace_core.
//!
//! This crate demonstrates inter-crate dependencies within a workspace.

use workspace_core::{compute, validate_input, Config};

/// Extended configuration with additional utility features.
pub struct ExtendedConfig {
    pub core: Config,
    pub prefix: String,
}

impl ExtendedConfig {
    /// Create an extended config from a core config.
    pub fn from_core(core: Config, prefix: impl Into<String>) -> Self {
        Self {
            core,
            prefix: prefix.into(),
        }
    }

    /// Returns a prefixed greeting.
    pub fn prefixed_greeting(&self) -> String {
        format!("[{}] {}", self.prefix, self.core.greeting())
    }
}

/// Batch compute operation using core's compute function.
pub fn batch_compute(pairs: &[(i32, i32)]) -> Vec<i32> {
    pairs.iter().map(|(a, b)| compute(*a, *b)).collect()
}

/// Process multiple inputs through validation.
pub fn process_inputs(inputs: &[&str]) -> Vec<Result<String, &'static str>> {
    inputs.iter().map(|input| validate_input(input)).collect()
}

/// Format a value with the workspace version.
pub fn format_with_version(value: &str) -> String {
    let config = Config::new("formatter");
    format!("{} ({})", value, config.version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extended_config() {
        let core = Config::new("test");
        let extended = ExtendedConfig::from_core(core, "PREFIX");
        assert_eq!(extended.prefix, "PREFIX");
    }

    #[test]
    fn test_prefixed_greeting() {
        let core = Config::new("app");
        let extended = ExtendedConfig::from_core(core, "INFO");
        let greeting = extended.prefixed_greeting();
        assert!(greeting.starts_with("[INFO]"));
        assert!(greeting.contains("app"));
    }

    #[test]
    fn test_batch_compute() {
        let pairs = vec![(1, 2), (3, 4), (5, 6)];
        let results = batch_compute(&pairs);
        assert_eq!(results, vec![3, 7, 11]);
    }

    #[test]
    fn test_batch_compute_empty() {
        let results = batch_compute(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_process_inputs() {
        let inputs = vec!["hello", "", "world"];
        let results = process_inputs(&inputs);
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
        assert!(results[2].is_ok());
    }

    #[test]
    fn test_format_with_version() {
        let formatted = format_with_version("test value");
        assert!(formatted.contains("test value"));
        assert!(formatted.contains("0.1.0"));
    }
}
