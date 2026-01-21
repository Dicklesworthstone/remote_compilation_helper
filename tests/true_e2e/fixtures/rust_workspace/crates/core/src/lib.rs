//! Core library providing foundational types and functions.
//!
//! This crate has no dependencies and is the base of the workspace dependency graph.

/// A simple configuration struct used across the workspace.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub name: String,
    pub version: String,
    pub debug: bool,
}

impl Config {
    /// Create a new configuration with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            debug: cfg!(debug_assertions),
        }
    }

    /// Returns a greeting message based on the config.
    pub fn greeting(&self) -> String {
        format!("Hello from {} v{}", self.name, self.version)
    }
}

/// Core computation function used by other crates.
pub fn compute(a: i32, b: i32) -> i32 {
    a + b
}

/// Validates input according to core rules.
pub fn validate_input(input: &str) -> Result<String, &'static str> {
    if input.is_empty() {
        Err("Input cannot be empty")
    } else if input.len() > 100 {
        Err("Input too long")
    } else {
        Ok(input.to_uppercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = Config::new("test_app");
        assert_eq!(config.name, "test_app");
        assert_eq!(config.version, "0.1.0");
    }

    #[test]
    fn test_config_greeting() {
        let config = Config::new("rch_fixture");
        let greeting = config.greeting();
        assert!(greeting.contains("rch_fixture"));
        assert!(greeting.contains("0.1.0"));
    }

    #[test]
    fn test_compute() {
        assert_eq!(compute(2, 3), 5);
        assert_eq!(compute(-1, 1), 0);
        assert_eq!(compute(0, 0), 0);
    }

    #[test]
    fn test_validate_input_success() {
        let result = validate_input("hello");
        assert_eq!(result, Ok("HELLO".to_string()));
    }

    #[test]
    fn test_validate_input_empty() {
        let result = validate_input("");
        assert_eq!(result, Err("Input cannot be empty"));
    }

    #[test]
    fn test_validate_input_too_long() {
        let long_input = "x".repeat(101);
        let result = validate_input(&long_input);
        assert_eq!(result, Err("Input too long"));
    }
}
