//! Main application binary that uses both core and utils crates.
//!
//! This demonstrates a complete workspace dependency chain: app -> utils -> core

use workspace_core::{compute, Config};
use workspace_utils::{batch_compute, format_with_version, ExtendedConfig};

fn main() {
    println!("=== RCH Workspace Fixture App ===");

    // Use core directly
    let config = Config::new("workspace_app");
    println!("Core greeting: {}", config.greeting());

    // Use utils (which internally uses core)
    let extended = ExtendedConfig::from_core(config.clone(), "APP");
    println!("Extended greeting: {}", extended.prefixed_greeting());

    // Demonstrate compute functions
    let sum = compute(10, 20);
    println!("Core compute(10, 20) = {}", sum);

    let batch_results = batch_compute(&[(1, 1), (2, 2), (3, 3)]);
    println!("Batch compute results: {:?}", batch_results);

    // Format with version
    let formatted = format_with_version("Application ready");
    println!("{}", formatted);

    println!("=== Fixture Test Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_uses_core() {
        let config = Config::new("test");
        assert_eq!(config.name, "test");
    }

    #[test]
    fn test_app_uses_utils() {
        let core = Config::new("app");
        let extended = ExtendedConfig::from_core(core, "TEST");
        assert!(extended.prefixed_greeting().contains("[TEST]"));
    }

    #[test]
    fn test_dependency_chain() {
        // This test verifies the full dependency chain works
        let results = batch_compute(&[(5, 5)]);
        assert_eq!(results[0], 10);
    }
}
