//! Integration tests that test the workspace as a whole.

use workspace_core::Config;
use workspace_utils::{batch_compute, ExtendedConfig};

#[test]
fn test_workspace_integration() {
    // Create config through core
    let config = Config::new("integration_test");

    // Extend it through utils
    let extended = ExtendedConfig::from_core(config, "INTEGRATION");

    // Verify the chain works
    let greeting = extended.prefixed_greeting();
    assert!(greeting.contains("[INTEGRATION]"));
    assert!(greeting.contains("integration_test"));
}

#[test]
fn test_cross_crate_computation() {
    // Use utils' batch_compute which internally uses core's compute
    let results = batch_compute(&[(100, 200), (0, 0), (-5, 5)]);
    assert_eq!(results, vec![300, 0, 0]);
}

#[test]
fn test_all_crates_accessible() {
    // Verify we can import from all workspace crates
    let _ = workspace_core::compute(1, 1);
    let _ = workspace_utils::format_with_version("test");
    // workspace_app is a binary, not importable
}
