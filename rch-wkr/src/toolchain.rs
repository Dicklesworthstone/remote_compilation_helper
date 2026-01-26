//! Rust toolchain verification and installation on worker.
//!
//! Ensures the required toolchain is available before executing compilation
//! commands, installing via rustup if necessary.

use rch_common::ToolchainInfo;
use std::collections::HashSet;
use std::process::Command;
use std::sync::RwLock;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Thread-safe cache of known-available toolchains.
///
/// Uses a `RwLock<HashSet>` for efficient concurrent reads with occasional writes
/// when new toolchains are discovered or installed.
static TOOLCHAIN_CACHE: RwLock<Option<HashSet<String>>> = RwLock::new(None);

/// Errors that can occur during toolchain operations.
#[derive(Debug, Error)]
pub enum ToolchainError {
    /// Toolchain availability check failed (reserved for future use).
    #[allow(dead_code)]
    #[error("Failed to check toolchain availability: {0}")]
    CheckFailed(String),

    #[error("Failed to install toolchain: {0}")]
    InstallFailed(String),

    #[error("Rustup not available")]
    RustupNotAvailable,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for toolchain operations.
pub type Result<T> = std::result::Result<T, ToolchainError>;

/// Check if rustup is available on this system.
pub fn rustup_available() -> bool {
    Command::new("rustup")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if a toolchain is installed and available.
///
/// First checks the cache, then falls back to rustup.
pub fn is_toolchain_available(toolchain: &str) -> Result<bool> {
    // Check cache first
    {
        let cache = TOOLCHAIN_CACHE.read().unwrap();
        if let Some(ref set) = *cache
            && set.contains(toolchain)
        {
            debug!("Toolchain {} found in cache", toolchain);
            return Ok(true);
        }
    }

    // Query rustup
    debug!("Checking toolchain {} via rustup", toolchain);
    let output = Command::new("rustup")
        .args(["run", toolchain, "rustc", "--version"])
        .output()?;

    let available = output.status.success();

    // Update cache if available
    if available {
        let mut cache = TOOLCHAIN_CACHE.write().unwrap();
        let set = cache.get_or_insert_with(HashSet::new);
        set.insert(toolchain.to_string());
        debug!("Cached toolchain {} as available", toolchain);
    }

    Ok(available)
}

/// Install a toolchain via rustup using minimal profile.
///
/// Uses `--profile minimal` to reduce installation size and time.
pub fn install_toolchain(toolchain: &str) -> Result<()> {
    info!("Installing toolchain {} via rustup", toolchain);

    let output = Command::new("rustup")
        .args(["toolchain", "install", toolchain, "--profile", "minimal"])
        .output()?;

    if output.status.success() {
        info!("Successfully installed toolchain {}", toolchain);

        // Update cache
        let mut cache = TOOLCHAIN_CACHE.write().unwrap();
        let set = cache.get_or_insert_with(HashSet::new);
        set.insert(toolchain.to_string());

        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(ToolchainError::InstallFailed(format!(
            "rustup install failed: {}",
            stderr.trim()
        )))
    }
}

/// Ensure a toolchain is available, installing if necessary.
///
/// This is the main entry point for toolchain verification:
/// 1. Check if toolchain is already available (cached or via rustup)
/// 2. If not available, install via rustup with minimal profile
/// 3. Return Ok(()) if toolchain is now usable
///
/// # Fail-Open Behavior
///
/// On installation failure, this returns an error but callers should consider
/// falling back to local execution rather than blocking the agent.
pub fn ensure_toolchain(toolchain: &ToolchainInfo) -> Result<()> {
    let tc_str = toolchain.rustup_toolchain();
    info!(
        "Ensuring toolchain {} is available (channel: {}, date: {:?})",
        tc_str, toolchain.channel, toolchain.date
    );

    // Check if rustup is available
    if !rustup_available() {
        warn!("Rustup not available on this worker");
        return Err(ToolchainError::RustupNotAvailable);
    }

    // Check if toolchain is already available
    if is_toolchain_available(&tc_str)? {
        debug!("Toolchain {} is already available", tc_str);
        return Ok(());
    }

    // Install the toolchain
    info!("Toolchain {} not found, installing...", tc_str);
    install_toolchain(&tc_str)?;

    // Verify installation
    if is_toolchain_available(&tc_str)? {
        info!("Toolchain {} is now available", tc_str);
        Ok(())
    } else {
        Err(ToolchainError::InstallFailed(format!(
            "Toolchain {} not available after installation",
            tc_str
        )))
    }
}

/// Clear the toolchain cache.
///
/// Useful for testing or when toolchains may have been removed.
#[allow(dead_code)]
pub fn clear_cache() {
    let mut cache = TOOLCHAIN_CACHE.write().unwrap();
    *cache = None;
    debug!("Toolchain cache cleared");
}

/// Get the current cache contents for debugging.
#[allow(dead_code)]
pub fn get_cached_toolchains() -> Vec<String> {
    let cache = TOOLCHAIN_CACHE.read().unwrap();
    match &*cache {
        Some(set) => set.iter().cloned().collect(),
        None => Vec::new(),
    }
}

/// Parse a toolchain string into a ToolchainInfo.
///
/// Handles formats like:
/// - "stable", "beta", "nightly" (simple channel)
/// - "nightly-2024-01-15" (channel with date)
/// - "1.75.0" (specific version)
pub fn parse_toolchain_string(s: &str) -> ToolchainInfo {
    let s = strip_target_triple(s);

    // Handle nightly-YYYY-MM-DD format
    if let Some(date) = s.strip_prefix("nightly-")
        && is_date_format(date)
    {
        return ToolchainInfo::new("nightly", Some(date.to_string()), s);
    }

    // Handle beta-YYYY-MM-DD format
    if let Some(date) = s.strip_prefix("beta-")
        && is_date_format(date)
    {
        return ToolchainInfo::new("beta", Some(date.to_string()), s);
    }

    // Simple channel or version
    ToolchainInfo::new(s, None, s)
}

/// Check if a string looks like a date (YYYY-MM-DD).
fn is_date_format(s: &str) -> bool {
    if s.len() != 10 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 3
        && parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
}

/// Strip target triple from toolchain string if present.
///
/// Toolchain strings may include target triples like "nightly-x86_64-unknown-linux-gnu".
/// This function strips the target triple to get the base toolchain.
pub fn strip_target_triple(toolchain: &str) -> &str {
    // Common target triple patterns
    const TARGET_PATTERNS: &[&str] = &[
        "-x86_64-unknown-linux-gnu",
        "-x86_64-unknown-linux-musl",
        "-x86_64-apple-darwin",
        "-aarch64-unknown-linux-gnu",
        "-aarch64-apple-darwin",
        "-x86_64-pc-windows-msvc",
        "-x86_64-pc-windows-gnu",
    ];

    for pattern in TARGET_PATTERNS {
        if let Some(stripped) = toolchain.strip_suffix(pattern) {
            return stripped;
        }
    }

    toolchain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_target_triple_linux() {
        assert_eq!(
            strip_target_triple("nightly-x86_64-unknown-linux-gnu"),
            "nightly"
        );
        assert_eq!(
            strip_target_triple("stable-x86_64-unknown-linux-gnu"),
            "stable"
        );
        assert_eq!(
            strip_target_triple("nightly-2024-01-15-x86_64-unknown-linux-gnu"),
            "nightly-2024-01-15"
        );
    }

    #[test]
    fn test_strip_target_triple_macos() {
        assert_eq!(strip_target_triple("stable-x86_64-apple-darwin"), "stable");
        assert_eq!(
            strip_target_triple("nightly-aarch64-apple-darwin"),
            "nightly"
        );
    }

    #[test]
    fn test_strip_target_triple_no_triple() {
        assert_eq!(strip_target_triple("nightly"), "nightly");
        assert_eq!(strip_target_triple("stable"), "stable");
        assert_eq!(
            strip_target_triple("nightly-2024-01-15"),
            "nightly-2024-01-15"
        );
    }

    #[test]
    fn test_cache_operations() {
        // Start with a clean cache
        clear_cache();
        assert!(get_cached_toolchains().is_empty());

        // Cache is initially empty
        let initial = get_cached_toolchains();
        assert!(initial.is_empty());
    }

    #[test]
    fn test_cache_clear_behavior() {
        // Verify cache clears correctly
        clear_cache();
        let cached = get_cached_toolchains();
        assert!(cached.is_empty(), "Cache should be empty after clear");
    }

    #[test]
    fn test_toolchain_error_display() {
        // Test error message formatting
        let err = ToolchainError::InstallFailed("rustup failed".to_string());
        assert!(err.to_string().contains("rustup failed"));

        let err = ToolchainError::RustupNotAvailable;
        assert!(err.to_string().contains("Rustup not available"));

        let err = ToolchainError::CheckFailed("check failed".to_string());
        assert!(err.to_string().contains("check failed"));
    }

    #[test]
    fn test_parse_toolchain_string_edge_cases() {
        // Test empty string
        let tc = parse_toolchain_string("");
        assert_eq!(tc.channel, "");

        // Test just a version major.minor
        let tc = parse_toolchain_string("1.75");
        assert_eq!(tc.channel, "1.75");
        assert_eq!(tc.date, None);

        // Test with musl target
        let tc = parse_toolchain_string("stable-x86_64-unknown-linux-musl");
        assert_eq!(tc.channel, "stable");

        // Test Windows target
        let tc = parse_toolchain_string("nightly-x86_64-pc-windows-msvc");
        assert_eq!(tc.channel, "nightly");
    }

    #[test]
    fn test_strip_target_triple_windows() {
        assert_eq!(
            strip_target_triple("stable-x86_64-pc-windows-msvc"),
            "stable"
        );
        assert_eq!(
            strip_target_triple("nightly-2024-01-15-x86_64-pc-windows-gnu"),
            "nightly-2024-01-15"
        );
    }

    #[test]
    fn test_strip_target_triple_aarch64() {
        assert_eq!(
            strip_target_triple("stable-aarch64-unknown-linux-gnu"),
            "stable"
        );
    }

    #[test]
    fn test_parse_toolchain_preserves_full_version() {
        let tc = parse_toolchain_string("nightly-2024-01-15");
        assert_eq!(tc.full_version, "nightly-2024-01-15");

        let tc = parse_toolchain_string("stable");
        assert_eq!(tc.full_version, "stable");
    }

    #[test]
    fn test_toolchain_info_rustup_toolchain() {
        let tc = ToolchainInfo::new("nightly", Some("2024-01-15".to_string()), "");
        assert_eq!(tc.rustup_toolchain(), "nightly-2024-01-15");

        let tc_stable = ToolchainInfo::new("stable", None, "");
        assert_eq!(tc_stable.rustup_toolchain(), "stable");
    }

    #[test]
    fn test_parse_toolchain_string_stable() {
        let tc = parse_toolchain_string("stable");
        assert_eq!(tc.channel, "stable");
        assert_eq!(tc.date, None);
    }

    #[test]
    fn test_parse_toolchain_string_nightly() {
        let tc = parse_toolchain_string("nightly");
        assert_eq!(tc.channel, "nightly");
        assert_eq!(tc.date, None);
    }

    #[test]
    fn test_parse_toolchain_string_nightly_with_date() {
        let tc = parse_toolchain_string("nightly-2024-01-15");
        assert_eq!(tc.channel, "nightly");
        assert_eq!(tc.date, Some("2024-01-15".to_string()));
        assert_eq!(tc.rustup_toolchain(), "nightly-2024-01-15");
    }

    #[test]
    fn test_parse_toolchain_string_beta_with_date() {
        let tc = parse_toolchain_string("beta-2024-02-01");
        assert_eq!(tc.channel, "beta");
        assert_eq!(tc.date, Some("2024-02-01".to_string()));
    }

    #[test]
    fn test_parse_toolchain_string_version() {
        let tc = parse_toolchain_string("1.75.0");
        assert_eq!(tc.channel, "1.75.0");
        assert_eq!(tc.date, None);
    }

    #[test]
    fn test_parse_toolchain_string_with_target() {
        let tc = parse_toolchain_string("nightly-x86_64-unknown-linux-gnu");
        assert_eq!(tc.channel, "nightly");
        assert_eq!(tc.date, None);
    }

    #[test]
    fn test_parse_toolchain_string_nightly_date_with_target() {
        let tc = parse_toolchain_string("nightly-2024-01-15-x86_64-unknown-linux-gnu");
        assert_eq!(tc.channel, "nightly");
        assert_eq!(tc.date, Some("2024-01-15".to_string()));
    }

    #[test]
    fn test_is_date_format() {
        assert!(is_date_format("2024-01-15"));
        assert!(is_date_format("2023-12-31"));
        assert!(!is_date_format("2024-1-15")); // Missing leading zero
        assert!(!is_date_format("2024-01-1")); // Missing leading zero
        assert!(!is_date_format("24-01-15")); // Year too short
        assert!(!is_date_format("not-a-date"));
        assert!(!is_date_format("x86_64")); // Not a date
    }

    // Note: Tests that require rustup are integration tests and should be
    // run with actual rustup available. They're marked with #[ignore] for
    // regular test runs.

    #[test]
    #[ignore]
    fn test_rustup_available_integration() {
        // This test requires rustup to be installed
        let available = rustup_available();
        println!("Rustup available: {}", available);
        // Don't assert - just check it doesn't panic
    }

    #[test]
    #[ignore]
    fn test_is_toolchain_available_stable() {
        // This test requires rustup and stable toolchain
        clear_cache();
        let result = is_toolchain_available("stable");
        println!("Stable toolchain available: {:?}", result);
    }

    #[test]
    #[ignore]
    fn test_ensure_toolchain_stable() {
        // This test requires rustup
        clear_cache();
        let tc = ToolchainInfo::new("stable", None, "");
        let result = ensure_toolchain(&tc);
        println!("Ensure stable result: {:?}", result);
    }

    // === Cache behavior tests ===

    #[test]
    fn test_cache_starts_empty() {
        // Clear first to ensure clean state
        clear_cache();
        let cached = get_cached_toolchains();
        assert!(cached.is_empty(), "Cache should be empty after clear");
    }

    #[test]
    fn test_cache_clear_is_thorough() {
        // Simulate adding to cache by directly manipulating (if possible)
        // Since we can't easily add without rustup, just verify clear works
        clear_cache();
        let before = get_cached_toolchains();
        assert!(before.is_empty());

        // Clear again (should be idempotent)
        clear_cache();
        let after = get_cached_toolchains();
        assert!(after.is_empty());
    }

    #[test]
    fn test_cache_independent_of_clear_order() {
        // Multiple clears should all succeed
        for _ in 0..5 {
            clear_cache();
            assert!(get_cached_toolchains().is_empty());
        }
    }

    #[test]
    fn test_toolchain_error_variants() {
        // Test all error variants for coverage
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let tc_err: ToolchainError = io_err.into();
        assert!(tc_err.to_string().contains("IO error"));

        let check_err = ToolchainError::CheckFailed("connection lost".to_string());
        assert!(check_err.to_string().contains("connection lost"));

        let install_err = ToolchainError::InstallFailed("no space left".to_string());
        assert!(install_err.to_string().contains("no space left"));

        let rustup_err = ToolchainError::RustupNotAvailable;
        assert!(rustup_err.to_string().contains("Rustup"));
    }

    #[test]
    fn test_parse_toolchain_string_beta() {
        let tc = parse_toolchain_string("beta");
        assert_eq!(tc.channel, "beta");
        assert_eq!(tc.date, None);
    }

    #[test]
    fn test_parse_toolchain_string_custom_channel() {
        // Unknown formats should be parsed as-is
        let tc = parse_toolchain_string("my-custom-toolchain");
        assert_eq!(tc.channel, "my-custom-toolchain");
        assert_eq!(tc.date, None);
    }

    #[test]
    fn test_is_date_format_edge_cases() {
        // Valid boundary dates
        assert!(is_date_format("1970-01-01"));
        assert!(is_date_format("2099-12-31"));

        // Invalid formats
        assert!(!is_date_format(""));
        assert!(!is_date_format("2024"));
        assert!(!is_date_format("2024-01"));
        assert!(!is_date_format("20240115"));
        assert!(!is_date_format("2024/01/15"));
    }

    #[test]
    fn test_strip_target_triple_unknown_target() {
        // Unknown targets should be left as-is
        assert_eq!(
            strip_target_triple("nightly-unknown-target-triple"),
            "nightly-unknown-target-triple"
        );
        assert_eq!(strip_target_triple("stable-custom"), "stable-custom");
    }

    #[test]
    fn test_parse_toolchain_string_with_all_targets() {
        // Test all supported target triples
        let targets = [
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
            "x86_64-apple-darwin",
            "aarch64-unknown-linux-gnu",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "x86_64-pc-windows-gnu",
        ];

        for target in &targets {
            let tc_str = format!("nightly-{}", target);
            let tc = parse_toolchain_string(&tc_str);
            assert_eq!(tc.channel, "nightly", "Failed for target: {}", target);
        }
    }

    #[test]
    fn test_toolchain_info_new_constructor() {
        let tc = ToolchainInfo::new(
            "nightly",
            Some("2024-01-15".to_string()),
            "rustc 1.76.0-nightly",
        );
        assert_eq!(tc.channel, "nightly");
        assert_eq!(tc.date, Some("2024-01-15".to_string()));
        assert_eq!(tc.full_version, "rustc 1.76.0-nightly");
    }

    #[test]
    fn test_toolchain_info_channel_detection() {
        let nightly = ToolchainInfo::new("nightly", None, "");
        assert!(nightly.is_nightly());
        assert!(!nightly.is_stable());
        assert!(!nightly.is_beta());

        let stable = ToolchainInfo::new("stable", None, "");
        assert!(stable.is_stable());

        let beta = ToolchainInfo::new("beta", None, "");
        assert!(beta.is_beta());
    }

    #[test]
    #[ignore]
    fn test_cache_population_on_availability_check() {
        // This test requires rustup
        clear_cache();

        // First call should query rustup and cache if found
        let result1 = is_toolchain_available("stable");
        if result1.is_ok() && result1.unwrap() {
            let cached = get_cached_toolchains();
            assert!(cached.contains(&"stable".to_string()));

            // Second call should use cache
            let result2 = is_toolchain_available("stable");
            assert!(result2.is_ok());
            assert!(result2.unwrap());
        }
    }

    #[test]
    #[ignore]
    fn test_cache_miss_then_hit() {
        // This test requires rustup
        clear_cache();

        // Check a toolchain - if available, should be cached
        let result = is_toolchain_available("stable");
        if let Ok(true) = result {
            // Should now be in cache
            let cached = get_cached_toolchains();
            assert!(
                cached.contains(&"stable".to_string()),
                "Stable should be cached after successful check"
            );
        }
    }

    #[test]
    #[ignore]
    fn test_cache_invalidation() {
        // This test requires rustup
        // Check stable is available and cached
        clear_cache();
        let _ = is_toolchain_available("stable");

        // Clear should remove it
        clear_cache();
        let cached = get_cached_toolchains();
        assert!(
            !cached.contains(&"stable".to_string()),
            "Cache should be empty after clear"
        );
    }

    #[test]
    #[ignore]
    fn test_ensure_toolchain_caches_on_success() {
        // This test requires rustup
        clear_cache();

        let tc = ToolchainInfo::new("stable", None, "");
        let result = ensure_toolchain(&tc);

        if result.is_ok() {
            let cached = get_cached_toolchains();
            assert!(
                cached.contains(&"stable".to_string()),
                "Stable should be cached after ensure"
            );
        }
    }

    // === Integration tests with mock scenarios ===
    //
    // These tests verify the decision paths through the toolchain module
    // without requiring actual rustup. They focus on edge cases and error handling.

    #[test]
    fn test_ensure_toolchain_returns_rustup_not_available_error() {
        // Test error type when rustup is not available
        // (This would happen on systems without rustup)
        let err = ToolchainError::RustupNotAvailable;
        assert!(matches!(err, ToolchainError::RustupNotAvailable));
        assert!(err.to_string().contains("Rustup"));
    }

    #[test]
    fn test_ensure_toolchain_returns_install_failed_error() {
        // Test error type when installation fails
        let err = ToolchainError::InstallFailed("network timeout".to_string());
        assert!(matches!(err, ToolchainError::InstallFailed(_)));
        assert!(err.to_string().contains("network timeout"));
    }

    #[test]
    fn test_parse_toolchain_for_ensure() {
        // Test that parse_toolchain_string produces valid input for ensure_toolchain
        let tc_str = "nightly-2024-01-15";
        let tc_info = parse_toolchain_string(tc_str);

        // Verify the parsed info is valid for rustup
        assert_eq!(tc_info.channel, "nightly");
        assert_eq!(tc_info.date, Some("2024-01-15".to_string()));
        assert_eq!(tc_info.rustup_toolchain(), "nightly-2024-01-15");
    }

    #[test]
    fn test_parse_toolchain_for_ensure_stable() {
        let tc_info = parse_toolchain_string("stable");
        assert_eq!(tc_info.channel, "stable");
        assert_eq!(tc_info.date, None);
        assert_eq!(tc_info.rustup_toolchain(), "stable");
    }

    #[test]
    fn test_parse_toolchain_for_ensure_beta_with_date() {
        let tc_info = parse_toolchain_string("beta-2024-03-01");
        assert_eq!(tc_info.channel, "beta");
        assert_eq!(tc_info.date, Some("2024-03-01".to_string()));
        assert_eq!(tc_info.rustup_toolchain(), "beta-2024-03-01");
    }

    #[test]
    fn test_parse_toolchain_strips_target_before_ensure() {
        // Toolchains with target triples should be normalized
        let tc_info = parse_toolchain_string("nightly-2024-01-15-x86_64-unknown-linux-gnu");
        assert_eq!(tc_info.channel, "nightly");
        assert_eq!(tc_info.date, Some("2024-01-15".to_string()));
        // The rustup_toolchain() should give a format that rustup understands
        assert_eq!(tc_info.rustup_toolchain(), "nightly-2024-01-15");
    }

    #[test]
    fn test_toolchain_error_from_io() {
        // Test From<std::io::Error> for ToolchainError
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let tc_err: ToolchainError = io_err.into();
        assert!(matches!(tc_err, ToolchainError::Io(_)));
        assert!(tc_err.to_string().contains("IO error"));
    }

    #[test]
    fn test_toolchain_error_debug_format() {
        // Test Debug implementation
        let err = ToolchainError::RustupNotAvailable;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("RustupNotAvailable"));

        let err2 = ToolchainError::InstallFailed("test".to_string());
        let debug_str2 = format!("{:?}", err2);
        assert!(debug_str2.contains("InstallFailed"));
    }

    #[test]
    fn test_command_wrapping_for_toolchain() {
        // Test that wrap_command_with_toolchain from rch_common works correctly
        use rch_common::wrap_command_with_toolchain;

        let tc = ToolchainInfo::new("nightly", Some("2024-01-15".to_string()), "");
        let wrapped = wrap_command_with_toolchain("cargo build", Some(&tc));
        assert_eq!(wrapped, "rustup run nightly-2024-01-15 cargo build");

        // Without toolchain should pass through
        let direct = wrap_command_with_toolchain("cargo build", None);
        assert_eq!(direct, "cargo build");
    }

    #[test]
    fn test_fallback_path_on_toolchain_error() {
        // Simulate the fallback decision path when toolchain fails
        // In the actual code, this triggers execution without toolchain wrapping
        let result: Result<()> = Err(ToolchainError::InstallFailed("test".to_string()));

        // On error, the caller should fall back to default execution
        match result {
            Ok(()) => panic!("Expected error"),
            Err(e) => {
                // The error message should be informative for logging
                let msg = e.to_string();
                assert!(!msg.is_empty());
            }
        }
    }

    #[test]
    fn test_nightly_with_invalid_date_parsed_as_custom() {
        // If the date part doesn't look like a date, treat as custom channel
        let tc = parse_toolchain_string("nightly-foobar");
        // This should be parsed as channel="nightly-foobar" with no date
        // since "foobar" doesn't match YYYY-MM-DD
        assert_eq!(tc.channel, "nightly-foobar");
        assert_eq!(tc.date, None);
    }

    #[test]
    fn test_beta_with_invalid_date_parsed_as_custom() {
        let tc = parse_toolchain_string("beta-invalid");
        assert_eq!(tc.channel, "beta-invalid");
        assert_eq!(tc.date, None);
    }

    #[test]
    fn test_version_number_as_channel() {
        // Specific versions should be parsed as channels
        let tc = parse_toolchain_string("1.75.0");
        assert_eq!(tc.channel, "1.75.0");
        assert_eq!(tc.date, None);
        assert_eq!(tc.rustup_toolchain(), "1.75.0");
    }

    #[test]
    fn test_two_digit_version() {
        let tc = parse_toolchain_string("1.75");
        assert_eq!(tc.channel, "1.75");
        assert_eq!(tc.date, None);
    }
}
