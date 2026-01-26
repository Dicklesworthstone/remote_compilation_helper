//! Rust toolchain version detection.
//!
//! Detects the active Rust toolchain for a project by checking:
//! 1. rust-toolchain.toml override file
//! 2. Legacy rust-toolchain file
//! 3. rustc --version output
//!
//! NOTE: This module is newly implemented and awaiting integration with the
//! transfer pipeline. Functions are intentionally public for future use.

#![allow(dead_code)]

use rch_common::ToolchainInfo;
use std::path::Path;
use std::process::Command;

/// Errors that can occur during toolchain detection.
#[derive(Debug, thiserror::Error)]
pub enum ToolchainError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid toolchain file format")]
    InvalidFormat,
    #[error("Failed to parse rustc version: {0}")]
    ParseError(String),
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
}

/// Detect the active Rust toolchain for a project.
///
/// Checks in order:
/// 1. rust-toolchain.toml in project root
/// 2. rust-toolchain (legacy format) in project root
/// 3. Falls back to rustc --version
pub fn detect_toolchain(project_root: &Path) -> Result<ToolchainInfo, ToolchainError> {
    // 1. Check for rust-toolchain.toml override
    let toolchain_file = project_root.join("rust-toolchain.toml");
    if toolchain_file.exists()
        && let Ok(info) = parse_toolchain_file(&toolchain_file)
    {
        return Ok(info);
    }

    // 2. Check for rust-toolchain (legacy format)
    let legacy_file = project_root.join("rust-toolchain");
    if legacy_file.exists()
        && let Ok(info) = parse_legacy_toolchain_file(&legacy_file)
    {
        return Ok(info);
    }

    // 3. Fall back to rustc --version
    detect_from_rustc()
}

/// Parse a rust-toolchain.toml file.
fn parse_toolchain_file(path: &Path) -> Result<ToolchainInfo, ToolchainError> {
    let content = std::fs::read_to_string(path)?;
    let toml: toml::Value = toml::from_str(&content)?;

    let channel = toml
        .get("toolchain")
        .and_then(|t| t.get("channel"))
        .and_then(|c| c.as_str())
        .ok_or(ToolchainError::InvalidFormat)?;

    parse_channel_string(channel)
}

/// Parse a legacy rust-toolchain file (plain text channel name).
fn parse_legacy_toolchain_file(path: &Path) -> Result<ToolchainInfo, ToolchainError> {
    let content = std::fs::read_to_string(path)?;
    let channel = content.trim();
    if channel.is_empty() {
        return Err(ToolchainError::InvalidFormat);
    }
    parse_channel_string(channel)
}

/// Parse a channel string like "nightly-2024-01-15" or "stable".
pub fn parse_channel_string(channel: &str) -> Result<ToolchainInfo, ToolchainError> {
    // Handle nightly-YYYY-MM-DD format
    if let Some(date) = channel.strip_prefix("nightly-")
        && is_valid_date(date)
    {
        return Ok(ToolchainInfo {
            channel: "nightly".to_string(),
            date: Some(date.to_string()),
            full_version: channel.to_string(),
        });
    }

    // Handle beta-YYYY-MM-DD format
    if let Some(date) = channel.strip_prefix("beta-")
        && is_valid_date(date)
    {
        return Ok(ToolchainInfo {
            channel: "beta".to_string(),
            date: Some(date.to_string()),
            full_version: channel.to_string(),
        });
    }

    // Handle simple channel names
    if channel == "stable" || channel == "beta" || channel == "nightly" {
        return Ok(ToolchainInfo {
            channel: channel.to_string(),
            date: None,
            full_version: channel.to_string(),
        });
    }

    // Handle specific version like "1.75.0"
    if is_version_number(channel) {
        return Ok(ToolchainInfo {
            channel: channel.to_string(),
            date: None,
            full_version: channel.to_string(),
        });
    }

    // Unknown format, treat as channel name
    Ok(ToolchainInfo {
        channel: channel.to_string(),
        date: None,
        full_version: channel.to_string(),
    })
}

/// Check if a string looks like a date (YYYY-MM-DD).
fn is_valid_date(s: &str) -> bool {
    if s.len() != 10 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    // Check format: YYYY-MM-DD with all digits
    if !(parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit())))
    {
        return false;
    }
    // Validate month and day ranges
    let month: u32 = parts[1].parse().unwrap_or(0);
    let day: u32 = parts[2].parse().unwrap_or(0);
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

/// Check if a string looks like a version number (X.Y.Z).
fn is_version_number(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 2
        && parts.len() <= 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Detect toolchain from rustc --version output.
fn detect_from_rustc() -> Result<ToolchainInfo, ToolchainError> {
    let output = Command::new("rustc").arg("--version").output()?;

    if !output.status.success() {
        return Err(ToolchainError::ParseError(
            "rustc --version failed".to_string(),
        ));
    }

    let version_str = String::from_utf8_lossy(&output.stdout);
    parse_rustc_version(&version_str)
}

/// Parse rustc --version output.
///
/// Examples:
/// - "rustc 1.76.0-nightly (abc123def 2024-01-15)"
/// - "rustc 1.75.0 (82e1608df 2023-12-21)"
pub fn parse_rustc_version(version_str: &str) -> Result<ToolchainInfo, ToolchainError> {
    // Pattern: rustc VERSION(-CHANNEL)? (HASH DATE)
    // VERSION = major.minor.patch
    // CHANNEL = nightly or beta
    // HASH = hex commit hash
    // DATE = YYYY-MM-DD

    let version_str = version_str.trim();

    // First try with regex for accurate parsing
    if let Ok(re) = regex::Regex::new(
        r"rustc (\d+\.\d+\.\d+)(-nightly|-beta)? \([a-f0-9]+ (\d{4}-\d{2}-\d{2})\)",
    ) && let Some(caps) = re.captures(version_str)
    {
        let _version = caps.get(1).unwrap().as_str();
        let channel_suffix = caps.get(2).map(|m| m.as_str());
        let date = caps.get(3).map(|m| m.as_str().to_string());

        let channel = match channel_suffix {
            Some("-nightly") => "nightly".to_string(),
            Some("-beta") => "beta".to_string(),
            Some(other) => other.trim_start_matches('-').to_string(),
            None => "stable".to_string(),
        };

        return Ok(ToolchainInfo {
            channel,
            date,
            full_version: version_str.to_string(),
        });
    }

    // Fallback: simple parsing for edge cases
    if version_str.starts_with("rustc ") {
        let parts: Vec<&str> = version_str.split_whitespace().collect();
        if parts.len() >= 2 {
            let version_part = parts[1];
            if version_part.contains("-nightly") {
                return Ok(ToolchainInfo {
                    channel: "nightly".to_string(),
                    date: None,
                    full_version: version_str.to_string(),
                });
            } else if version_part.contains("-beta") {
                return Ok(ToolchainInfo {
                    channel: "beta".to_string(),
                    date: None,
                    full_version: version_str.to_string(),
                });
            } else {
                return Ok(ToolchainInfo {
                    channel: "stable".to_string(),
                    date: None,
                    full_version: version_str.to_string(),
                });
            }
        }
    }

    Err(ToolchainError::ParseError(version_str.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_parse_nightly_channel() {
        let info = parse_channel_string("nightly-2024-01-15").unwrap();
        assert_eq!(info.channel, "nightly");
        assert_eq!(info.date, Some("2024-01-15".to_string()));
        assert_eq!(info.rustup_toolchain(), "nightly-2024-01-15");
    }

    #[test]
    fn test_parse_beta_channel() {
        let info = parse_channel_string("beta-2024-02-01").unwrap();
        assert_eq!(info.channel, "beta");
        assert_eq!(info.date, Some("2024-02-01".to_string()));
        assert_eq!(info.rustup_toolchain(), "beta-2024-02-01");
    }

    #[test]
    fn test_parse_stable_channel() {
        let info = parse_channel_string("stable").unwrap();
        assert_eq!(info.channel, "stable");
        assert_eq!(info.date, None);
        assert_eq!(info.rustup_toolchain(), "stable");
    }

    #[test]
    fn test_parse_nightly_channel_no_date() {
        let info = parse_channel_string("nightly").unwrap();
        assert_eq!(info.channel, "nightly");
        assert_eq!(info.date, None);
        assert_eq!(info.rustup_toolchain(), "nightly");
    }

    #[test]
    fn test_parse_specific_version() {
        let info = parse_channel_string("1.75.0").unwrap();
        assert_eq!(info.channel, "1.75.0");
        assert_eq!(info.date, None);
        assert_eq!(info.rustup_toolchain(), "1.75.0");
    }

    #[test]
    fn test_parse_rustc_version_nightly() {
        let info = parse_rustc_version("rustc 1.76.0-nightly (abc123def 2024-01-15)").unwrap();
        assert_eq!(info.channel, "nightly");
        assert_eq!(info.date, Some("2024-01-15".to_string()));
    }

    #[test]
    fn test_parse_rustc_version_stable() {
        let info = parse_rustc_version("rustc 1.75.0 (82e1608df 2023-12-21)").unwrap();
        assert_eq!(info.channel, "stable");
        assert_eq!(info.date, Some("2023-12-21".to_string()));
    }

    #[test]
    fn test_parse_rustc_version_beta() {
        let info = parse_rustc_version("rustc 1.76.0-beta (abcdef123 2024-01-20)").unwrap();
        assert_eq!(info.channel, "beta");
        assert_eq!(info.date, Some("2024-01-20".to_string()));
    }

    #[test]
    fn test_is_valid_date() {
        assert!(is_valid_date("2024-01-15"));
        assert!(is_valid_date("2023-12-31"));
        assert!(!is_valid_date("2024-1-15")); // Missing leading zero
        assert!(!is_valid_date("2024-01-1")); // Missing leading zero
        assert!(!is_valid_date("24-01-15")); // Year too short
        assert!(!is_valid_date("not-a-date"));
    }

    #[test]
    fn test_is_version_number() {
        assert!(is_version_number("1.75.0"));
        assert!(is_version_number("1.76"));
        assert!(is_version_number("2.0.0"));
        assert!(!is_version_number("stable"));
        assert!(!is_version_number("1.75.0-nightly"));
        assert!(!is_version_number(""));
    }

    #[test]
    fn test_toolchain_info_serialization() {
        let info = ToolchainInfo {
            channel: "nightly".to_string(),
            date: Some("2024-01-15".to_string()),
            full_version: "rustc 1.76.0-nightly".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: ToolchainInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn test_detect_toolchain_from_toml() {
        let tmp = TempDir::new().unwrap();
        let toolchain_path = tmp.path().join("rust-toolchain.toml");
        let mut file = std::fs::File::create(&toolchain_path).unwrap();
        writeln!(file, "[toolchain]").unwrap();
        writeln!(file, "channel = \"nightly-2024-01-15\"").unwrap();

        let info = detect_toolchain(tmp.path()).unwrap();
        assert_eq!(info.channel, "nightly");
        assert_eq!(info.date, Some("2024-01-15".to_string()));
    }

    #[test]
    fn test_detect_toolchain_from_legacy() {
        let tmp = TempDir::new().unwrap();
        let toolchain_path = tmp.path().join("rust-toolchain");
        std::fs::write(&toolchain_path, "stable\n").unwrap();

        let info = detect_toolchain(tmp.path()).unwrap();
        assert_eq!(info.channel, "stable");
        assert_eq!(info.date, None);
    }

    #[test]
    fn test_detect_toolchain_toml_priority() {
        // If both files exist, rust-toolchain.toml takes priority
        let tmp = TempDir::new().unwrap();

        let toml_path = tmp.path().join("rust-toolchain.toml");
        let mut file = std::fs::File::create(&toml_path).unwrap();
        writeln!(file, "[toolchain]").unwrap();
        writeln!(file, "channel = \"nightly\"").unwrap();

        let legacy_path = tmp.path().join("rust-toolchain");
        std::fs::write(&legacy_path, "stable").unwrap();

        let info = detect_toolchain(tmp.path()).unwrap();
        assert_eq!(info.channel, "nightly");
    }

    #[test]
    fn test_detect_toolchain_fallback_to_rustc() {
        // In a directory with no toolchain files, should fall back to rustc
        let tmp = TempDir::new().unwrap();
        let info = detect_toolchain(tmp.path());
        // This will succeed if rustc is available, which it is in most dev environments
        if let Ok(info) = info {
            assert!(!info.channel.is_empty());
        }
    }

    // === Additional edge case tests for toolchain synchronization ===

    #[test]
    fn test_parse_channel_string_beta_no_date() {
        let info = parse_channel_string("beta").unwrap();
        assert_eq!(info.channel, "beta");
        assert_eq!(info.date, None);
        assert_eq!(info.rustup_toolchain(), "beta");
    }

    #[test]
    fn test_parse_channel_string_two_digit_version() {
        // Handle two-part versions like "1.75"
        let info = parse_channel_string("1.75").unwrap();
        assert_eq!(info.channel, "1.75");
        assert_eq!(info.date, None);
    }

    #[test]
    fn test_parse_channel_string_unknown_format() {
        // Unknown formats should still parse without error
        let info = parse_channel_string("custom-toolchain").unwrap();
        assert_eq!(info.channel, "custom-toolchain");
        assert_eq!(info.date, None);
    }

    #[test]
    fn test_parse_channel_string_nightly_with_invalid_date() {
        // "nightly-" prefix but not a valid date should treat as custom channel
        let info = parse_channel_string("nightly-not-a-date").unwrap();
        // Should not extract as date since it's not a valid date format
        assert_eq!(info.channel, "nightly-not-a-date");
        assert_eq!(info.date, None);
    }

    #[test]
    fn test_is_valid_date_edge_cases() {
        // Boundary dates
        assert!(is_valid_date("2000-01-01"));
        assert!(is_valid_date("2099-12-31"));

        // Invalid formats
        assert!(!is_valid_date(""));
        assert!(!is_valid_date("2024"));
        assert!(!is_valid_date("2024-01"));
        assert!(!is_valid_date("2024/01/15"));
        assert!(!is_valid_date("01-15-2024"));
        assert!(!is_valid_date("2024-13-01")); // Technically valid format, but invalid month
    }

    #[test]
    fn test_is_version_number_edge_cases() {
        // Valid versions
        assert!(is_version_number("0.0.1"));
        assert!(is_version_number("99.99.99"));
        assert!(is_version_number("1.0"));

        // Invalid versions
        assert!(!is_version_number("1"));
        assert!(!is_version_number("1."));
        assert!(!is_version_number(".1.0"));
        assert!(!is_version_number("1.2.3.4")); // Too many parts
        assert!(!is_version_number("a.b.c"));
    }

    #[test]
    fn test_parse_rustc_version_edge_cases() {
        // Minimal nightly format
        let info = parse_rustc_version("rustc 1.80.0-nightly (abcdef123 2025-01-01)").unwrap();
        assert_eq!(info.channel, "nightly");
        assert_eq!(info.date, Some("2025-01-01".to_string()));

        // Minimal beta format
        let info = parse_rustc_version("rustc 1.80.0-beta.1 (abcdef123 2025-02-01)");
        // beta.1 format should fall back to simple parsing
        assert!(info.is_ok());

        // Fallback for unusual formats
        let info = parse_rustc_version("rustc 1.80.0-nightly");
        assert!(info.is_ok());
        let info = info.unwrap();
        assert_eq!(info.channel, "nightly");
    }

    #[test]
    fn test_parse_rustc_version_invalid_formats() {
        // Empty string
        let result = parse_rustc_version("");
        assert!(result.is_err());

        // Not rustc output
        let result = parse_rustc_version("cargo 1.75.0");
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_toolchain_toml_with_components() {
        // TOML with additional fields like components and targets
        let tmp = TempDir::new().unwrap();
        let toolchain_path = tmp.path().join("rust-toolchain.toml");
        let mut file = std::fs::File::create(&toolchain_path).unwrap();
        writeln!(file, "[toolchain]").unwrap();
        writeln!(file, "channel = \"nightly-2024-06-01\"").unwrap();
        writeln!(file, "components = [\"rustfmt\", \"clippy\"]").unwrap();
        writeln!(file, "targets = [\"wasm32-unknown-unknown\"]").unwrap();

        let info = detect_toolchain(tmp.path()).unwrap();
        assert_eq!(info.channel, "nightly");
        assert_eq!(info.date, Some("2024-06-01".to_string()));
    }

    #[test]
    fn test_detect_toolchain_toml_with_profile() {
        // TOML with profile field
        let tmp = TempDir::new().unwrap();
        let toolchain_path = tmp.path().join("rust-toolchain.toml");
        let mut file = std::fs::File::create(&toolchain_path).unwrap();
        writeln!(file, "[toolchain]").unwrap();
        writeln!(file, "channel = \"stable\"").unwrap();
        writeln!(file, "profile = \"minimal\"").unwrap();

        let info = detect_toolchain(tmp.path()).unwrap();
        assert_eq!(info.channel, "stable");
    }

    #[test]
    fn test_detect_toolchain_legacy_with_whitespace() {
        // Legacy file with extra whitespace
        let tmp = TempDir::new().unwrap();
        let toolchain_path = tmp.path().join("rust-toolchain");
        std::fs::write(&toolchain_path, "  nightly-2024-03-15  \n\n").unwrap();

        let info = detect_toolchain(tmp.path()).unwrap();
        assert_eq!(info.channel, "nightly");
        assert_eq!(info.date, Some("2024-03-15".to_string()));
    }

    #[test]
    fn test_detect_toolchain_legacy_empty_file() {
        // Empty legacy file should fail
        let tmp = TempDir::new().unwrap();
        let toolchain_path = tmp.path().join("rust-toolchain");
        std::fs::write(&toolchain_path, "").unwrap();

        // Should fall through to legacy file, find it invalid, then fall back to rustc
        let result = detect_toolchain(tmp.path());
        // Either falls back to rustc or returns error depending on rustc availability
        // Don't assert success/failure - just that it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_detect_toolchain_invalid_toml() {
        // Invalid TOML should fall through to legacy or rustc
        let tmp = TempDir::new().unwrap();
        let toolchain_path = tmp.path().join("rust-toolchain.toml");
        std::fs::write(&toolchain_path, "this is not valid toml [[[").unwrap();

        // Should fall through to rustc fallback (if available)
        let result = detect_toolchain(tmp.path());
        // Don't assert success/failure - just verify no panic
        let _ = result;
    }

    #[test]
    fn test_detect_toolchain_toml_missing_channel() {
        // TOML without channel field
        let tmp = TempDir::new().unwrap();
        let toolchain_path = tmp.path().join("rust-toolchain.toml");
        let mut file = std::fs::File::create(&toolchain_path).unwrap();
        writeln!(file, "[toolchain]").unwrap();
        writeln!(file, "components = [\"rustfmt\"]").unwrap();
        // No channel field

        // Should fall through to rustc fallback
        let result = detect_toolchain(tmp.path());
        let _ = result;
    }

    #[test]
    fn test_toolchain_info_display() {
        // Test Display trait implementation (via rustup_toolchain)
        let info = ToolchainInfo {
            channel: "nightly".to_string(),
            date: Some("2024-01-15".to_string()),
            full_version: "rustc 1.76.0-nightly".to_string(),
        };
        assert_eq!(format!("{}", info), "nightly-2024-01-15");

        let info = ToolchainInfo {
            channel: "stable".to_string(),
            date: None,
            full_version: "rustc 1.75.0".to_string(),
        };
        assert_eq!(format!("{}", info), "stable");
    }

    #[test]
    fn test_toolchain_info_equality() {
        let info1 = ToolchainInfo {
            channel: "nightly".to_string(),
            date: Some("2024-01-15".to_string()),
            full_version: "a".to_string(),
        };
        let info2 = ToolchainInfo {
            channel: "nightly".to_string(),
            date: Some("2024-01-15".to_string()),
            full_version: "b".to_string(),
        };
        // Different full_version means not equal
        assert_ne!(info1, info2);

        let info3 = info1.clone();
        assert_eq!(info1, info3);
    }

    #[test]
    fn test_toolchain_info_methods() {
        let nightly = ToolchainInfo::new("nightly", Some("2024-01-15".to_string()), "");
        assert!(nightly.is_nightly());
        assert!(!nightly.is_stable());
        assert!(!nightly.is_beta());

        let stable = ToolchainInfo::new("stable", None, "");
        assert!(stable.is_stable());
        assert!(!stable.is_nightly());
        assert!(!stable.is_beta());

        let beta = ToolchainInfo::new("beta", None, "");
        assert!(beta.is_beta());
        assert!(!beta.is_stable());
        assert!(!beta.is_nightly());

        // Custom channel
        let custom = ToolchainInfo::new("1.75.0", None, "");
        assert!(!custom.is_nightly());
        assert!(!custom.is_stable());
        assert!(!custom.is_beta());
    }
}
