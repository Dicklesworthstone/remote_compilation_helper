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
    if toolchain_file.exists() {
        if let Ok(info) = parse_toolchain_file(&toolchain_file) {
            return Ok(info);
        }
    }

    // 2. Check for rust-toolchain (legacy format)
    let legacy_file = project_root.join("rust-toolchain");
    if legacy_file.exists() {
        if let Ok(info) = parse_legacy_toolchain_file(&legacy_file) {
            return Ok(info);
        }
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
    if let Some(date) = channel.strip_prefix("nightly-") {
        if is_valid_date(date) {
            return Ok(ToolchainInfo {
                channel: "nightly".to_string(),
                date: Some(date.to_string()),
                full_version: channel.to_string(),
            });
        }
    }

    // Handle beta-YYYY-MM-DD format
    if let Some(date) = channel.strip_prefix("beta-") {
        if is_valid_date(date) {
            return Ok(ToolchainInfo {
                channel: "beta".to_string(),
                date: Some(date.to_string()),
                full_version: channel.to_string(),
            });
        }
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
    parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
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
    ) {
        if let Some(caps) = re.captures(version_str) {
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
        if info.is_ok() {
            let info = info.unwrap();
            assert!(!info.channel.is_empty());
        }
    }
}
