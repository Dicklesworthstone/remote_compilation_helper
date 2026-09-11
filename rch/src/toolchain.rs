//! Rust toolchain version detection.
//!
//! Resolves project toolchain declarations and active rustup identities.
//! Compiler commit dates are diagnostic metadata, never rustup archive dates.

#![allow(dead_code)]

use rch_common::ToolchainInfo;
use std::path::{Path, PathBuf};
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
/// Ambient explicit overrides precede the nearest ancestor declaration.
/// Without a declaration, ask rustup in the caller's directory before using
/// rustc's channel. Explicit command selectors are handled by the hook first.
/// This file fast path does not resolve rustup's stored directory overrides.
pub fn detect_toolchain(project_root: &Path) -> Result<ToolchainInfo, ToolchainError> {
    let ambient = std::env::var("RUSTUP_TOOLCHAIN").ok();
    detect_toolchain_with(project_root, ambient.as_deref(), detect_active_toolchain)
}

fn detect_toolchain_with(
    project_root: &Path,
    ambient: Option<&str>,
    fallback: impl FnOnce(&Path) -> Result<ToolchainInfo, ToolchainError>,
) -> Result<ToolchainInfo, ToolchainError> {
    if let Some(name) = ambient.filter(|name| !name.is_empty()) {
        return parse_active_toolchain(name);
    }
    if let Some(path) = nearest_toolchain_file(project_root)? {
        let parsed = if path
            .file_name()
            .is_some_and(|name| name == "rust-toolchain")
        {
            parse_legacy_toolchain_file(&path)
        } else {
            parse_toolchain_file(&path)
        };
        match parsed {
            Ok(info) => return Ok(info),
            // A valid TOML file may declare only components/profile. Let
            // rustup resolve its unspecified channel in the caller's cwd.
            Err(ToolchainError::InvalidFormat) => {}
            Err(error) => return Err(error),
        }
    }
    fallback(project_root)
}

/// Read the components explicitly declared by the project's rust-toolchain
/// file. Plain-text legacy files declare no components. Invalid or unreadable
/// files return an empty set so callers can still report connectivity without
/// inventing requirements.
pub fn detect_declared_components(project_root: &Path) -> Vec<String> {
    nearest_toolchain_file(project_root)
        .ok()
        .flatten()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|content| parse_declared_components(&content))
        .unwrap_or_default()
}

/// Match rustup's ancestor search and same-directory filename precedence.
/// A nearer declaration shadows the entire ancestor declaration, including
/// components; unreadable entries must not reveal a farther declaration.
fn nearest_toolchain_file(project_root: &Path) -> Result<Option<PathBuf>, ToolchainError> {
    let root = project_root.canonicalize()?;
    for directory in root.ancestors() {
        for name in ["rust-toolchain", "rust-toolchain.toml"] {
            let path = directory.join(name);
            match path.try_exists() {
                Ok(true) => return Ok(Some(path)),
                Ok(false) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(None)
}

fn parse_declared_components(content: &str) -> Vec<String> {
    let Ok(value) = toml::from_str::<toml::Value>(content) else {
        return Vec::new();
    };
    let Some(values) = value
        .get("toolchain")
        .and_then(|toolchain| toolchain.get("components"))
        .and_then(toml::Value::as_array)
    else {
        return Vec::new();
    };

    let mut components = values
        .iter()
        .filter_map(toml::Value::as_str)
        .map(str::trim)
        .filter(|component| !component.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    components.sort();
    components.dedup();
    components
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

/// Parse a legacy rust-toolchain file (plain text channel name or TOML).
fn parse_legacy_toolchain_file(path: &Path) -> Result<ToolchainInfo, ToolchainError> {
    let content = std::fs::read_to_string(path)?;

    // rustup allows `rust-toolchain` (no extension) to be either TOML or plain text.
    // Try TOML parsing first.
    if let Ok(toml) = toml::from_str::<toml::Value>(&content) {
        let channel = toml
            .get("toolchain")
            .and_then(|t| t.get("channel"))
            .and_then(|c| c.as_str())
            .ok_or(ToolchainError::InvalidFormat)?;
        return parse_channel_string(channel);
    }

    // Fallback: treat as plain text channel name (trim whitespace)
    let channel = content.trim();
    if channel.is_empty() || channel.contains(char::is_whitespace) {
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

/// Keep rustup proxies from installing missing toolchains during detection.
fn toolchain_probe(program: &str, args: &[&str], project_root: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(project_root)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .stdin(std::process::Stdio::null());
    command
}

fn detect_active_toolchain(project_root: &Path) -> Result<ToolchainInfo, ToolchainError> {
    detect_active_toolchain_with(project_root, "rustup", "rustc")
}

fn detect_active_toolchain_with(
    project_root: &Path,
    rustup: &str,
    rustc: &str,
) -> Result<ToolchainInfo, ToolchainError> {
    if let Ok(output) =
        toolchain_probe(rustup, &["show", "active-toolchain"], project_root).output()
        && output.status.success()
        && let Ok(info) = parse_active_toolchain(&String::from_utf8_lossy(&output.stdout))
    {
        return Ok(info);
    }
    let output = toolchain_probe(rustc, &["--version"], project_root).output()?;
    if !output.status.success() {
        return Err(ToolchainError::ParseError(
            "rustc --version failed".to_string(),
        ));
    }
    parse_rustc_version(&String::from_utf8_lossy(&output.stdout))
}

/// Rustup appends the controller host to official identities. A remote
/// worker must resolve the same release for its own host. Strip recognized
/// Linux/macOS/Windows controller hosts only; unknown/custom suffixes remain
/// opaque. Do not obtain the release date from a compiler version.
fn parse_active_toolchain(output: &str) -> Result<ToolchainInfo, ToolchainError> {
    let output = output.trim();
    let identity = output.split_once(" (").map_or(output, |(name, _)| name);
    if identity.is_empty() || identity.contains(char::is_whitespace) {
        return Err(ToolchainError::InvalidFormat);
    }
    let official = regex::Regex::new(
        r"^((?:stable|beta|nightly)(?:-\d{4}-\d{2}-\d{2})?|\d+\.\d+(?:\.\d+)?(?:-beta(?:\.\d+)?)?)-(?:x86_64|aarch64|i686)-(?:unknown-linux-(?:gnu|musl)|apple-darwin|pc-windows-(?:msvc|gnu|gnullvm))$",
    )
    .map_err(|error| ToolchainError::ParseError(error.to_string()))?;
    let release = official
        .captures(identity)
        .and_then(|captures| captures.get(1))
        .map_or(identity, |matched| matched.as_str());
    parse_channel_string(release)
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

        let channel = match channel_suffix {
            Some("-nightly") => "nightly".to_string(),
            Some("-beta") => "beta".to_string(),
            Some(other) => other.trim_start_matches('-').to_string(),
            None => "stable".to_string(),
        };

        // This is the compiler commit date, which can precede the archive
        // date even for nightly/beta. Only a declared or active rustup
        // identity can establish an archive date.
        return Ok(ToolchainInfo {
            channel,
            date: None,
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

    fn declared_toolchain(root: &Path) -> Result<ToolchainInfo, ToolchainError> {
        detect_toolchain_with(root, None, |_| Err(ToolchainError::InvalidFormat))
    }

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
        assert_eq!(info.date, None);
        assert_eq!(info.rustup_toolchain(), "nightly");
    }

    #[test]
    fn test_parse_rustc_version_stable() {
        let info = parse_rustc_version("rustc 1.75.0 (82e1608df 2023-12-21)").unwrap();
        assert_eq!(info.channel, "stable");
        // Commit date must NOT leak into the toolchain identity for stable:
        // `stable-2023-12-21` is not a rustup archive name and cannot be
        // installed. The identifier handed to `rustup run` must be `stable`.
        assert_eq!(info.date, None);
        assert_eq!(info.rustup_toolchain(), "stable");
    }

    #[test]
    fn test_parse_rustc_version_stable_fallback_resolvable_identifier() {
        // Regression for issue #43: the exact scenario from the report.
        let info = parse_rustc_version("rustc 1.97.1 (8bab26f4f 2026-07-14)").unwrap();
        assert_eq!(info.channel, "stable");
        assert_eq!(info.rustup_toolchain(), "stable");
        assert!(!info.rustup_toolchain().contains("2026-07-14"));
    }

    #[test]
    fn test_parse_rustc_version_beta() {
        let info = parse_rustc_version("rustc 1.76.0-beta (abcdef123 2024-01-20)").unwrap();
        assert_eq!(info.channel, "beta");
        assert_eq!(info.date, None);
        assert_eq!(info.rustup_toolchain(), "beta");
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

        let info = declared_toolchain(tmp.path()).unwrap();
        assert_eq!(info.channel, "nightly");
        assert_eq!(info.date, Some("2024-01-15".to_string()));
    }

    #[test]
    fn test_detect_toolchain_from_legacy() {
        let tmp = TempDir::new().unwrap();
        let toolchain_path = tmp.path().join("rust-toolchain");
        std::fs::write(&toolchain_path, "stable\n").unwrap();

        let info = declared_toolchain(tmp.path()).unwrap();
        assert_eq!(info.channel, "stable");
        assert_eq!(info.date, None);
    }

    #[test]
    fn test_detect_toolchain_legacy_priority() {
        // Rustup gives rust-toolchain priority, even when both files are TOML.
        let tmp = TempDir::new().unwrap();

        let toml_path = tmp.path().join("rust-toolchain.toml");
        let mut file = std::fs::File::create(&toml_path).unwrap();
        writeln!(file, "[toolchain]").unwrap();
        writeln!(file, "channel = \"nightly\"").unwrap();

        let legacy_path = tmp.path().join("rust-toolchain");
        std::fs::write(&legacy_path, "stable").unwrap();

        let info = declared_toolchain(tmp.path()).unwrap();
        assert_eq!(info.channel, "stable");
        assert!(detect_declared_components(tmp.path()).is_empty());

        std::fs::write(
            &legacy_path,
            "[toolchain]\nchannel = 'beta'\ncomponents = ['rustfmt']\n",
        )
        .unwrap();
        assert_eq!(declared_toolchain(tmp.path()).unwrap().channel, "beta");
        assert_eq!(detect_declared_components(tmp.path()), ["rustfmt"]);
    }

    #[test]
    fn test_unspecified_channel_fallback_uses_caller_directory() {
        let tmp = TempDir::new().unwrap();
        let caller = tmp.path().join("nested");
        std::fs::create_dir(&caller).unwrap();
        // TMPDIR can itself live beneath a repository pin. A nearest
        // component-only declaration shadows that pin without supplying a
        // channel, so this test must exercise the fallback on every host.
        std::fs::write(
            caller.join("rust-toolchain.toml"),
            "[toolchain]\ncomponents = ['rustfmt']\n",
        )
        .unwrap();
        let calls = std::cell::Cell::new(0);
        let info = detect_toolchain_with(&caller, None, |cwd| {
            calls.set(calls.get() + 1);
            assert_eq!(cwd, caller);
            parse_active_toolchain(
                "nightly-2026-08-31-x86_64-unknown-linux-gnu (directory override for '/project')",
            )
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(info.rustup_toolchain(), "nightly-2026-08-31");
        assert!(
            detect_toolchain_with(&caller, None, |cwd| {
                calls.set(calls.get() + 1);
                assert_eq!(cwd, caller);
                Err(ToolchainError::InvalidFormat)
            })
            .is_err()
        );
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn test_inherited_pin_components_and_nearest_shadowing() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("tests/fixtures/hello_world");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            tmp.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = 'nightly-2026-08-31'\ncomponents = ['rustfmt', 'clippy']\n",
        )
        .unwrap();
        assert_eq!(
            declared_toolchain(&nested).unwrap().rustup_toolchain(),
            "nightly-2026-08-31"
        );
        assert_eq!(detect_declared_components(&nested), ["clippy", "rustfmt"]);
        let compiler = parse_rustc_version("rustc 1.100.0-nightly (908501772 2026-08-30)").unwrap();
        assert_eq!(compiler.date, None);
        assert_eq!(compiler.rustup_toolchain(), "nightly");

        std::fs::write(nested.parent().unwrap().join("rust-toolchain"), "stable\n").unwrap();
        assert_eq!(declared_toolchain(&nested).unwrap().channel, "stable");
        assert!(detect_declared_components(&nested).is_empty());
        std::fs::write(
            nested.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = 'beta'\ncomponents = ['clippy']\n",
        )
        .unwrap();
        assert_eq!(declared_toolchain(&nested).unwrap().channel, "beta");
        assert_eq!(detect_declared_components(&nested), ["clippy"]);
    }

    #[test]
    fn test_ambient_override_precedes_pin_without_installing() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("rust-toolchain"), "stable").unwrap();
        let info = detect_toolchain_with(
            tmp.path(),
            Some("nightly-1999-01-01-x86_64-unknown-linux-gnu"),
            |_| panic!("an explicit identity must not require an installed toolchain"),
        )
        .unwrap();
        assert_eq!(info.rustup_toolchain(), "nightly-1999-01-01");
        assert_eq!(
            detect_toolchain_with(tmp.path(), Some(""), |_| {
                panic!("empty ambient override must preserve the file fast path")
            })
            .unwrap()
            .channel,
            "stable"
        );
    }

    #[test]
    fn test_active_identity_preserves_archive_and_custom_names() {
        for (active, expected) in [
            (
                "nightly-2026-08-31-x86_64-unknown-linux-gnu (default)",
                "nightly-2026-08-31",
            ),
            (
                "beta-2026-08-31-aarch64-apple-darwin (default)",
                "beta-2026-08-31",
            ),
            ("stable-x86_64-pc-windows-msvc (default)", "stable"),
            ("1.90.0-x86_64-unknown-linux-gnu (default)", "1.90.0"),
            (
                "custom-x86_64-unknown-linux-gnu (default)",
                "custom-x86_64-unknown-linux-gnu",
            ),
            (
                "nightly-optimized-with-assertions (default)",
                "nightly-optimized-with-assertions",
            ),
            (
                "beta-custom-with-checks (default)",
                "beta-custom-with-checks",
            ),
        ] {
            assert_eq!(
                parse_active_toolchain(active).unwrap().rustup_toolchain(),
                expected
            );
        }
        assert!(parse_active_toolchain("").is_err());
        assert!(parse_active_toolchain("no active toolchain").is_err());

        // An explicitly host-qualified project pin is intentional and does
        // not pass through active-output normalization.
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = 'nightly-2026-08-31-x86_64-pc-windows-msvc'\n",
        )
        .unwrap();
        assert_eq!(
            declared_toolchain(tmp.path()).unwrap().rustup_toolchain(),
            "nightly-2026-08-31-x86_64-pc-windows-msvc"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_read_only_probes_use_caller_directory() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let caller = tmp.path().join("caller");
        std::fs::create_dir(&caller).unwrap();
        let program = tmp.path().join("identity-probe");
        // A shell protocol fixture, not evidence of an installed toolchain.
        // Relative input paths prove the subprocess actually runs in caller.
        std::fs::write(
            &program,
            "#!/bin/sh\n[ \"$RUSTUP_AUTO_INSTALL\" = 0 ] || exit 91\ncase \"$*\" in\n'show active-toolchain') cat active; exit 0;;\n'--version') cat compiler;;\n*) exit 92;;\nesac\n",
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            caller.join("active"),
            "nightly-2026-08-31-x86_64-unknown-linux-gnu (default)\n",
        )
        .unwrap();
        std::fs::write(
            caller.join("compiler"),
            "rustc 1.100.0-nightly (908501772 2026-08-30)\n",
        )
        .unwrap();
        let executable = program.to_str().unwrap();
        let info = detect_active_toolchain_with(&caller, executable, executable).unwrap();
        assert_eq!(info.rustup_toolchain(), "nightly-2026-08-31");

        // Unavailable and malformed rustup identities both use the compiler
        // channel without inventing an archive from its commit date.
        let absent = tmp.path().join("not-installed");
        let info =
            detect_active_toolchain_with(&caller, absent.to_str().unwrap(), executable).unwrap();
        assert_eq!(info.rustup_toolchain(), "nightly");
        std::fs::write(caller.join("active"), "no active toolchain\n").unwrap();
        let info = detect_active_toolchain_with(&caller, executable, executable).unwrap();
        assert_eq!(info.rustup_toolchain(), "nightly");
        std::fs::write(caller.join("compiler"), "not a compiler\n").unwrap();
        assert!(detect_active_toolchain_with(&caller, executable, executable).is_err());
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
        assert_eq!(info.date, None);

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

        let info = declared_toolchain(tmp.path()).unwrap();
        assert_eq!(info.channel, "nightly");
        assert_eq!(info.date, Some("2024-06-01".to_string()));
    }

    #[test]
    fn test_parse_declared_components_is_sorted_deduplicated_and_nonblank() {
        let components = parse_declared_components(
            r#"
                [toolchain]
                channel = "nightly-2026-07-05"
                components = ["rustfmt", "clippy", "rustfmt", ""]
            "#,
        );
        assert_eq!(components, vec!["clippy", "rustfmt"]);
        assert!(parse_declared_components("nightly-2026-07-05").is_empty());
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

        let info = declared_toolchain(tmp.path()).unwrap();
        assert_eq!(info.channel, "stable");
    }

    #[test]
    fn test_detect_toolchain_legacy_with_whitespace() {
        // Legacy file with extra whitespace
        let tmp = TempDir::new().unwrap();
        let toolchain_path = tmp.path().join("rust-toolchain");
        std::fs::write(&toolchain_path, "  nightly-2024-03-15  \n\n").unwrap();

        let info = declared_toolchain(tmp.path()).unwrap();
        assert_eq!(info.channel, "nightly");
        assert_eq!(info.date, Some("2024-03-15".to_string()));
    }

    #[test]
    fn test_detect_toolchain_legacy_empty_file() {
        // Empty legacy file should fail
        let tmp = TempDir::new().unwrap();
        let toolchain_path = tmp.path().join("rust-toolchain");
        std::fs::write(&toolchain_path, "").unwrap();

        assert!(matches!(
            declared_toolchain(tmp.path()),
            Err(ToolchainError::InvalidFormat)
        ));
        assert!(detect_declared_components(tmp.path()).is_empty());
    }

    #[test]
    fn test_detect_toolchain_invalid_toml() {
        // Invalid TOML must not silently select an unrelated ancestor pin.
        let tmp = TempDir::new().unwrap();
        let toolchain_path = tmp.path().join("rust-toolchain.toml");
        std::fs::write(&toolchain_path, "this is not valid toml [[[").unwrap();

        assert!(matches!(
            declared_toolchain(tmp.path()),
            Err(ToolchainError::Toml(_))
        ));
        assert!(detect_declared_components(tmp.path()).is_empty());
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

        let info = detect_toolchain_with(tmp.path(), None, |cwd| {
            assert_eq!(cwd, tmp.path());
            parse_active_toolchain("stable-x86_64-unknown-linux-gnu (default)")
        })
        .unwrap();
        assert_eq!(info.channel, "stable");
        assert_eq!(detect_declared_components(tmp.path()), ["rustfmt"]);
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
