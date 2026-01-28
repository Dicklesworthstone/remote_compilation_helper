//! Core types for the update system.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;

/// Cache duration for version check results (24 hours).
pub const CACHE_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum number of backup versions to keep.
pub const MAX_BACKUPS: usize = 3;

/// Error types for update operations.
#[derive(Error, Debug)]
pub enum UpdateError {
    #[error("Failed to check for updates: {0}")]
    CheckFailed(String),

    #[error("Failed to download release: {0}")]
    DownloadFailed(String),

    #[error("Checksum verification failed: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("Installation failed: {0}")]
    InstallFailed(String),

    #[error("Update lock held by another process")]
    LockHeld,

    #[error("No backup available for rollback")]
    NoBackupAvailable,

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid version format: {0}")]
    InvalidVersion(String),

    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),
}

/// Release channel for updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    #[default]
    Stable,
    Beta,
    Nightly,
}

impl FromStr for Channel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "stable" => Ok(Channel::Stable),
            "beta" => Ok(Channel::Beta),
            "nightly" => Ok(Channel::Nightly),
            _ => Err(format!("Unknown channel: {}", s)),
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Channel::Stable => write!(f, "stable"),
            Channel::Beta => write!(f, "beta"),
            Channel::Nightly => write!(f, "nightly"),
        }
    }
}

/// Semantic version with comparison support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub prerelease: Option<String>,
    raw: String,
}

impl Version {
    /// Parse a version string (e.g., "0.1.0", "v0.1.0", "0.1.0-beta.1").
    pub fn parse(s: &str) -> Result<Self, UpdateError> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let raw = s.to_string();

        // Split prerelease suffix
        let (version_part, prerelease) = if let Some(idx) = s.find('-') {
            (&s[..idx], Some(s[idx + 1..].to_string()))
        } else {
            (s, None)
        };

        let parts: Vec<&str> = version_part.split('.').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(UpdateError::InvalidVersion(raw));
        }

        let major = parts[0]
            .parse()
            .map_err(|_| UpdateError::InvalidVersion(raw.clone()))?;
        let minor = parts[1]
            .parse()
            .map_err(|_| UpdateError::InvalidVersion(raw.clone()))?;
        let patch = if parts.len() > 2 {
            parts[2]
                .parse()
                .map_err(|_| UpdateError::InvalidVersion(raw.clone()))?
        } else {
            0
        };

        Ok(Self {
            major,
            minor,
            patch,
            prerelease,
            raw,
        })
    }

    /// Check if this is a prerelease version.
    #[allow(dead_code)]
    pub fn is_prerelease(&self) -> bool {
        self.prerelease.is_some()
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref pre) = self.prerelease {
            write!(f, "{}.{}.{}-{}", self.major, self.minor, self.patch, pre)
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.major == other.major
            && self.minor == other.minor
            && self.patch == other.patch
            && self.prerelease == other.prerelease
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.cmp(&other.patch) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Prerelease versions are less than release versions
        match (&self.prerelease, &other.prerelease) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

/// Information about a GitHub release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub tag_name: String,
    pub name: String,
    pub prerelease: bool,
    pub draft: bool,
    pub html_url: String,
    pub body: Option<String>,
    pub assets: Vec<ReleaseAsset>,
    pub published_at: Option<String>,
}

/// A release asset (downloadable file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
    pub content_type: String,
}

#[allow(dead_code)]
impl ReleaseAsset {
    /// Check if this asset is for the current platform.
    pub fn is_for_current_platform(&self) -> bool {
        let target = current_target();
        self.name.contains(&target)
    }
}

/// Get the current target triple.
pub fn current_target() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;

    let arch_str = arch;

    let os_str = match os {
        "linux" => "unknown-linux-gnu",
        "macos" => "apple-darwin",
        "windows" => "pc-windows-msvc",
        _ => os,
    };

    format!("{}-{}", arch_str, os_str)
}

/// Result of checking for updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheck {
    pub current_version: Version,
    pub latest_version: Version,
    pub update_available: bool,
    pub release_url: String,
    pub release_notes: Option<String>,
    pub changelog_diff: Option<String>,
    pub assets: Vec<ReleaseAsset>,
}

/// Cached version check result with timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCheck {
    /// The cached update check result.
    pub result: UpdateCheck,
    /// Unix timestamp (seconds) when the check was cached.
    pub cached_at_secs: u64,
}

impl CachedCheck {
    /// Check if the cache is still valid (less than CACHE_DURATION old).
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(self.cached_at_secs) < CACHE_DURATION.as_secs()
    }
}

/// Metadata for a backup entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    /// Version string of the backup.
    pub version: String,
    /// Unix timestamp (seconds) when the backup was created.
    pub created_at: u64,
    /// Original installation path that was backed up.
    pub original_path: PathBuf,
    /// The backup directory path.
    #[serde(default)]
    pub backup_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parse() {
        let v = Version::parse("0.1.0").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 1);
        assert_eq!(v.patch, 0);
        assert!(v.prerelease.is_none());
    }

    #[test]
    fn test_version_parse_with_v_prefix() {
        let v = Version::parse("v1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_version_parse_prerelease() {
        let v = Version::parse("0.2.0-beta.1").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 0);
        assert_eq!(v.prerelease, Some("beta.1".to_string()));
        assert!(v.is_prerelease());
    }

    #[test]
    fn test_version_comparison() {
        let v1 = Version::parse("0.1.0").unwrap();
        let v2 = Version::parse("0.2.0").unwrap();
        let v3 = Version::parse("0.2.0-beta.1").unwrap();

        assert!(v1 < v2);
        assert!(v3 < v2); // prerelease < release
        assert!(v1 < v3);
    }

    #[test]
    fn test_version_display() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.to_string(), "1.2.3");

        let v_pre = Version::parse("1.2.3-rc.1").unwrap();
        assert_eq!(v_pre.to_string(), "1.2.3-rc.1");
    }

    #[test]
    fn test_channel_from_str() {
        assert_eq!(Channel::from_str("stable").unwrap(), Channel::Stable);
        assert_eq!(Channel::from_str("BETA").unwrap(), Channel::Beta);
        assert_eq!(Channel::from_str("Nightly").unwrap(), Channel::Nightly);
        assert!(Channel::from_str("unknown").is_err());
    }

    #[test]
    fn test_current_target() {
        let target = current_target();
        assert!(!target.is_empty());
        // Should contain architecture
        assert!(target.contains("x86_64") || target.contains("aarch64") || target.contains("arm"));
    }

    #[test]
    fn test_version_parse_invalid_empty() {
        let result = Version::parse("");
        assert!(result.is_err());
    }

    #[test]
    fn test_version_parse_invalid_non_numeric() {
        let result = Version::parse("a.b.c");
        assert!(result.is_err());
    }

    #[test]
    fn test_version_parse_invalid_single_number() {
        let result = Version::parse("1");
        assert!(result.is_err());
    }

    #[test]
    fn test_version_parse_two_parts() {
        // Two-part version should work (patch defaults to 0)
        let v = Version::parse("1.2").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_version_parse_too_many_parts() {
        let result = Version::parse("1.2.3.4");
        assert!(result.is_err());
    }

    #[test]
    fn test_version_equality() {
        let v1 = Version::parse("1.2.3").unwrap();
        let v2 = Version::parse("1.2.3").unwrap();
        assert_eq!(v1, v2);

        let v3 = Version::parse("v1.2.3").unwrap();
        assert_eq!(v1, v3); // v prefix should be stripped
    }

    #[test]
    fn test_version_prerelease_ordering() {
        let alpha = Version::parse("1.0.0-alpha").unwrap();
        let beta = Version::parse("1.0.0-beta").unwrap();
        let release = Version::parse("1.0.0").unwrap();

        assert!(alpha < beta); // alpha < beta lexicographically
        assert!(beta < release); // prerelease < release
        assert!(alpha < release);
    }

    #[test]
    fn test_version_ordering_across_major() {
        let v1 = Version::parse("0.9.9").unwrap();
        let v2 = Version::parse("1.0.0").unwrap();
        assert!(v1 < v2);
    }

    #[test]
    fn test_channel_display() {
        assert_eq!(Channel::Stable.to_string(), "stable");
        assert_eq!(Channel::Beta.to_string(), "beta");
        assert_eq!(Channel::Nightly.to_string(), "nightly");
    }

    #[test]
    fn test_cached_check_is_valid_fresh() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cached = CachedCheck {
            result: UpdateCheck {
                current_version: Version::parse("1.0.0").unwrap(),
                latest_version: Version::parse("1.0.0").unwrap(),
                update_available: false,
                release_url: String::new(),
                release_notes: None,
                changelog_diff: None,
                assets: vec![],
            },
            cached_at_secs: now,
        };

        assert!(cached.is_valid());
    }

    #[test]
    fn test_cached_check_is_valid_stale() {
        // Set cached_at to 25 hours ago (beyond CACHE_DURATION of 24 hours)
        let stale_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - (25 * 60 * 60);

        let cached = CachedCheck {
            result: UpdateCheck {
                current_version: Version::parse("1.0.0").unwrap(),
                latest_version: Version::parse("1.0.0").unwrap(),
                update_available: false,
                release_url: String::new(),
                release_notes: None,
                changelog_diff: None,
                assets: vec![],
            },
            cached_at_secs: stale_time,
        };

        assert!(!cached.is_valid());
    }

    #[test]
    fn test_update_error_display() {
        let err = UpdateError::ChecksumMismatch {
            expected: "abc".to_string(),
            actual: "def".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("abc"));
        assert!(msg.contains("def"));

        let err = UpdateError::LockHeld;
        assert!(format!("{}", err).contains("lock"));

        let err = UpdateError::InvalidVersion("bad".to_string());
        assert!(format!("{}", err).contains("bad"));
    }

    #[test]
    fn test_backup_entry_serde() {
        let entry = BackupEntry {
            version: "1.0.0".to_string(),
            created_at: 1234567890,
            original_path: PathBuf::from("/usr/bin/rch"),
            backup_path: PathBuf::from("/var/backup/rch-1.0.0"),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: BackupEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, "1.0.0");
        assert_eq!(parsed.created_at, 1234567890);
    }
}
