//! Version checking against GitHub releases.

use super::types::{Channel, ReleaseAsset, ReleaseInfo, UpdateError, Version};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// GitHub API base URL.
const GITHUB_API_BASE: &str = "https://api.github.com";

/// Repository owner and name.
const REPO_OWNER: &str = "Dicklesworthstone";
const REPO_NAME: &str = "remote_compilation_helper";

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

/// Check for updates from GitHub releases.
pub async fn check_for_updates(
    channel: Channel,
    target_version: Option<String>,
) -> Result<UpdateCheck, UpdateError> {
    let current_version = get_current_version()?;

    // If a specific version is requested, fetch that release
    if let Some(ref version) = target_version {
        return fetch_specific_version(&current_version, version).await;
    }

    // Fetch releases and filter by channel
    let releases = fetch_releases().await?;
    let latest = filter_by_channel(&releases, channel)
        .ok_or_else(|| UpdateError::CheckFailed("No releases found for channel".to_string()))?;

    let latest_version = Version::parse(&latest.tag_name)?;
    let update_available = latest_version > current_version;

    Ok(UpdateCheck {
        current_version,
        latest_version,
        update_available,
        release_url: latest.html_url.clone(),
        release_notes: latest.body.clone(),
        changelog_diff: None, // TODO: Compute diff
        assets: latest.assets.clone(),
    })
}

/// Get the current installed version.
fn get_current_version() -> Result<Version, UpdateError> {
    // Use the version from Cargo.toml at compile time
    let version_str = env!("CARGO_PKG_VERSION");
    Version::parse(version_str)
}

/// Fetch a specific version from GitHub.
async fn fetch_specific_version(
    current: &Version,
    target: &str,
) -> Result<UpdateCheck, UpdateError> {
    let tag = if target.starts_with('v') {
        target.to_string()
    } else {
        format!("v{}", target)
    };

    let url = format!(
        "{}/repos/{}/{}/releases/tags/{}",
        GITHUB_API_BASE, REPO_OWNER, REPO_NAME, tag
    );

    let release = fetch_release_from_url(&url).await?;
    let target_version = Version::parse(&release.tag_name)?;
    let update_available = target_version != *current;

    Ok(UpdateCheck {
        current_version: current.clone(),
        latest_version: target_version,
        update_available,
        release_url: release.html_url.clone(),
        release_notes: release.body.clone(),
        changelog_diff: None,
        assets: release.assets.clone(),
    })
}

/// Fetch all releases from GitHub.
async fn fetch_releases() -> Result<Vec<ReleaseInfo>, UpdateError> {
    let url = format!(
        "{}/repos/{}/{}/releases",
        GITHUB_API_BASE, REPO_OWNER, REPO_NAME
    );

    let client = build_http_client()?;
    let response = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", format!("rch/{}", env!("CARGO_PKG_VERSION")))
        .send()
        .await
        .map_err(|e| UpdateError::NetworkError(e.to_string()))?;

    if !response.status().is_success() {
        return Err(UpdateError::CheckFailed(format!(
            "GitHub API returned {}",
            response.status()
        )));
    }

    let releases: Vec<ReleaseInfo> = response
        .json()
        .await
        .map_err(|e| UpdateError::CheckFailed(format!("Failed to parse releases: {}", e)))?;

    Ok(releases)
}

/// Fetch a single release from a URL.
async fn fetch_release_from_url(url: &str) -> Result<ReleaseInfo, UpdateError> {
    let client = build_http_client()?;
    let response = client
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", format!("rch/{}", env!("CARGO_PKG_VERSION")))
        .send()
        .await
        .map_err(|e| UpdateError::NetworkError(e.to_string()))?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(UpdateError::CheckFailed("Release not found".to_string()));
    }

    if !response.status().is_success() {
        return Err(UpdateError::CheckFailed(format!(
            "GitHub API returned {}",
            response.status()
        )));
    }

    let release: ReleaseInfo = response
        .json()
        .await
        .map_err(|e| UpdateError::CheckFailed(format!("Failed to parse release: {}", e)))?;

    Ok(release)
}

/// Filter releases by channel.
fn filter_by_channel(releases: &[ReleaseInfo], channel: Channel) -> Option<&ReleaseInfo> {
    releases.iter().find(|r| {
        if r.draft {
            return false;
        }

        match channel {
            Channel::Stable => !r.prerelease,
            Channel::Beta => r.prerelease,
            Channel::Nightly => true, // Accept any, prefer latest
        }
    })
}

/// Build an HTTP client with appropriate timeouts.
fn build_http_client() -> Result<reqwest::Client, UpdateError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| UpdateError::NetworkError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_version() {
        let version = get_current_version().unwrap();
        // Should parse successfully - checking the struct is valid
        assert!(!version.to_string().is_empty());
    }

    #[test]
    fn test_filter_by_channel_stable() {
        let releases = vec![
            ReleaseInfo {
                tag_name: "v0.2.0-beta.1".to_string(),
                name: "Beta".to_string(),
                prerelease: true,
                draft: false,
                html_url: "".to_string(),
                body: None,
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v0.1.0".to_string(),
                name: "Stable".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: None,
                assets: vec![],
                published_at: None,
            },
        ];

        let stable = filter_by_channel(&releases, Channel::Stable).unwrap();
        assert_eq!(stable.tag_name, "v0.1.0");

        let beta = filter_by_channel(&releases, Channel::Beta).unwrap();
        assert_eq!(beta.tag_name, "v0.2.0-beta.1");
    }

    #[test]
    fn test_filter_by_channel_skips_drafts() {
        let releases = vec![ReleaseInfo {
            tag_name: "v0.1.0".to_string(),
            name: "Draft".to_string(),
            prerelease: false,
            draft: true,
            html_url: "".to_string(),
            body: None,
            assets: vec![],
            published_at: None,
        }];

        assert!(filter_by_channel(&releases, Channel::Stable).is_none());
    }

    #[test]
    fn test_filter_by_channel_nightly_accepts_any() {
        let releases = vec![
            ReleaseInfo {
                tag_name: "v0.3.0-alpha.1".to_string(),
                name: "Alpha".to_string(),
                prerelease: true,
                draft: false,
                html_url: "".to_string(),
                body: None,
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v0.2.0".to_string(),
                name: "Stable".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: None,
                assets: vec![],
                published_at: None,
            },
        ];

        // Nightly should accept any release, preferring first (latest)
        let nightly = filter_by_channel(&releases, Channel::Nightly).unwrap();
        assert_eq!(nightly.tag_name, "v0.3.0-alpha.1");
    }

    #[test]
    fn test_filter_by_channel_empty_releases() {
        let releases: Vec<ReleaseInfo> = vec![];

        assert!(filter_by_channel(&releases, Channel::Stable).is_none());
        assert!(filter_by_channel(&releases, Channel::Beta).is_none());
        assert!(filter_by_channel(&releases, Channel::Nightly).is_none());
    }

    #[test]
    fn test_filter_by_channel_beta_only() {
        let releases = vec![ReleaseInfo {
            tag_name: "v0.1.0".to_string(),
            name: "Stable Only".to_string(),
            prerelease: false,
            draft: false,
            html_url: "".to_string(),
            body: None,
            assets: vec![],
            published_at: None,
        }];

        // Beta channel requires prerelease flag
        assert!(filter_by_channel(&releases, Channel::Beta).is_none());
    }
}
