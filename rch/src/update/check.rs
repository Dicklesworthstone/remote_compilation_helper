//! Version checking against GitHub releases.

use super::types::{
    CachedCheck, Channel, ReleaseAsset, ReleaseInfo, UpdateCheck, UpdateError, Version,
    CACHE_DURATION,
};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

/// GitHub API base URL.
const GITHUB_API_BASE: &str = "https://api.github.com";

/// Repository owner and name.
const REPO_OWNER: &str = "Dicklesworthstone";
const REPO_NAME: &str = "remote_compilation_helper";

/// Get the cache directory for version checks.
fn get_cache_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("rch"))
}

/// Get the cache file path for version checks.
fn get_cache_file() -> Option<PathBuf> {
    get_cache_dir().map(|d| d.join("version_check.json"))
}

/// Read cached version check if valid (< 24 hours old).
pub fn read_cached_check() -> Option<UpdateCheck> {
    let cache_file = get_cache_file()?;
    let content = fs::read_to_string(&cache_file).ok()?;
    let cached: CachedCheck = serde_json::from_str(&content).ok()?;

    if cached.is_valid() {
        Some(cached.result)
    } else {
        // Cache is stale, remove it
        let _ = fs::remove_file(&cache_file);
        None
    }
}

/// Write update check result to cache.
fn write_cache(check: &UpdateCheck) {
    let Some(cache_file) = get_cache_file() else {
        return;
    };

    // Ensure cache directory exists
    if let Some(cache_dir) = get_cache_dir() {
        let _ = fs::create_dir_all(&cache_dir);
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let cached = CachedCheck {
        result: check.clone(),
        cached_at_secs: now,
    };

    if let Ok(json) = serde_json::to_string_pretty(&cached) {
        if let Ok(mut file) = fs::File::create(&cache_file) {
            let _ = file.write_all(json.as_bytes());
        }
    }
}

/// Spawn a background thread to refresh the cache if stale.
///
/// This function is designed to be called early in program startup
/// to proactively refresh the version cache without blocking the main thread.
pub fn spawn_update_check_if_needed() {
    // Respect the environment variable to disable update checks
    if std::env::var("RCH_NO_UPDATE_CHECK").is_ok() {
        return;
    }

    // If cache is valid, no need to refresh
    if read_cached_check().is_some() {
        return;
    }

    // Spawn background thread to refresh cache
    std::thread::spawn(|| {
        // Create a small runtime for the async check
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => return,
        };

        // Run the check and ignore errors (this is just cache warming)
        let _ = rt.block_on(async {
            let _ = check_for_updates(Channel::Stable, None).await;
        });
    });
}

/// Check for updates from GitHub releases.
///
/// This function checks the cache first and returns cached results if valid (< 24 hours old).
/// When fetching fresh results, they are written to cache for future calls.
pub async fn check_for_updates(
    channel: Channel,
    target_version: Option<String>,
) -> Result<UpdateCheck, UpdateError> {
    let current_version = get_current_version()?;

    // If a specific version is requested, don't use cache
    if let Some(ref version) = target_version {
        return fetch_specific_version(&current_version, version).await;
    }

    // Check cache first (only for stable channel default checks)
    if channel == Channel::Stable {
        if let Some(cached) = read_cached_check() {
            // Verify current version matches cached
            if cached.current_version == current_version {
                return Ok(cached);
            }
            // Version changed (e.g., after update), need fresh check
        }
    }

    // Fetch releases and filter by channel
    let releases = fetch_releases().await?;
    let latest = filter_by_channel(&releases, channel)
        .ok_or_else(|| UpdateError::CheckFailed("No releases found for channel".to_string()))?;

    let latest_version = Version::parse(&latest.tag_name)?;
    let update_available = latest_version > current_version;

    let check = UpdateCheck {
        current_version,
        latest_version,
        update_available,
        release_url: latest.html_url.clone(),
        release_notes: latest.body.clone(),
        changelog_diff: None, // TODO: Compute diff
        assets: latest.assets.clone(),
    };

    // Write to cache for stable channel
    if channel == Channel::Stable {
        write_cache(&check);
    }

    Ok(check)
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
