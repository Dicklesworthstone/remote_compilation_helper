//! Version checking against GitHub releases.

use super::types::{CachedCheck, Channel, ReleaseInfo, UpdateCheck, UpdateError, Version};
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

    if let Ok(json) = serde_json::to_string_pretty(&cached)
        && let Ok(mut file) = fs::File::create(&cache_file)
    {
        let _ = file.write_all(json.as_bytes());
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
        rt.block_on(async {
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
    if channel == Channel::Stable
        && let Some(cached) = read_cached_check()
    {
        // Verify current version matches cached
        if cached.current_version == current_version {
            return Ok(cached);
        }
        // Version changed (e.g., after update), need fresh check
    }

    // Fetch releases and filter by channel
    let releases = fetch_releases().await?;
    let latest = filter_by_channel(&releases, channel)
        .ok_or_else(|| UpdateError::CheckFailed("No releases found for channel".to_string()))?;

    let latest_version = Version::parse(&latest.tag_name)?;
    let update_available = latest_version > current_version;

    // Compute changelog diff from intermediate releases
    let changelog_diff = if update_available {
        compute_changelog_diff(&releases, &current_version, &latest_version)
    } else {
        None
    };

    let check = UpdateCheck {
        current_version,
        latest_version,
        update_available,
        release_url: latest.html_url.clone(),
        release_notes: latest.body.clone(),
        changelog_diff,
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

    // Fetch all releases to compute changelog diff if updating
    let changelog_diff = if update_available && target_version > *current {
        // Fetch all releases to get intermediate versions
        match fetch_releases().await {
            Ok(releases) => compute_changelog_diff(&releases, current, &target_version),
            Err(_) => None, // Fall back to no diff if we can't fetch all releases
        }
    } else {
        None
    };

    Ok(UpdateCheck {
        current_version: current.clone(),
        latest_version: target_version,
        update_available,
        release_url: release.html_url.clone(),
        release_notes: release.body.clone(),
        changelog_diff,
        assets: release.assets.clone(),
    })
}

/// Maximum attempts for a GitHub API metadata fetch.
const MAX_API_ATTEMPTS: u32 = 4;

/// Backoff schedule waited before the 2nd/3rd/4th API attempts (~22s total).
const API_BACKOFF: [Duration; 3] = [
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(15),
];

/// GitHub API responses (rate limiting, abuse detection, upstream 5xx) are
/// retryable on 5xx and 429; everything else is terminal.
fn is_retryable_api_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

/// Run a single-shot GitHub API GET with retry-and-backoff for transient
/// failures (connection/timeout errors and retryable HTTP statuses). `op`
/// returns `Ok(Some(_))` on success, `Ok(None)` to signal a transient HTTP
/// status worth retrying, and `Err(_)` for a terminal failure.
async fn api_get_with_retry<T, F, Fut>(label: &str, op: F) -> Result<T, UpdateError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>, UpdateError>>,
{
    let mut last_err: Option<UpdateError> = None;

    for attempt in 1..=MAX_API_ATTEMPTS {
        match op().await {
            Ok(Some(value)) => return Ok(value),
            // Transient HTTP status flagged by the caller.
            Ok(None) if attempt < MAX_API_ATTEMPTS => {
                let wait = backoff_for(attempt);
                tracing::warn!(
                    "{label} attempt {attempt}/{MAX_API_ATTEMPTS} hit a transient status; \
                     retrying in {wait:?}"
                );
                tokio::time::sleep(wait).await;
            }
            Ok(None) => {
                return Err(last_err.unwrap_or_else(|| {
                    UpdateError::CheckFailed(format!(
                        "{label} failed after {MAX_API_ATTEMPTS} attempts (transient status)"
                    ))
                }));
            }
            // Connection/timeout errors are transient; retry them too.
            Err(e) if matches!(e, UpdateError::NetworkError(_)) && attempt < MAX_API_ATTEMPTS => {
                let wait = backoff_for(attempt);
                tracing::warn!(
                    "{label} attempt {attempt}/{MAX_API_ATTEMPTS} failed ({e}); \
                     retrying in {wait:?}"
                );
                last_err = Some(e);
                tokio::time::sleep(wait).await;
            }
            Err(e) => return Err(e),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        UpdateError::CheckFailed(format!("{label} failed after {MAX_API_ATTEMPTS} attempts"))
    }))
}

fn backoff_for(attempt: u32) -> Duration {
    API_BACKOFF
        .get((attempt - 1) as usize)
        .copied()
        .unwrap_or_else(|| API_BACKOFF[API_BACKOFF.len() - 1])
}

/// Fetch all releases from GitHub.
async fn fetch_releases() -> Result<Vec<ReleaseInfo>, UpdateError> {
    let url = format!(
        "{}/repos/{}/{}/releases",
        GITHUB_API_BASE, REPO_OWNER, REPO_NAME
    );

    api_get_with_retry("Fetching releases", || async {
        let client = build_http_client()?;
        let response = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", format!("rch/{}", env!("CARGO_PKG_VERSION")))
            .send()
            .await
            .map_err(|e| UpdateError::NetworkError(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            if is_retryable_api_status(status) {
                // Signal transient → retry.
                return Ok(None);
            }
            return Err(UpdateError::CheckFailed(format!(
                "GitHub API returned {status}"
            )));
        }

        let releases: Vec<ReleaseInfo> = response
            .json()
            .await
            .map_err(|e| UpdateError::CheckFailed(format!("Failed to parse releases: {}", e)))?;
        Ok(Some(releases))
    })
    .await
}

/// Fetch a single release from a URL.
async fn fetch_release_from_url(url: &str) -> Result<ReleaseInfo, UpdateError> {
    api_get_with_retry("Fetching release", || async {
        let client = build_http_client()?;
        let response = client
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", format!("rch/{}", env!("CARGO_PKG_VERSION")))
            .send()
            .await
            .map_err(|e| UpdateError::NetworkError(e.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            // 404 is terminal — the requested release genuinely does not exist.
            return Err(UpdateError::CheckFailed("Release not found".to_string()));
        }

        if !status.is_success() {
            if is_retryable_api_status(status) {
                return Ok(None);
            }
            return Err(UpdateError::CheckFailed(format!(
                "GitHub API returned {status}"
            )));
        }

        let release: ReleaseInfo = response
            .json()
            .await
            .map_err(|e| UpdateError::CheckFailed(format!("Failed to parse release: {}", e)))?;
        Ok(Some(release))
    })
    .await
}

/// Filter releases by channel.
fn filter_by_channel(releases: &[ReleaseInfo], channel: Channel) -> Option<&ReleaseInfo> {
    releases
        .iter()
        .filter_map(|release| {
            if release.draft {
                return None;
            }

            let version = Version::parse(&release.tag_name).ok()?;
            let is_prerelease = release.prerelease || version.is_prerelease();

            let matches_channel = match channel {
                Channel::Stable => !is_prerelease,
                Channel::Beta => is_prerelease,
                Channel::Nightly => true,
            };

            matches_channel.then_some((version, release))
        })
        .max_by(|(left_version, _), (right_version, _)| left_version.cmp(right_version))
        .map(|(_, release)| release)
}

/// Compute changelog diff by collecting release notes from versions between current and target.
fn compute_changelog_diff(
    releases: &[ReleaseInfo],
    current: &Version,
    target: &Version,
) -> Option<String> {
    // Collect release notes from all releases between current (exclusive) and target (inclusive)
    let mut notes = Vec::new();

    for release in releases {
        // Skip drafts
        if release.draft {
            continue;
        }

        // Parse version
        let Ok(version) = Version::parse(&release.tag_name) else {
            continue;
        };

        // Only include releases > current and <= target with non-empty body
        if version > *current
            && version <= *target
            && let Some(ref body) = release.body
            && !body.trim().is_empty()
        {
            notes.push((version, format!("## {}\n{}", release.tag_name, body)));
        }
    }

    if notes.is_empty() {
        None
    } else {
        notes.sort_by(|(left_version, _), (right_version, _)| left_version.cmp(right_version));
        Some(
            notes
                .into_iter()
                .map(|(_, note)| note)
                .collect::<Vec<_>>()
                .join("\n\n---\n\n"),
        )
    }
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
    fn test_is_retryable_api_status() {
        use reqwest::StatusCode;

        assert!(is_retryable_api_status(StatusCode::GATEWAY_TIMEOUT)); // 504
        assert!(is_retryable_api_status(StatusCode::BAD_GATEWAY)); // 502
        assert!(is_retryable_api_status(StatusCode::SERVICE_UNAVAILABLE)); // 503
        assert!(is_retryable_api_status(StatusCode::TOO_MANY_REQUESTS)); // 429

        assert!(!is_retryable_api_status(StatusCode::NOT_FOUND)); // 404
        assert!(!is_retryable_api_status(StatusCode::UNAUTHORIZED)); // 401
        assert!(!is_retryable_api_status(StatusCode::FORBIDDEN)); // 403
    }

    #[test]
    fn test_api_backoff_is_bounded() {
        let total: Duration = API_BACKOFF.iter().copied().sum();
        assert_eq!(API_BACKOFF.len() as u32, MAX_API_ATTEMPTS - 1);
        assert!(total <= Duration::from_secs(45));
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
    fn test_filter_by_channel_selects_highest_semver_not_first_release() {
        let releases = vec![
            ReleaseInfo {
                tag_name: "v1.0.1".to_string(),
                name: "Backfilled patch".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: None,
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.2.0".to_string(),
                name: "Actual latest".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: None,
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.1.0".to_string(),
                name: "Intermediate".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: None,
                assets: vec![],
                published_at: None,
            },
        ];

        let stable = filter_by_channel(&releases, Channel::Stable).unwrap();
        assert_eq!(stable.tag_name, "v1.2.0");
    }

    #[test]
    fn test_filter_by_channel_selects_highest_prerelease_semver() {
        let releases = vec![
            ReleaseInfo {
                tag_name: "v1.0.0-beta.2".to_string(),
                name: "Older beta".to_string(),
                prerelease: true,
                draft: false,
                html_url: "".to_string(),
                body: None,
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.0.0-beta.10".to_string(),
                name: "Newer beta".to_string(),
                prerelease: true,
                draft: false,
                html_url: "".to_string(),
                body: None,
                assets: vec![],
                published_at: None,
            },
        ];

        let beta = filter_by_channel(&releases, Channel::Beta).unwrap();
        assert_eq!(beta.tag_name, "v1.0.0-beta.10");
    }

    #[test]
    fn test_filter_by_channel_skips_unparseable_release_tags() {
        let releases = vec![
            ReleaseInfo {
                tag_name: "nightly-build".to_string(),
                name: "Invalid tag".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: None,
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.2.0".to_string(),
                name: "Valid tag".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: None,
                assets: vec![],
                published_at: None,
            },
        ];

        let stable = filter_by_channel(&releases, Channel::Stable).unwrap();
        assert_eq!(stable.tag_name, "v1.2.0");
    }

    #[test]
    fn test_filter_by_channel_stable_rejects_prerelease_tag_even_without_github_flag() {
        let releases = vec![
            ReleaseInfo {
                tag_name: "v2.0.0-beta.1".to_string(),
                name: "Misflagged prerelease".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: None,
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.2.0".to_string(),
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
        assert_eq!(stable.tag_name, "v1.2.0");

        let beta = filter_by_channel(&releases, Channel::Beta).unwrap();
        assert_eq!(beta.tag_name, "v2.0.0-beta.1");
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

        // Nightly accepts any release and chooses the highest semantic version.
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

        // Beta channel requires prerelease semantics.
        assert!(filter_by_channel(&releases, Channel::Beta).is_none());
    }

    #[test]
    fn test_compute_changelog_diff_collects_intermediate_releases() {
        let releases = vec![
            ReleaseInfo {
                tag_name: "v1.3.0".to_string(),
                name: "Latest".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("Added feature C".to_string()),
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.2.0".to_string(),
                name: "Middle".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("Added feature B".to_string()),
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.1.0".to_string(),
                name: "Old".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("Added feature A".to_string()),
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.0.0".to_string(),
                name: "Current".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("Initial release".to_string()),
                assets: vec![],
                published_at: None,
            },
        ];

        let current = Version::parse("v1.0.0").unwrap();
        let target = Version::parse("v1.3.0").unwrap();

        let diff = compute_changelog_diff(&releases, &current, &target);
        assert!(diff.is_some());

        let diff = diff.unwrap();
        // Should include v1.1.0, v1.2.0, v1.3.0 but not v1.0.0 (current)
        assert!(diff.contains("v1.1.0"));
        assert!(diff.contains("v1.2.0"));
        assert!(diff.contains("v1.3.0"));
        assert!(diff.contains("feature A"));
        assert!(diff.contains("feature B"));
        assert!(diff.contains("feature C"));
        assert!(!diff.contains("Initial release"));
    }

    #[test]
    fn test_compute_changelog_diff_empty_when_no_intermediate() {
        let releases = vec![
            ReleaseInfo {
                tag_name: "v1.1.0".to_string(),
                name: "Target".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: None, // No body
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.0.0".to_string(),
                name: "Current".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("Current release".to_string()),
                assets: vec![],
                published_at: None,
            },
        ];

        let current = Version::parse("v1.0.0").unwrap();
        let target = Version::parse("v1.1.0").unwrap();

        // v1.1.0 has no body, so diff should be None
        let diff = compute_changelog_diff(&releases, &current, &target);
        assert!(diff.is_none());
    }

    #[test]
    fn test_compute_changelog_diff_skips_drafts() {
        let releases = vec![
            ReleaseInfo {
                tag_name: "v1.2.0".to_string(),
                name: "Target".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("Target release".to_string()),
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.1.0".to_string(),
                name: "Draft".to_string(),
                prerelease: false,
                draft: true, // Draft should be skipped
                html_url: "".to_string(),
                body: Some("Draft notes".to_string()),
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.0.0".to_string(),
                name: "Current".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("Current release".to_string()),
                assets: vec![],
                published_at: None,
            },
        ];

        let current = Version::parse("v1.0.0").unwrap();
        let target = Version::parse("v1.2.0").unwrap();

        let diff = compute_changelog_diff(&releases, &current, &target);
        assert!(diff.is_some());

        let diff = diff.unwrap();
        // Should include v1.2.0 but not v1.1.0 (draft)
        assert!(diff.contains("v1.2.0"));
        assert!(diff.contains("Target release"));
        assert!(!diff.contains("Draft notes"));
    }

    #[test]
    fn test_compute_changelog_diff_chronological_order() {
        let releases = vec![
            ReleaseInfo {
                tag_name: "v1.3.0".to_string(),
                name: "Latest".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("Third".to_string()),
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.2.0".to_string(),
                name: "Middle".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("Second".to_string()),
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.1.0".to_string(),
                name: "First".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("First".to_string()),
                assets: vec![],
                published_at: None,
            },
        ];

        let current = Version::parse("v1.0.0").unwrap();
        let target = Version::parse("v1.3.0").unwrap();

        let diff = compute_changelog_diff(&releases, &current, &target).unwrap();

        // Should be in chronological order (oldest first)
        let first_pos = diff.find("v1.1.0").unwrap();
        let second_pos = diff.find("v1.2.0").unwrap();
        let third_pos = diff.find("v1.3.0").unwrap();

        assert!(first_pos < second_pos);
        assert!(second_pos < third_pos);
    }

    #[test]
    fn test_compute_changelog_diff_sorts_unsorted_release_input() {
        let releases = vec![
            ReleaseInfo {
                tag_name: "v1.1.0".to_string(),
                name: "First".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("First".to_string()),
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.3.0".to_string(),
                name: "Third".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("Third".to_string()),
                assets: vec![],
                published_at: None,
            },
            ReleaseInfo {
                tag_name: "v1.2.0".to_string(),
                name: "Second".to_string(),
                prerelease: false,
                draft: false,
                html_url: "".to_string(),
                body: Some("Second".to_string()),
                assets: vec![],
                published_at: None,
            },
        ];

        let current = Version::parse("v1.0.0").unwrap();
        let target = Version::parse("v1.3.0").unwrap();

        let diff = compute_changelog_diff(&releases, &current, &target).unwrap();

        let first_pos = diff.find("v1.1.0").unwrap();
        let second_pos = diff.find("v1.2.0").unwrap();
        let third_pos = diff.find("v1.3.0").unwrap();

        assert!(first_pos < second_pos);
        assert!(second_pos < third_pos);
    }
}
