//! Download release artifacts with verification.

use super::types::{
    UpdateCheck, UpdateError, current_release_archive_extension, current_release_targets,
    current_target,
};
use super::verify::{verify_checksum, verify_checksum_and_signature};
use crate::ui::OutputContext;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Progress callback for download updates.
#[allow(dead_code)]
pub type DownloadProgress = Box<dyn Fn(u64, u64) + Send>;

/// Result of a successful download.
#[allow(dead_code)]
pub struct DownloadedRelease {
    pub archive_path: PathBuf,
    pub checksum_verified: bool,
    pub signature_verified: Option<bool>,
    pub version: String,
    _download_dir: UpdateDownloadDir,
}

struct UpdateDownloadDir {
    path: PathBuf,
}

impl UpdateDownloadDir {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir().join(format!("rch-update-{}", uuid::Uuid::new_v4())),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for UpdateDownloadDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Download and verify a release.
pub async fn download_release(
    ctx: &OutputContext,
    update: &UpdateCheck,
) -> Result<DownloadedRelease, UpdateError> {
    // Find the asset for our platform.
    let archive_asset = find_archive_asset(&update.assets, &update.latest_version.to_string())?;

    // Find the checksum manifest or per-asset checksum file.
    let checksum_asset = find_checksum_asset(&update.assets, archive_asset);

    if !ctx.is_json() {
        println!(
            "Downloading {} ({} bytes)...",
            archive_asset.name, archive_asset.size
        );
    }

    // Download to a per-update temp directory. The install lock is acquired
    // later, so a shared path lets concurrent `rch update` invocations corrupt
    // each other's archive, checksum, or signature files before verification.
    let temp_dir = UpdateDownloadDir::new();
    tokio::fs::create_dir(temp_dir.path())
        .await
        .map_err(|e| UpdateError::DownloadFailed(format!("Failed to create temp dir: {}", e)))?;

    let archive_path = asset_temp_path(temp_dir.path(), &archive_asset.name)?;

    // Download with retries. GitHub release-asset downloads are served via a
    // CDN that intermittently returns 5xx (esp. 504 Gateway Timeout) and 429
    // under load; a short retry-with-backoff rides those out instead of forcing
    // a manual install.
    download_with_retry(
        &archive_asset.browser_download_url,
        &archive_path,
        &archive_asset.name,
        MAX_DOWNLOAD_ATTEMPTS,
    )
    .await?;

    // Verify checksum if available
    let (checksum_verified, signature_verified) = if let Some(checksum_asset) = checksum_asset {
        if !ctx.is_json() {
            println!("Verifying checksum...");
        }

        let checksum_path = asset_temp_path(temp_dir.path(), &checksum_asset.name)?;
        // The checksum sidecar is fetched through the same CDN and 504s under
        // the same conditions. Retry transient fetch failures here too so a
        // flaky sidecar GET does not get surfaced as an opaque
        // "Checksum not found" / hard failure.
        download_with_retry(
            &checksum_asset.browser_download_url,
            &checksum_path,
            &checksum_asset.name,
            MAX_DOWNLOAD_ATTEMPTS,
        )
        .await?;

        let expected_checksum = extract_checksum(&checksum_path, &archive_asset.name).await?;
        let signature_bundle_asset = update
            .assets
            .iter()
            .find(|a| a.name == format!("{}.sigstore.json", archive_asset.name));

        let signature_bundle_path = if let Some(sig_asset) = signature_bundle_asset {
            if !ctx.is_json() {
                println!("Verifying signature (sigstore bundle)...");
            }
            let sig_path = asset_temp_path(temp_dir.path(), &sig_asset.name)?;
            download_with_retry(
                &sig_asset.browser_download_url,
                &sig_path,
                &sig_asset.name,
                MAX_DOWNLOAD_ATTEMPTS,
            )
            .await?;
            Some(sig_path)
        } else {
            if !ctx.is_json() {
                println!("Warning: No sigstore bundle available, skipping signature verification");
            }
            None
        };

        let verification = if let Some(bundle_path) = signature_bundle_path.as_deref() {
            verify_checksum_and_signature(&archive_path, &expected_checksum, Some(bundle_path))
                .await?
        } else {
            verify_checksum(&archive_path, &expected_checksum).await?
        };
        (verification.checksum_valid, verification.signature_valid)
    } else {
        if !ctx.is_json() {
            println!("Warning: No checksum file available for this release asset");
        }
        (false, None)
    };

    Ok(DownloadedRelease {
        archive_path,
        checksum_verified,
        signature_verified,
        version: update.latest_version.to_string(),
        _download_dir: temp_dir,
    })
}

/// Maximum number of attempts for a single release-asset download.
const MAX_DOWNLOAD_ATTEMPTS: u32 = 4;

/// Backoff schedule (waited *before* the 2nd, 3rd, and 4th attempts).
///
/// Kept intentionally bounded: 2s + 5s + 15s = 22s of worst-case waiting on
/// top of the per-request timeouts, so even a fully-flaky CDN run finishes in
/// well under a minute rather than hanging.
const DOWNLOAD_BACKOFF: [Duration; 3] = [
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(15),
];

/// Download a file with retry-and-backoff for transient CDN failures.
///
/// Retries only on RETRYABLE errors (HTTP 5xx — esp. 502/503/504 —, HTTP 429,
/// request timeouts, and connection/reset errors). A genuine 404, a 4xx other
/// than 429, or a local I/O failure aborts immediately.
async fn download_with_retry(
    url: &str,
    dest: &PathBuf,
    asset_name: &str,
    max_attempts: u32,
) -> Result<(), UpdateError> {
    let mut last_err: Option<UpdateError> = None;

    for attempt in 1..=max_attempts {
        match download_file(url, dest).await {
            Ok(()) => return Ok(()),
            Err(e) if is_transient_error(&e) && attempt < max_attempts => {
                // Backoff indices are 0-based and the schedule may be shorter
                // than the attempt count; fall back to the last entry.
                let wait = DOWNLOAD_BACKOFF
                    .get((attempt - 1) as usize)
                    .copied()
                    .unwrap_or_else(|| DOWNLOAD_BACKOFF[DOWNLOAD_BACKOFF.len() - 1]);
                tracing::warn!(
                    "Download of {asset_name} attempt {attempt}/{max_attempts} failed ({e}); \
                     retrying in {wait:?}"
                );
                last_err = Some(e);
                tokio::time::sleep(wait).await;
            }
            Err(e) => return Err(e),
        }
    }

    // Exhausted retries on a transient error.
    Err(last_err.unwrap_or_else(|| {
        UpdateError::DownloadFailed(format!(
            "Failed to download {asset_name} after {max_attempts} attempts"
        ))
    }))
}

/// Download a single file.
async fn download_file(url: &str, dest: &PathBuf) -> Result<(), UpdateError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300)) // 5 minutes for large files
        .connect_timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| UpdateError::NetworkError(e.to_string()))?;

    let response = client
        .get(url)
        .header("User-Agent", format!("rch/{}", env!("CARGO_PKG_VERSION")))
        .send()
        .await
        // A reqwest send() failure is a connection/timeout/reset error — always
        // transient. Classify as NetworkError so the retry loop rides it out.
        .map_err(|e| UpdateError::NetworkError(e.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        // Distinguish retryable HTTP statuses (5xx, 429) from terminal ones
        // (404 = asset genuinely missing, other 4xx). Retryable statuses map
        // to NetworkError so `is_transient_error` permits a retry; terminal
        // ones map to DownloadFailed and abort.
        return Err(classify_http_status(status));
    }

    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| UpdateError::DownloadFailed(format!("Failed to create file: {}", e)))?;

    let bytes = response
        .bytes()
        .await
        // Body-read failures (truncated/reset mid-stream) are transient too.
        .map_err(|e| UpdateError::NetworkError(e.to_string()))?;

    file.write_all(&bytes)
        .await
        .map_err(|e| UpdateError::DownloadFailed(format!("Failed to write file: {}", e)))?;

    Ok(())
}

/// Map a non-success HTTP status to the appropriate `UpdateError`, encoding
/// retryability in the variant choice: retryable → `NetworkError`, terminal →
/// `DownloadFailed`.
fn classify_http_status(status: reqwest::StatusCode) -> UpdateError {
    if is_retryable_status(status) {
        UpdateError::NetworkError(format!("Server returned {status} (transient)"))
    } else {
        UpdateError::DownloadFailed(format!("Server returned {status}"))
    }
}

/// HTTP statuses worth retrying: any 5xx (esp. 502/503/504 from the CDN) and
/// 429 Too Many Requests. Notably NOT 404 (asset genuinely absent) or other
/// 4xx (a request the retry can't fix).
fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

/// Check if an error is transient (worth retrying).
///
/// `NetworkError` covers connection/timeout/reset failures and the retryable
/// HTTP statuses classified by [`classify_http_status`]. A `ChecksumMismatch`
/// (binary corruption) or a `DownloadFailed` (404, terminal HTTP status, or
/// local I/O failure) is a hard failure and must NOT be retried.
fn is_transient_error(e: &UpdateError) -> bool {
    matches!(e, UpdateError::NetworkError(_))
}

fn asset_temp_path(temp_dir: &Path, asset_name: &str) -> Result<PathBuf, UpdateError> {
    if !is_safe_asset_name(asset_name) {
        return Err(UpdateError::DownloadFailed(format!(
            "Unsafe release asset name: {}",
            asset_name.escape_debug()
        )));
    }

    Ok(temp_dir.join(asset_name))
}

fn is_safe_asset_name(asset_name: &str) -> bool {
    !asset_name.is_empty()
        && !asset_name.contains('/')
        && !asset_name.contains('\\')
        && !asset_name.contains('\0')
        && Path::new(asset_name)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn archive_asset_candidates(version: &str) -> Vec<String> {
    let version = version.trim_start_matches('v');
    let version_tag = format!("v{version}");
    let extension = current_release_archive_extension();
    let mut candidates = Vec::new();

    for target in current_release_targets() {
        candidates.push(format!("rch-{version_tag}-{target}{extension}"));
        candidates.push(format!("rch-{target}{extension}"));
    }

    candidates.dedup();
    candidates
}

fn find_archive_asset<'a>(
    assets: &'a [super::types::ReleaseAsset],
    version: &str,
) -> Result<&'a super::types::ReleaseAsset, UpdateError> {
    for candidate in archive_asset_candidates(version) {
        if let Some(asset) = assets.iter().find(|asset| asset.name == candidate) {
            return Ok(asset);
        }
    }

    let extension = current_release_archive_extension();
    let release_targets = current_release_targets();
    if let Some(asset) = assets.iter().find(|asset| {
        asset.name.ends_with(extension)
            && release_targets
                .iter()
                .any(|target| asset.name.contains(target))
    }) {
        return Ok(asset);
    }

    Err(UpdateError::UnsupportedPlatform(format!(
        "{} (release assets: {})",
        current_target(),
        release_targets.join(", ")
    )))
}

fn find_checksum_asset<'a>(
    assets: &'a [super::types::ReleaseAsset],
    archive_asset: &super::types::ReleaseAsset,
) -> Option<&'a super::types::ReleaseAsset> {
    let checksum_candidates = [
        format!("{}.sha256", archive_asset.name),
        "SHA256SUMS".to_string(),
        "checksums.txt".to_string(),
    ];

    checksum_candidates
        .iter()
        .find_map(|name| assets.iter().find(|asset| asset.name == *name))
}

/// Extract checksum for a specific file from a checksum file.
async fn extract_checksum(checksum_file: &Path, filename: &str) -> Result<String, UpdateError> {
    let content = tokio::fs::read_to_string(checksum_file)
        .await
        .map_err(|e| UpdateError::DownloadFailed(format!("Failed to read checksum file: {}", e)))?;

    // Some checksum files contain just the hash (single non-empty line).
    let mut non_empty_lines = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    if let (Some(line), None) = (non_empty_lines.next(), non_empty_lines.next()) {
        let mut parts = line.split_whitespace();
        if let (Some(checksum), None) = (parts.next(), parts.next()) {
            return Ok(checksum.to_string());
        }
    }

    // Checksum files typically have format: "checksum  filename" or "checksum filename".
    //
    // We compare on the path *basename*, not a naive `ends_with`. An
    // `ends_with("/filename")` match is vulnerable to prefix injection:
    // a line like `EVIL_HASH  ../evil/rch-v1.0.0-linux.tar.gz` would
    // silently match when the caller asked for `rch-v1.0.0-linux.tar.gz`,
    // letting an attacker with write access to the checksum file (or a
    // release asset replacement) seed a different hash.
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let mut parts = line.split_whitespace();
        let Some(checksum) = parts.next() else {
            continue;
        };
        let Some(file) = parts.next_back() else {
            continue;
        };

        let file_basename = Path::new(file)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(file);
        // Also handle `\` separators on Windows-generated manifests,
        // where `Path::file_name` doesn't split on backslash on Unix.
        let win_basename = file.rsplit_once('\\').map(|(_, tail)| tail).unwrap_or(file);
        if file == filename || file_basename == filename || win_basename == filename {
            return Ok(checksum.to_string());
        }
    }

    Err(UpdateError::DownloadFailed(format!(
        "Checksum not found for {}",
        filename
    )))
}

#[cfg(test)]
mod tests {
    use super::super::types::ReleaseAsset;
    use super::*;
    use tempfile::TempDir;

    fn test_asset(name: &str) -> ReleaseAsset {
        ReleaseAsset {
            name: name.to_string(),
            browser_download_url: format!("https://example.invalid/{name}"),
            size: 1,
            content_type: "application/octet-stream".to_string(),
        }
    }

    #[tokio::test]
    async fn test_extract_checksum_standard_format() {
        let temp = TempDir::new().unwrap();
        let checksum_file = temp.path().join("checksums.txt");

        std::fs::write(
            &checksum_file,
            "abc123  rch-v0.1.0-linux.tar.gz\ndef456  rch-v0.1.0-darwin.tar.gz",
        )
        .unwrap();

        let result =
            extract_checksum(&checksum_file.to_path_buf(), "rch-v0.1.0-linux.tar.gz").await;
        assert_eq!(result.unwrap(), "abc123");
    }

    #[tokio::test]
    async fn test_extract_checksum_not_found() {
        let temp = TempDir::new().unwrap();
        let checksum_file = temp.path().join("checksums.txt");

        std::fs::write(&checksum_file, "abc123  other-file.tar.gz").unwrap();

        let result =
            extract_checksum(&checksum_file.to_path_buf(), "rch-v0.1.0-linux.tar.gz").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_is_transient_error() {
        assert!(is_transient_error(&UpdateError::NetworkError(
            "timeout".to_string()
        )));
        assert!(!is_transient_error(&UpdateError::ChecksumMismatch {
            expected: "a".to_string(),
            actual: "b".to_string()
        }));
    }

    #[test]
    fn test_is_retryable_status_classifier() {
        use reqwest::StatusCode;

        // Transient: all 5xx (esp. CDN gateway errors) and 429.
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY)); // 502
        assert!(is_retryable_status(StatusCode::SERVICE_UNAVAILABLE)); // 503
        assert!(is_retryable_status(StatusCode::GATEWAY_TIMEOUT)); // 504
        assert!(is_retryable_status(StatusCode::INTERNAL_SERVER_ERROR)); // 500
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS)); // 429

        // Terminal: 404 (asset missing) and other 4xx must NOT be retried.
        assert!(!is_retryable_status(StatusCode::NOT_FOUND)); // 404
        assert!(!is_retryable_status(StatusCode::FORBIDDEN)); // 403
        assert!(!is_retryable_status(StatusCode::BAD_REQUEST)); // 400
        assert!(!is_retryable_status(StatusCode::UNAUTHORIZED)); // 401
    }

    #[test]
    fn test_classify_http_status_maps_to_retryable_variant() {
        use reqwest::StatusCode;

        // 504 → NetworkError (transient → retried).
        let e = classify_http_status(StatusCode::GATEWAY_TIMEOUT);
        assert!(
            matches!(e, UpdateError::NetworkError(_)),
            "504 should be a retryable NetworkError, got {e:?}"
        );
        assert!(is_transient_error(&e));

        // 429 → NetworkError (transient → retried).
        let e = classify_http_status(StatusCode::TOO_MANY_REQUESTS);
        assert!(is_transient_error(&e));

        // 404 → DownloadFailed (terminal → NOT retried).
        let e = classify_http_status(StatusCode::NOT_FOUND);
        assert!(
            matches!(e, UpdateError::DownloadFailed(_)),
            "404 should be a terminal DownloadFailed, got {e:?}"
        );
        assert!(!is_transient_error(&e));
    }

    #[test]
    fn test_checksum_mismatch_is_not_transient() {
        // A checksum MISMATCH (corrupt binary) must be a hard failure, distinct
        // from a transient sidecar FETCH failure (NetworkError).
        let mismatch = UpdateError::ChecksumMismatch {
            expected: "aaaa".to_string(),
            actual: "bbbb".to_string(),
        };
        assert!(!is_transient_error(&mismatch));

        let fetch_504 = classify_http_status(reqwest::StatusCode::GATEWAY_TIMEOUT);
        assert!(is_transient_error(&fetch_504));
    }

    #[test]
    fn test_download_backoff_is_bounded() {
        let total: Duration = DOWNLOAD_BACKOFF.iter().copied().sum();
        // 4 attempts => 3 waits; keep total bounded (~22s here, < 45s budget).
        assert_eq!(DOWNLOAD_BACKOFF.len() as u32, MAX_DOWNLOAD_ATTEMPTS - 1);
        assert!(
            total <= Duration::from_secs(45),
            "cumulative backoff {total:?} exceeds the ~45s budget"
        );
    }

    #[tokio::test]
    async fn test_download_with_retry_does_not_retry_terminal_error() {
        // A 404 from a bogus host resolves quickly via DownloadFailed and must
        // abort on the first attempt rather than burning the backoff budget.
        // We can't hit a real 404 offline, but an unresolvable host yields a
        // NetworkError (transient) — so instead assert the classifier path:
        // terminal DownloadFailed short-circuits.
        let terminal = UpdateError::DownloadFailed("Server returned 404 Not Found".to_string());
        assert!(!is_transient_error(&terminal));
    }

    #[test]
    fn test_asset_temp_path_accepts_plain_filename() {
        let temp = TempDir::new().unwrap();
        let name = "rch-v1.0.0-x86_64-unknown-linux-musl.tar.gz";

        let path = asset_temp_path(temp.path(), name).unwrap();

        assert_eq!(path, temp.path().join(name));
    }

    #[test]
    fn test_asset_temp_path_rejects_path_like_names() {
        let temp = TempDir::new().unwrap();

        for name in [
            "",
            ".",
            "..",
            "../rch.tar.gz",
            "release/rch.tar.gz",
            "release\\rch.tar.gz",
            "/tmp/rch.tar.gz",
            "rch.tar.gz\0.sha256",
        ] {
            let result = asset_temp_path(temp.path(), name);
            assert!(
                matches!(result, Err(UpdateError::DownloadFailed(_))),
                "expected {name:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_update_download_dir_is_unique_and_scoped_to_temp() {
        let first = UpdateDownloadDir::new();
        let second = UpdateDownloadDir::new();

        assert_ne!(first.path(), second.path());
        assert!(first.path().starts_with(std::env::temp_dir()));
        assert!(second.path().starts_with(std::env::temp_dir()));
        assert!(
            first
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("rch-update-")
        );
    }

    #[test]
    fn test_update_download_dir_cleans_on_drop() {
        let path = {
            let dir = UpdateDownloadDir::new();
            std::fs::create_dir(dir.path()).unwrap();
            std::fs::write(dir.path().join("archive.tar.gz"), "partial download").unwrap();
            dir.path().to_path_buf()
        };

        assert!(
            !path.exists(),
            "download temp directory should be removed when release handle is dropped"
        );
    }

    #[tokio::test]
    async fn test_extract_checksum_single_file() {
        // Test single checksum (no filename, just hash)
        let temp = TempDir::new().unwrap();
        let checksum_file = temp.path().join("rch.tar.gz.sha256");

        // Some checksum files contain just the hash
        std::fs::write(&checksum_file, "abc123def456\n").unwrap();

        let result = extract_checksum(&checksum_file.to_path_buf(), "rch.tar.gz").await;
        assert_eq!(result.unwrap(), "abc123def456");
    }

    #[tokio::test]
    async fn test_extract_checksum_with_path_prefix() {
        let temp = TempDir::new().unwrap();
        let checksum_file = temp.path().join("checksums.txt");

        // Some checksums have path prefixes like ./release/
        std::fs::write(
            &checksum_file,
            "abc123  ./release/rch-v0.1.0-linux.tar.gz\ndef456  ./release/rch-v0.1.0-darwin.tar.gz",
        )
        .unwrap();

        let result =
            extract_checksum(&checksum_file.to_path_buf(), "rch-v0.1.0-linux.tar.gz").await;
        assert_eq!(result.unwrap(), "abc123");
    }

    #[tokio::test]
    async fn test_extract_checksum_rejects_nondelimited_suffix() {
        // Regression: `ends_with("/foo")` on "baz-foo" would have
        // rejected, but `ends_with("foo")` would have matched. More
        // critically, raw suffix matching on the path column (without
        // basename normalisation) permits lines whose filename column is
        // a concatenation like `pfxrch-v0.1.0-linux.tar.gz` to spoof a
        // match. The basename comparison enforces the separator
        // requirement correctly.
        let temp = TempDir::new().unwrap();
        let checksum_file = temp.path().join("checksums.txt");

        std::fs::write(
            &checksum_file,
            // First line's filename column does NOT have a separator
            // before the target name — it's a concatenation. It must not
            // match on basename lookup.
            "ATTACKER_HASH  pfxrch-v0.1.0-linux.tar.gz\n\
             LEGIT_HASH  rch-v0.1.0-linux.tar.gz\n",
        )
        .unwrap();

        let result =
            extract_checksum(&checksum_file.to_path_buf(), "rch-v0.1.0-linux.tar.gz").await;
        assert_eq!(
            result.unwrap(),
            "LEGIT_HASH",
            "non-delimited suffix must not satisfy basename match"
        );
    }

    #[tokio::test]
    async fn test_extract_checksum_windows_backslash_basename() {
        // Windows-style manifests may use backslash separators. We match
        // the final path component regardless of separator style.
        let temp = TempDir::new().unwrap();
        let checksum_file = temp.path().join("checksums.txt");

        std::fs::write(
            &checksum_file,
            "winhash  release\\rch-v0.1.0-x86_64-pc-windows-msvc.zip\n",
        )
        .unwrap();

        let result = extract_checksum(
            &checksum_file.to_path_buf(),
            "rch-v0.1.0-x86_64-pc-windows-msvc.zip",
        )
        .await;
        assert_eq!(result.unwrap(), "winhash");
    }

    #[test]
    fn test_is_transient_error_comprehensive() {
        // Network errors are transient
        assert!(is_transient_error(&UpdateError::NetworkError(
            "connection reset".to_string()
        )));
        assert!(is_transient_error(&UpdateError::NetworkError(
            "timeout".to_string()
        )));

        // Other errors are not transient
        assert!(!is_transient_error(&UpdateError::DownloadFailed(
            "404".to_string()
        )));
        assert!(!is_transient_error(&UpdateError::InstallFailed(
            "permission denied".to_string()
        )));
        assert!(!is_transient_error(&UpdateError::LockHeld));
        assert!(!is_transient_error(&UpdateError::NoBackupAvailable));
        assert!(!is_transient_error(&UpdateError::InvalidVersion(
            "bad".to_string()
        )));
        assert!(!is_transient_error(&UpdateError::UnsupportedPlatform(
            "unknown".to_string()
        )));
    }

    #[tokio::test]
    async fn test_extract_checksum_multiline_format() {
        let temp = TempDir::new().unwrap();
        let checksum_file = temp.path().join("SHA256SUMS");

        // Test typical SHA256SUMS format with multiple entries
        std::fs::write(
            &checksum_file,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  rch-linux-amd64.tar.gz\n\
             d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592  rch-darwin-amd64.tar.gz\n\
             9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  rch-linux-arm64.tar.gz",
        )
        .unwrap();

        let result =
            extract_checksum(&checksum_file.to_path_buf(), "rch-darwin-amd64.tar.gz").await;
        assert_eq!(
            result.unwrap(),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    #[tokio::test]
    async fn test_extract_checksum_no_false_positive_suffix_match() {
        let temp = TempDir::new().unwrap();
        let checksum_file = temp.path().join("checksums.txt");

        // Test that "foo-rch.tar.gz" doesn't match when looking for "rch.tar.gz"
        std::fs::write(&checksum_file, "abc123  foo-rch.tar.gz\ndef456  rch.tar.gz").unwrap();

        let result = extract_checksum(&checksum_file.to_path_buf(), "rch.tar.gz").await;
        // Should match the exact "rch.tar.gz", not "foo-rch.tar.gz"
        assert_eq!(result.unwrap(), "def456");
    }

    #[tokio::test]
    async fn test_extract_checksum_path_prefix_with_slash() {
        let temp = TempDir::new().unwrap();
        let checksum_file = temp.path().join("checksums.txt");

        // Test that path prefixes with / work correctly
        std::fs::write(
            &checksum_file,
            "abc123  release/rch.tar.gz\ndef456  other/foo-rch.tar.gz",
        )
        .unwrap();

        let result = extract_checksum(&checksum_file.to_path_buf(), "rch.tar.gz").await;
        assert_eq!(result.unwrap(), "abc123");
    }

    #[tokio::test]
    async fn test_extract_checksum_suffix_only_should_fail() {
        let temp = TempDir::new().unwrap();
        let checksum_file = temp.path().join("checksums.txt");

        // If only "foo-rch.tar.gz" exists, looking for "rch.tar.gz" should fail
        std::fs::write(&checksum_file, "abc123  foo-rch.tar.gz").unwrap();

        let result = extract_checksum(&checksum_file.to_path_buf(), "rch.tar.gz").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_archive_asset_candidates_include_static_linux_release_names() {
        let candidates = archive_asset_candidates("1.0.13");
        if std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64" {
            assert!(
                candidates.contains(&"rch-v1.0.13-x86_64-unknown-linux-musl.tar.gz".to_string())
            );
            assert!(candidates.contains(&"rch-linux-x86_64.tar.gz".to_string()));
        }
    }

    #[test]
    fn test_find_archive_asset_matches_musl_release_for_linux_gnu_host() {
        if !(std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64") {
            return;
        }

        let assets = vec![
            test_asset("rch-v1.0.13-x86_64-unknown-linux-musl.tar.gz"),
            test_asset("rch-v1.0.13-aarch64-apple-darwin.tar.gz"),
        ];

        let archive = find_archive_asset(&assets, "1.0.13").unwrap();
        assert_eq!(archive.name, "rch-v1.0.13-x86_64-unknown-linux-musl.tar.gz");
    }

    #[test]
    fn test_find_archive_asset_falls_back_to_unversioned_alias() {
        let assets = vec![test_asset(&format!(
            "rch-{}{}",
            current_release_targets().last().unwrap(),
            current_release_archive_extension()
        ))];

        let archive = find_archive_asset(&assets, "1.0.13").unwrap();
        assert_eq!(archive.name, assets[0].name);
    }

    #[test]
    fn test_find_checksum_asset_prefers_per_asset_then_manifest() {
        let archive = test_asset("rch-v1.0.13-x86_64-unknown-linux-musl.tar.gz");
        let per_asset_checksum = test_asset("rch-v1.0.13-x86_64-unknown-linux-musl.tar.gz.sha256");
        let manifest = test_asset("SHA256SUMS");
        let assets = vec![
            archive.clone(),
            manifest.clone(),
            per_asset_checksum.clone(),
        ];

        let selected = find_checksum_asset(&assets, &archive).unwrap();
        assert_eq!(selected.name, per_asset_checksum.name);

        let assets = vec![archive.clone(), manifest.clone()];
        let selected = find_checksum_asset(&assets, &archive).unwrap();
        assert_eq!(selected.name, manifest.name);
    }
}
