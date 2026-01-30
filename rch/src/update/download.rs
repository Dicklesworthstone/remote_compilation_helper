//! Download release artifacts with verification.

use super::types::{UpdateCheck, UpdateError, current_target};
use super::verify::{verify_checksum, verify_checksum_and_signature};
use crate::ui::OutputContext;
use std::path::PathBuf;
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
}

/// Download and verify a release.
pub async fn download_release(
    ctx: &OutputContext,
    update: &UpdateCheck,
) -> Result<DownloadedRelease, UpdateError> {
    // Find the asset for our platform
    let target = current_target();
    let archive_asset = update
        .assets
        .iter()
        .find(|a| a.name.contains(&target) && a.name.ends_with(".tar.gz"))
        .ok_or_else(|| UpdateError::UnsupportedPlatform(target.clone()))?;

    // Find the checksum file
    let checksum_asset = update
        .assets
        .iter()
        .find(|a| a.name == format!("{}.sha256", archive_asset.name))
        .or_else(|| update.assets.iter().find(|a| a.name == "checksums.txt"));

    if !ctx.is_json() {
        println!(
            "Downloading {} ({} bytes)...",
            archive_asset.name, archive_asset.size
        );
    }

    // Download to temp directory
    let temp_dir = std::env::temp_dir().join("rch-update");
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|e| UpdateError::DownloadFailed(format!("Failed to create temp dir: {}", e)))?;

    let archive_path = temp_dir.join(&archive_asset.name);

    // Download with retries
    download_with_retry(&archive_asset.browser_download_url, &archive_path, 3).await?;

    // Verify checksum if available
    let (checksum_verified, signature_verified) = if let Some(checksum_asset) = checksum_asset {
        if !ctx.is_json() {
            println!("Verifying checksum...");
        }

        let checksum_path = temp_dir.join(&checksum_asset.name);
        download_with_retry(&checksum_asset.browser_download_url, &checksum_path, 3).await?;

        let expected_checksum = extract_checksum(&checksum_path, &archive_asset.name).await?;
        let signature_bundle_asset = update
            .assets
            .iter()
            .find(|a| a.name == format!("{}.sigstore.json", archive_asset.name));

        let signature_bundle_path = if let Some(sig_asset) = signature_bundle_asset {
            if !ctx.is_json() {
                println!("Verifying signature (sigstore bundle)...");
            }
            let sig_path = temp_dir.join(&sig_asset.name);
            download_with_retry(&sig_asset.browser_download_url, &sig_path, 3).await?;
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
    })
}

/// Download a file with retry logic.
async fn download_with_retry(
    url: &str,
    dest: &PathBuf,
    max_retries: u32,
) -> Result<(), UpdateError> {
    let mut delay = Duration::from_secs(1);

    for attempt in 0..max_retries {
        match download_file(url, dest).await {
            Ok(()) => return Ok(()),
            Err(e) if is_transient_error(&e) => {
                if attempt + 1 < max_retries {
                    tracing::warn!(
                        "Download attempt {} failed: {}, retrying in {:?}",
                        attempt + 1,
                        e,
                        delay
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(60));
                } else {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }

    Err(UpdateError::DownloadFailed(format!(
        "Failed after {} retries",
        max_retries
    )))
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
        .map_err(|e| UpdateError::NetworkError(e.to_string()))?;

    if !response.status().is_success() {
        return Err(UpdateError::DownloadFailed(format!(
            "Server returned {}",
            response.status()
        )));
    }

    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| UpdateError::DownloadFailed(format!("Failed to create file: {}", e)))?;

    let bytes = response
        .bytes()
        .await
        .map_err(|e| UpdateError::NetworkError(e.to_string()))?;

    file.write_all(&bytes)
        .await
        .map_err(|e| UpdateError::DownloadFailed(format!("Failed to write file: {}", e)))?;

    Ok(())
}

/// Check if an error is transient (worth retrying).
fn is_transient_error(e: &UpdateError) -> bool {
    matches!(e, UpdateError::NetworkError(_))
}

/// Extract checksum for a specific file from a checksum file.
async fn extract_checksum(checksum_file: &PathBuf, filename: &str) -> Result<String, UpdateError> {
    let content = tokio::fs::read_to_string(checksum_file)
        .await
        .map_err(|e| UpdateError::DownloadFailed(format!("Failed to read checksum file: {}", e)))?;

    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    // Some checksum files contain just the hash (single non-empty line).
    if lines.len() == 1 {
        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() == 1 {
            return Ok(parts[0].to_string());
        }
    }

    // Checksum files typically have format: "checksum  filename" or "checksum filename"
    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let checksum = parts[0];
            let file = parts.last().unwrap();
            // Exact match, or path prefix match (e.g., "./release/filename" matches "filename")
            if *file == filename
                || file.ends_with(&format!("/{}", filename))
                || file.ends_with(&format!("\\{}", filename))
            {
                return Ok(checksum.to_string());
            }
        }
    }

    Err(UpdateError::DownloadFailed(format!(
        "Checksum not found for {}",
        filename
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
}
