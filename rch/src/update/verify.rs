//! Checksum and signature verification.

use super::types::UpdateError;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use which::which;

/// Result of verification.
#[derive(Debug)]
#[allow(dead_code)]
pub struct VerificationResult {
    pub checksum_valid: bool,
    pub signature_valid: Option<bool>,
}

/// Verify SHA256 checksum of a file.
pub async fn verify_checksum(
    file_path: &std::path::Path,
    expected: &str,
) -> Result<VerificationResult, UpdateError> {
    verify_checksum_and_signature(file_path, expected, None).await
}

/// Verify checksum and optional signature bundle of a file.
pub async fn verify_checksum_and_signature(
    file_path: &std::path::Path,
    expected: &str,
    signature_bundle: Option<&std::path::Path>,
) -> Result<VerificationResult, UpdateError> {
    let mut file = tokio::fs::File::open(file_path)
        .await
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to open file: {}", e)))?;

    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 64 * 1024]; // 64KB buffer

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .await
            .map_err(|e| UpdateError::InstallFailed(format!("Failed to read file: {}", e)))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let actual = hasher.finalize().to_hex().to_string();

    // Also try SHA256 if BLAKE3 doesn't match (GitHub uses SHA256)
    let sha256_actual = compute_sha256(file_path).await?;

    // Check both BLAKE3 and SHA256
    let checksum_valid =
        actual.eq_ignore_ascii_case(expected) || sha256_actual.eq_ignore_ascii_case(expected);

    if !checksum_valid {
        return Err(UpdateError::ChecksumMismatch {
            expected: expected.to_string(),
            actual: sha256_actual,
        });
    }

    let signature_valid = if let Some(bundle_path) = signature_bundle {
        Some(verify_signature(file_path, bundle_path).await?)
    } else {
        None
    };

    Ok(VerificationResult {
        checksum_valid: true,
        signature_valid,
    })
}

/// Compute SHA256 hash of a file.
async fn compute_sha256(file_path: &std::path::Path) -> Result<String, UpdateError> {
    use std::io::Read;

    // Use blocking I/O wrapped in spawn_blocking for SHA256
    let path = file_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(&path)
            .map_err(|e| UpdateError::InstallFailed(format!("Failed to open file: {}", e)))?;

        let mut hasher = sha2::Sha256::new();
        let mut buffer = vec![0u8; 64 * 1024];

        loop {
            let bytes_read = file
                .read(&mut buffer)
                .map_err(|e| UpdateError::InstallFailed(format!("Failed to read file: {}", e)))?;

            if bytes_read == 0 {
                break;
            }

            use sha2::Digest;
            hasher.update(&buffer[..bytes_read]);
        }

        use sha2::Digest;
        Ok(format!("{:x}", hasher.finalize()))
    })
    .await
    .map_err(|e| UpdateError::InstallFailed(format!("Task failed: {}", e)))?
}

/// Verify Sigstore/cosign signature bundle for a file.
async fn verify_signature(
    file_path: &std::path::Path,
    bundle_path: &std::path::Path,
) -> Result<bool, UpdateError> {
    let cosign_path = which("cosign").map_err(|_| {
        UpdateError::SignatureVerificationFailed("cosign not found in PATH".to_string())
    })?;

    let output = Command::new(cosign_path)
        .arg("verify-blob")
        .arg("--bundle")
        .arg(bundle_path)
        .arg("--certificate-identity-regexp")
        .arg(".*")
        .arg("--certificate-oidc-issuer-regexp")
        .arg(".*")
        .arg(file_path)
        .output()
        .await
        .map_err(|e| {
            UpdateError::SignatureVerificationFailed(format!("Failed to execute cosign: {}", e))
        })?;

    if output.status.success() {
        Ok(true)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(UpdateError::SignatureVerificationFailed(format!(
            "cosign verify-blob failed: {}{}",
            stderr.trim(),
            if stdout.trim().is_empty() {
                String::new()
            } else {
                format!(" | {}", stdout.trim())
            }
        )))
    }
}

/// Verify a byte slice against expected checksum.
#[allow(dead_code)]
pub fn verify_sha256_bytes(content: &[u8], expected: &str) -> Result<(), UpdateError> {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(content);
    let actual = format!("{:x}", hasher.finalize());

    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(UpdateError::ChecksumMismatch {
            expected: expected.to_string(),
            actual,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_verify_sha256_bytes() {
        let content = b"test content";
        // SHA256 of "test content"
        let expected = "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72";

        assert!(verify_sha256_bytes(content, expected).is_ok());
    }

    #[test]
    fn test_verify_sha256_bytes_mismatch() {
        let content = b"test content";
        let wrong = "0000000000000000000000000000000000000000000000000000000000000000";

        let result = verify_sha256_bytes(content, wrong);
        assert!(matches!(result, Err(UpdateError::ChecksumMismatch { .. })));
    }

    #[tokio::test]
    async fn test_compute_sha256() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.txt");

        std::fs::write(&file_path, "test content").unwrap();

        let hash = compute_sha256(&file_path.to_path_buf()).await.unwrap();
        assert_eq!(
            hash,
            "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"
        );
    }

    #[test]
    fn test_verify_sha256_bytes_case_insensitive() {
        let content = b"test content";
        // SHA256 in uppercase
        let expected_upper = "6AE8A75555209FD6C44157C0AED8016E763FF435A19CF186F76863140143FF72";

        assert!(verify_sha256_bytes(content, expected_upper).is_ok());
    }

    #[test]
    fn test_verify_sha256_bytes_empty_content() {
        let content = b"";
        // SHA256 of empty string
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        assert!(verify_sha256_bytes(content, expected).is_ok());
    }

    #[tokio::test]
    async fn test_compute_sha256_large_file() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("large.bin");

        // Create a larger file (1MB of zeros)
        let content = vec![0u8; 1024 * 1024];
        std::fs::write(&file_path, &content).unwrap();

        let hash = compute_sha256(&file_path.to_path_buf()).await.unwrap();
        // SHA256 of 1MB of zeros
        assert_eq!(
            hash,
            "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58"
        );
    }

    #[tokio::test]
    async fn test_verify_checksum_sha256() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.txt");

        std::fs::write(&file_path, "test content").unwrap();

        // Verify using SHA256
        let expected = "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72";
        let result = verify_checksum(&file_path, expected).await.unwrap();

        assert!(result.checksum_valid);
    }

    #[tokio::test]
    async fn test_verify_checksum_mismatch() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.txt");

        std::fs::write(&file_path, "test content").unwrap();

        // Wrong checksum
        let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = verify_checksum(&file_path, wrong).await;

        assert!(matches!(result, Err(UpdateError::ChecksumMismatch { .. })));
    }

    #[test]
    fn test_verify_sha256_bytes_binary_content() {
        // Test with binary (non-UTF8) content
        let content: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
        // SHA256 of the above bytes
        let expected = "feb1aba6fea741741b1bbcc974f74fed337b535b8eec7223b6dd15d7108f08e3";

        assert!(verify_sha256_bytes(content, expected).is_ok());
    }

    #[tokio::test]
    async fn test_verify_checksum_file_not_found() {
        let temp = TempDir::new().unwrap();
        let nonexistent = temp.path().join("does_not_exist.bin");

        let result = verify_checksum(&nonexistent, "0".repeat(64).as_str()).await;
        assert!(result.is_err());
        match result {
            Err(UpdateError::InstallFailed(msg)) => {
                assert!(msg.contains("Failed to open file"));
            }
            _ => panic!("Expected InstallFailed error"),
        }
    }

    #[tokio::test]
    async fn test_compute_sha256_file_not_found() {
        let temp = TempDir::new().unwrap();
        let nonexistent = temp.path().join("nonexistent.txt");

        let result = compute_sha256(&nonexistent).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_checksum_blake3() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("blake3_test.txt");

        std::fs::write(&file_path, "test content").unwrap();

        // Compute BLAKE3 hash of "test content"
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"test content");
        let blake3_hash = hasher.finalize().to_hex().to_string();

        // verify_checksum should accept BLAKE3 hash
        let result = verify_checksum(&file_path, &blake3_hash).await.unwrap();
        assert!(result.checksum_valid);
    }

    #[test]
    fn test_verification_result_fields() {
        let result = VerificationResult {
            checksum_valid: true,
            signature_valid: Some(true),
        };
        assert!(result.checksum_valid);
        assert_eq!(result.signature_valid, Some(true));

        let result_no_sig = VerificationResult {
            checksum_valid: false,
            signature_valid: None,
        };
        assert!(!result_no_sig.checksum_valid);
        assert!(result_no_sig.signature_valid.is_none());
    }

    #[test]
    fn test_verify_sha256_bytes_invalid_hex_length() {
        let content = b"test";
        // Too short to be a valid SHA256 hash
        let short_hash = "abc123";

        // Should fail because actual hash won't match this short string
        let result = verify_sha256_bytes(content, short_hash);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_checksum_with_mixed_case_hex() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("mixedcase.txt");

        std::fs::write(&file_path, "test content").unwrap();

        // Mixed case SHA256 hash
        let expected = "6Ae8A75555209fD6C44157c0AED8016E763Ff435a19cF186F76863140143Ff72";
        let result = verify_checksum(&file_path, expected).await.unwrap();

        assert!(result.checksum_valid);
    }

    #[tokio::test]
    async fn test_compute_sha256_empty_file() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("empty.txt");

        std::fs::write(&file_path, "").unwrap();

        let hash = compute_sha256(&file_path).await.unwrap();
        // SHA256 of empty file
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
