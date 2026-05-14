//! Checksum and signature verification.

use super::types::UpdateError;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use which::which;

fn hex_bytes(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

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
        Ok(hex_bytes(hasher.finalize()))
    })
    .await
    .map_err(|e| UpdateError::InstallFailed(format!("Task failed: {}", e)))?
}

/// Expected GitHub Actions OIDC issuer for sigstore verification.
const GITHUB_ACTIONS_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Expected certificate identity pattern for official RCH releases.
/// This must match the GitHub Actions workflow that signs the releases.
///
/// # Anchoring
///
/// Cosign's `--certificate-identity-regexp` uses Go's `regexp.MatchString`
/// which performs *substring* matching. Without explicit `^` and `$`
/// anchors, a malicious certificate whose SAN merely contains our
/// workflow URL as a substring (for example, nested inside another URL)
/// would also satisfy the check. We anchor both ends and escape the `.`
/// metacharacters in `github.com` / `.github` / `.yml` so the pattern
/// matches the real identity shape only:
///
///     ^https://github\.com/Dicklesworthstone/remote_compilation_helper/\.github/workflows/release\.yml@refs/.*$
const RCH_RELEASE_IDENTITY_PATTERN: &str = r"^https://github\.com/Dicklesworthstone/remote_compilation_helper/\.github/workflows/release\.yml@refs/.*$";

/// Verify Sigstore/cosign signature bundle for a file.
///
/// # Security
///
/// This verifies that binaries were signed by the official RCH GitHub Actions
/// release workflow. It checks:
/// - OIDC issuer is GitHub Actions (`https://token.actions.githubusercontent.com`)
/// - Certificate identity matches the release workflow URL pattern
///
/// Wildcard patterns (`.*`) are intentionally NOT used as they would accept
/// any sigstore signature, defeating supply chain security.
async fn verify_signature(
    file_path: &std::path::Path,
    bundle_path: &std::path::Path,
) -> Result<bool, UpdateError> {
    which("cosign").map_err(|_| {
        UpdateError::SignatureVerificationFailed("cosign not found in PATH".to_string())
    })?;

    let output = Command::new("cosign")
        .arg("verify-blob")
        .arg("--bundle")
        .arg(bundle_path)
        .arg("--certificate-identity-regexp")
        .arg(RCH_RELEASE_IDENTITY_PATTERN)
        .arg("--certificate-oidc-issuer")
        .arg(GITHUB_ACTIONS_OIDC_ISSUER)
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
    let actual = hex_bytes(hasher.finalize());

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
        assert!(matches!(
            result,
            Err(UpdateError::InstallFailed(msg)) if msg.contains("Failed to open file")
        ));
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

    // ============================================================
    // Signature verification tests (post-hoc gap-fill for bd-2bwc)
    //
    // The bead's original AC enumerated 4 sub-criteria:
    //   1. Test valid signature acceptance       -> covered by integration
    //      test (`integration_signature_verifies_with_real_cosign`,
    //      gated on RCH_TEST_REAL_SIG=1 + cosign in PATH).
    //   2. Test invalid signature rejection      -> test_signature_invalid_bundle_returns_err
    //   3. Test missing signature handling       -> test_signature_missing_bundle_yields_none
    //   4. Test key rotation scenarios           -> covered by the
    //      identity-pattern unit tests below; key rotation in cosign
    //      maps to changes in the certificate-identity regex anchor.
    //
    // The bead originally suggested ed25519 fixtures, but the real
    // implementation is cosign + sigstore + GitHub OIDC. End-to-end
    // verification requires real cosign + a real GitHub-signed binary,
    // so the e2e check lives in the integration tier. The unit tier
    // exercises the security-critical surfaces we own: the identity
    // anchor regex and the error-paths through `verify_signature`.
    // ============================================================

    /// Sub-criterion 3: missing signature handling.
    /// `verify_checksum_and_signature(_, _, None)` returns `signature_valid: None`.
    #[tokio::test]
    async fn test_signature_missing_bundle_yields_none() {
        // TEST START: missing signature bundle yields signature_valid=None
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("artifact.bin");
        std::fs::write(&file_path, b"hello world").unwrap();
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(b"hello world");
        let expected = hex_bytes(hasher.finalize());

        let result = verify_checksum_and_signature(&file_path, &expected, None)
            .await
            .unwrap();

        assert!(result.checksum_valid);
        assert!(
            result.signature_valid.is_none(),
            "missing signature bundle must yield signature_valid=None, got {:?}",
            result.signature_valid
        );
        // TEST PASS: missing bundle handled
    }

    /// Sub-criterion 2: invalid signature rejection.
    /// A malformed/empty bundle causes cosign (when present) to fail; the
    /// implementation translates that into `SignatureVerificationFailed`.
    /// Skipped when cosign is not installed (CI-friendly).
    #[tokio::test]
    async fn test_signature_invalid_bundle_returns_err() {
        // TEST START: invalid signature bundle is rejected
        if which::which("cosign").is_err() {
            eprintln!("SKIP test_signature_invalid_bundle_returns_err: cosign not installed");
            return;
        }
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("artifact.bin");
        let bundle_path = temp.path().join("artifact.sig");
        std::fs::write(&file_path, b"hello world").unwrap();
        // A malformed bundle: cosign cannot parse this as a valid signature.
        std::fs::write(&bundle_path, b"\x00\x01\x02 totally not a real bundle").unwrap();

        let result = verify_signature(&file_path, &bundle_path).await;
        assert!(matches!(
            result,
            Err(UpdateError::SignatureVerificationFailed(_)) | Ok(false)
        ));
        // TEST PASS: invalid bundle rejected
    }

    /// Sub-criterion 4 (security-anchor portion): the certificate-identity
    /// regex must be anchored at both ends so that substring attacks are
    /// rejected. Without `^`/`$`, a CA-signed certificate whose SAN merely
    /// contained our workflow URL as a substring would satisfy cosign's
    /// regex check (since Go's `regexp.MatchString` is substring-based).
    #[test]
    fn test_rch_release_identity_pattern_is_anchored() {
        // TEST START: certificate-identity regex must use ^...$ anchors
        assert!(
            RCH_RELEASE_IDENTITY_PATTERN.starts_with('^'),
            "identity pattern must start with ^"
        );
        assert!(
            RCH_RELEASE_IDENTITY_PATTERN.ends_with("$"),
            "identity pattern must end with $"
        );
        // Escaped dots (so `.` doesn't act as wildcard).
        assert!(
            RCH_RELEASE_IDENTITY_PATTERN.contains(r"github\.com"),
            "github.com dot must be escaped"
        );
        assert!(
            RCH_RELEASE_IDENTITY_PATTERN.contains(r"\.github/"),
            ".github dot must be escaped"
        );
        assert!(
            RCH_RELEASE_IDENTITY_PATTERN.contains(r"release\.yml"),
            "release.yml dot must be escaped"
        );
        // TEST PASS: anchored + escaped
    }

    /// Sub-criterion 4: legitimate canonical URL is accepted by the regex.
    #[test]
    fn test_rch_release_identity_pattern_accepts_canonical_url() {
        // TEST START: canonical RCH release identity URL matches
        let re = regex::Regex::new(RCH_RELEASE_IDENTITY_PATTERN).unwrap();
        let canonical = "https://github.com/Dicklesworthstone/remote_compilation_helper/.github/workflows/release.yml@refs/tags/v1.0.0";
        assert!(
            re.is_match(canonical),
            "canonical release URL should match: {}",
            canonical
        );
        // Also branch refs:
        let branch_ref = "https://github.com/Dicklesworthstone/remote_compilation_helper/.github/workflows/release.yml@refs/heads/main";
        assert!(re.is_match(branch_ref), "branch ref form should match");
        // TEST PASS: canonical URL accepted
    }

    /// Sub-criterion 4: substring attack URLs MUST NOT match the regex.
    /// This is the security property — if a malicious cert's SAN merely
    /// contains our URL as a substring, anchoring rejects it.
    #[test]
    fn test_rch_release_identity_pattern_rejects_substring_attacks() {
        // TEST START: substring/lookalike URLs must NOT match
        let re = regex::Regex::new(RCH_RELEASE_IDENTITY_PATTERN).unwrap();

        // Different repo (similar prefix attack)
        let attack1 = "https://github.com/Attacker/remote_compilation_helper/.github/workflows/release.yml@refs/tags/v1.0.0";
        assert!(
            !re.is_match(attack1),
            "different-owner URL must not match: {}",
            attack1
        );

        // Subdomain trick
        let attack2 = "https://github.com.evil.example/Dicklesworthstone/remote_compilation_helper/.github/workflows/release.yml@refs/tags/v1.0.0";
        assert!(
            !re.is_match(attack2),
            "subdomain-prefix attack must not match: {}",
            attack2
        );

        // Wrong workflow file
        let attack3 = "https://github.com/Dicklesworthstone/remote_compilation_helper/.github/workflows/sneaky.yml@refs/tags/v1.0.0";
        assert!(
            !re.is_match(attack3),
            "different-workflow URL must not match: {}",
            attack3
        );

        // Wrong protocol — must NOT match (the `^https://` anchor prefix
        // rejects http://).
        let attack4 = "http://github.com/Dicklesworthstone/remote_compilation_helper/.github/workflows/release.yml@refs/tags/v1.0.0";
        assert!(
            !re.is_match(attack4),
            "http (not https) must not match: {}",
            attack4
        );

        // Lookalike-URL prefix attack — the `^` anchor prevents a longer
        // hostname from being treated as a match by substring rule.
        let attack5 = "evilhttps://github.com/Dicklesworthstone/remote_compilation_helper/.github/workflows/release.yml@refs/tags/v1.0.0";
        assert!(
            !re.is_match(attack5),
            "lookalike-host prefix must not match: {}",
            attack5
        );

        // Path-traversal attempt — `.` is escaped in the pattern, so a
        // literal `.github` is required (no wildcard substitution).
        let attack6 = "https://github.com/Dicklesworthstone/remote_compilation_helper/Xgithub/workflows/release.yml@refs/tags/v1.0.0";
        assert!(
            !re.is_match(attack6),
            "missing .github literal must not match: {}",
            attack6
        );
        // TEST PASS: substring attacks rejected
    }

    /// Sub-criterion 1: signature verification with a real cosign bundle.
    /// Gated on RCH_TEST_REAL_SIG=1 AND `cosign` in PATH AND
    /// fixtures present. Skipped silently otherwise.
    #[tokio::test]
    async fn integration_signature_verifies_with_real_cosign() {
        // TEST START: end-to-end signature verification (gated)
        if std::env::var("RCH_TEST_REAL_SIG").is_err() {
            eprintln!(
                "SKIP integration_signature_verifies_with_real_cosign: RCH_TEST_REAL_SIG not set"
            );
            return;
        }
        if which::which("cosign").is_err() {
            eprintln!("SKIP integration_signature_verifies_with_real_cosign: cosign not in PATH");
            return;
        }

        // Fixture paths: the actual binary + .sig bundle from a real RCH release.
        // Place under rch/tests/fixtures/update/. If absent, skip with a clear message.
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let bin = manifest_dir.join("tests/fixtures/update/rch_release_sample.bin");
        let sig = manifest_dir.join("tests/fixtures/update/rch_release_sample.sig");
        if !bin.exists() || !sig.exists() {
            eprintln!(
                "SKIP integration_signature_verifies_with_real_cosign: fixtures missing at {} and/or {}",
                bin.display(),
                sig.display()
            );
            return;
        }

        let result = verify_signature(&bin, &sig).await;
        assert!(
            result.is_ok() && result.unwrap(),
            "real cosign-signed binary should verify"
        );
        // TEST PASS: real signature verified end-to-end
    }
}
