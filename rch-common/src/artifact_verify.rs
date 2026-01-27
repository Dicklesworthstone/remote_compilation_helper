//! Artifact integrity verification using blake3 hashes (bd-377q).
//!
//! This module provides types and utilities for verifying artifact integrity
//! after remote compilation and transfer.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use tracing::{debug, info, warn};

/// Result of computing a file hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHash {
    /// Blake3 hash of the file (64-char hex string).
    pub hash: String,
    /// File size in bytes.
    pub size: u64,
}

/// Manifest of artifact hashes for verification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactManifest {
    /// Map of relative file path to hash.
    pub files: HashMap<String, FileHash>,
    /// Timestamp when manifest was created (Unix epoch seconds).
    pub created_at: u64,
    /// Worker ID that created this manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
}

/// Result of artifact verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Files that passed verification.
    pub passed: Vec<String>,
    /// Files that failed verification with mismatch details.
    pub failed: Vec<VerificationFailure>,
    /// Files that were skipped (missing, too large, etc.).
    pub skipped: Vec<String>,
}

/// Details of a verification failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationFailure {
    /// File path that failed.
    pub path: String,
    /// Expected hash (from manifest).
    pub expected_hash: String,
    /// Actual hash (computed locally).
    pub actual_hash: String,
    /// Expected size.
    pub expected_size: u64,
    /// Actual size.
    pub actual_size: u64,
}

impl VerificationResult {
    /// Check if all verified files passed.
    pub fn all_passed(&self) -> bool {
        self.failed.is_empty()
    }

    /// Get a summary string.
    pub fn summary(&self) -> String {
        format!(
            "{} passed, {} failed, {} skipped",
            self.passed.len(),
            self.failed.len(),
            self.skipped.len()
        )
    }

    /// Format a detailed error message for failed verifications.
    pub fn format_failures(&self) -> String {
        if self.failed.is_empty() {
            return String::new();
        }

        let mut msg = String::new();
        msg.push_str("Artifact integrity verification failed:\n\n");

        for failure in &self.failed {
            msg.push_str(&format!("  {} - HASH MISMATCH\n", failure.path));
            msg.push_str(&format!(
                "    Expected: {} ({} bytes)\n",
                &failure.expected_hash[..16],
                failure.expected_size
            ));
            msg.push_str(&format!(
                "    Actual:   {} ({} bytes)\n",
                &failure.actual_hash[..16],
                failure.actual_size
            ));
        }

        msg.push_str("\nThis may indicate:\n");
        msg.push_str("  - Transfer corruption (retry may help)\n");
        msg.push_str("  - Incomplete transfer\n");
        msg.push_str("  - Worker build cache inconsistency\n");
        msg.push_str("\nSuggested actions:\n");
        msg.push_str("  1. Run `rch diagnose` for detailed analysis\n");
        msg.push_str("  2. Re-run the build to verify consistency\n");
        msg.push_str("  3. Check worker health: `rch workers probe`\n");

        msg
    }
}

impl VerificationFailure {
    /// Create a new verification failure.
    pub fn new(
        path: impl Into<String>,
        expected_hash: impl Into<String>,
        actual_hash: impl Into<String>,
        expected_size: u64,
        actual_size: u64,
    ) -> Self {
        Self {
            path: path.into(),
            expected_hash: expected_hash.into(),
            actual_hash: actual_hash.into(),
            expected_size,
            actual_size,
        }
    }
}

/// Compute blake3 hash of a file.
///
/// # Arguments
/// * `path` - Path to the file to hash.
///
/// # Returns
/// `FileHash` with the blake3 hash (64-char hex) and file size.
pub fn compute_file_hash(path: &Path) -> std::io::Result<FileHash> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let size = metadata.len();

    let mut reader = BufReader::new(file);
    let mut hasher = Hasher::new();
    let mut buffer = [0u8; 65536]; // 64KB buffer

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize().to_hex().to_string();

    Ok(FileHash { hash, size })
}

/// Verify artifacts against a manifest.
///
/// # Arguments
/// * `base_dir` - Base directory containing the artifacts.
/// * `manifest` - Expected hashes from the manifest.
/// * `max_size` - Maximum file size to verify (skip larger files).
///
/// # Returns
/// `VerificationResult` with details of passed, failed, and skipped files.
pub fn verify_artifacts(
    base_dir: &Path,
    manifest: &ArtifactManifest,
    max_size: u64,
) -> VerificationResult {
    let mut result = VerificationResult {
        passed: Vec::new(),
        failed: Vec::new(),
        skipped: Vec::new(),
    };

    for (rel_path, expected) in &manifest.files {
        let full_path = base_dir.join(rel_path);

        // Skip if file doesn't exist
        if !full_path.exists() {
            debug!("Skipping verification of missing file: {}", rel_path);
            result.skipped.push(rel_path.clone());
            continue;
        }

        // Skip if file is too large
        if expected.size > max_size {
            debug!(
                "Skipping verification of large file: {} ({} bytes > {} max)",
                rel_path, expected.size, max_size
            );
            result.skipped.push(rel_path.clone());
            continue;
        }

        // Compute hash
        match compute_file_hash(&full_path) {
            Ok(actual) => {
                if actual.hash == expected.hash && actual.size == expected.size {
                    debug!("Verification passed: {}", rel_path);
                    result.passed.push(rel_path.clone());
                } else {
                    warn!(
                        "Verification failed for {}: expected {} ({} bytes), got {} ({} bytes)",
                        rel_path,
                        &expected.hash[..16],
                        expected.size,
                        &actual.hash[..16],
                        actual.size
                    );
                    result.failed.push(VerificationFailure::new(
                        rel_path,
                        &expected.hash,
                        actual.hash,
                        expected.size,
                        actual.size,
                    ));
                }
            }
            Err(e) => {
                warn!("Failed to hash {}: {}", rel_path, e);
                result.skipped.push(rel_path.clone());
            }
        }
    }

    info!("Artifact verification complete: {}", result.summary());

    result
}

/// Create a manifest from a list of files.
///
/// # Arguments
/// * `base_dir` - Base directory containing the files.
/// * `rel_paths` - Relative paths to include in the manifest.
/// * `worker_id` - Optional worker ID to record.
///
/// # Returns
/// `ArtifactManifest` with hashes of all successfully read files.
pub fn create_manifest(
    base_dir: &Path,
    rel_paths: &[String],
    worker_id: Option<String>,
) -> ArtifactManifest {
    let mut manifest = ArtifactManifest {
        files: HashMap::new(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        worker_id,
    };

    for rel_path in rel_paths {
        let full_path = base_dir.join(rel_path);
        match compute_file_hash(&full_path) {
            Ok(hash) => {
                manifest.files.insert(rel_path.clone(), hash);
            }
            Err(e) => {
                debug!("Skipping {} in manifest: {}", rel_path, e);
            }
        }
    }

    manifest
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;
    use tracing::info;

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }

    #[test]
    fn test_compute_file_hash_basic() {
        init_test_logging();
        info!("TEST START: test_compute_file_hash_basic");

        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");

        // Write known content
        let content = b"Hello, World!";
        std::fs::write(&test_file, content).unwrap();

        let hash = compute_file_hash(&test_file).unwrap();

        assert_eq!(hash.size, 13);
        assert_eq!(hash.hash.len(), 64); // blake3 hex is 64 chars
        info!("Hash: {}", hash.hash);

        // Hash should be deterministic
        let hash2 = compute_file_hash(&test_file).unwrap();
        assert_eq!(hash.hash, hash2.hash);

        info!("TEST PASS: test_compute_file_hash_basic");
    }

    #[test]
    fn test_compute_file_hash_empty() {
        init_test_logging();
        info!("TEST START: test_compute_file_hash_empty");

        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("empty.txt");
        std::fs::write(&test_file, b"").unwrap();

        let hash = compute_file_hash(&test_file).unwrap();

        assert_eq!(hash.size, 0);
        assert_eq!(hash.hash.len(), 64);
        info!("Empty file hash: {}", hash.hash);

        info!("TEST PASS: test_compute_file_hash_empty");
    }

    #[test]
    fn test_compute_file_hash_nonexistent() {
        init_test_logging();
        info!("TEST START: test_compute_file_hash_nonexistent");

        let result = compute_file_hash(Path::new("/nonexistent/file"));
        assert!(result.is_err());

        info!("TEST PASS: test_compute_file_hash_nonexistent");
    }

    #[test]
    fn test_verify_artifacts_all_pass() {
        init_test_logging();
        info!("TEST START: test_verify_artifacts_all_pass");

        let temp_dir = TempDir::new().unwrap();

        // Create test files
        std::fs::write(temp_dir.path().join("a.txt"), b"content a").unwrap();
        std::fs::write(temp_dir.path().join("b.txt"), b"content b").unwrap();

        // Create manifest
        let manifest = create_manifest(
            temp_dir.path(),
            &["a.txt".to_string(), "b.txt".to_string()],
            Some("worker1".to_string()),
        );

        // Verify
        let result = verify_artifacts(temp_dir.path(), &manifest, 1024 * 1024);

        assert!(result.all_passed());
        assert_eq!(result.passed.len(), 2);
        assert!(result.failed.is_empty());

        info!("TEST PASS: test_verify_artifacts_all_pass");
    }

    #[test]
    fn test_verify_artifacts_with_mismatch() {
        init_test_logging();
        info!("TEST START: test_verify_artifacts_with_mismatch");

        let temp_dir = TempDir::new().unwrap();

        // Create initial file
        std::fs::write(temp_dir.path().join("test.txt"), b"original").unwrap();

        // Create manifest with original content
        let manifest = create_manifest(temp_dir.path(), &["test.txt".to_string()], None);

        // Modify file
        std::fs::write(temp_dir.path().join("test.txt"), b"modified").unwrap();

        // Verify should fail
        let result = verify_artifacts(temp_dir.path(), &manifest, 1024 * 1024);

        assert!(!result.all_passed());
        assert_eq!(result.failed.len(), 1);
        assert_eq!(result.failed[0].path, "test.txt");

        info!("Failure details:\n{}", result.format_failures());

        info!("TEST PASS: test_verify_artifacts_with_mismatch");
    }

    #[test]
    fn test_verify_artifacts_skip_large() {
        init_test_logging();
        info!("TEST START: test_verify_artifacts_skip_large");

        let temp_dir = TempDir::new().unwrap();

        // Create a file
        std::fs::write(temp_dir.path().join("large.txt"), b"some content here").unwrap();

        let manifest = create_manifest(temp_dir.path(), &["large.txt".to_string()], None);

        // Verify with very small max size - should skip
        let result = verify_artifacts(temp_dir.path(), &manifest, 5);

        assert!(result.all_passed()); // No failures
        assert_eq!(result.skipped.len(), 1);

        info!("TEST PASS: test_verify_artifacts_skip_large");
    }

    #[test]
    fn test_verify_artifacts_missing_file() {
        init_test_logging();
        info!("TEST START: test_verify_artifacts_missing_file");

        let temp_dir = TempDir::new().unwrap();

        // Create manifest pointing to nonexistent file
        let mut manifest = ArtifactManifest::default();
        manifest.files.insert(
            "missing.txt".to_string(),
            FileHash {
                hash: "abcd1234".repeat(8),
                size: 100,
            },
        );

        let result = verify_artifacts(temp_dir.path(), &manifest, 1024 * 1024);

        assert!(result.all_passed()); // No failures, just skipped
        assert_eq!(result.skipped.len(), 1);

        info!("TEST PASS: test_verify_artifacts_missing_file");
    }

    #[test]
    fn test_verification_result_summary() {
        init_test_logging();
        info!("TEST START: test_verification_result_summary");

        let result = VerificationResult {
            passed: vec!["a.txt".to_string(), "b.txt".to_string()],
            failed: vec![VerificationFailure::new("c.txt", "abc", "def", 100, 200)],
            skipped: vec!["d.txt".to_string()],
        };

        let summary = result.summary();
        assert!(summary.contains("2 passed"));
        assert!(summary.contains("1 failed"));
        assert!(summary.contains("1 skipped"));

        info!("Summary: {}", summary);
        info!("TEST PASS: test_verification_result_summary");
    }

    #[test]
    fn test_create_manifest() {
        init_test_logging();
        info!("TEST START: test_create_manifest");

        let temp_dir = TempDir::new().unwrap();

        std::fs::write(temp_dir.path().join("file1.txt"), b"content1").unwrap();
        std::fs::write(temp_dir.path().join("file2.txt"), b"content2").unwrap();

        let manifest = create_manifest(
            temp_dir.path(),
            &[
                "file1.txt".to_string(),
                "file2.txt".to_string(),
                "missing.txt".to_string(),
            ],
            Some("test-worker".to_string()),
        );

        // Should have 2 files (missing one is skipped)
        assert_eq!(manifest.files.len(), 2);
        assert!(manifest.files.contains_key("file1.txt"));
        assert!(manifest.files.contains_key("file2.txt"));
        assert!(!manifest.files.contains_key("missing.txt"));
        assert_eq!(manifest.worker_id, Some("test-worker".to_string()));
        assert!(manifest.created_at > 0);

        info!("TEST PASS: test_create_manifest");
    }

    #[test]
    fn test_file_hash_equality() {
        init_test_logging();
        info!("TEST START: test_file_hash_equality");

        let hash1 = FileHash {
            hash: "abc123".to_string(),
            size: 100,
        };
        let hash2 = FileHash {
            hash: "abc123".to_string(),
            size: 100,
        };
        let hash3 = FileHash {
            hash: "def456".to_string(),
            size: 100,
        };

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);

        info!("TEST PASS: test_file_hash_equality");
    }

    #[test]
    fn test_file_hash_serialization() {
        init_test_logging();
        info!("TEST START: test_file_hash_serialization");

        let hash = FileHash {
            hash: "0".repeat(64),
            size: 1024,
        };

        let json = serde_json::to_string(&hash).unwrap();
        let deserialized: FileHash = serde_json::from_str(&json).unwrap();

        assert_eq!(hash, deserialized);
        assert!(json.contains("\"hash\""));
        assert!(json.contains("\"size\""));

        info!("TEST PASS: test_file_hash_serialization");
    }

    #[test]
    fn test_file_hash_clone() {
        init_test_logging();
        info!("TEST START: test_file_hash_clone");

        let original = FileHash {
            hash: "test_hash".to_string(),
            size: 500,
        };
        let cloned = original.clone();

        assert_eq!(original.hash, cloned.hash);
        assert_eq!(original.size, cloned.size);

        info!("TEST PASS: test_file_hash_clone");
    }

    #[test]
    fn test_artifact_manifest_default() {
        init_test_logging();
        info!("TEST START: test_artifact_manifest_default");

        let manifest = ArtifactManifest::default();

        assert!(manifest.files.is_empty());
        assert_eq!(manifest.created_at, 0);
        assert!(manifest.worker_id.is_none());

        info!("TEST PASS: test_artifact_manifest_default");
    }

    #[test]
    fn test_artifact_manifest_serialization() {
        init_test_logging();
        info!("TEST START: test_artifact_manifest_serialization");

        let mut manifest = ArtifactManifest::default();
        manifest.created_at = 1706380800;
        manifest.worker_id = Some("worker-1".to_string());
        manifest.files.insert(
            "test.bin".to_string(),
            FileHash {
                hash: "a".repeat(64),
                size: 256,
            },
        );

        let json = serde_json::to_string(&manifest).unwrap();
        let deserialized: ArtifactManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(manifest.created_at, deserialized.created_at);
        assert_eq!(manifest.worker_id, deserialized.worker_id);
        assert_eq!(manifest.files.len(), deserialized.files.len());

        info!("TEST PASS: test_artifact_manifest_serialization");
    }

    #[test]
    fn test_artifact_manifest_without_worker_id() {
        init_test_logging();
        info!("TEST START: test_artifact_manifest_without_worker_id");

        let manifest = ArtifactManifest {
            files: HashMap::new(),
            created_at: 0,
            worker_id: None,
        };

        let json = serde_json::to_string(&manifest).unwrap();
        // worker_id should be skipped when None
        assert!(!json.contains("worker_id"));

        info!("TEST PASS: test_artifact_manifest_without_worker_id");
    }

    #[test]
    fn test_verification_result_all_passed_empty() {
        init_test_logging();
        info!("TEST START: test_verification_result_all_passed_empty");

        let result = VerificationResult {
            passed: vec![],
            failed: vec![],
            skipped: vec![],
        };

        assert!(result.all_passed());
        assert_eq!(result.summary(), "0 passed, 0 failed, 0 skipped");

        info!("TEST PASS: test_verification_result_all_passed_empty");
    }

    #[test]
    fn test_verification_result_format_failures_empty() {
        init_test_logging();
        info!("TEST START: test_verification_result_format_failures_empty");

        let result = VerificationResult {
            passed: vec!["a.txt".to_string()],
            failed: vec![],
            skipped: vec![],
        };

        let failures = result.format_failures();
        assert!(failures.is_empty());

        info!("TEST PASS: test_verification_result_format_failures_empty");
    }

    #[test]
    fn test_verification_result_format_failures_content() {
        init_test_logging();
        info!("TEST START: test_verification_result_format_failures_content");

        let result = VerificationResult {
            passed: vec![],
            failed: vec![VerificationFailure::new(
                "binary.exe",
                "a".repeat(64),
                "b".repeat(64),
                1000,
                1001,
            )],
            skipped: vec![],
        };

        let failures = result.format_failures();
        assert!(failures.contains("binary.exe"));
        assert!(failures.contains("HASH MISMATCH"));
        assert!(failures.contains("Expected:"));
        assert!(failures.contains("Actual:"));
        assert!(failures.contains("1000 bytes"));
        assert!(failures.contains("1001 bytes"));
        assert!(failures.contains("Suggested actions"));
        assert!(failures.contains("rch diagnose"));

        info!("TEST PASS: test_verification_result_format_failures_content");
    }

    #[test]
    fn test_verification_failure_new() {
        init_test_logging();
        info!("TEST START: test_verification_failure_new");

        let failure = VerificationFailure::new(
            "path/to/file.bin",
            "expected_hash_value",
            "actual_hash_value",
            500,
            600,
        );

        assert_eq!(failure.path, "path/to/file.bin");
        assert_eq!(failure.expected_hash, "expected_hash_value");
        assert_eq!(failure.actual_hash, "actual_hash_value");
        assert_eq!(failure.expected_size, 500);
        assert_eq!(failure.actual_size, 600);

        info!("TEST PASS: test_verification_failure_new");
    }

    #[test]
    fn test_verification_failure_from_string() {
        init_test_logging();
        info!("TEST START: test_verification_failure_from_string");

        // Test that Into<String> works (owned strings)
        let failure = VerificationFailure::new(
            String::from("owned_path"),
            String::from("owned_expected"),
            String::from("owned_actual"),
            100,
            200,
        );

        assert_eq!(failure.path, "owned_path");
        assert_eq!(failure.expected_hash, "owned_expected");
        assert_eq!(failure.actual_hash, "owned_actual");

        info!("TEST PASS: test_verification_failure_from_string");
    }

    #[test]
    fn test_verification_failure_serialization() {
        init_test_logging();
        info!("TEST START: test_verification_failure_serialization");

        let failure = VerificationFailure::new("test.bin", "hash1", "hash2", 100, 200);

        let json = serde_json::to_string(&failure).unwrap();
        let deserialized: VerificationFailure = serde_json::from_str(&json).unwrap();

        assert_eq!(failure.path, deserialized.path);
        assert_eq!(failure.expected_hash, deserialized.expected_hash);
        assert_eq!(failure.actual_hash, deserialized.actual_hash);
        assert_eq!(failure.expected_size, deserialized.expected_size);
        assert_eq!(failure.actual_size, deserialized.actual_size);

        info!("TEST PASS: test_verification_failure_serialization");
    }

    #[test]
    fn test_verification_result_serialization() {
        init_test_logging();
        info!("TEST START: test_verification_result_serialization");

        let result = VerificationResult {
            passed: vec!["a.txt".to_string()],
            failed: vec![VerificationFailure::new("b.txt", "h1", "h2", 10, 20)],
            skipped: vec!["c.txt".to_string()],
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: VerificationResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result.passed, deserialized.passed);
        assert_eq!(result.failed.len(), deserialized.failed.len());
        assert_eq!(result.skipped, deserialized.skipped);

        info!("TEST PASS: test_verification_result_serialization");
    }

    #[test]
    fn test_compute_file_hash_deterministic() {
        init_test_logging();
        info!("TEST START: test_compute_file_hash_deterministic");

        let temp_dir = TempDir::new().unwrap();
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");

        // Same content in different files
        let content = b"Identical content for hashing test";
        std::fs::write(&file1, content).unwrap();
        std::fs::write(&file2, content).unwrap();

        let hash1 = compute_file_hash(&file1).unwrap();
        let hash2 = compute_file_hash(&file2).unwrap();

        assert_eq!(hash1.hash, hash2.hash);
        assert_eq!(hash1.size, hash2.size);

        info!("TEST PASS: test_compute_file_hash_deterministic");
    }

    #[test]
    fn test_compute_file_hash_different_content() {
        init_test_logging();
        info!("TEST START: test_compute_file_hash_different_content");

        let temp_dir = TempDir::new().unwrap();
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");

        std::fs::write(&file1, b"content one").unwrap();
        std::fs::write(&file2, b"content two").unwrap();

        let hash1 = compute_file_hash(&file1).unwrap();
        let hash2 = compute_file_hash(&file2).unwrap();

        assert_ne!(hash1.hash, hash2.hash);

        info!("TEST PASS: test_compute_file_hash_different_content");
    }

    #[test]
    fn test_verification_with_size_mismatch() {
        init_test_logging();
        info!("TEST START: test_verification_with_size_mismatch");

        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("test.txt"), b"content").unwrap();

        // Create manifest with wrong size
        let hash = compute_file_hash(&temp_dir.path().join("test.txt")).unwrap();
        let mut manifest = ArtifactManifest::default();
        manifest.files.insert(
            "test.txt".to_string(),
            FileHash {
                hash: hash.hash, // Same hash
                size: 9999,      // Wrong size
            },
        );

        let result = verify_artifacts(temp_dir.path(), &manifest, 1024 * 1024);

        // Should fail due to size mismatch
        assert!(!result.all_passed());
        assert_eq!(result.failed.len(), 1);

        info!("TEST PASS: test_verification_with_size_mismatch");
    }

    #[test]
    fn test_create_manifest_empty_list() {
        init_test_logging();
        info!("TEST START: test_create_manifest_empty_list");

        let temp_dir = TempDir::new().unwrap();
        let manifest = create_manifest(temp_dir.path(), &[], None);

        assert!(manifest.files.is_empty());
        assert!(manifest.worker_id.is_none());

        info!("TEST PASS: test_create_manifest_empty_list");
    }

    #[test]
    fn test_verification_clone_traits() {
        init_test_logging();
        info!("TEST START: test_verification_clone_traits");

        let result = VerificationResult {
            passed: vec!["a.txt".to_string()],
            failed: vec![],
            skipped: vec![],
        };

        let cloned = result.clone();
        assert_eq!(result.passed, cloned.passed);
        assert_eq!(result.failed.len(), cloned.failed.len());
        assert_eq!(result.skipped, cloned.skipped);

        info!("TEST PASS: test_verification_clone_traits");
    }

    #[test]
    fn test_verification_failure_clone() {
        init_test_logging();
        info!("TEST START: test_verification_failure_clone");

        let failure = VerificationFailure::new("path", "h1", "h2", 10, 20);
        let cloned = failure.clone();

        assert_eq!(failure.path, cloned.path);
        assert_eq!(failure.expected_hash, cloned.expected_hash);
        assert_eq!(failure.actual_hash, cloned.actual_hash);

        info!("TEST PASS: test_verification_failure_clone");
    }

    #[test]
    fn test_artifact_manifest_clone() {
        init_test_logging();
        info!("TEST START: test_artifact_manifest_clone");

        let mut manifest = ArtifactManifest::default();
        manifest.created_at = 12345;
        manifest.worker_id = Some("worker".to_string());
        manifest.files.insert(
            "f.txt".to_string(),
            FileHash {
                hash: "h".to_string(),
                size: 1,
            },
        );

        let cloned = manifest.clone();
        assert_eq!(manifest.created_at, cloned.created_at);
        assert_eq!(manifest.worker_id, cloned.worker_id);
        assert_eq!(manifest.files.len(), cloned.files.len());

        info!("TEST PASS: test_artifact_manifest_clone");
    }

    #[test]
    fn test_file_hash_debug() {
        init_test_logging();
        info!("TEST START: test_file_hash_debug");

        let hash = FileHash {
            hash: "abc".to_string(),
            size: 100,
        };

        let debug = format!("{:?}", hash);
        assert!(debug.contains("FileHash"));
        assert!(debug.contains("abc"));
        assert!(debug.contains("100"));

        info!("TEST PASS: test_file_hash_debug");
    }

    #[test]
    fn test_verification_result_debug() {
        init_test_logging();
        info!("TEST START: test_verification_result_debug");

        let result = VerificationResult {
            passed: vec!["a.txt".to_string()],
            failed: vec![],
            skipped: vec![],
        };

        let debug = format!("{:?}", result);
        assert!(debug.contains("VerificationResult"));
        assert!(debug.contains("a.txt"));

        info!("TEST PASS: test_verification_result_debug");
    }

    #[test]
    fn test_multiple_failures_format() {
        init_test_logging();
        info!("TEST START: test_multiple_failures_format");

        let result = VerificationResult {
            passed: vec![],
            failed: vec![
                VerificationFailure::new("file1.bin", "a".repeat(64), "b".repeat(64), 100, 101),
                VerificationFailure::new("file2.bin", "c".repeat(64), "d".repeat(64), 200, 201),
            ],
            skipped: vec![],
        };

        let failures = result.format_failures();
        assert!(failures.contains("file1.bin"));
        assert!(failures.contains("file2.bin"));
        assert!(failures.contains("HASH MISMATCH"));

        info!("TEST PASS: test_multiple_failures_format");
    }
}
