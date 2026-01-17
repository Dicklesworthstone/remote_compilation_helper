//! Binary hash computation utility for verifying remote compilation correctness.
//!
//! This module provides deterministic hashing of compiled binaries by focusing on
//! code sections (.text, .rodata) while ignoring non-deterministic metadata like
//! timestamps and paths.

use anyhow::{Context, Result, anyhow};
use blake3::Hasher;
use object::{Object, ObjectSection};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Result of computing hashes for a binary file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryHashResult {
    /// Hash of the entire binary file (includes non-deterministic elements).
    pub full_hash: String,
    /// Hash of only code sections (.text, .rodata) - deterministic across builds.
    pub code_hash: String,
    /// Size of the .text section in bytes.
    pub text_section_size: u64,
    /// Whether the binary contains debug information.
    pub is_debug: bool,
}

/// Compute hash of the entire binary file using BLAKE3.
///
/// This hash includes all non-deterministic elements (timestamps, paths, etc.)
/// and will differ between builds even of identical source code.
fn compute_full_hash(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("Failed to open binary: {:?}", path))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Hasher::new();
    let mut buffer = [0u8; 65536];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Compute hash of code sections only using BLAKE3.
///
/// This hash focuses on executable code and read-only data sections,
/// ignoring non-deterministic metadata. This provides a more reliable
/// comparison between builds of the same source code.
fn compute_code_hash(data: &[u8]) -> Result<String> {
    let file = object::File::parse(data).context("Failed to parse binary format")?;
    let mut hasher = Hasher::new();
    let mut sections_hashed = 0;

    // Hash only executable code and read-only data sections
    for section in file.sections() {
        let name = section.name().unwrap_or("");

        // Include .text (code), .rodata (read-only data), and subsections
        if name == ".text" || name == ".rodata" || name.starts_with(".text.") {
            if let Ok(section_data) = section.data() {
                hasher.update(section_data);
                sections_hashed += 1;
            }
        }
    }

    if sections_hashed == 0 {
        return Err(anyhow!("No code sections found in binary"));
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Extract metadata about the binary.
///
/// Returns (text_section_size, has_debug_info).
fn extract_metadata(data: &[u8]) -> Result<(u64, bool)> {
    let file = object::File::parse(data).context("Failed to parse binary for metadata")?;

    let text_size: u64 = file
        .sections()
        .filter(|s| s.name().unwrap_or("") == ".text")
        .map(|s| s.size())
        .sum();

    let has_debug = file
        .sections()
        .any(|s| s.name().unwrap_or("").starts_with(".debug"));

    Ok((text_size, has_debug))
}

/// Compute comprehensive hash information for a binary file.
///
/// This function returns both a full file hash and a deterministic code hash
/// that can be used to verify remote compilation correctness.
///
/// # Arguments
/// * `path` - Path to the binary file
///
/// # Returns
/// A `BinaryHashResult` containing:
/// - `full_hash`: Complete file hash (non-deterministic)
/// - `code_hash`: Hash of code sections only (deterministic)
/// - `text_section_size`: Size of executable code
/// - `is_debug`: Whether debug symbols are present
pub fn compute_binary_hash(path: &Path) -> Result<BinaryHashResult> {
    info!("Computing binary hash for {:?}", path);

    // Compute full file hash
    let full_hash = compute_full_hash(path)?;
    info!("Full hash computed: {}", &full_hash[..16]);

    // Read file for section analysis
    let data = std::fs::read(path).with_context(|| format!("Failed to read binary: {:?}", path))?;

    // Compute code-only hash
    let code_hash = compute_code_hash(&data)?;
    info!("Code hash computed: {}", &code_hash[..16]);

    // Extract metadata
    let (text_section_size, is_debug) = extract_metadata(&data)?;
    info!(
        "Metadata: text_size={}, is_debug={}",
        text_section_size, is_debug
    );

    Ok(BinaryHashResult {
        full_hash,
        code_hash,
        text_section_size,
        is_debug,
    })
}

/// Check if a binary contains a specific marker string.
///
/// This is used to verify that the remote worker actually compiled the code
/// by checking for a unique test marker that was added to the source.
///
/// # Arguments
/// * `path` - Path to the binary file
/// * `marker` - The marker string to search for
///
/// # Returns
/// `true` if the marker is found in the binary's string data
pub fn binary_contains_marker(path: &Path, marker: &str) -> Result<bool> {
    info!("Searching for marker '{}' in {:?}", marker, path);

    let data = std::fs::read(path).with_context(|| format!("Failed to read binary: {:?}", path))?;

    // Search for the marker in the raw binary data
    // The marker should appear as a string literal in .rodata or similar sections
    let marker_bytes = marker.as_bytes();
    let contains = data
        .windows(marker_bytes.len())
        .any(|window| window == marker_bytes);

    info!("Marker search result: found={}", contains);
    Ok(contains)
}

/// Compare two binaries for functional equivalence.
///
/// Two binaries are considered equivalent if they have:
/// - Matching code hashes (same executable code)
/// - Matching text section sizes
/// - Matching debug status
///
/// The full hash may differ due to timestamps and paths, so it is not used
/// for equivalence checking.
///
/// # Arguments
/// * `local` - Hash result from local build
/// * `remote` - Hash result from remote build
///
/// # Returns
/// `true` if the binaries are functionally equivalent
pub fn binaries_equivalent(local: &BinaryHashResult, remote: &BinaryHashResult) -> bool {
    // Code hash must match exactly
    if local.code_hash != remote.code_hash {
        info!(
            "Code hash mismatch: local={}, remote={}",
            &local.code_hash[..local.code_hash.len().min(16)],
            &remote.code_hash[..remote.code_hash.len().min(16)]
        );
        return false;
    }

    // Text section size should match
    if local.text_section_size != remote.text_section_size {
        info!(
            "Text section size mismatch: local={}, remote={}",
            local.text_section_size, remote.text_section_size
        );
        return false;
    }

    // Debug status should match
    if local.is_debug != remote.is_debug {
        info!(
            "Debug status mismatch: local={}, remote={}",
            local.is_debug, remote.is_debug
        );
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::INFO)
            .try_init();
    }

    /// Find a binary in the project for testing
    fn find_test_binary() -> Option<PathBuf> {
        // Try release binary first, then debug
        let candidates = [
            "target/release/rch",
            "target/debug/rch",
            "target/release/rchd",
            "target/debug/rchd",
            "/bin/ls",    // Fallback to system binary
            "/bin/cat",   // Another fallback
            "/usr/bin/ls",
        ];

        for candidate in candidates {
            let path = PathBuf::from(candidate);
            if path.exists() {
                return Some(path);
            }
        }
        None
    }

    #[test]
    fn test_hash_same_binary_twice() {
        init_test_logging();
        info!("TEST START: test_hash_same_binary_twice");

        let binary_path = match find_test_binary() {
            Some(p) => p,
            None => {
                info!("SKIP: No test binary found");
                return;
            }
        };

        info!("INPUT: compute_binary_hash({:?}) twice", binary_path);

        let hash1 = compute_binary_hash(&binary_path).unwrap();
        let hash2 = compute_binary_hash(&binary_path).unwrap();

        info!(
            "RESULT: hash1.code_hash={}, hash2.code_hash={}",
            &hash1.code_hash[..16],
            &hash2.code_hash[..16]
        );

        assert_eq!(hash1.code_hash, hash2.code_hash, "Code hash should match");
        assert_eq!(hash1.full_hash, hash2.full_hash, "Full hash should match");
        assert_eq!(
            hash1.text_section_size, hash2.text_section_size,
            "Text section size should match"
        );
        assert_eq!(hash1.is_debug, hash2.is_debug, "Debug status should match");

        info!("VERIFY: Same binary produces identical hashes");
        info!("TEST PASS: test_hash_same_binary_twice");
    }

    #[test]
    fn test_binaries_equivalent_matching() {
        init_test_logging();
        info!("TEST START: test_binaries_equivalent_matching");

        let local = BinaryHashResult {
            full_hash: "abc123def456".into(),
            code_hash: "xyz789abc".into(),
            text_section_size: 12345,
            is_debug: false,
        };
        let remote = BinaryHashResult {
            full_hash: "different_full_hash".into(), // Full hash may differ
            code_hash: "xyz789abc".into(),           // Code hash matches
            text_section_size: 12345,
            is_debug: false,
        };

        info!(
            "INPUT: local.code_hash={}, remote.code_hash={}",
            local.code_hash, remote.code_hash
        );

        let result = binaries_equivalent(&local, &remote);
        info!("RESULT: binaries_equivalent = {}", result);

        assert!(result, "Binaries with matching code hash should be equivalent");
        info!("VERIFY: Binaries with matching code hash are equivalent");
        info!("TEST PASS: test_binaries_equivalent_matching");
    }

    #[test]
    fn test_binaries_not_equivalent_different_code_hash() {
        init_test_logging();
        info!("TEST START: test_binaries_not_equivalent_different_code_hash");

        let local = BinaryHashResult {
            full_hash: "abc123".into(),
            code_hash: "hash_v1".into(),
            text_section_size: 12345,
            is_debug: false,
        };
        let remote = BinaryHashResult {
            full_hash: "abc123".into(),
            code_hash: "hash_v2".into(), // Different code hash
            text_section_size: 12345,
            is_debug: false,
        };

        info!(
            "INPUT: local.code_hash={}, remote.code_hash={}",
            local.code_hash, remote.code_hash
        );

        let result = binaries_equivalent(&local, &remote);
        info!("RESULT: binaries_equivalent = {}", result);

        assert!(!result, "Binaries with different code hash should not be equivalent");
        info!("VERIFY: Different code hash makes binaries non-equivalent");
        info!("TEST PASS: test_binaries_not_equivalent_different_code_hash");
    }

    #[test]
    fn test_binaries_not_equivalent_different_size() {
        init_test_logging();
        info!("TEST START: test_binaries_not_equivalent_different_size");

        let local = BinaryHashResult {
            full_hash: "abc123".into(),
            code_hash: "same_hash".into(),
            text_section_size: 12345,
            is_debug: false,
        };
        let remote = BinaryHashResult {
            full_hash: "abc123".into(),
            code_hash: "same_hash".into(),
            text_section_size: 54321, // Different size
            is_debug: false,
        };

        info!(
            "INPUT: local.text_size={}, remote.text_size={}",
            local.text_section_size, remote.text_section_size
        );

        let result = binaries_equivalent(&local, &remote);
        info!("RESULT: binaries_equivalent = {}", result);

        assert!(!result, "Binaries with different text size should not be equivalent");
        info!("VERIFY: Different text section size makes binaries non-equivalent");
        info!("TEST PASS: test_binaries_not_equivalent_different_size");
    }

    #[test]
    fn test_binaries_not_equivalent_different_debug_status() {
        init_test_logging();
        info!("TEST START: test_binaries_not_equivalent_different_debug_status");

        let local = BinaryHashResult {
            full_hash: "abc123".into(),
            code_hash: "same_hash".into(),
            text_section_size: 12345,
            is_debug: false,
        };
        let remote = BinaryHashResult {
            full_hash: "abc123".into(),
            code_hash: "same_hash".into(),
            text_section_size: 12345,
            is_debug: true, // Different debug status
        };

        info!(
            "INPUT: local.is_debug={}, remote.is_debug={}",
            local.is_debug, remote.is_debug
        );

        let result = binaries_equivalent(&local, &remote);
        info!("RESULT: binaries_equivalent = {}", result);

        assert!(!result, "Binaries with different debug status should not be equivalent");
        info!("VERIFY: Different debug status makes binaries non-equivalent");
        info!("TEST PASS: test_binaries_not_equivalent_different_debug_status");
    }

    #[test]
    fn test_compute_binary_hash_nonexistent_file() {
        init_test_logging();
        info!("TEST START: test_compute_binary_hash_nonexistent_file");

        let path = Path::new("/nonexistent/path/to/binary");
        info!("INPUT: compute_binary_hash({:?})", path);

        let result = compute_binary_hash(path);
        info!("RESULT: is_err = {}", result.is_err());

        assert!(result.is_err(), "Should fail for nonexistent file");
        info!("VERIFY: Nonexistent file returns error");
        info!("TEST PASS: test_compute_binary_hash_nonexistent_file");
    }

    #[test]
    fn test_compute_binary_hash_invalid_file() {
        init_test_logging();
        info!("TEST START: test_compute_binary_hash_invalid_file");

        // Try to hash a text file which is not a valid binary
        let path = Path::new("Cargo.toml");
        if !path.exists() {
            info!("SKIP: Cargo.toml not found");
            return;
        }

        info!("INPUT: compute_binary_hash({:?}) on text file", path);

        let result = compute_binary_hash(path);
        info!("RESULT: is_err = {}", result.is_err());

        assert!(result.is_err(), "Should fail for non-binary file");
        info!("VERIFY: Non-binary file returns error");
        info!("TEST PASS: test_compute_binary_hash_invalid_file");
    }

    #[test]
    fn test_binary_hash_result_fields() {
        init_test_logging();
        info!("TEST START: test_binary_hash_result_fields");

        let binary_path = match find_test_binary() {
            Some(p) => p,
            None => {
                info!("SKIP: No test binary found");
                return;
            }
        };

        info!("INPUT: compute_binary_hash({:?})", binary_path);

        let result = compute_binary_hash(&binary_path).unwrap();

        info!("RESULT: full_hash_len={}", result.full_hash.len());
        info!("RESULT: code_hash_len={}", result.code_hash.len());
        info!("RESULT: text_section_size={}", result.text_section_size);
        info!("RESULT: is_debug={}", result.is_debug);

        // BLAKE3 produces 64-character hex string
        assert_eq!(result.full_hash.len(), 64, "Full hash should be 64 hex chars");
        assert_eq!(result.code_hash.len(), 64, "Code hash should be 64 hex chars");
        assert!(result.text_section_size > 0, "Text section should have content");

        info!("VERIFY: All fields have valid values");
        info!("TEST PASS: test_binary_hash_result_fields");
    }

    #[test]
    fn test_binary_contains_marker_found() {
        init_test_logging();
        info!("TEST START: test_binary_contains_marker_found");

        let binary_path = match find_test_binary() {
            Some(p) => p,
            None => {
                info!("SKIP: No test binary found");
                return;
            }
        };

        // Look for a common string that should exist in any ELF binary
        // Most binaries contain "ELF" or common library strings
        let marker = "ELF";
        info!("INPUT: binary_contains_marker({:?}, '{}')", binary_path, marker);

        let result = binary_contains_marker(&binary_path, marker).unwrap();
        info!("RESULT: contains_marker = {}", result);

        // ELF binaries start with the ELF magic number which includes "ELF"
        assert!(result, "ELF binary should contain 'ELF' string");
        info!("VERIFY: Marker 'ELF' found in binary");
        info!("TEST PASS: test_binary_contains_marker_found");
    }

    #[test]
    fn test_binary_contains_marker_not_found() {
        init_test_logging();
        info!("TEST START: test_binary_contains_marker_not_found");

        let binary_path = match find_test_binary() {
            Some(p) => p,
            None => {
                info!("SKIP: No test binary found");
                return;
            }
        };

        // Look for a unique string that should NOT exist in any binary
        let marker = "RCH_TEST_MARKER_UNIQUE_12345_XYZ";
        info!("INPUT: binary_contains_marker({:?}, '{}')", binary_path, marker);

        let result = binary_contains_marker(&binary_path, marker).unwrap();
        info!("RESULT: contains_marker = {}", result);

        assert!(!result, "Binary should not contain made-up marker");
        info!("VERIFY: Unique marker not found in binary");
        info!("TEST PASS: test_binary_contains_marker_not_found");
    }

    #[test]
    fn test_binary_contains_marker_nonexistent_file() {
        init_test_logging();
        info!("TEST START: test_binary_contains_marker_nonexistent_file");

        let path = Path::new("/nonexistent/path/to/binary");
        let marker = "test";
        info!("INPUT: binary_contains_marker({:?}, '{}')", path, marker);

        let result = binary_contains_marker(path, marker);
        info!("RESULT: is_err = {}", result.is_err());

        assert!(result.is_err(), "Should fail for nonexistent file");
        info!("VERIFY: Nonexistent file returns error");
        info!("TEST PASS: test_binary_contains_marker_nonexistent_file");
    }
}
