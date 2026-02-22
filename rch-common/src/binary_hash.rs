//! Binary hash computation utility for verifying remote compilation correctness.
//!
//! This module provides deterministic hashing of compiled binaries by focusing on
//! code sections (.text, .rodata) while ignoring non-deterministic metadata like
//! timestamps and paths.

use anyhow::{Context, Result, anyhow};
use blake3::Hasher;
use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
use object::{Architecture, Object, ObjectSection};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
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

/// Get the current architecture for selecting the right slice from a fat binary.
#[cfg(target_arch = "x86_64")]
fn native_architecture() -> Architecture {
    Architecture::X86_64
}

#[cfg(target_arch = "aarch64")]
fn native_architecture() -> Architecture {
    Architecture::Aarch64
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn native_architecture() -> Architecture {
    Architecture::Unknown
}

/// Try to extract a slice from a fat binary using the given arch list.
fn try_extract_from_fat<'a, F: FatArch>(
    data: &'a [u8],
    arches: &[F],
    native_arch: Architecture,
) -> Option<&'a [u8]> {
    // First try to find a slice matching our native architecture
    for arch in arches {
        if arch.architecture() == native_arch
            && let Ok(slice) = arch.data(data)
        {
            info!("Extracted {:?} slice from fat binary", native_arch);
            return Some(slice);
        }
    }

    // No exact match found, use the first valid slice
    if let Some(arch) = arches.first()
        && let Ok(slice) = arch.data(data)
    {
        info!("Using first available slice from fat binary");
        return Some(slice);
    }

    None
}

/// Extract the appropriate binary slice from a fat/universal binary.
///
/// macOS universal binaries (fat binaries) contain multiple architecture slices.
/// This function extracts the slice matching the current native architecture,
/// or the first available slice if no exact match is found.
///
/// For non-fat binaries, returns the original data unchanged.
fn extract_binary_slice(data: &[u8]) -> Result<&[u8]> {
    // Try parsing as 32-bit fat binary first (more common)
    if let Ok(fat) = MachOFatFile32::parse(data) {
        let arches = fat.arches();
        if arches.is_empty() {
            return Err(anyhow!("Fat binary contains no architecture slices"));
        }

        let native_arch = native_architecture();
        if let Some(slice) = try_extract_from_fat(data, arches, native_arch) {
            return Ok(slice);
        }
        return Err(anyhow!("Failed to extract any valid slice from fat binary"));
    }

    // Try parsing as 64-bit fat binary
    if let Ok(fat) = MachOFatFile64::parse(data) {
        let arches = fat.arches();
        if arches.is_empty() {
            return Err(anyhow!("Fat64 binary contains no architecture slices"));
        }

        let native_arch = native_architecture();
        if let Some(slice) = try_extract_from_fat(data, arches, native_arch) {
            return Ok(slice);
        }
        return Err(anyhow!(
            "Failed to extract any valid slice from fat64 binary"
        ));
    }

    // Not a fat binary, return as-is
    Ok(data)
}

/// Check if a section name represents code or read-only data.
///
/// Supports both ELF (.text, .rodata) and Mach-O (__text, __const) section names.
fn is_code_section(name: &str) -> bool {
    // ELF section names
    name == ".text"
        || name == ".rodata"
        || name.starts_with(".text.")
        || name.starts_with(".rodata.")
        // Mach-O section names (lowercase, within __TEXT segment)
        || name == "__text"
        || name == "__const"
        || name == "__cstring"
        || name == "__stubs"
        || name == "__stub_helper"
}

/// Compute hash of code sections only using BLAKE3.
///
/// This hash focuses on executable code and read-only data sections,
/// ignoring non-deterministic metadata. This provides a more reliable
/// comparison between builds of the same source code.
///
/// Supports both ELF (Linux) and Mach-O (macOS) binary formats,
/// including macOS universal (fat) binaries.
fn compute_code_hash(data: &[u8]) -> Result<String> {
    // Handle fat/universal binaries by extracting the appropriate slice
    let binary_data = extract_binary_slice(data)?;
    let file = object::File::parse(binary_data).context("Failed to parse binary format")?;
    let mut hasher = Hasher::new();
    let mut sections_hashed = 0;

    // Hash only executable code and read-only data sections
    for section in file.sections() {
        let name = section.name().unwrap_or("");

        // Include code sections from both ELF and Mach-O formats
        if is_code_section(name)
            && let Ok(section_data) = section.data()
        {
            hasher.update(section_data);
            sections_hashed += 1;
        }
    }

    if sections_hashed == 0 {
        return Err(anyhow!("No code sections found in binary"));
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Check if a section name represents the main text/code section.
fn is_text_section(name: &str) -> bool {
    // ELF and Mach-O text sections
    name == ".text" || name == "__text"
}

/// Check if a section name represents debug information.
fn is_debug_section(name: &str) -> bool {
    // ELF debug sections
    name.starts_with(".debug")
        // Mach-O debug sections (DWARF)
        || name.starts_with("__debug")
        || name == "__DWARF"
}

/// Extract metadata about the binary.
///
/// Returns (text_section_size, has_debug_info).
/// Supports both ELF (Linux) and Mach-O (macOS) binary formats,
/// including macOS universal (fat) binaries.
fn extract_metadata(data: &[u8]) -> Result<(u64, bool)> {
    // Handle fat/universal binaries by extracting the appropriate slice
    let binary_data = extract_binary_slice(data)?;
    let file = object::File::parse(binary_data).context("Failed to parse binary for metadata")?;

    let text_size: u64 = file
        .sections()
        .filter(|s| is_text_section(s.name().unwrap_or("")))
        .map(|s| s.size())
        .sum();

    let has_debug = file
        .sections()
        .any(|s| is_debug_section(s.name().unwrap_or("")));

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

    // Empty marker is trivially contained in any file (consistent with str::contains(""))
    if marker.is_empty() {
        return Ok(true);
    }

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
            "/bin/ls",  // Fallback to system binary
            "/bin/cat", // Another fallback
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

        assert!(
            result,
            "Binaries with matching code hash should be equivalent"
        );
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

        assert!(
            !result,
            "Binaries with different code hash should not be equivalent"
        );
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

        assert!(
            !result,
            "Binaries with different text size should not be equivalent"
        );
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

        assert!(
            !result,
            "Binaries with different debug status should not be equivalent"
        );
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
        assert_eq!(
            result.full_hash.len(),
            64,
            "Full hash should be 64 hex chars"
        );
        assert_eq!(
            result.code_hash.len(),
            64,
            "Code hash should be 64 hex chars"
        );
        assert!(
            result.text_section_size > 0,
            "Text section should have content"
        );

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

        // Look for a common string that should exist in any binary
        // ELF binaries contain "ELF", Mach-O binaries don't have that marker
        // so we test for common strings that appear in most system binaries
        #[cfg(target_os = "linux")]
        let marker = "ELF";
        #[cfg(target_os = "macos")]
        let marker = "__TEXT"; // Mach-O segment name commonly found in binaries
        #[cfg(target_os = "windows")]
        let marker = "PE"; // PE header marker (though this test may be skipped on Windows)
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let marker = "ELF";

        info!(
            "INPUT: binary_contains_marker({:?}, '{}')",
            binary_path, marker
        );

        let result = binary_contains_marker(&binary_path, marker).unwrap();
        info!("RESULT: contains_marker = {}", result);

        // The marker should be found in the binary
        assert!(result, "Binary should contain '{}' string", marker);
        info!("VERIFY: Marker '{}' found in binary", marker);
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
        info!(
            "INPUT: binary_contains_marker({:?}, '{}')",
            binary_path, marker
        );

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

    // ===================================================================
    // Empty / non-binary file edge cases
    // ===================================================================

    #[test]
    fn test_compute_binary_hash_empty_file() {
        init_test_logging();
        info!("TEST START: test_compute_binary_hash_empty_file");

        let dir = std::env::temp_dir().join("rch-binary-hash-test-empty");
        let _ = std::fs::create_dir_all(&dir);
        let empty_path = dir.join("empty_binary");
        std::fs::write(&empty_path, b"").unwrap();

        let result = compute_binary_hash(&empty_path);
        assert!(
            result.is_err(),
            "empty file should fail binary hash (not a valid binary format)"
        );

        let _ = std::fs::remove_dir_all(&dir);
        info!("TEST PASS: test_compute_binary_hash_empty_file");
    }

    #[test]
    fn test_compute_binary_hash_text_file() {
        init_test_logging();
        info!("TEST START: test_compute_binary_hash_text_file");

        let dir = std::env::temp_dir().join("rch-binary-hash-test-text");
        let _ = std::fs::create_dir_all(&dir);
        let text_path = dir.join("not_a_binary.txt");
        std::fs::write(&text_path, b"Hello, this is not a binary file.").unwrap();

        let result = compute_binary_hash(&text_path);
        assert!(
            result.is_err(),
            "text file should fail binary hash computation"
        );

        let _ = std::fs::remove_dir_all(&dir);
        info!("TEST PASS: test_compute_binary_hash_text_file");
    }

    #[test]
    fn test_compute_binary_hash_truncated_elf_header() {
        init_test_logging();
        info!("TEST START: test_compute_binary_hash_truncated_elf_header");

        let dir = std::env::temp_dir().join("rch-binary-hash-test-truncated");
        let _ = std::fs::create_dir_all(&dir);
        let trunc_path = dir.join("truncated_elf");
        // ELF magic followed by truncated header
        std::fs::write(&trunc_path, b"\x7fELF\x02\x01\x01\x00").unwrap();

        let result = compute_binary_hash(&trunc_path);
        assert!(
            result.is_err(),
            "truncated ELF should fail binary hash computation"
        );

        let _ = std::fs::remove_dir_all(&dir);
        info!("TEST PASS: test_compute_binary_hash_truncated_elf_header");
    }

    // ===================================================================
    // BinaryHashResult equivalence edge cases
    // ===================================================================

    #[test]
    fn test_binaries_equivalent_ignores_full_hash() {
        init_test_logging();

        let result1 = BinaryHashResult {
            full_hash: "aaaa".to_string(),
            code_hash: "same_code".to_string(),
            text_section_size: 1024,
            is_debug: false,
        };
        let result2 = BinaryHashResult {
            full_hash: "bbbb".to_string(), // different full hash
            code_hash: "same_code".to_string(),
            text_section_size: 1024,
            is_debug: false,
        };

        assert!(
            binaries_equivalent(&result1, &result2),
            "equivalence should only consider code_hash, text_section_size, is_debug"
        );
    }

    #[test]
    fn test_binaries_not_equivalent_debug_vs_release() {
        init_test_logging();

        let debug = BinaryHashResult {
            full_hash: "a".to_string(),
            code_hash: "same".to_string(),
            text_section_size: 1024,
            is_debug: true,
        };
        let release = BinaryHashResult {
            full_hash: "a".to_string(),
            code_hash: "same".to_string(),
            text_section_size: 1024,
            is_debug: false,
        };

        assert!(
            !binaries_equivalent(&debug, &release),
            "debug vs release should not be equivalent"
        );
    }

    #[test]
    fn test_binaries_not_equivalent_different_text_size() {
        init_test_logging();

        let small = BinaryHashResult {
            full_hash: "a".to_string(),
            code_hash: "same".to_string(),
            text_section_size: 1024,
            is_debug: false,
        };
        let large = BinaryHashResult {
            full_hash: "a".to_string(),
            code_hash: "same".to_string(),
            text_section_size: 2048,
            is_debug: false,
        };

        assert!(
            !binaries_equivalent(&small, &large),
            "different text section sizes should not be equivalent"
        );
    }

    // ===================================================================
    // BinaryHashResult serialization
    // ===================================================================

    #[test]
    fn test_binary_hash_result_serialization_round_trip() {
        let result = BinaryHashResult {
            full_hash: "abc123def456".to_string(),
            code_hash: "789ghi012".to_string(),
            text_section_size: 65536,
            is_debug: true,
        };

        let json = serde_json::to_string(&result).expect("should serialize");
        let deserialized: BinaryHashResult =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(result, deserialized);
    }

    // ===================================================================
    // Marker search edge cases
    // ===================================================================

    #[test]
    fn test_binary_contains_marker_empty_marker() {
        init_test_logging();

        let binary_path = match find_test_binary() {
            Some(p) => p,
            None => {
                info!("SKIP: No test binary found");
                return;
            }
        };

        // Empty marker is trivially contained (consistent with str::contains(""))
        let result = binary_contains_marker(&binary_path, "");
        assert!(result.is_ok(), "empty marker should not panic");
        assert!(result.unwrap(), "empty marker should be trivially found");
    }

    #[test]
    fn test_binary_contains_marker_very_long_marker() {
        init_test_logging();

        let binary_path = match find_test_binary() {
            Some(p) => p,
            None => {
                info!("SKIP: No test binary found");
                return;
            }
        };

        // Very long marker that surely doesn't exist
        let marker = "X".repeat(1024);
        let result = binary_contains_marker(&binary_path, &marker).unwrap();
        assert!(
            !result,
            "very long marker should not be found in any binary"
        );
    }

    // ===================================================================
    // Hash determinism verification
    // ===================================================================

    #[test]
    fn test_full_hash_determinism() {
        init_test_logging();

        let binary_path = match find_test_binary() {
            Some(p) => p,
            None => return,
        };

        let result1 = compute_binary_hash(&binary_path).unwrap();
        let result2 = compute_binary_hash(&binary_path).unwrap();

        assert_eq!(
            result1.full_hash, result2.full_hash,
            "full_hash must be deterministic"
        );
        assert_eq!(
            result1.code_hash, result2.code_hash,
            "code_hash must be deterministic"
        );
        assert_eq!(
            result1.text_section_size, result2.text_section_size,
            "text_section_size must be deterministic"
        );
        assert_eq!(
            result1.is_debug, result2.is_debug,
            "is_debug must be deterministic"
        );
    }

    #[test]
    fn test_code_hash_differs_from_full_hash() {
        init_test_logging();

        let binary_path = match find_test_binary() {
            Some(p) => p,
            None => return,
        };

        let result = compute_binary_hash(&binary_path).unwrap();
        assert_ne!(
            result.code_hash, result.full_hash,
            "code_hash should differ from full_hash (unless binary has only code sections)"
        );
    }

    #[test]
    fn test_text_section_size_nonzero_for_real_binary() {
        init_test_logging();

        let binary_path = match find_test_binary() {
            Some(p) => p,
            None => return,
        };

        let result = compute_binary_hash(&binary_path).unwrap();
        assert!(
            result.text_section_size > 0,
            "real binary should have non-zero text section"
        );
    }

    #[test]
    fn test_hash_format_is_hex_string() {
        init_test_logging();

        let binary_path = match find_test_binary() {
            Some(p) => p,
            None => return,
        };

        let result = compute_binary_hash(&binary_path).unwrap();
        assert!(
            result.full_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "full_hash should be hex string"
        );
        assert!(
            result.code_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "code_hash should be hex string"
        );
        // BLAKE3 produces 64-char hex (256 bits)
        assert_eq!(
            result.full_hash.len(),
            64,
            "BLAKE3 hash should be 64 hex chars"
        );
        assert_eq!(
            result.code_hash.len(),
            64,
            "BLAKE3 hash should be 64 hex chars"
        );
    }
}
