//! Test code change generator for verifying remote compilation.
//!
//! This module provides utilities to create minimal, detectable, reversible
//! code changes that can verify whether remote compilation actually processes
//! the source code.

use anyhow::{Context, Result};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{error, info};

use crate::binary_hash::binary_contains_marker;

/// Represents a test modification to source code.
///
/// The change is designed to be:
/// - Minimal: Single file modification
/// - Detectable: Produces a different binary hash
/// - Reversible: Can be applied and reverted cleanly
/// - Deterministic: Same change always produces same result
#[derive(Debug, Clone)]
pub struct TestCodeChange {
    /// Path to the file being modified.
    pub file_path: PathBuf,
    /// Original file content before modification.
    pub original_content: String,
    /// Content with the test change applied.
    pub modified_content: String,
    /// Unique identifier for this change (appears in binary).
    pub change_id: String,
}

impl TestCodeChange {
    /// Create a test change that adds a unique marker constant.
    ///
    /// This adds a const string to the specified file that will be compiled
    /// into the binary, allowing verification that compilation actually occurred.
    ///
    /// # Arguments
    /// * `file_path` - Path to the source file to modify
    ///
    /// # Example
    /// ```no_run
    /// use std::path::Path;
    /// use rch_common::test_change::TestCodeChange;
    ///
    /// let change = TestCodeChange::for_file(Path::new("src/main.rs")).unwrap();
    /// println!("Change ID: {}", change.change_id);
    /// ```
    pub fn for_file(file_path: &Path) -> Result<Self> {
        let original = fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read source file: {:?}", file_path))?;

        // Generate a unique change ID based on timestamp
        let change_id = format!("RCH_TEST_{}", Utc::now().timestamp_millis());

        // Modify: add a const that will be compiled into the binary
        let modified = format!(
            "{}\n\n// RCH Self-Test Marker (auto-generated, safe to remove)\n\
             #[used]\n\
             #[allow(dead_code)]\n\
             static {}: &str = \"{}\";\n",
            original, change_id, change_id
        );

        Ok(TestCodeChange {
            file_path: file_path.to_path_buf(),
            original_content: original,
            modified_content: modified,
            change_id,
        })
    }

    /// Create a test change for the main.rs file in a project directory.
    ///
    /// # Arguments
    /// * `project_dir` - Path to the Rust project root
    pub fn for_main_rs(project_dir: &Path) -> Result<Self> {
        let file_path = project_dir.join("src/main.rs");
        Self::for_file(&file_path)
    }

    /// Create a test change for lib.rs in a project directory.
    ///
    /// # Arguments
    /// * `project_dir` - Path to the Rust project root
    pub fn for_lib_rs(project_dir: &Path) -> Result<Self> {
        let file_path = project_dir.join("src/lib.rs");
        Self::for_file(&file_path)
    }

    /// Apply the test change to the file.
    ///
    /// This writes the modified content to the file path.
    pub fn apply(&self) -> Result<()> {
        info!(
            "Applying test change {} to {:?}",
            self.change_id, self.file_path
        );
        fs::write(&self.file_path, &self.modified_content)
            .with_context(|| format!("Failed to write modified content to {:?}", self.file_path))?;
        Ok(())
    }

    /// Revert the test change, restoring original content.
    pub fn revert(&self) -> Result<()> {
        info!(
            "Reverting test change {} from {:?}",
            self.change_id, self.file_path
        );
        fs::write(&self.file_path, &self.original_content).with_context(|| {
            format!("Failed to restore original content to {:?}", self.file_path)
        })?;
        Ok(())
    }

    /// Check if the compiled binary contains the test marker.
    ///
    /// This verifies that the remote compilation actually processed our change.
    ///
    /// # Arguments
    /// * `binary_path` - Path to the compiled binary
    ///
    /// # Returns
    /// `true` if the marker is found in the binary
    pub fn verify_in_binary(&self, binary_path: &Path) -> Result<bool> {
        binary_contains_marker(binary_path, &self.change_id)
    }
}

/// RAII guard for test changes that auto-reverts on drop.
///
/// This ensures that test changes are always cleaned up, even if the test
/// panics or returns early.
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use rch_common::test_change::{TestCodeChange, TestChangeGuard};
///
/// fn run_test() -> anyhow::Result<()> {
///     let change = TestCodeChange::for_main_rs(Path::new("/my/project"))?;
///     let guard = TestChangeGuard::new(change)?;
///     
///     // Do compilation and testing here...
///     // File will be automatically reverted when guard goes out of scope
///     
///     Ok(())
/// }
/// ```
pub struct TestChangeGuard {
    change: TestCodeChange,
    applied: bool,
}

impl TestChangeGuard {
    /// Create a new guard and apply the test change.
    ///
    /// The change is applied immediately upon creation.
    pub fn new(change: TestCodeChange) -> Result<Self> {
        let mut guard = Self {
            change,
            applied: false,
        };
        guard.change.apply()?;
        guard.applied = true;
        Ok(guard)
    }

    /// Get the change ID for this test modification.
    pub fn change_id(&self) -> &str {
        &self.change.change_id
    }

    /// Get the path to the modified file.
    pub fn file_path(&self) -> &Path {
        &self.change.file_path
    }

    /// Check if the compiled binary contains the test marker.
    pub fn verify_in_binary(&self, binary_path: &Path) -> Result<bool> {
        self.change.verify_in_binary(binary_path)
    }

    /// Manually revert the change without dropping the guard.
    ///
    /// After calling this, the guard will not revert again on drop.
    pub fn revert(mut self) -> Result<()> {
        if self.applied {
            self.change.revert()?;
            self.applied = false;
        }
        Ok(())
    }
}

impl Drop for TestChangeGuard {
    fn drop(&mut self) {
        if self.applied {
            if let Err(e) = self.change.revert() {
                error!("Failed to revert test change: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::INFO)
            .try_init();
    }

    #[test]
    fn test_create_test_change() {
        init_test_logging();
        info!("TEST START: test_create_test_change");

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.rs");
        let original_content = "fn main() {\n    println!(\"Hello\");\n}\n";
        fs::write(&file_path, original_content).unwrap();

        info!("INPUT: TestCodeChange::for_file({:?})", file_path);

        let change = TestCodeChange::for_file(&file_path).unwrap();

        info!("RESULT: change_id={}", change.change_id);
        info!(
            "RESULT: modified_content_len={}",
            change.modified_content.len()
        );

        assert!(change.change_id.starts_with("RCH_TEST_"));
        assert!(change.modified_content.contains(&change.change_id));
        assert!(change.modified_content.contains("// RCH Self-Test Marker"));
        assert_eq!(change.original_content, original_content);

        info!("VERIFY: Test change created successfully");
        info!("TEST PASS: test_create_test_change");
    }

    #[test]
    fn test_apply_and_revert() {
        init_test_logging();
        info!("TEST START: test_apply_and_revert");

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.rs");
        let original_content = "fn main() {}\n";
        fs::write(&file_path, original_content).unwrap();

        let change = TestCodeChange::for_file(&file_path).unwrap();

        info!("INPUT: apply then revert test change");

        // Apply the change
        change.apply().unwrap();
        let after_apply = fs::read_to_string(&file_path).unwrap();
        info!(
            "AFTER APPLY: contains_marker={}",
            after_apply.contains(&change.change_id)
        );
        assert!(after_apply.contains(&change.change_id));

        // Revert the change
        change.revert().unwrap();
        let after_revert = fs::read_to_string(&file_path).unwrap();
        info!(
            "AFTER REVERT: equals_original={}",
            after_revert == original_content
        );
        assert_eq!(after_revert, original_content);

        info!("VERIFY: Apply and revert work correctly");
        info!("TEST PASS: test_apply_and_revert");
    }

    #[test]
    fn test_guard_auto_reverts() {
        init_test_logging();
        info!("TEST START: test_guard_auto_reverts");

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.rs");
        let original_content = "fn main() {}\n";
        fs::write(&file_path, original_content).unwrap();

        let change_id: String;
        {
            let change = TestCodeChange::for_file(&file_path).unwrap();
            change_id = change.change_id.clone();
            let _guard = TestChangeGuard::new(change).unwrap();

            // While guard is alive, file should be modified
            let during = fs::read_to_string(&file_path).unwrap();
            info!(
                "DURING GUARD: contains_marker={}",
                during.contains(&change_id)
            );
            assert!(during.contains(&change_id));

            // Guard will be dropped here
        }

        // After guard dropped, file should be reverted
        let after = fs::read_to_string(&file_path).unwrap();
        info!("AFTER DROP: equals_original={}", after == original_content);
        assert_eq!(after, original_content);
        assert!(!after.contains(&change_id));

        info!("VERIFY: Guard auto-reverts on drop");
        info!("TEST PASS: test_guard_auto_reverts");
    }

    #[test]
    fn test_change_id_unique() {
        init_test_logging();
        info!("TEST START: test_change_id_unique");

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.rs");
        fs::write(&file_path, "fn main() {}\n").unwrap();

        let change1 = TestCodeChange::for_file(&file_path).unwrap();
        // Small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(2));
        let change2 = TestCodeChange::for_file(&file_path).unwrap();

        info!(
            "RESULT: change1_id={}, change2_id={}",
            change1.change_id, change2.change_id
        );

        assert_ne!(change1.change_id, change2.change_id);

        info!("VERIFY: Each change has unique ID");
        info!("TEST PASS: test_change_id_unique");
    }

    #[test]
    fn test_for_main_rs() {
        init_test_logging();
        info!("TEST START: test_for_main_rs");

        let temp_dir = TempDir::new().unwrap();
        let src_dir = temp_dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        let main_rs = src_dir.join("main.rs");
        fs::write(&main_rs, "fn main() {}\n").unwrap();

        info!("INPUT: TestCodeChange::for_main_rs({:?})", temp_dir.path());

        let change = TestCodeChange::for_main_rs(temp_dir.path()).unwrap();

        info!("RESULT: file_path={:?}", change.file_path);

        assert_eq!(change.file_path, main_rs);

        info!("VERIFY: for_main_rs finds correct path");
        info!("TEST PASS: test_for_main_rs");
    }

    #[test]
    fn test_nonexistent_file_error() {
        init_test_logging();
        info!("TEST START: test_nonexistent_file_error");

        let result = TestCodeChange::for_file(Path::new("/nonexistent/file.rs"));

        info!("RESULT: is_err={}", result.is_err());

        assert!(result.is_err());

        info!("VERIFY: Nonexistent file returns error");
        info!("TEST PASS: test_nonexistent_file_error");
    }
}
