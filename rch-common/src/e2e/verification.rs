//! Remote Compilation Verification
//!
//! Provides infrastructure for verifying that remote compilation works correctly
//! by building code on a remote worker and comparing the result with a local build.
//!
//! # Verification Flow
//!
//! 1. Apply a unique test change to the source code
//! 2. Build locally to get a reference binary hash
//! 3. rsync source files to the remote worker
//! 4. Execute the build on the remote worker
//! 5. rsync the artifacts back
//! 6. Compare the binary hashes to verify correctness
//!
//! # Example
//!
//! ```rust,ignore
//! use rch_common::e2e::verification::{RemoteCompilationTest, VerificationConfig};
//! use rch_common::types::WorkerConfig;
//!
//! let config = VerificationConfig::default();
//! let test = RemoteCompilationTest::new(worker_config, project_path, config);
//! let result = test.run().await?;
//!
//! if result.success {
//!     println!("Remote compilation verified!");
//! }
//! ```

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use tracing::{debug, error, info, warn};

use crate::binary_hash::{BinaryHashResult, binaries_equivalent, compute_binary_hash};
use crate::test_change::{TestChangeGuard, TestCodeChange};
use crate::types::WorkerConfig;

/// Configuration for remote compilation verification.
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Timeout for the entire verification process.
    pub timeout: Duration,
    /// Timeout for individual build operations.
    pub build_timeout: Duration,
    /// Whether to use release mode for builds.
    pub release_mode: bool,
    /// Additional cargo flags to pass to builds.
    pub cargo_flags: Vec<String>,
    /// rsync compression level (0-9).
    pub rsync_compression: u32,
    /// Patterns to exclude from rsync transfer.
    pub exclude_patterns: Vec<String>,
    /// Whether to clean target directory before remote build.
    pub clean_before_build: bool,
    /// Remote base path for project caching.
    pub remote_base_path: PathBuf,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300),
            build_timeout: Duration::from_secs(180),
            release_mode: false,
            cargo_flags: vec![],
            rsync_compression: 3,
            exclude_patterns: vec![
                "target/".to_string(),
                ".git/objects/".to_string(),
                "node_modules/".to_string(),
            ],
            clean_before_build: false,
            remote_base_path: PathBuf::from("/tmp/rch_verify"),
        }
    }
}

/// Result of a remote compilation verification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the verification succeeded (binaries match).
    pub success: bool,
    /// Hash result from the local build.
    pub local_hash: Option<BinaryHashResult>,
    /// Hash result from the remote build.
    pub remote_hash: Option<BinaryHashResult>,
    /// Time spent syncing files to the worker (ms).
    pub rsync_up_ms: u64,
    /// Time spent on remote compilation (ms).
    pub compilation_ms: u64,
    /// Time spent syncing artifacts back (ms).
    pub rsync_down_ms: u64,
    /// Total time for the entire verification (ms).
    pub total_ms: u64,
    /// Bytes transferred to the worker.
    pub bytes_up: u64,
    /// Bytes transferred from the worker.
    pub bytes_down: u64,
    /// Error message if verification failed.
    pub error: Option<String>,
    /// The test change ID used for verification.
    pub change_id: String,
    /// Whether the test marker was found in the binary.
    pub marker_verified: bool,
}

impl VerificationResult {
    /// Create a failed result with an error message.
    pub fn failed(error: impl Into<String>, elapsed_ms: u64, change_id: String) -> Self {
        Self {
            success: false,
            local_hash: None,
            remote_hash: None,
            rsync_up_ms: 0,
            compilation_ms: 0,
            rsync_down_ms: 0,
            total_ms: elapsed_ms,
            bytes_up: 0,
            bytes_down: 0,
            error: Some(error.into()),
            change_id,
            marker_verified: false,
        }
    }
}

/// Remote compilation test runner.
///
/// Verifies that the RCH pipeline works correctly by:
/// 1. Making a detectable change to the source
/// 2. Building locally for a reference
/// 3. Building remotely
/// 4. Comparing the results
pub struct RemoteCompilationTest {
    /// Worker to use for remote compilation.
    worker: WorkerConfig,
    /// Path to the test project.
    project_path: PathBuf,
    /// Verification configuration.
    config: VerificationConfig,
}

impl RemoteCompilationTest {
    /// Create a new remote compilation test.
    ///
    /// # Arguments
    /// * `worker` - Worker configuration for remote execution
    /// * `project_path` - Path to the Rust project to test
    /// * `config` - Verification configuration
    pub fn new(
        worker: WorkerConfig,
        project_path: impl Into<PathBuf>,
        config: VerificationConfig,
    ) -> Self {
        Self {
            worker,
            project_path: project_path.into(),
            config,
        }
    }

    /// Run the verification test.
    ///
    /// This performs the full verification flow:
    /// 1. Apply test change to make binary unique
    /// 2. Build locally for reference hash
    /// 3. rsync source to worker
    /// 4. Build on worker
    /// 5. rsync artifacts back
    /// 6. Compare hashes
    pub fn run(&self) -> Result<VerificationResult> {
        let start = Instant::now();
        info!(
            "Starting remote compilation verification for {:?} on {}",
            self.project_path, self.worker.id
        );

        // 1. Apply test change to make binary unique
        let change = TestCodeChange::for_main_rs(&self.project_path)
            .with_context(|| "Failed to create test change")?;
        let change_id = change.change_id.clone();
        let guard = TestChangeGuard::new(change).with_context(|| "Failed to apply test change")?;

        info!("Applied test change: {}", guard.change_id());

        // 2. Build locally first
        info!("Building locally for reference hash");
        let local_build_start = Instant::now();
        if let Err(e) = self.build_local() {
            return Ok(VerificationResult::failed(
                format!("Local build failed: {}", e),
                start.elapsed().as_millis() as u64,
                change_id,
            ));
        }
        let local_build_ms = local_build_start.elapsed().as_millis() as u64;
        debug!("Local build completed in {}ms", local_build_ms);

        // Get local binary hash
        let local_binary = self.binary_path();
        let local_hash = compute_binary_hash(&local_binary)
            .with_context(|| format!("Failed to hash local binary: {:?}", local_binary))?;
        info!(
            "Local build hash: {} (code_hash: {})",
            &local_hash.full_hash[..16],
            &local_hash.code_hash[..16]
        );

        // Verify marker is in local binary
        let local_marker_ok = guard.verify_in_binary(&local_binary)?;
        if !local_marker_ok {
            return Ok(VerificationResult::failed(
                "Test marker not found in local binary",
                start.elapsed().as_millis() as u64,
                change_id,
            ));
        }
        info!("Test marker verified in local binary");

        // 3. rsync up to worker
        info!("Syncing source to worker {}", self.worker.id);
        let rsync_up_start = Instant::now();
        let bytes_up = match self.rsync_to_worker() {
            Ok(bytes) => bytes,
            Err(e) => {
                return Ok(VerificationResult::failed(
                    format!("rsync to worker failed: {}", e),
                    start.elapsed().as_millis() as u64,
                    change_id,
                ));
            }
        };
        let rsync_up_ms = rsync_up_start.elapsed().as_millis() as u64;
        info!("Synced {} bytes in {}ms", bytes_up, rsync_up_ms);

        // 4. Build on worker
        info!("Building on worker {}", self.worker.id);
        let compilation_start = Instant::now();
        if let Err(e) = self.build_remote() {
            return Ok(VerificationResult::failed(
                format!("Remote build failed: {}", e),
                start.elapsed().as_millis() as u64,
                change_id,
            ));
        }
        let compilation_ms = compilation_start.elapsed().as_millis() as u64;
        info!("Remote build completed in {}ms", compilation_ms);

        // 5. rsync artifacts back
        info!("Syncing artifacts from worker");
        let rsync_down_start = Instant::now();
        let bytes_down = match self.rsync_from_worker() {
            Ok(bytes) => bytes,
            Err(e) => {
                return Ok(VerificationResult::failed(
                    format!("rsync from worker failed: {}", e),
                    start.elapsed().as_millis() as u64,
                    change_id,
                ));
            }
        };
        let rsync_down_ms = rsync_down_start.elapsed().as_millis() as u64;
        info!("Retrieved {} bytes in {}ms", bytes_down, rsync_down_ms);

        // 6. Compare hashes
        let remote_binary = self.remote_binary_path_local();
        let remote_hash = match compute_binary_hash(&remote_binary) {
            Ok(h) => h,
            Err(e) => {
                return Ok(VerificationResult::failed(
                    format!("Failed to hash remote binary: {}", e),
                    start.elapsed().as_millis() as u64,
                    change_id,
                ));
            }
        };
        info!(
            "Remote build hash: {} (code_hash: {})",
            &remote_hash.full_hash[..16],
            &remote_hash.code_hash[..16]
        );

        // Verify marker is in remote binary
        let marker_verified = guard.verify_in_binary(&remote_binary)?;
        if !marker_verified {
            warn!("Test marker not found in remote binary");
        }

        // Check if binaries are equivalent
        let success = binaries_equivalent(&local_hash, &remote_hash);
        let total_ms = start.elapsed().as_millis() as u64;

        if success {
            info!(
                "Verification PASSED: code hashes match (total: {}ms)",
                total_ms
            );
        } else {
            error!(
                "Verification FAILED: code hashes differ (local={}, remote={})",
                &local_hash.code_hash[..16],
                &remote_hash.code_hash[..16]
            );
        }

        // Guard will auto-revert the test change on drop
        Ok(VerificationResult {
            success,
            local_hash: Some(local_hash),
            remote_hash: Some(remote_hash),
            rsync_up_ms,
            compilation_ms,
            rsync_down_ms,
            total_ms,
            bytes_up,
            bytes_down,
            error: if success {
                None
            } else {
                Some("Code hashes do not match".to_string())
            },
            change_id,
            marker_verified,
        })
    }

    /// Build the project locally.
    fn build_local(&self) -> Result<()> {
        let mut cmd = Command::new("cargo");
        cmd.arg("build");
        if self.config.release_mode {
            cmd.arg("--release");
        }
        for flag in &self.config.cargo_flags {
            cmd.arg(flag);
        }
        cmd.current_dir(&self.project_path);

        debug!("Running local build: {:?}", cmd);
        let output = cmd.output().context("Failed to execute cargo build")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("cargo build failed: {}", stderr));
        }

        Ok(())
    }

    /// Build the project on the remote worker.
    fn build_remote(&self) -> Result<()> {
        let remote_path = self.remote_project_path();
        let build_cmd = if self.config.release_mode {
            "cargo build --release"
        } else {
            "cargo build"
        };

        let ssh_cmd = format!("cd {} && {}", remote_path.display(), build_cmd);

        let identity_file = shellexpand::tilde(&self.worker.identity_file).to_string();
        let mut cmd = Command::new("ssh");
        cmd.args([
            "-i",
            &identity_file,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "BatchMode=yes",
            &format!("{}@{}", self.worker.user, self.worker.host),
            &ssh_cmd,
        ]);

        debug!("Running remote build via SSH: {:?}", cmd);
        let output = cmd.output().context("Failed to execute SSH command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Remote build failed: {}", stderr));
        }

        Ok(())
    }

    /// rsync source files to the worker.
    fn rsync_to_worker(&self) -> Result<u64> {
        let remote_path = self.remote_project_path();
        let identity_file = shellexpand::tilde(&self.worker.identity_file).to_string();

        // Ensure remote directory exists
        let mkdir_cmd = format!("mkdir -p {}", remote_path.display());
        let mut mkdir = Command::new("ssh");
        mkdir.args([
            "-i",
            &identity_file,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "BatchMode=yes",
            &format!("{}@{}", self.worker.user, self.worker.host),
            &mkdir_cmd,
        ]);
        mkdir
            .output()
            .context("Failed to create remote directory")?;

        // Build rsync command
        let mut cmd = Command::new("rsync");
        cmd.args([
            "-az",
            "--compress-level",
            &self.config.rsync_compression.to_string(),
            "--delete",
            "-e",
            &format!(
                "ssh -i {} -o StrictHostKeyChecking=no -o BatchMode=yes",
                identity_file
            ),
        ]);

        // Add exclude patterns
        for pattern in &self.config.exclude_patterns {
            cmd.args(["--exclude", pattern]);
        }

        // Source and destination
        let src = format!("{}/", self.project_path.display());
        let dest = format!(
            "{}@{}:{}",
            self.worker.user,
            self.worker.host,
            remote_path.display()
        );
        cmd.args([&src, &dest]);

        debug!("Running rsync to worker: {:?}", cmd);
        let output = cmd.output().context("Failed to execute rsync")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("rsync to worker failed: {}", stderr));
        }

        // Estimate bytes transferred from rsync output
        let stdout = String::from_utf8_lossy(&output.stdout);
        let bytes = parse_rsync_bytes_transferred(&stdout);
        Ok(bytes)
    }

    /// rsync artifacts back from the worker.
    fn rsync_from_worker(&self) -> Result<u64> {
        let remote_path = self.remote_project_path();
        let identity_file = shellexpand::tilde(&self.worker.identity_file).to_string();

        // Local path for remote artifacts
        let local_artifact_dir = self.project_path.join("target_remote");
        std::fs::create_dir_all(&local_artifact_dir)?;

        // Build rsync command - only sync the target directory
        let profile = if self.config.release_mode {
            "release"
        } else {
            "debug"
        };

        let mut cmd = Command::new("rsync");
        cmd.args([
            "-az",
            "--compress-level",
            &self.config.rsync_compression.to_string(),
            "-e",
            &format!(
                "ssh -i {} -o StrictHostKeyChecking=no -o BatchMode=yes",
                identity_file
            ),
        ]);

        // Source (remote target/debug or target/release) and destination
        let remote_target = format!(
            "{}@{}:{}/target/{}/",
            self.worker.user,
            self.worker.host,
            remote_path.display(),
            profile
        );
        let local_target = format!("{}/", local_artifact_dir.display());
        cmd.args([&remote_target, &local_target]);

        debug!("Running rsync from worker: {:?}", cmd);
        let output = cmd.output().context("Failed to execute rsync")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("rsync from worker failed: {}", stderr));
        }

        // Estimate bytes transferred
        let stdout = String::from_utf8_lossy(&output.stdout);
        let bytes = parse_rsync_bytes_transferred(&stdout);
        Ok(bytes)
    }

    /// Get the path to the local binary.
    fn binary_path(&self) -> PathBuf {
        let profile = if self.config.release_mode {
            "release"
        } else {
            "debug"
        };

        // Get project name from Cargo.toml
        let binary_name = self.get_binary_name().unwrap_or_else(|| "main".to_string());
        self.project_path
            .join("target")
            .join(profile)
            .join(&binary_name)
    }

    /// Get the path to the remote binary (stored locally after rsync).
    fn remote_binary_path_local(&self) -> PathBuf {
        let binary_name = self.get_binary_name().unwrap_or_else(|| "main".to_string());
        self.project_path.join("target_remote").join(&binary_name)
    }

    /// Get the remote project path on the worker.
    fn remote_project_path(&self) -> PathBuf {
        // Create a unique path based on project name
        let project_name = self
            .project_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("project");

        self.config.remote_base_path.join(project_name)
    }

    /// Get the binary name from Cargo.toml.
    fn get_binary_name(&self) -> Option<String> {
        let cargo_toml = self.project_path.join("Cargo.toml");
        let content = std::fs::read_to_string(&cargo_toml).ok()?;

        // Simple parser - look for name = "..."
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("name") && line.contains('=') {
                if let Some(name) = line.split('=').nth(1) {
                    let name = name.trim().trim_matches('"');
                    return Some(name.to_string());
                }
            }
        }
        None
    }
}

/// Parse bytes transferred from rsync output.
fn parse_rsync_bytes_transferred(output: &str) -> u64 {
    // rsync output contains lines like "sent 12,345 bytes  received 678 bytes"
    // We'll look for any numeric value in the output
    for line in output.lines() {
        if line.contains("bytes") {
            // Extract numbers from the line
            let nums: Vec<u64> = line
                .split_whitespace()
                .filter_map(|w| w.replace(',', "").parse().ok())
                .collect();
            if !nums.is_empty() {
                return nums.iter().sum();
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }

    #[test]
    fn test_verification_config_default() {
        init_test_logging();
        info!("TEST START: test_verification_config_default");

        let config = VerificationConfig::default();

        info!("RESULT: timeout={:?}", config.timeout);
        info!("RESULT: release_mode={}", config.release_mode);
        info!("RESULT: rsync_compression={}", config.rsync_compression);

        assert_eq!(config.timeout, Duration::from_secs(300));
        assert!(!config.release_mode);
        assert_eq!(config.rsync_compression, 3);
        assert!(config.exclude_patterns.contains(&"target/".to_string()));

        info!("TEST PASS: test_verification_config_default");
    }

    #[test]
    fn test_verification_result_failed() {
        init_test_logging();
        info!("TEST START: test_verification_result_failed");

        let result = VerificationResult::failed("Test error", 1000, "RCH_TEST_123".to_string());

        info!("RESULT: success={}", result.success);
        info!("RESULT: error={:?}", result.error);

        assert!(!result.success);
        assert_eq!(result.error, Some("Test error".to_string()));
        assert_eq!(result.total_ms, 1000);
        assert_eq!(result.change_id, "RCH_TEST_123");

        info!("TEST PASS: test_verification_result_failed");
    }

    #[test]
    fn test_parse_rsync_bytes() {
        init_test_logging();
        info!("TEST START: test_parse_rsync_bytes");

        let output = "sent 12,345 bytes  received 678 bytes  8,682.00 bytes/sec";
        let bytes = parse_rsync_bytes_transferred(output);

        info!("INPUT: {:?}", output);
        info!("RESULT: bytes={}", bytes);

        assert!(bytes > 0);

        info!("TEST PASS: test_parse_rsync_bytes");
    }

    #[test]
    fn test_parse_rsync_bytes_empty() {
        init_test_logging();
        info!("TEST START: test_parse_rsync_bytes_empty");

        let output = "";
        let bytes = parse_rsync_bytes_transferred(output);

        info!("INPUT: empty string");
        info!("RESULT: bytes={}", bytes);

        assert_eq!(bytes, 0);

        info!("TEST PASS: test_parse_rsync_bytes_empty");
    }

    #[test]
    fn test_remote_compilation_test_paths() {
        init_test_logging();
        info!("TEST START: test_remote_compilation_test_paths");

        let worker = WorkerConfig {
            id: crate::types::WorkerId::new("test-worker"),
            host: "localhost".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        };

        let config = VerificationConfig::default();
        let test = RemoteCompilationTest::new(worker, "/tmp/test-project", config);

        let remote_path = test.remote_project_path();
        info!("RESULT: remote_path={:?}", remote_path);
        assert!(remote_path.to_string_lossy().contains("test-project"));

        info!("TEST PASS: test_remote_compilation_test_paths");
    }
}
