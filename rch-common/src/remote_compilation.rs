//! Remote Compilation Verification via SSH.
//!
//! This module provides infrastructure for verifying that remote compilation
//! actually works correctly by:
//! 1. Applying a test change to make the binary unique
//! 2. Building locally for a reference hash
//! 3. Syncing source to worker via rsync
//! 4. Building on the remote worker
//! 5. Syncing artifacts back
//! 6. Comparing binary hashes to verify correctness

use crate::binary_hash::{BinaryHashResult, binaries_equivalent, compute_binary_hash};
use crate::ssh::{SshClient, SshOptions};
use crate::test_change::{TestChangeGuard, TestCodeChange};
use crate::types::WorkerConfig;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use shell_escape::escape;
use std::borrow::Cow;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Result of a remote compilation verification test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the verification succeeded (hashes match).
    pub success: bool,
    /// Hash result from local build.
    pub local_hash: BinaryHashResult,
    /// Hash result from remote build.
    pub remote_hash: BinaryHashResult,
    /// Time spent on rsync upload in milliseconds.
    pub rsync_up_ms: u64,
    /// Time spent on remote compilation in milliseconds.
    pub compilation_ms: u64,
    /// Time spent on rsync download in milliseconds.
    pub rsync_down_ms: u64,
    /// Total time for the entire verification in milliseconds.
    pub total_ms: u64,
    /// Error message if verification failed.
    pub error: Option<String>,
    /// The test marker ID that was embedded in the binary.
    pub test_marker: String,
}

/// Configuration for a remote compilation test.
#[derive(Debug, Clone)]
pub struct RemoteCompilationTest {
    /// Worker to test compilation on.
    pub worker: WorkerConfig,
    /// Path to the test project (must be a Rust project with src/main.rs or src/lib.rs).
    pub test_project: PathBuf,
    /// Timeout for the entire test operation.
    pub timeout: Duration,
    /// SSH options for connections.
    pub ssh_options: SshOptions,
    /// Whether to use release mode for builds.
    pub release_mode: bool,
    /// Binary name to verify (defaults to project directory name).
    pub binary_name: Option<String>,
    /// Remote base directory for builds.
    pub remote_base: String,
}

impl Default for RemoteCompilationTest {
    fn default() -> Self {
        Self {
            worker: WorkerConfig::default(),
            test_project: PathBuf::new(),
            timeout: Duration::from_secs(300),
            ssh_options: SshOptions::default(),
            release_mode: true,
            binary_name: None,
            remote_base: "/tmp/rch_self_test".to_string(),
        }
    }
}

impl RemoteCompilationTest {
    /// Create a new remote compilation test.
    pub fn new(worker: WorkerConfig, test_project: PathBuf) -> Self {
        Self {
            worker,
            test_project,
            ..Default::default()
        }
    }

    /// Set the timeout for the test.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set SSH options.
    pub fn with_ssh_options(mut self, options: SshOptions) -> Self {
        self.ssh_options = options;
        self
    }

    /// Set release mode (default: true).
    pub fn with_release_mode(mut self, release: bool) -> Self {
        self.release_mode = release;
        self
    }

    /// Set the binary name to verify.
    pub fn with_binary_name(mut self, name: impl Into<String>) -> Self {
        self.binary_name = Some(name.into());
        self
    }

    /// Run the remote compilation verification test.
    ///
    /// This performs the full pipeline:
    /// 1. Apply test change to make binary unique
    /// 2. Build locally for reference hash
    /// 3. rsync source to worker
    /// 4. Build on worker
    /// 5. rsync artifacts back
    /// 6. Compare hashes
    pub async fn run(&self) -> Result<VerificationResult> {
        let start = Instant::now();

        info!(
            "Starting remote compilation verification for {:?} on worker {}",
            self.test_project,
            self.worker.id
        );

        // 1. Apply test change to make binary unique
        let change = TestCodeChange::for_main_rs(&self.test_project)
            .or_else(|_| TestCodeChange::for_lib_rs(&self.test_project))
            .context("Failed to create test change - no src/main.rs or src/lib.rs found")?;
        let _guard = TestChangeGuard::new(change.clone())?;
        let test_marker = change.change_id.clone();

        info!("Applied test marker: {}", test_marker);

        // 2. Build locally first
        info!("Building locally for reference hash");
        let local_build_start = Instant::now();
        self.build_local().await.context("Local build failed")?;
        let local_build_ms = local_build_start.elapsed().as_millis() as u64;
        info!("Local build complete in {}ms", local_build_ms);

        let local_binary_path = self.local_binary_path();
        let local_hash = compute_binary_hash(&local_binary_path)
            .with_context(|| format!("Failed to hash local binary: {:?}", local_binary_path))?;
        info!("Local hash: {}", &local_hash.code_hash[..16]);

        // 3. rsync up to worker
        info!("Syncing source to worker {}", self.worker.id);
        let rsync_up_start = Instant::now();
        self.rsync_to_worker().await.context("rsync to worker failed")?;
        let rsync_up_ms = rsync_up_start.elapsed().as_millis() as u64;
        info!("rsync upload complete in {}ms", rsync_up_ms);

        // 4. Build on worker
        info!("Building on remote worker");
        let compile_start = Instant::now();
        self.build_remote().await.context("Remote build failed")?;
        let compilation_ms = compile_start.elapsed().as_millis() as u64;
        info!("Remote build complete in {}ms", compilation_ms);

        // 5. rsync back
        info!("Syncing artifacts from worker");
        let rsync_down_start = Instant::now();
        self.rsync_from_worker().await.context("rsync from worker failed")?;
        let rsync_down_ms = rsync_down_start.elapsed().as_millis() as u64;
        info!("rsync download complete in {}ms", rsync_down_ms);

        // 6. Compute remote binary hash
        let remote_binary_path = self.remote_binary_path();
        let remote_hash = compute_binary_hash(&remote_binary_path)
            .with_context(|| format!("Failed to hash remote binary: {:?}", remote_binary_path))?;
        info!("Remote hash: {}", &remote_hash.code_hash[..16]);

        // 7. Compare
        let success = binaries_equivalent(&local_hash, &remote_hash);
        let total_ms = start.elapsed().as_millis() as u64;

        let error = if success {
            info!("Verification PASSED: Binary hashes match");
            None
        } else {
            let msg = format!(
                "Binary hash mismatch: local={} remote={}",
                &local_hash.code_hash[..16],
                &remote_hash.code_hash[..16]
            );
            warn!("Verification FAILED: {}", msg);
            Some(msg)
        };

        Ok(VerificationResult {
            success,
            local_hash,
            remote_hash,
            rsync_up_ms,
            compilation_ms,
            rsync_down_ms,
            total_ms,
            error,
            test_marker,
        })
    }

    /// Get the path to the local binary after build.
    fn local_binary_path(&self) -> PathBuf {
        let binary_name = self.get_binary_name();
        let profile = if self.release_mode { "release" } else { "debug" };
        self.test_project.join("target").join(profile).join(binary_name)
    }

    /// Get the path where remote binary will be stored locally after retrieval.
    fn remote_binary_path(&self) -> PathBuf {
        let binary_name = self.get_binary_name();
        let profile = if self.release_mode { "release" } else { "debug" };
        self.test_project
            .join("target")
            .join(format!("{}_remote", profile))
            .join(binary_name)
    }

    /// Get the binary name to verify.
    fn get_binary_name(&self) -> String {
        self.binary_name.clone().unwrap_or_else(|| {
            self.test_project
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .replace('-', "_")
        })
    }

    /// Get the remote project path on the worker.
    fn remote_project_path(&self) -> String {
        let project_name = self
            .test_project
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("self_test");
        format!("{}/{}", self.remote_base, project_name)
    }

    /// Build the project locally.
    async fn build_local(&self) -> Result<()> {
        let mut cmd = Command::new("cargo");
        cmd.arg("build");

        if self.release_mode {
            cmd.arg("--release");
        }

        cmd.current_dir(&self.test_project)
            .env("CARGO_INCREMENTAL", "0") // Disable incremental for reproducibility
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        debug!("Running local build: cargo build {}", if self.release_mode { "--release" } else { "" });

        let output = cmd.output().await.context("Failed to execute cargo build")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Local build failed: {}", stderr);
        }

        Ok(())
    }

    /// Sync source files to the worker via rsync.
    async fn rsync_to_worker(&self) -> Result<()> {
        let remote_path = self.remote_project_path();
        let escaped_remote_path = escape(Cow::from(&remote_path));

        // First ensure remote directory exists
        let mut client = SshClient::new(self.worker.clone(), self.ssh_options.clone());
        client.connect().await?;
        let mkdir_cmd = format!("mkdir -p {}", escaped_remote_path);
        let mkdir_result = client.execute(&mkdir_cmd).await?;
        client.disconnect().await?;

        if !mkdir_result.success() {
            bail!("Failed to create remote directory: {}", mkdir_result.stderr);
        }

        let destination = format!(
            "{}@{}:{}",
            self.worker.user, self.worker.host, escaped_remote_path
        );

        let identity_file = shellexpand::tilde(&self.worker.identity_file);
        let escaped_identity = escape(Cow::from(identity_file.as_ref()));

        let mut cmd = Command::new("rsync");
        cmd.arg("-az")
            .arg("--delete")
            .arg("--exclude")
            .arg("target/")
            .arg("--exclude")
            .arg(".git/")
            .arg("-e")
            .arg(format!(
                "ssh -i {} -o StrictHostKeyChecking=no -o BatchMode=yes",
                escaped_identity
            ))
            .arg(format!("{}/", self.test_project.display()))
            .arg(&destination)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        debug!("Running rsync to worker: {:?}", cmd.as_std().get_args().collect::<Vec<_>>());

        let output = cmd.output().await.context("Failed to execute rsync")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("rsync to worker failed: {}", stderr);
        }

        Ok(())
    }

    /// Build the project on the remote worker.
    async fn build_remote(&self) -> Result<()> {
        let remote_path = self.remote_project_path();
        let escaped_remote_path = escape(Cow::from(&remote_path));

        let build_cmd = if self.release_mode {
            format!(
                "cd {} && CARGO_INCREMENTAL=0 cargo build --release",
                escaped_remote_path
            )
        } else {
            format!(
                "cd {} && CARGO_INCREMENTAL=0 cargo build",
                escaped_remote_path
            )
        };

        debug!("Running remote build: {}", build_cmd);

        let mut client = SshClient::new(self.worker.clone(), self.ssh_options.clone());
        client.connect().await?;
        let result = client.execute(&build_cmd).await?;
        client.disconnect().await?;

        if !result.success() {
            bail!("Remote build failed (exit {}): {}", result.exit_code, result.stderr);
        }

        Ok(())
    }

    /// Sync build artifacts from the worker via rsync.
    async fn rsync_from_worker(&self) -> Result<()> {
        let remote_path = self.remote_project_path();
        let profile = if self.release_mode { "release" } else { "debug" };

        // Create local destination directory for remote artifacts
        let local_dest = self.test_project.join("target").join(format!("{}_remote", profile));
        std::fs::create_dir_all(&local_dest)
            .with_context(|| format!("Failed to create directory: {:?}", local_dest))?;

        let remote_target = format!(
            "{}@{}:{}/target/{}/",
            self.worker.user, self.worker.host, remote_path, profile
        );

        let identity_file = shellexpand::tilde(&self.worker.identity_file);
        let escaped_identity = escape(Cow::from(identity_file.as_ref()));

        let mut cmd = Command::new("rsync");
        cmd.arg("-az")
            .arg("-e")
            .arg(format!(
                "ssh -i {} -o StrictHostKeyChecking=no -o BatchMode=yes",
                escaped_identity
            ))
            .arg(&remote_target)
            .arg(format!("{}/", local_dest.display()))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        debug!("Running rsync from worker: {:?}", cmd.as_std().get_args().collect::<Vec<_>>());

        let output = cmd.output().await.context("Failed to retrieve artifacts")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("rsync from worker failed: {}", stderr);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WorkerId;

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }

    // ========================
    // VerificationResult tests
    // ========================

    #[test]
    fn verification_result_serializes_roundtrip() {
        init_test_logging();
        info!("TEST START: verification_result_serializes_roundtrip");

        let result = VerificationResult {
            success: true,
            local_hash: BinaryHashResult {
                full_hash: "abc123".to_string(),
                code_hash: "def456".to_string(),
                text_section_size: 12345,
                is_debug: false,
            },
            remote_hash: BinaryHashResult {
                full_hash: "abc123".to_string(),
                code_hash: "def456".to_string(),
                text_section_size: 12345,
                is_debug: false,
            },
            rsync_up_ms: 100,
            compilation_ms: 5000,
            rsync_down_ms: 200,
            total_ms: 5300,
            error: None,
            test_marker: "RCH_TEST_12345".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        info!("RESULT: serialized={}", &json[..json.len().min(100)]);

        let restored: VerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.success, true);
        assert_eq!(restored.rsync_up_ms, 100);
        assert_eq!(restored.compilation_ms, 5000);
        assert_eq!(restored.test_marker, "RCH_TEST_12345");

        info!("VERIFY: Serialization roundtrip successful");
        info!("TEST PASS: verification_result_serializes_roundtrip");
    }

    #[test]
    fn verification_result_with_error() {
        init_test_logging();
        info!("TEST START: verification_result_with_error");

        let result = VerificationResult {
            success: false,
            local_hash: BinaryHashResult {
                full_hash: "abc".to_string(),
                code_hash: "local_hash".to_string(),
                text_section_size: 1000,
                is_debug: false,
            },
            remote_hash: BinaryHashResult {
                full_hash: "xyz".to_string(),
                code_hash: "remote_hash".to_string(),
                text_section_size: 1000,
                is_debug: false,
            },
            rsync_up_ms: 50,
            compilation_ms: 3000,
            rsync_down_ms: 50,
            total_ms: 3100,
            error: Some("Binary hash mismatch".to_string()),
            test_marker: "RCH_TEST_99999".to_string(),
        };

        assert!(!result.success);
        assert!(result.error.is_some());
        assert_eq!(result.error.as_ref().unwrap(), "Binary hash mismatch");

        info!("VERIFY: Error result correctly captured");
        info!("TEST PASS: verification_result_with_error");
    }

    // ========================
    // RemoteCompilationTest tests
    // ========================

    #[test]
    fn remote_compilation_test_default_values() {
        init_test_logging();
        info!("TEST START: remote_compilation_test_default_values");

        let test = RemoteCompilationTest::default();

        assert_eq!(test.timeout, Duration::from_secs(300));
        assert!(test.release_mode);
        assert!(test.binary_name.is_none());
        assert_eq!(test.remote_base, "/tmp/rch_self_test");

        info!("VERIFY: Default values are correct");
        info!("TEST PASS: remote_compilation_test_default_values");
    }

    #[test]
    fn remote_compilation_test_builder_pattern() {
        init_test_logging();
        info!("TEST START: remote_compilation_test_builder_pattern");

        let worker = WorkerConfig {
            id: WorkerId::new("test-worker"),
            host: "worker.example.com".to_string(),
            user: "builder".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 4,
            ..Default::default()
        };

        let test = RemoteCompilationTest::new(worker.clone(), PathBuf::from("/tmp/project"))
            .with_timeout(Duration::from_secs(120))
            .with_release_mode(false)
            .with_binary_name("my_binary");

        assert_eq!(test.timeout, Duration::from_secs(120));
        assert!(!test.release_mode);
        assert_eq!(test.binary_name, Some("my_binary".to_string()));
        assert_eq!(test.worker.id.as_str(), "test-worker");

        info!("VERIFY: Builder pattern works correctly");
        info!("TEST PASS: remote_compilation_test_builder_pattern");
    }

    #[test]
    fn remote_compilation_test_binary_path_release() {
        init_test_logging();
        info!("TEST START: remote_compilation_test_binary_path_release");

        let worker = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "host".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 1,
            ..Default::default()
        };

        let test = RemoteCompilationTest::new(worker, PathBuf::from("/home/user/my-project"))
            .with_release_mode(true)
            .with_binary_name("my_binary");

        let local_path = test.local_binary_path();
        let remote_path = test.remote_binary_path();

        info!("RESULT: local_path={:?}", local_path);
        info!("RESULT: remote_path={:?}", remote_path);

        assert!(local_path.to_string_lossy().contains("target/release/my_binary"));
        assert!(remote_path.to_string_lossy().contains("target/release_remote/my_binary"));

        info!("VERIFY: Binary paths are correct for release mode");
        info!("TEST PASS: remote_compilation_test_binary_path_release");
    }

    #[test]
    fn remote_compilation_test_binary_path_debug() {
        init_test_logging();
        info!("TEST START: remote_compilation_test_binary_path_debug");

        let worker = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "host".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 1,
            ..Default::default()
        };

        let test = RemoteCompilationTest::new(worker, PathBuf::from("/home/user/my-project"))
            .with_release_mode(false)
            .with_binary_name("my_binary");

        let local_path = test.local_binary_path();
        let remote_path = test.remote_binary_path();

        info!("RESULT: local_path={:?}", local_path);
        info!("RESULT: remote_path={:?}", remote_path);

        assert!(local_path.to_string_lossy().contains("target/debug/my_binary"));
        assert!(remote_path.to_string_lossy().contains("target/debug_remote/my_binary"));

        info!("VERIFY: Binary paths are correct for debug mode");
        info!("TEST PASS: remote_compilation_test_binary_path_debug");
    }

    #[test]
    fn remote_compilation_test_infers_binary_name() {
        init_test_logging();
        info!("TEST START: remote_compilation_test_infers_binary_name");

        let worker = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "host".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 1,
            ..Default::default()
        };

        // Test with hyphenated project name (should convert to underscore)
        let test = RemoteCompilationTest::new(worker, PathBuf::from("/home/user/my-cool-project"));

        let binary_name = test.get_binary_name();
        info!("RESULT: binary_name={}", binary_name);

        assert_eq!(binary_name, "my_cool_project");

        info!("VERIFY: Binary name inferred and converted correctly");
        info!("TEST PASS: remote_compilation_test_infers_binary_name");
    }

    #[test]
    fn remote_compilation_test_remote_project_path() {
        init_test_logging();
        info!("TEST START: remote_compilation_test_remote_project_path");

        let worker = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "host".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 1,
            ..Default::default()
        };

        let test = RemoteCompilationTest::new(worker, PathBuf::from("/home/user/test-project"));

        let remote_path = test.remote_project_path();
        info!("RESULT: remote_path={}", remote_path);

        assert_eq!(remote_path, "/tmp/rch_self_test/test-project");

        info!("VERIFY: Remote project path is correct");
        info!("TEST PASS: remote_compilation_test_remote_project_path");
    }

    #[test]
    fn remote_compilation_test_with_custom_remote_base() {
        init_test_logging();
        info!("TEST START: remote_compilation_test_with_custom_remote_base");

        let worker = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "host".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 1,
            ..Default::default()
        };

        let mut test = RemoteCompilationTest::new(worker, PathBuf::from("/home/user/project"));
        test.remote_base = "/custom/build/dir".to_string();

        let remote_path = test.remote_project_path();
        info!("RESULT: remote_path={}", remote_path);

        assert_eq!(remote_path, "/custom/build/dir/project");

        info!("VERIFY: Custom remote base is used");
        info!("TEST PASS: remote_compilation_test_with_custom_remote_base");
    }

    #[test]
    fn verification_result_timing_fields() {
        init_test_logging();
        info!("TEST START: verification_result_timing_fields");

        let result = VerificationResult {
            success: true,
            local_hash: BinaryHashResult {
                full_hash: "a".to_string(),
                code_hash: "b".to_string(),
                text_section_size: 100,
                is_debug: false,
            },
            remote_hash: BinaryHashResult {
                full_hash: "a".to_string(),
                code_hash: "b".to_string(),
                text_section_size: 100,
                is_debug: false,
            },
            rsync_up_ms: 150,
            compilation_ms: 8000,
            rsync_down_ms: 200,
            total_ms: 8500,
            error: None,
            test_marker: "RCH_TEST_1".to_string(),
        };

        // Verify timing breakdown makes sense
        let sum = result.rsync_up_ms + result.compilation_ms + result.rsync_down_ms;
        info!("RESULT: sum={}, total={}", sum, result.total_ms);

        // Total should be >= sum (may include overhead)
        assert!(result.total_ms >= sum - 100); // Allow some timing variance

        info!("VERIFY: Timing fields are consistent");
        info!("TEST PASS: verification_result_timing_fields");
    }
}
