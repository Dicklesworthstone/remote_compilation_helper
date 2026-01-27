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
use crate::mock::{self, MockConfig, MockRsync, MockRsyncConfig, MockSshClient};
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
    /// Time spent on local compilation in milliseconds.
    pub local_build_ms: u64,
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

fn use_mock_transport(worker: &WorkerConfig) -> bool {
    mock::is_mock_enabled() || mock::is_mock_worker(worker)
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
            self.test_project, self.worker.id
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
        self.rsync_to_worker()
            .await
            .context("rsync to worker failed")?;
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
        self.rsync_from_worker()
            .await
            .context("rsync from worker failed")?;
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
            local_build_ms,
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
        let profile = if self.release_mode {
            "release"
        } else {
            "debug"
        };
        self.test_project
            .join("target")
            .join(profile)
            .join(binary_name)
    }

    /// Get the path where remote binary will be stored locally after retrieval.
    fn remote_binary_path(&self) -> PathBuf {
        let binary_name = self.get_binary_name();
        let profile = if self.release_mode {
            "release"
        } else {
            "debug"
        };
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

        debug!(
            "Running local build: cargo build {}",
            if self.release_mode { "--release" } else { "" }
        );

        let output = cmd
            .output()
            .await
            .context("Failed to execute cargo build")?;

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

        if use_mock_transport(&self.worker) {
            let mut client = MockSshClient::new(self.worker.clone(), MockConfig::from_env());
            client.connect().await?;
            let mkdir_cmd = format!("mkdir -p {}", escaped_remote_path);
            let mkdir_result = client.execute(&mkdir_cmd).await?;
            client.disconnect().await?;

            if !mkdir_result.success() {
                bail!("Failed to create remote directory: {}", mkdir_result.stderr);
            }

            let rsync = MockRsync::new(MockRsyncConfig::from_env());
            let destination = format!(
                "{}@{}:{}",
                self.worker.user, self.worker.host, escaped_remote_path
            );
            rsync
                .sync_to_remote(&self.test_project.display().to_string(), &destination, &[])
                .await?;
            return Ok(());
        }

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

        debug!(
            "Running rsync to worker: {:?}",
            cmd.as_std().get_args().collect::<Vec<_>>()
        );

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

        if use_mock_transport(&self.worker) {
            let mut client = MockSshClient::new(self.worker.clone(), MockConfig::from_env());
            client.connect().await?;
            let result = client.execute(&build_cmd).await?;
            client.disconnect().await?;

            if !result.success() {
                bail!(
                    "Remote build failed (exit {}): {}",
                    result.exit_code,
                    result.stderr
                );
            }

            return Ok(());
        }

        let mut client = SshClient::new(self.worker.clone(), self.ssh_options.clone());
        client.connect().await?;
        let result = client.execute(&build_cmd).await?;
        client.disconnect().await?;

        if !result.success() {
            bail!(
                "Remote build failed (exit {}): {}",
                result.exit_code,
                result.stderr
            );
        }

        Ok(())
    }

    /// Sync build artifacts from the worker via rsync.
    async fn rsync_from_worker(&self) -> Result<()> {
        let remote_path = self.remote_project_path();
        let profile = if self.release_mode {
            "release"
        } else {
            "debug"
        };

        // Create local destination directory for remote artifacts
        let local_dest = self
            .test_project
            .join("target")
            .join(format!("{}_remote", profile));
        std::fs::create_dir_all(&local_dest)
            .with_context(|| format!("Failed to create directory: {:?}", local_dest))?;

        if use_mock_transport(&self.worker) {
            let rsync = MockRsync::new(MockRsyncConfig::from_env());
            let remote_target = format!(
                "{}@{}:{}/target/{}/",
                self.worker.user, self.worker.host, remote_path, profile
            );
            rsync
                .retrieve_artifacts(&remote_target, &local_dest.display().to_string(), &[])
                .await?;
            return Ok(());
        }

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

        debug!(
            "Running rsync from worker: {:?}",
            cmd.as_std().get_args().collect::<Vec<_>>()
        );

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
    use crate::mock::{
        MockConfig, MockRsyncConfig, clear_global_invocations, clear_mock_overrides,
        global_rsync_invocations_snapshot, global_ssh_invocations_snapshot, is_mock_enabled,
        set_mock_enabled_override, set_mock_rsync_config_override, set_mock_ssh_config_override,
    };
    use crate::testing::{TestLogger, TestPhase};
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
        let logger = TestLogger::for_test("verification_result_serializes_roundtrip");

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
            local_build_ms: 1200,
            rsync_up_ms: 100,
            compilation_ms: 5000,
            rsync_down_ms: 200,
            total_ms: 5300,
            error: None,
            test_marker: "RCH_TEST_12345".to_string(),
        };

        logger.log(TestPhase::Execute, "Serializing VerificationResult to JSON");
        let json = serde_json::to_string(&result).unwrap();
        logger.log_with_data(
            TestPhase::Execute,
            "Serialized result",
            serde_json::json!({ "json_len": json.len() }),
        );

        let restored: VerificationResult = serde_json::from_str(&json).unwrap();

        logger.log(TestPhase::Verify, "Checking restored fields");
        assert!(restored.success);
        assert_eq!(restored.rsync_up_ms, 100);
        assert_eq!(restored.compilation_ms, 5000);
        assert_eq!(restored.test_marker, "RCH_TEST_12345");

        logger.pass();
    }

    #[test]
    fn verification_result_with_error() {
        let logger = TestLogger::for_test("verification_result_with_error");

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
            local_build_ms: 900,
            rsync_up_ms: 50,
            compilation_ms: 3000,
            rsync_down_ms: 50,
            total_ms: 3100,
            error: Some("Binary hash mismatch".to_string()),
            test_marker: "RCH_TEST_99999".to_string(),
        };

        logger.log(TestPhase::Verify, "Checking failed verification result");
        assert!(!result.success);
        assert!(result.error.is_some());
        assert_eq!(result.error.as_ref().unwrap(), "Binary hash mismatch");

        logger.log_with_data(
            TestPhase::Verify,
            "Error captured correctly",
            serde_json::json!({ "error": result.error }),
        );
        logger.pass();
    }

    #[test]
    fn verification_result_serializes_with_all_fields() {
        let logger = TestLogger::for_test("verification_result_serializes_with_all_fields");

        let result = VerificationResult {
            success: false,
            local_hash: BinaryHashResult {
                full_hash: "full_local".to_string(),
                code_hash: "code_local".to_string(),
                text_section_size: 5000,
                is_debug: true,
            },
            remote_hash: BinaryHashResult {
                full_hash: "full_remote".to_string(),
                code_hash: "code_remote".to_string(),
                text_section_size: 5001,
                is_debug: true,
            },
            local_build_ms: 2500,
            rsync_up_ms: 300,
            compilation_ms: 15000,
            rsync_down_ms: 400,
            total_ms: 18200,
            error: Some("Size mismatch: 5000 vs 5001".to_string()),
            test_marker: "RCH_FULL_TEST".to_string(),
        };

        logger.log(TestPhase::Execute, "Serializing result with all fields");
        let json = serde_json::to_string_pretty(&result).unwrap();

        // Verify all fields are present in serialization
        assert!(json.contains("\"success\": false"));
        assert!(json.contains("\"local_build_ms\": 2500"));
        assert!(json.contains("\"rsync_up_ms\": 300"));
        assert!(json.contains("\"compilation_ms\": 15000"));
        assert!(json.contains("\"rsync_down_ms\": 400"));
        assert!(json.contains("\"total_ms\": 18200"));
        assert!(json.contains("RCH_FULL_TEST"));
        assert!(json.contains("Size mismatch"));

        logger.log_with_data(
            TestPhase::Verify,
            "All fields serialized",
            serde_json::json!({ "fields_checked": 8 }),
        );
        logger.pass();
    }

    // ========================
    // RemoteCompilationTest tests
    // ========================

    #[test]
    fn remote_compilation_test_default_values() {
        let logger = TestLogger::for_test("remote_compilation_test_default_values");

        let test = RemoteCompilationTest::default();

        logger.log(TestPhase::Verify, "Checking default values");
        assert_eq!(test.timeout, Duration::from_secs(300));
        assert!(test.release_mode);
        assert!(test.binary_name.is_none());
        assert_eq!(test.remote_base, "/tmp/rch_self_test");

        logger.log_with_data(
            TestPhase::Verify,
            "Default values correct",
            serde_json::json!({
                "timeout_secs": 300,
                "release_mode": true,
                "remote_base": "/tmp/rch_self_test"
            }),
        );
        logger.pass();
    }

    #[test]
    fn remote_compilation_test_builder_pattern() {
        let logger = TestLogger::for_test("remote_compilation_test_builder_pattern");

        let worker = WorkerConfig {
            id: WorkerId::new("test-worker"),
            host: "worker.example.com".to_string(),
            user: "builder".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 4,
            ..Default::default()
        };

        logger.log(TestPhase::Execute, "Building test with custom options");
        let test = RemoteCompilationTest::new(worker.clone(), PathBuf::from("/tmp/project"))
            .with_timeout(Duration::from_secs(120))
            .with_release_mode(false)
            .with_binary_name("my_binary");

        logger.log(TestPhase::Verify, "Checking builder-set values");
        assert_eq!(test.timeout, Duration::from_secs(120));
        assert!(!test.release_mode);
        assert_eq!(test.binary_name, Some("my_binary".to_string()));
        assert_eq!(test.worker.id.as_str(), "test-worker");

        logger.pass();
    }

    #[test]
    fn remote_compilation_test_with_ssh_options() {
        let logger = TestLogger::for_test("remote_compilation_test_with_ssh_options");

        let worker = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "host".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 1,
            ..Default::default()
        };

        let ssh_opts = SshOptions {
            connect_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(600),
            ..Default::default()
        };

        logger.log(TestPhase::Execute, "Creating test with custom SSH options");
        let test = RemoteCompilationTest::new(worker, PathBuf::from("/tmp/project"))
            .with_ssh_options(ssh_opts);

        logger.log(TestPhase::Verify, "Checking SSH options");
        assert_eq!(test.ssh_options.connect_timeout, Duration::from_secs(30));
        assert_eq!(test.ssh_options.command_timeout, Duration::from_secs(600));

        logger.pass();
    }

    #[test]
    fn remote_compilation_test_binary_path_release() {
        let logger = TestLogger::for_test("remote_compilation_test_binary_path_release");

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

        logger.log_with_data(
            TestPhase::Execute,
            "Computed binary paths",
            serde_json::json!({
                "local": local_path.to_string_lossy(),
                "remote": remote_path.to_string_lossy()
            }),
        );

        assert!(
            local_path
                .to_string_lossy()
                .contains("target/release/my_binary")
        );
        assert!(
            remote_path
                .to_string_lossy()
                .contains("target/release_remote/my_binary")
        );

        logger.pass();
    }

    #[test]
    fn remote_compilation_test_binary_path_debug() {
        let logger = TestLogger::for_test("remote_compilation_test_binary_path_debug");

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

        logger.log_with_data(
            TestPhase::Execute,
            "Computed debug binary paths",
            serde_json::json!({
                "local": local_path.to_string_lossy(),
                "remote": remote_path.to_string_lossy()
            }),
        );

        assert!(
            local_path
                .to_string_lossy()
                .contains("target/debug/my_binary")
        );
        assert!(
            remote_path
                .to_string_lossy()
                .contains("target/debug_remote/my_binary")
        );

        logger.pass();
    }

    #[test]
    fn remote_compilation_test_infers_binary_name() {
        let logger = TestLogger::for_test("remote_compilation_test_infers_binary_name");

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
        logger.log_with_data(
            TestPhase::Execute,
            "Inferred binary name",
            serde_json::json!({ "binary_name": &binary_name }),
        );

        assert_eq!(binary_name, "my_cool_project");

        logger.pass();
    }

    #[test]
    fn remote_compilation_test_infers_binary_name_edge_cases() {
        let logger = TestLogger::for_test("remote_compilation_test_infers_binary_name_edge_cases");

        let worker = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "host".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 1,
            ..Default::default()
        };

        // Test with multiple hyphens
        let test1 =
            RemoteCompilationTest::new(worker.clone(), PathBuf::from("/a/b/my-very-cool-project"));
        assert_eq!(test1.get_binary_name(), "my_very_cool_project");

        // Test with underscores (should remain unchanged)
        let test2 =
            RemoteCompilationTest::new(worker.clone(), PathBuf::from("/a/b/my_project_name"));
        assert_eq!(test2.get_binary_name(), "my_project_name");

        // Test with mixed
        let test3 = RemoteCompilationTest::new(worker.clone(), PathBuf::from("/a/b/my-project_v2"));
        assert_eq!(test3.get_binary_name(), "my_project_v2");

        // Test with explicit binary name (should override)
        let test4 = RemoteCompilationTest::new(worker.clone(), PathBuf::from("/a/b/my-project"))
            .with_binary_name("custom");
        assert_eq!(test4.get_binary_name(), "custom");

        logger.log_with_data(
            TestPhase::Verify,
            "All edge cases handled",
            serde_json::json!({ "cases_tested": 4 }),
        );
        logger.pass();
    }

    #[test]
    fn remote_compilation_test_remote_project_path() {
        let logger = TestLogger::for_test("remote_compilation_test_remote_project_path");

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
        logger.log_with_data(
            TestPhase::Execute,
            "Computed remote path",
            serde_json::json!({ "remote_path": &remote_path }),
        );

        assert_eq!(remote_path, "/tmp/rch_self_test/test-project");

        logger.pass();
    }

    #[test]
    fn remote_compilation_test_with_custom_remote_base() {
        let logger = TestLogger::for_test("remote_compilation_test_with_custom_remote_base");

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
        logger.log_with_data(
            TestPhase::Execute,
            "Computed remote path with custom base",
            serde_json::json!({
                "remote_base": "/custom/build/dir",
                "remote_path": &remote_path
            }),
        );

        assert_eq!(remote_path, "/custom/build/dir/project");

        logger.pass();
    }

    #[test]
    fn verification_result_timing_fields() {
        let logger = TestLogger::for_test("verification_result_timing_fields");

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
            local_build_ms: 1200,
            rsync_up_ms: 150,
            compilation_ms: 8000,
            rsync_down_ms: 200,
            total_ms: 8500,
            error: None,
            test_marker: "RCH_TEST_1".to_string(),
        };

        // Verify timing breakdown makes sense
        let sum = result.rsync_up_ms + result.compilation_ms + result.rsync_down_ms;
        logger.log_with_data(
            TestPhase::Verify,
            "Checking timing consistency",
            serde_json::json!({
                "sum_of_phases": sum,
                "total_reported": result.total_ms
            }),
        );

        // Total should be >= sum (may include overhead)
        assert!(result.total_ms >= sum - 100); // Allow some timing variance

        logger.pass();
    }

    // ========================
    // use_mock_transport tests
    // ========================

    #[test]
    fn use_mock_transport_with_mock_host() {
        let logger = TestLogger::for_test("use_mock_transport_with_mock_host");

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://localhost".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id".to_string(),
            total_slots: 4,
            ..Default::default()
        };

        logger.log(TestPhase::Execute, "Testing mock:// host detection");
        assert!(use_mock_transport(&worker));

        logger.pass();
    }

    /// Test use_mock_transport with real host and mock disabled.
    /// Uses global mock state - run with `cargo test -- --test-threads=1`.
    #[test]
    #[ignore = "uses global mock state; run with --test-threads=1"]
    fn use_mock_transport_with_real_host() {
        let logger = TestLogger::for_test("use_mock_transport_with_real_host");

        // Ensure mock mode is disabled
        set_mock_enabled_override(Some(false));

        let worker = WorkerConfig {
            id: WorkerId::new("real-worker"),
            host: "192.168.1.100".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id".to_string(),
            total_slots: 4,
            ..Default::default()
        };

        logger.log(TestPhase::Execute, "Testing real host (mock disabled)");
        assert!(!use_mock_transport(&worker));

        clear_mock_overrides();
        logger.pass();
    }

    /// Test use_mock_transport with real host but global mock override.
    /// Uses global mock state - run with `cargo test -- --test-threads=1`.
    #[test]
    #[ignore = "uses global mock state; run with --test-threads=1"]
    fn use_mock_transport_with_global_override() {
        let logger = TestLogger::for_test("use_mock_transport_with_global_override");

        // Enable mock mode globally
        set_mock_enabled_override(Some(true));

        let worker = WorkerConfig {
            id: WorkerId::new("real-worker"),
            host: "192.168.1.100".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id".to_string(),
            total_slots: 4,
            ..Default::default()
        };

        logger.log(
            TestPhase::Execute,
            "Testing real host with global mock override",
        );
        assert!(use_mock_transport(&worker));

        clear_mock_overrides();
        logger.pass();
    }

    // ========================
    // Async transport tests (using mock)
    // These tests use global mock state and must be run with --test-threads=1
    // ========================

    /// Test rsync_to_worker with mock transport succeeds.
    #[tokio::test]
    #[ignore = "uses global mock state; run with --test-threads=1"]
    async fn rsync_to_worker_mock_success() {
        init_test_logging();
        let logger = TestLogger::for_test("rsync_to_worker_mock_success");

        // Enable mock mode
        set_mock_enabled_override(Some(true));
        set_mock_ssh_config_override(Some(MockConfig::success()));
        set_mock_rsync_config_override(Some(MockRsyncConfig::success()));
        clear_global_invocations();

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://localhost".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/mock_key".to_string(),
            total_slots: 4,
            ..Default::default()
        };

        // Create a temporary directory for testing
        let temp_dir = tempfile::tempdir().unwrap();
        let test_project = temp_dir.path().to_path_buf();

        let test = RemoteCompilationTest::new(worker, test_project);

        logger.log(
            TestPhase::Execute,
            "Calling rsync_to_worker with mock transport",
        );
        let result = test.rsync_to_worker().await;

        logger.log_with_data(
            TestPhase::Verify,
            "Checking rsync result",
            serde_json::json!({ "success": result.is_ok() }),
        );

        assert!(result.is_ok());

        // Verify invocations were recorded
        let ssh_invocations = global_ssh_invocations_snapshot();
        let rsync_invocations = global_rsync_invocations_snapshot();

        logger.log_with_data(
            TestPhase::Verify,
            "Mock invocations recorded",
            serde_json::json!({
                "ssh_calls": ssh_invocations.len(),
                "rsync_calls": rsync_invocations.len()
            }),
        );

        // Should have SSH calls (connect, mkdir, disconnect) and rsync call
        assert!(!ssh_invocations.is_empty());
        assert!(!rsync_invocations.is_empty());

        clear_mock_overrides();
        logger.pass();
    }

    /// Test rsync_to_worker fails when SSH connection fails.
    #[tokio::test]
    #[ignore = "uses global mock state; run with --test-threads=1"]
    async fn rsync_to_worker_mock_ssh_failure() {
        init_test_logging();
        let logger = TestLogger::for_test("rsync_to_worker_mock_ssh_failure");

        // Enable mock mode with SSH connection failure
        set_mock_enabled_override(Some(true));
        set_mock_ssh_config_override(Some(MockConfig::connection_failure()));
        clear_global_invocations();

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://localhost".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/mock_key".to_string(),
            total_slots: 4,
            ..Default::default()
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let test_project = temp_dir.path().to_path_buf();

        let test = RemoteCompilationTest::new(worker, test_project);

        logger.log(
            TestPhase::Execute,
            "Calling rsync_to_worker with failing SSH",
        );
        let result = test.rsync_to_worker().await;

        logger.log_with_data(
            TestPhase::Verify,
            "Checking failure result",
            serde_json::json!({
                "is_err": result.is_err(),
                "error": result.as_ref().err().map(|e| e.to_string())
            }),
        );

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Connection failed") || err_msg.contains("failed"));

        clear_mock_overrides();
        logger.pass();
    }

    /// Test build_remote with mock transport succeeds.
    #[tokio::test]
    #[ignore = "uses global mock state; run with --test-threads=1"]
    async fn build_remote_mock_success() {
        init_test_logging();
        let logger = TestLogger::for_test("build_remote_mock_success");

        set_mock_enabled_override(Some(true));
        set_mock_ssh_config_override(Some(MockConfig::success()));
        clear_global_invocations();

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://localhost".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/mock_key".to_string(),
            total_slots: 4,
            ..Default::default()
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let test_project = temp_dir.path().to_path_buf();

        let test = RemoteCompilationTest::new(worker, test_project);

        logger.log(
            TestPhase::Execute,
            "Calling build_remote with mock transport",
        );
        let result = test.build_remote().await;

        logger.log_with_data(
            TestPhase::Verify,
            "Checking build result",
            serde_json::json!({ "success": result.is_ok() }),
        );

        assert!(result.is_ok());

        // Verify SSH execution happened
        let ssh_invocations = global_ssh_invocations_snapshot();
        assert!(ssh_invocations.iter().any(|inv| {
            inv.command
                .as_ref()
                .is_some_and(|c| c.contains("cargo build"))
        }));

        clear_mock_overrides();
        logger.pass();
    }

    /// Test build_remote fails when remote command fails.
    #[tokio::test]
    #[ignore = "uses global mock state; run with --test-threads=1"]
    async fn build_remote_mock_command_failure() {
        init_test_logging();
        let logger = TestLogger::for_test("build_remote_mock_command_failure");

        // Configure mock to fail command execution
        set_mock_enabled_override(Some(true));
        set_mock_ssh_config_override(Some(MockConfig::command_failure(1, "compilation error")));
        clear_global_invocations();

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://localhost".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/mock_key".to_string(),
            total_slots: 4,
            ..Default::default()
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let test_project = temp_dir.path().to_path_buf();

        let test = RemoteCompilationTest::new(worker, test_project);

        logger.log(
            TestPhase::Execute,
            "Calling build_remote with failing command",
        );
        let result = test.build_remote().await;

        logger.log_with_data(
            TestPhase::Verify,
            "Checking failure",
            serde_json::json!({
                "is_err": result.is_err(),
                "error": result.as_ref().err().map(|e| e.to_string())
            }),
        );

        // Note: command_failure sets fail_execute=true, which returns Err
        assert!(result.is_err());

        clear_mock_overrides();
        logger.pass();
    }

    /// Test rsync_from_worker with mock transport succeeds.
    #[tokio::test]
    #[ignore = "uses global mock state; run with --test-threads=1"]
    async fn rsync_from_worker_mock_success() {
        init_test_logging();
        let logger = TestLogger::for_test("rsync_from_worker_mock_success");

        set_mock_enabled_override(Some(true));
        set_mock_rsync_config_override(Some(MockRsyncConfig::success()));
        clear_global_invocations();

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://localhost".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/mock_key".to_string(),
            total_slots: 4,
            ..Default::default()
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let test_project = temp_dir.path().to_path_buf();

        let test = RemoteCompilationTest::new(worker, test_project);

        logger.log(
            TestPhase::Execute,
            "Calling rsync_from_worker with mock transport",
        );
        let result = test.rsync_from_worker().await;

        logger.log_with_data(
            TestPhase::Verify,
            "Checking rsync result",
            serde_json::json!({ "success": result.is_ok() }),
        );

        assert!(result.is_ok());

        // Verify artifact retrieval was called
        let rsync_invocations = global_rsync_invocations_snapshot();
        assert!(!rsync_invocations.is_empty());

        clear_mock_overrides();
        logger.pass();
    }

    /// Test rsync_from_worker fails when artifact retrieval fails.
    #[tokio::test]
    #[ignore = "uses global mock state; run with --test-threads=1"]
    async fn rsync_from_worker_mock_artifact_failure() {
        init_test_logging();
        let logger = TestLogger::for_test("rsync_from_worker_mock_artifact_failure");

        set_mock_enabled_override(Some(true));
        set_mock_rsync_config_override(Some(MockRsyncConfig::artifact_failure()));
        clear_global_invocations();

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://localhost".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/mock_key".to_string(),
            total_slots: 4,
            ..Default::default()
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let test_project = temp_dir.path().to_path_buf();

        let test = RemoteCompilationTest::new(worker, test_project);

        logger.log(
            TestPhase::Execute,
            "Calling rsync_from_worker with failing artifacts",
        );
        let result = test.rsync_from_worker().await;

        logger.log_with_data(
            TestPhase::Verify,
            "Checking failure",
            serde_json::json!({
                "is_err": result.is_err(),
                "error": result.as_ref().err().map(|e| e.to_string())
            }),
        );

        assert!(result.is_err());

        clear_mock_overrides();
        logger.pass();
    }

    // ========================
    // Edge case tests
    // ========================

    #[test]
    fn remote_compilation_test_empty_project_path() {
        let logger = TestLogger::for_test("remote_compilation_test_empty_project_path");

        let worker = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "host".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 1,
            ..Default::default()
        };

        // Empty path should still work (uses "unknown" as fallback)
        let test = RemoteCompilationTest::new(worker, PathBuf::new());

        let binary_name = test.get_binary_name();
        logger.log_with_data(
            TestPhase::Execute,
            "Binary name for empty path",
            serde_json::json!({ "binary_name": &binary_name }),
        );

        // Should fall back to "unknown"
        assert_eq!(binary_name, "unknown");

        logger.pass();
    }

    #[test]
    fn verification_result_zero_timings() {
        let logger = TestLogger::for_test("verification_result_zero_timings");

        let result = VerificationResult {
            success: true,
            local_hash: BinaryHashResult {
                full_hash: "h".to_string(),
                code_hash: "c".to_string(),
                text_section_size: 0,
                is_debug: false,
            },
            remote_hash: BinaryHashResult {
                full_hash: "h".to_string(),
                code_hash: "c".to_string(),
                text_section_size: 0,
                is_debug: false,
            },
            local_build_ms: 0,
            rsync_up_ms: 0,
            compilation_ms: 0,
            rsync_down_ms: 0,
            total_ms: 0,
            error: None,
            test_marker: "ZERO".to_string(),
        };

        logger.log(TestPhase::Execute, "Serializing zero-timing result");
        let json = serde_json::to_string(&result).unwrap();
        let restored: VerificationResult = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.local_build_ms, 0);
        assert_eq!(restored.total_ms, 0);
        assert!(restored.success);

        logger.pass();
    }

    #[test]
    fn verification_result_max_timings() {
        let logger = TestLogger::for_test("verification_result_max_timings");

        let result = VerificationResult {
            success: true,
            local_hash: BinaryHashResult {
                full_hash: "h".to_string(),
                code_hash: "c".to_string(),
                text_section_size: u64::MAX,
                is_debug: false,
            },
            remote_hash: BinaryHashResult {
                full_hash: "h".to_string(),
                code_hash: "c".to_string(),
                text_section_size: u64::MAX,
                is_debug: false,
            },
            local_build_ms: u64::MAX,
            rsync_up_ms: u64::MAX,
            compilation_ms: u64::MAX,
            rsync_down_ms: u64::MAX,
            total_ms: u64::MAX,
            error: None,
            test_marker: "MAX".to_string(),
        };

        logger.log(TestPhase::Execute, "Serializing max-timing result");
        let json = serde_json::to_string(&result).unwrap();
        let restored: VerificationResult = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.total_ms, u64::MAX);
        assert!(restored.success);

        logger.pass();
    }

    #[test]
    fn is_mock_enabled_respects_overrides() {
        let logger = TestLogger::for_test("is_mock_enabled_respects_overrides");

        // Start with clean state
        clear_mock_overrides();

        // Without override, depends on env (we'll set it false)
        set_mock_enabled_override(Some(false));
        assert!(!is_mock_enabled());

        // With override true
        set_mock_enabled_override(Some(true));
        assert!(is_mock_enabled());

        // Clear and test again
        clear_mock_overrides();
        set_mock_enabled_override(Some(false));
        assert!(!is_mock_enabled());

        clear_mock_overrides();
        logger.pass();
    }
}
