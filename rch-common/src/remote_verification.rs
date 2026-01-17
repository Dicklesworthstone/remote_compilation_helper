//! Remote compilation verification via SSH.
//!
//! This module implements SSH-based remote compilation verification that tests
//! the full RCH pipeline by building code on a remote worker and verifying
//! the output through binary hash comparison.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{error, info, warn};

use crate::binary_hash::{BinaryHashResult, binaries_equivalent, compute_binary_hash};
use crate::test_change::{TestChangeGuard, TestCodeChange};
use crate::types::WorkerConfig;

/// Configuration for remote verification testing.
/// Extends WorkerConfig with verification-specific settings.
#[derive(Debug, Clone)]
pub struct VerificationWorkerConfig {
    /// Unique identifier for the worker.
    pub id: String,
    /// SSH host string (e.g., "user@host" or just "host").
    pub ssh_host: String,
    /// SSH identity file path (optional).
    pub identity_file: Option<PathBuf>,
    /// Remote directory for builds.
    pub build_dir: PathBuf,
}

impl VerificationWorkerConfig {
    /// Create a verification config from an existing WorkerConfig.
    pub fn from_worker_config(config: &WorkerConfig, build_dir: PathBuf) -> Self {
        Self {
            id: config.id.to_string(),
            ssh_host: format!("{}@{}", config.user, config.host),
            identity_file: Some(PathBuf::from(&config.identity_file)),
            build_dir,
        }
    }
}

/// Result of a remote compilation verification test.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the verification succeeded (hashes match).
    pub success: bool,
    /// Hash result from the local build.
    pub local_hash: BinaryHashResult,
    /// Hash result from the remote build.
    pub remote_hash: BinaryHashResult,
    /// Time spent syncing files to the worker (ms).
    pub rsync_up_ms: u64,
    /// Time spent compiling on the worker (ms).
    pub compilation_ms: u64,
    /// Time spent syncing artifacts back (ms).
    pub rsync_down_ms: u64,
    /// Total test duration (ms).
    pub total_ms: u64,
    /// Error message if verification failed.
    pub error: Option<String>,
}

impl VerificationResult {
    /// Get the speedup factor (local time / remote time).
    /// Returns None if either time is zero.
    pub fn speedup_factor(&self, local_compilation_ms: u64) -> Option<f64> {
        if self.compilation_ms == 0 || local_compilation_ms == 0 {
            return None;
        }
        Some(local_compilation_ms as f64 / self.compilation_ms as f64)
    }
}

/// Remote compilation test configuration and executor.
pub struct RemoteCompilationTest {
    /// Worker configuration.
    pub worker: VerificationWorkerConfig,
    /// Path to the test project.
    pub test_project: PathBuf,
    /// Timeout for the entire test.
    pub timeout: Duration,
    /// Local compilation time for comparison (ms).
    local_compilation_ms: Option<u64>,
}

impl RemoteCompilationTest {
    /// Create a new remote compilation test.
    pub fn new(worker: VerificationWorkerConfig, test_project: PathBuf) -> Self {
        Self {
            worker,
            test_project,
            timeout: Duration::from_secs(120),
            local_compilation_ms: None,
        }
    }

    /// Set the timeout for the test.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get the path to the local binary after building.
    fn local_binary_path(&self) -> PathBuf {
        // Assuming this is a Rust project with a binary of the same name as the directory
        let project_name = self
            .test_project
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("test_project");
        self.test_project.join("target/release").join(project_name)
    }

    /// Get the path to the remote binary after syncing back.
    fn remote_binary_path(&self) -> PathBuf {
        let project_name = self
            .test_project
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("test_project");
        self.test_project
            .join("target/release_remote")
            .join(project_name)
    }

    /// Get the remote project path on the worker.
    fn remote_project_path(&self) -> PathBuf {
        let project_name = self
            .test_project
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("test_project");
        self.worker.build_dir.join("self_test").join(project_name)
    }

    /// Build SSH args with optional identity file.
    fn ssh_args(&self) -> Vec<String> {
        let mut args = vec!["-o".to_string(), "BatchMode=yes".to_string()];
        if let Some(ref identity) = self.worker.identity_file {
            args.push("-i".to_string());
            args.push(identity.to_string_lossy().to_string());
        }
        args.push(self.worker.ssh_host.clone());
        args
    }

    /// Build rsync args with optional identity file.
    fn rsync_ssh_option(&self) -> Option<String> {
        self.worker
            .identity_file
            .as_ref()
            .map(|identity| format!("ssh -o BatchMode=yes -i {}", identity.to_string_lossy()))
    }

    /// Run the full remote compilation verification test.
    pub async fn run(&mut self) -> Result<VerificationResult> {
        let start = Instant::now();
        info!(
            "Starting remote compilation verification for worker {}",
            self.worker.id
        );

        // 1. Apply test change to make binary unique
        let change = TestCodeChange::for_main_rs(&self.test_project)
            .context("Failed to create test code change")?;
        let guard = TestChangeGuard::new(change).context("Failed to apply test change")?;
        info!("Applied test change: {}", guard.change_id());

        // 2. Build locally first
        info!("Building locally for reference hash");
        let local_build_start = Instant::now();
        self.build_local().await.context("Local build failed")?;
        let local_compilation_ms = local_build_start.elapsed().as_millis() as u64;
        self.local_compilation_ms = Some(local_compilation_ms);

        let local_hash = compute_binary_hash(&self.local_binary_path())
            .context("Failed to compute local binary hash")?;
        info!(
            "Local build complete in {}ms: hash={}",
            local_compilation_ms,
            &local_hash.code_hash[..16]
        );

        // 3. rsync up to worker
        info!("Syncing source to worker {}", self.worker.id);
        let rsync_up_start = Instant::now();
        self.rsync_to_worker()
            .await
            .context("Failed to rsync to worker")?;
        let rsync_up_ms = rsync_up_start.elapsed().as_millis() as u64;
        info!("Source synced to worker in {}ms", rsync_up_ms);

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
            .context("Failed to rsync from worker")?;
        let rsync_down_ms = rsync_down_start.elapsed().as_millis() as u64;
        info!("Artifacts synced back in {}ms", rsync_down_ms);

        // 6. Compute remote binary hash
        let remote_hash = compute_binary_hash(&self.remote_binary_path())
            .context("Failed to compute remote binary hash")?;
        info!("Remote binary hash: {}", &remote_hash.code_hash[..16]);

        // 7. Compare
        let success = binaries_equivalent(&local_hash, &remote_hash);
        let total_ms = start.elapsed().as_millis() as u64;

        let error = if success {
            info!("Verification PASSED: local and remote hashes match");
            None
        } else {
            let msg = format!(
                "Binary hashes do not match: local={}, remote={}",
                &local_hash.code_hash[..16],
                &remote_hash.code_hash[..16]
            );
            error!("Verification FAILED: {}", msg);
            Some(msg)
        };

        // Guard will auto-revert on drop
        drop(guard);

        Ok(VerificationResult {
            success,
            local_hash,
            remote_hash,
            rsync_up_ms,
            compilation_ms,
            rsync_down_ms,
            total_ms,
            error,
        })
    }

    /// Build the project locally.
    async fn build_local(&self) -> Result<()> {
        info!("Running: cargo build --release in {:?}", self.test_project);

        let output = Command::new("cargo")
            .args(["build", "--release"])
            .current_dir(&self.test_project)
            .env("CARGO_INCREMENTAL", "0")
            .output()
            .await
            .context("Failed to execute cargo build")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Local build failed: {}", stderr);
        }
        Ok(())
    }

    /// Sync source files to the remote worker.
    async fn rsync_to_worker(&self) -> Result<()> {
        let remote_path = format!(
            "{}:{}",
            self.worker.ssh_host,
            self.worker.build_dir.join("self_test").display()
        );

        let mut cmd = Command::new("rsync");
        cmd.args([
            "-az",
            "--delete",
            "--exclude",
            "target/",
            "--exclude",
            ".git/",
        ]);

        if let Some(ssh_option) = self.rsync_ssh_option() {
            cmd.args(["-e", &ssh_option]);
        }

        cmd.arg(format!("{}/", self.test_project.display()));
        cmd.arg(&remote_path);

        info!("Running rsync to {}", remote_path);
        let output = cmd.output().await.context("Failed to execute rsync")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("rsync to worker failed: {}", stderr);
        }
        Ok(())
    }

    /// Build the project on the remote worker.
    async fn build_remote(&self) -> Result<()> {
        let remote_project = self.remote_project_path();
        let build_cmd = format!("cd {} && cargo build --release", remote_project.display());

        let mut cmd = Command::new("ssh");
        for arg in self.ssh_args() {
            cmd.arg(arg);
        }
        cmd.arg(&build_cmd);

        info!(
            "Running remote build: ssh {} '{}'",
            self.worker.ssh_host, build_cmd
        );
        let output = cmd
            .output()
            .await
            .context("Failed to execute remote build")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Remote build failed: {}", stderr);
        }
        Ok(())
    }

    /// Sync artifacts back from the remote worker.
    async fn rsync_from_worker(&self) -> Result<()> {
        let remote_project = self.remote_project_path();
        let remote_target = format!(
            "{}:{}/target/release/",
            self.worker.ssh_host,
            remote_project.display()
        );

        let local_target = self.test_project.join("target/release_remote/");
        std::fs::create_dir_all(&local_target)
            .context("Failed to create local target directory")?;

        let mut cmd = Command::new("rsync");
        cmd.args(["-az"]);

        if let Some(ssh_option) = self.rsync_ssh_option() {
            cmd.args(["-e", &ssh_option]);
        }

        cmd.arg(&remote_target);
        cmd.arg(format!("{}/", local_target.display()));

        info!("Running rsync from {}", remote_target);
        let output = cmd.output().await.context("Failed to execute rsync")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("rsync from worker failed: {}", stderr);
        }
        Ok(())
    }

    /// Clean up remote build artifacts.
    pub async fn cleanup_remote(&self) -> Result<()> {
        let remote_project = self.remote_project_path();
        let cleanup_cmd = format!("rm -rf {}", remote_project.display());

        let mut cmd = Command::new("ssh");
        for arg in self.ssh_args() {
            cmd.arg(arg);
        }
        cmd.arg(&cleanup_cmd);

        info!("Cleaning up remote: {}", cleanup_cmd);
        let output = cmd
            .output()
            .await
            .context("Failed to execute remote cleanup")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Remote cleanup failed (non-fatal): {}", stderr);
        }
        Ok(())
    }
}

#[cfg(test)]
mod basic_tests {
    use super::*;
    use crate::types::{WorkerConfig, WorkerId};

    fn sample_worker_config() -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new("worker-1"),
            host: "example.com".to_string(),
            user: "builder".to_string(),
            identity_file: "/tmp/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: Vec::new(),
        }
    }

    #[test]
    fn test_verification_worker_config_from_worker_config() {
        let worker = sample_worker_config();
        let build_dir = PathBuf::from("/tmp/rch-build");
        let verification = VerificationWorkerConfig::from_worker_config(&worker, build_dir.clone());

        assert_eq!(verification.id, "worker-1");
        assert_eq!(verification.ssh_host, "builder@example.com");
        assert_eq!(
            verification.identity_file,
            Some(PathBuf::from("/tmp/id_rsa"))
        );
        assert_eq!(verification.build_dir, build_dir);
    }

    #[test]
    fn test_remote_compilation_paths() {
        let verification = VerificationWorkerConfig {
            id: "worker-1".to_string(),
            ssh_host: "builder@example.com".to_string(),
            identity_file: Some(PathBuf::from("/tmp/id_rsa")),
            build_dir: PathBuf::from("/tmp/rch-builds"),
        };
        let test_project = PathBuf::from("/tmp/test-project");
        let test = RemoteCompilationTest::new(verification, test_project.clone());

        assert_eq!(
            test.local_binary_path(),
            test_project.join("target/release/test-project")
        );
        assert_eq!(
            test.remote_binary_path(),
            test_project.join("target/release_remote/test-project")
        );
        assert_eq!(
            test.remote_project_path(),
            PathBuf::from("/tmp/rch-builds/self_test/test-project")
        );
    }

    #[test]
    fn test_ssh_args_with_identity() {
        let verification = VerificationWorkerConfig {
            id: "worker-1".to_string(),
            ssh_host: "builder@example.com".to_string(),
            identity_file: Some(PathBuf::from("/tmp/key.pem")),
            build_dir: PathBuf::from("/tmp/rch-builds"),
        };
        let test = RemoteCompilationTest::new(verification, PathBuf::from("/tmp/project"));
        let args = test.ssh_args();

        assert!(args.contains(&"-i".to_string()));
        assert!(args.contains(&"/tmp/key.pem".to_string()));
        assert_eq!(args.last(), Some(&"builder@example.com".to_string()));
    }

    #[test]
    fn test_ssh_args_without_identity() {
        let verification = VerificationWorkerConfig {
            id: "worker-1".to_string(),
            ssh_host: "builder@example.com".to_string(),
            identity_file: None,
            build_dir: PathBuf::from("/tmp/rch-builds"),
        };
        let test = RemoteCompilationTest::new(verification, PathBuf::from("/tmp/project"));
        let args = test.ssh_args();

        assert!(!args.contains(&"-i".to_string()));
        assert_eq!(args.last(), Some(&"builder@example.com".to_string()));
    }

    #[test]
    fn test_rsync_ssh_option() {
        let verification = VerificationWorkerConfig {
            id: "worker-1".to_string(),
            ssh_host: "builder@example.com".to_string(),
            identity_file: Some(PathBuf::from("/tmp/key.pem")),
            build_dir: PathBuf::from("/tmp/rch-builds"),
        };
        let test = RemoteCompilationTest::new(verification, PathBuf::from("/tmp/project"));

        assert_eq!(
            test.rsync_ssh_option(),
            Some("ssh -o BatchMode=yes -i /tmp/key.pem".to_string())
        );
    }

    fn dummy_hash() -> BinaryHashResult {
        BinaryHashResult {
            full_hash: "full".to_string(),
            code_hash: "code".to_string(),
            text_section_size: 123,
            is_debug: false,
        }
    }

    #[test]
    fn test_speedup_factor() {
        let result = VerificationResult {
            success: true,
            local_hash: dummy_hash(),
            remote_hash: dummy_hash(),
            rsync_up_ms: 10,
            compilation_ms: 500,
            rsync_down_ms: 10,
            total_ms: 520,
            error: None,
        };

        assert_eq!(result.speedup_factor(1000), Some(2.0));
        assert_eq!(result.speedup_factor(0), None);

        let zero_remote = VerificationResult {
            compilation_ms: 0,
            ..result
        };
        assert_eq!(zero_remote.speedup_factor(1000), None);
    }
}

/// Quick verification that tests basic SSH connectivity to a worker.
pub async fn verify_ssh_connectivity(worker: &VerificationWorkerConfig) -> Result<bool> {
    let mut cmd = Command::new("ssh");
    cmd.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]);
    if let Some(ref identity) = worker.identity_file {
        cmd.args(["-i", &identity.to_string_lossy()]);
    }
    cmd.arg(&worker.ssh_host);
    cmd.arg("echo ok");

    let output = cmd
        .output()
        .await
        .context("Failed to execute SSH connectivity test")?;

    Ok(output.status.success())
}

/// Quick verification that rsync is available on the worker.
pub async fn verify_rsync_available(worker: &VerificationWorkerConfig) -> Result<bool> {
    let mut cmd = Command::new("ssh");
    cmd.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]);
    if let Some(ref identity) = worker.identity_file {
        cmd.args(["-i", &identity.to_string_lossy()]);
    }
    cmd.arg(&worker.ssh_host);
    cmd.arg("which rsync");

    let output = cmd
        .output()
        .await
        .context("Failed to check rsync availability")?;

    Ok(output.status.success())
}

/// Quick verification that cargo is available on the worker.
pub async fn verify_cargo_available(worker: &VerificationWorkerConfig) -> Result<bool> {
    let mut cmd = Command::new("ssh");
    cmd.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]);
    if let Some(ref identity) = worker.identity_file {
        cmd.args(["-i", &identity.to_string_lossy()]);
    }
    cmd.arg(&worker.ssh_host);
    cmd.arg("which cargo");

    let output = cmd
        .output()
        .await
        .context("Failed to check cargo availability")?;

    Ok(output.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::INFO)
            .try_init();
    }

    #[test]
    fn test_verification_worker_config_creation() {
        init_test_logging();
        info!("TEST START: test_verification_worker_config_creation");

        let worker = VerificationWorkerConfig {
            id: "test-worker".to_string(),
            ssh_host: "user@192.168.1.100".to_string(),
            identity_file: Some(PathBuf::from("/home/user/.ssh/id_rsa")),
            build_dir: PathBuf::from("/tmp/rch_builds"),
        };

        info!(
            "INPUT: VerificationWorkerConfig with id={}, host={}",
            worker.id, worker.ssh_host
        );

        assert_eq!(worker.id, "test-worker");
        assert_eq!(worker.ssh_host, "user@192.168.1.100");

        info!("VERIFY: VerificationWorkerConfig created successfully");
        info!("TEST PASS: test_verification_worker_config_creation");
    }

    #[test]
    fn test_remote_compilation_test_creation() {
        init_test_logging();
        info!("TEST START: test_remote_compilation_test_creation");

        let worker = VerificationWorkerConfig {
            id: "test-worker".to_string(),
            ssh_host: "localhost".to_string(),
            identity_file: None,
            build_dir: PathBuf::from("/tmp/rch_builds"),
        };

        let test = RemoteCompilationTest::new(worker, PathBuf::from("/tmp/test_project"))
            .with_timeout(Duration::from_secs(60));

        info!("INPUT: RemoteCompilationTest with timeout=60s");

        assert_eq!(test.timeout, Duration::from_secs(60));
        assert_eq!(test.test_project, PathBuf::from("/tmp/test_project"));

        info!("VERIFY: RemoteCompilationTest created with correct settings");
        info!("TEST PASS: test_remote_compilation_test_creation");
    }

    #[test]
    fn test_verification_result_speedup() {
        init_test_logging();
        info!("TEST START: test_verification_result_speedup");

        let result = VerificationResult {
            success: true,
            local_hash: BinaryHashResult {
                full_hash: "abc".to_string(),
                code_hash: "xyz".to_string(),
                text_section_size: 1000,
                is_debug: false,
            },
            remote_hash: BinaryHashResult {
                full_hash: "abc".to_string(),
                code_hash: "xyz".to_string(),
                text_section_size: 1000,
                is_debug: false,
            },
            rsync_up_ms: 100,
            compilation_ms: 5000,
            rsync_down_ms: 50,
            total_ms: 5150,
            error: None,
        };

        let speedup = result.speedup_factor(10000);
        info!("INPUT: local=10000ms, remote=5000ms");
        info!("RESULT: speedup_factor={:?}", speedup);

        assert!(speedup.is_some());
        assert!((speedup.unwrap() - 2.0).abs() < 0.01);

        info!("VERIFY: Speedup calculated correctly (2x)");
        info!("TEST PASS: test_verification_result_speedup");
    }

    #[test]
    fn test_local_binary_path() {
        init_test_logging();
        info!("TEST START: test_local_binary_path");

        let worker = VerificationWorkerConfig {
            id: "test".to_string(),
            ssh_host: "localhost".to_string(),
            identity_file: None,
            build_dir: PathBuf::from("/tmp"),
        };

        let test = RemoteCompilationTest::new(worker, PathBuf::from("/tmp/my_project"));
        let path = test.local_binary_path();

        info!("INPUT: test_project=/tmp/my_project");
        info!("RESULT: local_binary_path={:?}", path);

        assert_eq!(
            path,
            PathBuf::from("/tmp/my_project/target/release/my_project")
        );

        info!("VERIFY: Local binary path constructed correctly");
        info!("TEST PASS: test_local_binary_path");
    }

    #[test]
    fn test_remote_binary_path() {
        init_test_logging();
        info!("TEST START: test_remote_binary_path");

        let worker = VerificationWorkerConfig {
            id: "test".to_string(),
            ssh_host: "localhost".to_string(),
            identity_file: None,
            build_dir: PathBuf::from("/tmp"),
        };

        let test = RemoteCompilationTest::new(worker, PathBuf::from("/tmp/my_project"));
        let path = test.remote_binary_path();

        info!("INPUT: test_project=/tmp/my_project");
        info!("RESULT: remote_binary_path={:?}", path);

        assert_eq!(
            path,
            PathBuf::from("/tmp/my_project/target/release_remote/my_project")
        );

        info!("VERIFY: Remote binary path constructed correctly");
        info!("TEST PASS: test_remote_binary_path");
    }

    #[test]
    fn test_ssh_args_with_identity() {
        init_test_logging();
        info!("TEST START: test_ssh_args_with_identity");

        let worker = VerificationWorkerConfig {
            id: "test".to_string(),
            ssh_host: "user@host.example.com".to_string(),
            identity_file: Some(PathBuf::from("/home/user/.ssh/mykey")),
            build_dir: PathBuf::from("/tmp"),
        };

        let test = RemoteCompilationTest::new(worker, PathBuf::from("/tmp/project"));
        let args = test.ssh_args();

        info!("INPUT: identity_file=/home/user/.ssh/mykey");
        info!("RESULT: ssh_args={:?}", args);

        assert!(args.contains(&"-i".to_string()));
        assert!(args.contains(&"/home/user/.ssh/mykey".to_string()));
        assert!(args.contains(&"user@host.example.com".to_string()));

        info!("VERIFY: SSH args include identity file");
        info!("TEST PASS: test_ssh_args_with_identity");
    }

    #[test]
    fn test_ssh_args_without_identity() {
        init_test_logging();
        info!("TEST START: test_ssh_args_without_identity");

        let worker = VerificationWorkerConfig {
            id: "test".to_string(),
            ssh_host: "user@host".to_string(),
            identity_file: None,
            build_dir: PathBuf::from("/tmp"),
        };

        let test = RemoteCompilationTest::new(worker, PathBuf::from("/tmp/project"));
        let args = test.ssh_args();

        info!("INPUT: identity_file=None");
        info!("RESULT: ssh_args={:?}", args);

        assert!(!args.contains(&"-i".to_string()));
        assert!(args.contains(&"user@host".to_string()));

        info!("VERIFY: SSH args work without identity file");
        info!("TEST PASS: test_ssh_args_without_identity");
    }
}
