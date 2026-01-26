//! File transfer and remote execution pipeline.
//!
//! Handles synchronizing project files to remote workers, executing compilation
//! commands, and retrieving build artifacts.

use anyhow::{Context, Result, bail};
use rch_common::mock::{self, MockConfig, MockRsync, MockRsyncConfig, MockSshClient};
use rch_common::ssh::{EnvPrefix, build_env_prefix};
use rch_common::{
    ColorMode, CommandResult, SshClient, SshOptions, ToolchainInfo, TransferConfig, WorkerConfig,
    wrap_command_with_color, wrap_command_with_toolchain,
};
use shell_escape::escape;
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Remote project path prefix.
const REMOTE_BASE: &str = "/tmp/rch";

fn use_mock_transport(worker: &WorkerConfig) -> bool {
    mock::is_mock_enabled() || mock::is_mock_worker(worker)
}

/// Transfer pipeline for remote compilation.
pub struct TransferPipeline {
    /// Local project root.
    project_root: PathBuf,
    /// Project identifier (usually directory name).
    project_id: String,
    /// Project hash for cache invalidation.
    project_hash: String,
    /// Transfer configuration.
    transfer_config: TransferConfig,
    /// SSH options.
    ssh_options: SshOptions,
    /// Color mode for remote command output.
    color_mode: ColorMode,
    /// Environment variables to forward to workers.
    env_allowlist: Vec<String>,
    /// Optional environment overrides for testing.
    env_overrides: Option<HashMap<String, String>>,
}

impl TransferPipeline {
    /// Create a new transfer pipeline.
    pub fn new(
        project_root: PathBuf,
        project_id: String,
        project_hash: String,
        transfer_config: TransferConfig,
    ) -> Self {
        Self {
            project_root,
            project_id,
            project_hash,
            transfer_config,
            ssh_options: SshOptions::default(),
            color_mode: ColorMode::default(),
            env_allowlist: Vec::new(),
            env_overrides: None,
        }
    }

    /// Set custom SSH options.
    #[allow(dead_code)] // Reserved for future CLI/config support
    pub fn with_ssh_options(mut self, options: SshOptions) -> Self {
        self.ssh_options = options;
        self
    }

    /// Set color mode for remote command output.
    #[allow(dead_code)] // Reserved for future CLI/config support
    pub fn with_color_mode(mut self, color_mode: ColorMode) -> Self {
        self.color_mode = color_mode;
        self
    }

    /// Set environment allowlist for remote execution.
    pub fn with_env_allowlist(mut self, allowlist: Vec<String>) -> Self {
        self.env_allowlist = allowlist;
        self
    }

    #[cfg(test)]
    pub fn with_env_overrides(mut self, overrides: HashMap<String, String>) -> Self {
        self.env_overrides = Some(overrides);
        self
    }

    /// Set command timeout for remote execution.
    ///
    /// Different command types may need different timeouts. For example,
    /// test commands often need longer timeouts than build commands.
    #[allow(dead_code)] // Reserved for future CLI/config support
    pub fn with_command_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.ssh_options.command_timeout = timeout;
        self
    }

    fn build_env_prefix(&self) -> EnvPrefix {
        build_env_prefix(&self.env_allowlist, |key| {
            if let Some(ref overrides) = self.env_overrides
                && let Some(value) = overrides.get(key)
            {
                return Some(value.clone());
            }
            std::env::var(key).ok()
        })
    }

    /// Get the remote project path on the worker.
    pub fn remote_path(&self) -> String {
        format!("{}/{}/{}", REMOTE_BASE, self.project_id, self.project_hash)
    }

    /// Synchronize local project to remote worker.
    pub async fn sync_to_remote(&self, worker: &WorkerConfig) -> Result<SyncResult> {
        let remote_path = self.remote_path();
        let escaped_remote_path = escape(Cow::from(&remote_path));
        let destination = format!("{}@{}:{}", worker.user, worker.host, escaped_remote_path);

        if use_mock_transport(worker) {
            let rsync = MockRsync::new(MockRsyncConfig::from_env());
            let result = rsync
                .sync_to_remote(
                    &self.project_root.display().to_string(),
                    &destination,
                    &self.transfer_config.exclude_patterns,
                )
                .await?;
            return Ok(SyncResult {
                bytes_transferred: result.bytes_transferred,
                files_transferred: result.files_transferred,
                duration_ms: result.duration_ms,
            });
        }

        info!(
            "Syncing {} -> {} on {}",
            self.project_root.display(),
            remote_path,
            worker.id
        );

        // Build rsync command with excludes
        let mut cmd = Command::new("rsync");
        // Force C locale for consistent output parsing
        cmd.env("LC_ALL", "C");

        let identity_file = shellexpand::tilde(&worker.identity_file);
        let escaped_identity = escape(Cow::from(identity_file.as_ref()));

        cmd.arg("-az") // Archive mode + compression
            .arg("--delete") // Remove extraneous files from destination
            .arg("-e")
            .arg(format!(
                "ssh -i {} -o StrictHostKeyChecking=no -o BatchMode=yes",
                escaped_identity
            ));

        // Create remote directory implicitly using rsync-path wrapper
        // This saves a separate SSH handshake for 'mkdir -p'
        cmd.arg("--rsync-path")
            .arg(format!("mkdir -p {} && rsync", escaped_remote_path));

        // Add exclude patterns
        for pattern in &self.transfer_config.exclude_patterns {
            cmd.arg("--exclude").arg(pattern);
        }

        // Add zstd compression if available (rsync 3.2.3+)
        if self.transfer_config.compression_level > 0 {
            cmd.arg("--compress-choice=zstd");
            cmd.arg(format!(
                "--compress-level={}",
                self.transfer_config.compression_level
            ));
        }

        // Source and destination
        cmd.arg(format!("{}/", self.project_root.display())) // Trailing slash = contents only
            .arg(&destination);

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        debug!(
            "Running: rsync {:?}",
            cmd.as_std().get_args().collect::<Vec<_>>()
        );

        let start = std::time::Instant::now();
        let output = cmd.output().await.context("Failed to execute rsync")?;

        let duration = start.elapsed();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            warn!("rsync failed: {}", stderr);
            bail!(
                "rsync failed with exit code {:?}: {}",
                output.status.code(),
                stderr
            );
        }

        info!("Sync completed in {}ms", duration.as_millis());

        Ok(SyncResult {
            bytes_transferred: parse_rsync_bytes(&stdout),
            files_transferred: parse_rsync_files(&stdout),
            duration_ms: duration.as_millis() as u64,
        })
    }

    /// Execute a compilation command on the remote worker.
    ///
    /// If `toolchain` is provided, the command will be wrapped with `rustup run <toolchain>`.
    /// Color-forcing environment variables are applied based on the configured color mode.
    #[allow(dead_code)] // Reserved for future usage
    pub async fn execute_remote(
        &self,
        worker: &WorkerConfig,
        command: &str,
        toolchain: Option<&ToolchainInfo>,
    ) -> Result<CommandResult> {
        let remote_path = self.remote_path();
        let escaped_remote_path = escape(Cow::from(&remote_path));

        // Wrap command with toolchain if provided
        let toolchain_command = wrap_command_with_toolchain(command, toolchain);

        // Apply environment allowlist before color wrapping
        let env_prefix = self.build_env_prefix();
        if !env_prefix.applied.is_empty() {
            debug!("Forwarding env vars: {:?}", env_prefix.applied);
        }
        if !env_prefix.rejected.is_empty() {
            warn!("Skipping env vars: {:?}", env_prefix.rejected);
        }
        let env_command = if env_prefix.prefix.is_empty() {
            toolchain_command
        } else {
            format!("{}{}", env_prefix.prefix, toolchain_command)
        };

        // Apply color mode environment variables
        let colored_command = wrap_command_with_color(&env_command, self.color_mode);

        // Wrap command to run in project directory
        let wrapped_command = format!("cd {} && {}", escaped_remote_path, colored_command);

        if use_mock_transport(worker) {
            let mut client = MockSshClient::new(worker.clone(), MockConfig::from_env());
            client.connect().await?;
            let result = client.execute(&wrapped_command).await?;
            client.disconnect().await?;
            return Ok(result);
        }

        info!("Executing on {}: {}", worker.id, command);

        let mut client = SshClient::new(worker.clone(), self.ssh_options.clone());
        client.connect().await?;

        let result = client.execute(&wrapped_command).await?;

        client.disconnect().await?;

        if result.success() {
            info!("Command succeeded in {}ms", result.duration_ms);
        } else {
            warn!(
                "Command failed (exit={}) in {}ms",
                result.exit_code, result.duration_ms
            );
        }

        Ok(result)
    }

    /// Execute a command and stream output in real-time.
    ///
    /// If `toolchain` is provided, the command will be wrapped with `rustup run <toolchain>`.
    /// Color-forcing environment variables are applied based on the configured color mode
    /// to preserve ANSI colors in the streamed output.
    pub async fn execute_remote_streaming<F, G>(
        &self,
        worker: &WorkerConfig,
        command: &str,
        toolchain: Option<&ToolchainInfo>,
        on_stdout: F,
        on_stderr: G,
    ) -> Result<CommandResult>
    where
        F: FnMut(&str),
        G: FnMut(&str),
    {
        let remote_path = self.remote_path();
        let escaped_remote_path = escape(Cow::from(&remote_path));
        let toolchain_command = wrap_command_with_toolchain(command, toolchain);

        let env_prefix = self.build_env_prefix();
        if !env_prefix.applied.is_empty() {
            debug!("Forwarding env vars: {:?}", env_prefix.applied);
        }
        if !env_prefix.rejected.is_empty() {
            warn!("Skipping env vars: {:?}", env_prefix.rejected);
        }
        let env_command = if env_prefix.prefix.is_empty() {
            toolchain_command
        } else {
            format!("{}{}", env_prefix.prefix, toolchain_command)
        };

        // Apply color mode environment variables to preserve ANSI colors
        let colored_command = wrap_command_with_color(&env_command, self.color_mode);
        let wrapped_command = format!("cd {} && {}", escaped_remote_path, colored_command);

        if use_mock_transport(worker) {
            let mut client = MockSshClient::new(worker.clone(), MockConfig::from_env());
            client.connect().await?;
            let result = client
                .execute_streaming(&wrapped_command, on_stdout, on_stderr)
                .await?;
            client.disconnect().await?;
            return Ok(result);
        }

        let mut client = SshClient::new(worker.clone(), self.ssh_options.clone());
        client.connect().await?;

        let result = client
            .execute_streaming(&wrapped_command, on_stdout, on_stderr)
            .await?;

        client.disconnect().await?;

        Ok(result)
    }

    /// Retrieve build artifacts from the remote worker.
    pub async fn retrieve_artifacts(
        &self,
        worker: &WorkerConfig,
        artifact_patterns: &[String],
    ) -> Result<SyncResult> {
        let remote_path = self.remote_path();
        let escaped_remote_path = escape(Cow::from(&remote_path));

        if use_mock_transport(worker) {
            let rsync = MockRsync::new(MockRsyncConfig::from_env());
            let result = rsync
                .retrieve_artifacts(
                    &format!("{}@{}:{}/", worker.user, worker.host, escaped_remote_path),
                    &self.project_root.display().to_string(),
                    artifact_patterns,
                )
                .await?;
            return Ok(SyncResult {
                bytes_transferred: result.bytes_transferred,
                files_transferred: result.files_transferred,
                duration_ms: result.duration_ms,
            });
        }

        info!("Retrieving artifacts from {} on {}", remote_path, worker.id);

        let mut cmd = Command::new("rsync");
        // Force C locale for consistent output parsing
        cmd.env("LC_ALL", "C");

        let identity_file = shellexpand::tilde(&worker.identity_file);
        let escaped_identity = escape(Cow::from(identity_file.as_ref()));

        cmd.arg("-az").arg("-e").arg(format!(
            "ssh -i {} -o StrictHostKeyChecking=no -o BatchMode=yes",
            escaped_identity
        ));

        // Add zstd compression
        if self.transfer_config.compression_level > 0 {
            cmd.arg("--compress-choice=zstd");
            cmd.arg(format!(
                "--compress-level={}",
                self.transfer_config.compression_level
            ));
        }

        // Prune empty directories to prevent cluttering local project with
        // empty parents of excluded files (side effect of --include="*/")
        cmd.arg("--prune-empty-dirs");

        // Essential: Include all directories so rsync can traverse to match patterns.
        // Without this, the final --exclude "*" prevents rsync from entering directories
        // like "target/" to check for matches.
        cmd.arg("--include").arg("*/");

        // Include only specified artifact patterns
        for pattern in artifact_patterns {
            cmd.arg("--include").arg(pattern);
        }
        cmd.arg("--exclude").arg("*"); // Exclude everything else

        let source = format!("{}@{}:{}/", worker.user, worker.host, escaped_remote_path);
        cmd.arg(&source)
            .arg(format!("{}/", self.project_root.display()));

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        debug!(
            "Running artifact retrieval: rsync {:?}",
            cmd.as_std().get_args().collect::<Vec<_>>()
        );

        let start = std::time::Instant::now();
        let output = cmd.output().await.context("Failed to retrieve artifacts")?;

        let duration = start.elapsed();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            warn!("Artifact retrieval failed: {}", stderr);
            bail!(
                "rsync artifact retrieval failed with exit code {:?}: {}",
                output.status.code(),
                stderr
            );
        }

        info!("Artifacts retrieved in {}ms", duration.as_millis());

        Ok(SyncResult {
            bytes_transferred: parse_rsync_bytes(&stdout),
            files_transferred: parse_rsync_files(&stdout),
            duration_ms: duration.as_millis() as u64,
        })
    }

    /// Clean up remote project directory.
    #[allow(dead_code)] // Reserved for future cleanup routines
    pub async fn cleanup_remote(&self, worker: &WorkerConfig) -> Result<()> {
        let remote_path = self.remote_path();
        let escaped_remote_path = escape(Cow::from(&remote_path));

        if use_mock_transport(worker) {
            debug!("Mock cleanup of {} on {}", remote_path, worker.id);
            return Ok(());
        }

        info!("Cleaning up {} on {}", remote_path, worker.id);

        let mut client = SshClient::new(worker.clone(), self.ssh_options.clone());
        client.connect().await?;

        let result = client
            .execute(&format!("rm -rf {}", escaped_remote_path))
            .await?;

        client.disconnect().await?;

        if !result.success() {
            warn!("Cleanup failed: {}", result.stderr);
        }

        Ok(())
    }
}

/// Result of a file synchronization operation.
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Bytes transferred.
    pub bytes_transferred: u64,
    /// Number of files transferred.
    pub files_transferred: u32,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// Parse bytes transferred from rsync output.
fn parse_rsync_bytes(output: &str) -> u64 {
    // rsync output contains "sent X bytes  received Y bytes"
    for line in output.lines() {
        if line.contains("sent")
            && line.contains("bytes")
            && let Some(bytes_str) = line.split_whitespace().nth(1)
            && let Ok(bytes) = bytes_str.replace(',', "").parse()
        {
            return bytes;
        }
    }
    0
}

/// Parse files transferred from rsync output.
fn parse_rsync_files(output: &str) -> u32 {
    // rsync verbose output lists files, count them
    output
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.contains("sent"))
        .count() as u32
}

/// Compute a hash of the project for cache invalidation.
pub fn compute_project_hash(project_path: &Path) -> String {
    let mut hasher = blake3::Hasher::new();

    // Hash path
    hasher.update(project_path.to_string_lossy().as_bytes());

    // Hash modification time of key files to detect configuration changes
    // This helps route to workers with cached copies when dependencies haven't changed
    let key_files = [
        // Rust project files
        "Cargo.toml",
        "Cargo.lock",
        // Bun/Node.js project files
        "package.json",
        "bun.lockb",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        // TypeScript config
        "tsconfig.json",
        // Bun config
        "bunfig.toml",
    ];

    for filename in key_files {
        if let Ok(metadata) = std::fs::metadata(project_path.join(filename))
            && let Ok(modified) = metadata.modified()
            && let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH)
        {
            hasher.update(&duration.as_nanos().to_le_bytes());
        }
    }

    hasher.finalize().to_hex()[..16].to_string()
}

/// Get the project identifier from a path.
pub fn project_id_from_path(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string()
}

/// Default artifact patterns for Rust projects.
pub fn default_rust_artifact_patterns() -> Vec<String> {
    vec![
        "target/debug/**".to_string(),
        "target/release/**".to_string(),
        "target/.rustc_info.json".to_string(),
        "target/CACHEDIR.TAG".to_string(),
    ]
}

/// Minimal artifact patterns for Rust test-only commands.
///
/// Test runs stream their output via stdout/stderr and don't need the full
/// target/ directory returned. This function returns only patterns for:
/// - Coverage reports (when using cargo-llvm-cov, tarpaulin, etc.)
/// - Nextest archive/junit artifacts
/// - Benchmark results
///
/// This dramatically reduces artifact transfer time for test commands,
/// especially on large projects where target/ can be several gigabytes.
#[allow(dead_code)] // Reserved for future test-only artifact optimization
pub fn default_rust_test_artifact_patterns() -> Vec<String> {
    vec![
        // cargo-llvm-cov coverage data
        "target/llvm-cov-target/**".to_string(),
        // Alternative coverage output locations
        "target/coverage/**".to_string(),
        // Tarpaulin coverage reports
        "tarpaulin-report.html".to_string(),
        "tarpaulin-report.json".to_string(),
        "cobertura.xml".to_string(),
        // cargo-nextest artifacts
        "target/nextest/**".to_string(),
        // JUnit test result format (common CI integration)
        "junit.xml".to_string(),
        "test-results.xml".to_string(),
        // Criterion benchmark results
        "target/criterion/**".to_string(),
    ]
}

/// Default artifact patterns for Bun/Node.js projects.
///
/// These patterns retrieve test results and coverage reports generated
/// during `bun test` and `bun typecheck` execution.
pub fn default_bun_artifact_patterns() -> Vec<String> {
    vec![
        // Coverage reports (generated by bun test --coverage)
        "coverage/**".to_string(),
        // TypeScript incremental build info (speeds up subsequent typechecks)
        "*.tsbuildinfo".to_string(),
        "tsconfig.tsbuildinfo".to_string(),
        // Common test result formats
        "test-results/**".to_string(),
        "junit.xml".to_string(),
        "test-report.json".to_string(),
        // NYC (Istanbul) coverage output
        ".nyc_output/**".to_string(),
    ]
}

/// Default artifact patterns for C/C++ projects.
pub fn default_c_cpp_artifact_patterns() -> Vec<String> {
    vec![
        // Common build directories
        "build/**".to_string(),
        "bin/**".to_string(),
        "out/**".to_string(),
        ".libs/**".to_string(),
        // Object files
        "*.o".to_string(),
        "*.obj".to_string(),
        // Libraries
        "*.a".to_string(),
        "*.so".to_string(),
        "*.so.*".to_string(),
        "*.dylib".to_string(),
        "*.dll".to_string(),
        "*.lib".to_string(),
        // Executables (Windows)
        "*.exe".to_string(),
        // We also want to include executables in the root, but rsync include/exclude logic
        // makes "just executables" hard. We'll include all files in root that don't match excludes.
        // The "*/" in retrieve_artifacts covers directories.
        // We include "*" to catch files in the root (like the output binary).
        "*".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::mock;
    use rch_common::mock::Phase;
    use rch_common::{ColorMode, WorkerConfig, WorkerId};
    use std::collections::HashMap;

    #[test]
    fn test_remote_path() {
        let pipeline = TransferPipeline::new(
            PathBuf::from("/home/user/project"),
            "myproject".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        );

        assert_eq!(pipeline.remote_path(), "/tmp/rch/myproject/abc123");
    }

    #[test]
    fn test_project_id_from_path() {
        assert_eq!(
            project_id_from_path(Path::new("/home/user/my-project")),
            "my-project"
        );
        assert_eq!(
            project_id_from_path(Path::new("/workspace/remote_compilation_helper")),
            "remote_compilation_helper"
        );
    }

    #[test]
    fn test_parse_rsync_bytes() {
        let output = "sent 1,234 bytes  received 567 bytes  1800.50 bytes/sec";
        assert_eq!(parse_rsync_bytes(output), 1234);

        let empty = "";
        assert_eq!(parse_rsync_bytes(empty), 0);
    }

    #[test]
    fn test_default_artifact_patterns() {
        let patterns = default_rust_artifact_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.contains("debug")));
        assert!(patterns.iter().any(|p| p.contains("release")));
    }

    #[test]
    fn test_default_bun_artifact_patterns() {
        let patterns = default_bun_artifact_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.contains("coverage")));
        assert!(patterns.iter().any(|p| p.contains("tsbuildinfo")));
    }

    #[test]
    fn test_default_rust_test_artifact_patterns() {
        let patterns = default_rust_test_artifact_patterns();
        // Test patterns should be non-empty but minimal
        assert!(!patterns.is_empty());

        // Should include coverage-related patterns
        assert!(patterns.iter().any(|p| p.contains("llvm-cov")));
        assert!(patterns.iter().any(|p| p.contains("coverage")));

        // Should include nextest artifacts
        assert!(patterns.iter().any(|p| p.contains("nextest")));

        // Should NOT include full debug/release directories (that's the point!)
        assert!(!patterns.iter().any(|p| p == "target/debug/**"));
        assert!(!patterns.iter().any(|p| p == "target/release/**"));
    }

    #[test]
    fn test_rust_test_patterns_vs_full_patterns() {
        let test_patterns = default_rust_test_artifact_patterns();
        let full_patterns = default_rust_artifact_patterns();

        // Full patterns should include debug/release (the heavy directories)
        assert!(full_patterns.iter().any(|p| p.contains("debug")));
        assert!(full_patterns.iter().any(|p| p.contains("release")));

        // Test patterns should NOT include debug/release directories
        // (This is the key optimization - avoiding GB of data transfer)
        assert!(!test_patterns.iter().any(|p| p.contains("debug")));
        assert!(!test_patterns.iter().any(|p| p.contains("release")));

        // Test patterns focus on results/coverage, not build artifacts
        assert!(test_patterns.iter().any(|p| p.contains("coverage")));
    }

    #[test]
    fn test_execute_remote_applies_env_allowlist() {
        mock::clear_global_invocations();
        mock::set_mock_enabled_override(Some(true));

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://worker".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        };

        let mut overrides = HashMap::new();
        overrides.insert("RUSTFLAGS".to_string(), "-C target-cpu=native".to_string());
        overrides.insert("QUOTED".to_string(), "a'b".to_string());
        overrides.insert("BADVAL".to_string(), "line1\nline2".to_string());

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/project"),
            "project".to_string(),
            "hash".to_string(),
            TransferConfig::default(),
        )
        .with_color_mode(ColorMode::Auto)
        .with_env_allowlist(vec![
            "RUSTFLAGS".to_string(),
            "QUOTED".to_string(),
            "BADVAL".to_string(),
            "MISSING".to_string(),
            "BAD=KEY".to_string(),
        ])
        .with_env_overrides(overrides);

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            pipeline
                .execute_remote(&worker, "cargo build", None)
                .await
                .expect("execute_remote");
        });

        let invocations = mock::global_ssh_invocations_snapshot();
        let command = invocations
            .iter()
            .find(|inv| inv.phase == Phase::Execute)
            .and_then(|inv| inv.command.clone())
            .expect("execute invocation");

        assert!(command.contains("RUSTFLAGS='-C target-cpu=native'"));
        assert!(command.contains("QUOTED='a'\"'\"'b'"));
        assert!(!command.contains("BADVAL="));
        assert!(!command.contains("BAD=KEY"));
        assert!(command.contains("cargo build"));

        mock::clear_mock_overrides();
        mock::clear_global_invocations();
    }
}
