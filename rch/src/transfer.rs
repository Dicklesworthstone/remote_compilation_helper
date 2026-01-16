//! File transfer and remote execution pipeline.
//!
//! Handles synchronizing project files to remote workers, executing compilation
//! commands, and retrieving build artifacts.

use anyhow::{Context, Result, bail};
use rch_common::{CommandResult, SshClient, SshOptions, TransferConfig, WorkerConfig};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Remote project path prefix.
const REMOTE_BASE: &str = "/tmp/rch";

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
        }
    }

    /// Set custom SSH options.
    pub fn with_ssh_options(mut self, options: SshOptions) -> Self {
        self.ssh_options = options;
        self
    }

    /// Get the remote project path on the worker.
    pub fn remote_path(&self) -> String {
        format!("{}/{}/{}", REMOTE_BASE, self.project_id, self.project_hash)
    }

    /// Synchronize local project to remote worker.
    pub async fn sync_to_remote(&self, worker: &WorkerConfig) -> Result<SyncResult> {
        let remote_path = self.remote_path();
        let destination = format!("{}@{}:{}", worker.user, worker.host, remote_path);

        info!(
            "Syncing {} -> {} on {}",
            self.project_root.display(),
            remote_path,
            worker.id
        );

        // Build rsync command with excludes
        let mut cmd = Command::new("rsync");
        cmd.arg("-az") // Archive mode + compression
            .arg("--delete") // Remove extraneous files from destination
            .arg("-e")
            .arg(format!(
                "ssh -i {} -o StrictHostKeyChecking=no -o BatchMode=yes",
                shellexpand::tilde(&worker.identity_file)
            ));

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
    pub async fn execute_remote(
        &self,
        worker: &WorkerConfig,
        command: &str,
    ) -> Result<CommandResult> {
        let remote_path = self.remote_path();

        // Wrap command to run in project directory
        let wrapped_command = format!("cd {} && {}", remote_path, command);

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
    pub async fn execute_remote_streaming<F, G>(
        &self,
        worker: &WorkerConfig,
        command: &str,
        on_stdout: F,
        on_stderr: G,
    ) -> Result<CommandResult>
    where
        F: FnMut(&str),
        G: FnMut(&str),
    {
        let remote_path = self.remote_path();
        let wrapped_command = format!("cd {} && {}", remote_path, command);

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

        info!("Retrieving artifacts from {} on {}", remote_path, worker.id);

        let mut cmd = Command::new("rsync");
        cmd.arg("-az").arg("-e").arg(format!(
            "ssh -i {} -o StrictHostKeyChecking=no -o BatchMode=yes",
            shellexpand::tilde(&worker.identity_file)
        ));

        // Add zstd compression
        if self.transfer_config.compression_level > 0 {
            cmd.arg("--compress-choice=zstd");
            cmd.arg(format!(
                "--compress-level={}",
                self.transfer_config.compression_level
            ));
        }

        // Include only specified artifact patterns
        for pattern in artifact_patterns {
            cmd.arg("--include").arg(pattern);
        }
        cmd.arg("--exclude").arg("*"); // Exclude everything else

        let source = format!("{}@{}:{}/", worker.user, worker.host, remote_path);
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
    pub async fn cleanup_remote(&self, worker: &WorkerConfig) -> Result<()> {
        let remote_path = self.remote_path();

        info!("Cleaning up {} on {}", remote_path, worker.id);

        let mut client = SshClient::new(worker.clone(), self.ssh_options.clone());
        client.connect().await?;

        let result = client.execute(&format!("rm -rf {}", remote_path)).await?;

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
        if line.contains("sent") && line.contains("bytes") {
            if let Some(bytes_str) = line.split_whitespace().nth(1) {
                if let Ok(bytes) = bytes_str.replace(',', "").parse() {
                    return bytes;
                }
            }
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
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    // Hash path and modification time of key files
    if let Ok(metadata) = std::fs::metadata(project_path.join("Cargo.toml")) {
        if let Ok(modified) = metadata.modified() {
            modified.hash(&mut hasher);
        }
    }

    if let Ok(metadata) = std::fs::metadata(project_path.join("Cargo.lock")) {
        if let Ok(modified) = metadata.modified() {
            modified.hash(&mut hasher);
        }
    }

    project_path.hash(&mut hasher);

    format!("{:016x}", hasher.finish())
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
