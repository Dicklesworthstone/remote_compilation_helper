//! File transfer and remote execution pipeline.
//!
//! Handles synchronizing project files to remote workers, executing compilation
//! commands, and retrieving build artifacts.

use crate::error::TransferError;
use anyhow::{Context, Result};
use rch_common::mock::{self, MockConfig, MockRsync, MockRsyncConfig, MockSshClient};
use rch_common::ssh_utils::{
    EnvPrefix, is_retryable_transport_error, is_valid_env_key, shell_escape_value,
};
use rch_common::{
    ColorMode, CommandResult, CompilationKind, PathTopologyPolicy, RetryConfig, ToolchainInfo,
    TransferConfig, WorkerConfig, normalize_project_path_with_policy, wrap_command_with_color,
    wrap_command_with_toolchain,
};
#[cfg(unix)]
use rch_common::{SshClient, SshOptions};
use shell_escape::escape;
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::Instant as TokioInstant;
use tokio::time::sleep;
use tracing::{debug, info, warn};

const PROJECT_HASH_CONTENT_LIMIT_BYTES: u64 = 2 * 1024 * 1024;
const PROJECT_HASH_KEY_FILES: &[&str] = &[
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
const REMOTE_RUNTIME_EXCLUDE_PATTERNS: &[&str] = &[".rch-target/", ".rch-tmp/"];

// =============================================================================
// Retry Logic (bd-x1ek)
// =============================================================================

/// Execute an async operation with retry and exponential backoff.
///
/// Only retries on transient transport errors (connection timeout, reset, etc.).
/// Non-retryable errors (auth failure, host key issues) fail immediately.
///
/// Returns the result of the first successful attempt or the last error.
///
/// This variant works with operations that return `anyhow::Result<T>`.
async fn retry_with_backoff<T, F, Fut>(
    config: &RetryConfig,
    operation_name: &str,
    mut operation: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let start = std::time::Instant::now();
    let mut last_error: Option<anyhow::Error> = None;

    for attempt in 0..config.max_attempts {
        // Check total timeout before attempting
        if attempt > 0 && !config.should_retry(attempt, start.elapsed()) {
            debug!(
                "{}: total timeout exceeded after {} attempts",
                operation_name, attempt
            );
            break;
        }

        // Apply delay (exponential backoff with jitter) for retries
        if attempt > 0 {
            let delay = config.delay_for_attempt(attempt);
            debug!(
                "{}: attempt {}/{} after {}ms delay",
                operation_name,
                attempt + 1,
                config.max_attempts,
                delay.as_millis()
            );
            sleep(delay).await;
        }

        match operation().await {
            Ok(result) => {
                if attempt > 0 {
                    info!(
                        "{}: succeeded on attempt {}/{}",
                        operation_name,
                        attempt + 1,
                        config.max_attempts
                    );
                }
                return Ok(result);
            }
            Err(err) => {
                // Check if error is retryable
                if !is_retryable_transport_error(&err) {
                    debug!(
                        "{}: non-retryable error on attempt {}: {}",
                        operation_name,
                        attempt + 1,
                        err
                    );
                    return Err(err);
                }

                warn!(
                    "{}: retryable error on attempt {}/{}: {}",
                    operation_name,
                    attempt + 1,
                    config.max_attempts,
                    err
                );
                last_error = Some(err);
            }
        }
    }

    // All retries exhausted
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("{}: all retries exhausted", operation_name)))
}

/// Execute a tokio Command with retry logic.
///
/// Wraps the command execution in retry_with_backoff, retrying on transient
/// rsync/SSH errors.
async fn execute_rsync_with_retry(
    config: &RetryConfig,
    operation_name: &str,
    build_command: impl Fn() -> Command,
) -> Result<std::process::Output> {
    retry_with_backoff(config, operation_name, || async {
        let mut cmd = build_command();
        cmd.output()
            .await
            .map_err(|e| anyhow::anyhow!("rsync I/O error: {}", e))
    })
    .await
}

fn use_mock_transport(worker: &WorkerConfig) -> bool {
    mock::is_mock_enabled() || mock::is_mock_worker(worker)
}

/// Parse a .rchignore file and return patterns.
///
/// Format is similar to .gitignore:
/// - One pattern per line
/// - Lines starting with # are comments
/// - Empty lines and whitespace-only lines are ignored
/// - Leading/trailing whitespace is trimmed from patterns
///
/// Note: Unlike .gitignore, negation patterns (starting with !) are not
/// supported and will be treated as literal patterns.
pub fn parse_rchignore(path: &Path) -> std::io::Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    Ok(parse_rchignore_content(&content))
}

/// Parse .rchignore content (for testing).
pub fn parse_rchignore_content(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect()
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
    #[cfg(unix)]
    ssh_options: SshOptions,
    /// Color mode for remote command output.
    color_mode: ColorMode,
    /// Environment variables to forward to workers.
    env_allowlist: Vec<String>,
    /// Optional environment overrides for testing.
    env_overrides: Option<HashMap<String, String>>,
    /// Compilation kind for command-specific handling.
    ///
    /// Used to apply appropriate timeouts and wrappers (e.g., external timeout
    /// for bun test to protect against known CPU hang issues).
    compilation_kind: Option<CompilationKind>,
    /// Compilation configuration for timeouts and other settings.
    ///
    /// Provides configurable external timeout values per command type and
    /// the ability to enable/disable timeout wrapping entirely.
    compilation_config: rch_common::CompilationConfig,
    /// Optional estimated transfer size (bytes) for adaptive compression.
    ///
    /// Populated by `should_skip_transfer` when estimation is performed.
    estimated_transfer_bytes: Option<u64>,
    /// Optional explicit remote path override.
    ///
    /// When set, transfer and execution use this path directly instead of
    /// deriving `<remote_base>/<project_id>/<project_hash>`.
    remote_path_override: Option<String>,
}

/// Validate a project hash for safe use in file paths.
///
/// The hash should be a hex string (output of BLAKE3). This function
/// validates that it contains only hex digits to prevent path traversal
/// or shell injection attacks.
fn validate_project_hash(hash: &str) -> String {
    // Hash should be hex digits only
    if hash.is_empty() {
        return "0000000000000000".to_string();
    }

    // Reject if it contains anything other than hex digits
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        warn!(
            "Project hash contains non-hex characters, sanitizing: {:?}",
            hash
        );
        // Filter to only hex characters
        let sanitized: String = hash.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if sanitized.is_empty() {
            return "0000000000000000".to_string();
        }
        return sanitized;
    }

    hash.to_string()
}

/// Remote environment application plan.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteEnvPlan {
    /// Shell-safe environment variable prefix.
    env_prefix: EnvPrefix,
    /// Directories that must exist before command execution.
    ensure_dirs: Vec<String>,
}

impl TransferPipeline {
    /// Create a new transfer pipeline.
    ///
    /// The project_id and project_hash are sanitized to prevent path traversal
    /// and shell injection attacks.
    pub fn new(
        project_root: PathBuf,
        project_id: String,
        project_hash: String,
        transfer_config: TransferConfig,
    ) -> Self {
        // Sanitize inputs to prevent path traversal and injection attacks
        let safe_project_id = sanitize_project_id(&project_id);
        let safe_project_hash = validate_project_hash(&project_hash);

        if safe_project_id != project_id {
            warn!(
                "Project ID sanitized: {:?} -> {:?}",
                project_id, safe_project_id
            );
        }

        #[cfg(unix)]
        let ssh_options = SshOptions {
            server_alive_interval: transfer_config
                .ssh_server_alive_interval_secs
                .map(std::time::Duration::from_secs),
            control_persist_idle: transfer_config
                .ssh_control_persist_secs
                .map(std::time::Duration::from_secs),
            ..Default::default()
        };

        Self {
            project_root,
            project_id: safe_project_id,
            project_hash: safe_project_hash,
            transfer_config,
            #[cfg(unix)]
            ssh_options,
            color_mode: ColorMode::default(),
            env_allowlist: Vec::new(),
            env_overrides: None,
            compilation_kind: None,
            compilation_config: rch_common::CompilationConfig::default(),
            estimated_transfer_bytes: None,
            remote_path_override: None,
        }
    }

    /// Set custom SSH options.
    #[cfg(unix)]
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
    #[cfg(unix)]
    #[allow(dead_code)] // Reserved for future CLI/config support
    pub fn with_command_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.ssh_options.command_timeout = timeout;
        self
    }

    /// Set the compilation kind for command-specific handling.
    ///
    /// This enables the pipeline to apply appropriate wrappers for specific
    /// command types. For example, bun test commands are wrapped with an
    /// external timeout to protect against known CPU hang issues.
    pub fn with_compilation_kind(mut self, kind: Option<CompilationKind>) -> Self {
        self.compilation_kind = kind;
        self
    }

    /// Set the compilation configuration for timeout settings.
    ///
    /// This allows customizing external timeout durations for different command
    /// types and enables/disables timeout wrapping entirely.
    #[cfg(test)]
    pub fn with_compilation_config(mut self, config: rch_common::CompilationConfig) -> Self {
        self.compilation_config = config;
        self
    }

    #[cfg(test)]
    pub fn with_estimated_transfer_bytes(mut self, bytes: Option<u64>) -> Self {
        self.estimated_transfer_bytes = bytes;
        self
    }

    /// Override the remote project path used for sync and command execution.
    ///
    /// Intended for canonical multi-repo layouts where the remote path must
    /// match deterministic host topology (for example `/data/projects/<repo>`).
    pub fn with_remote_path_override(mut self, remote_path: impl Into<String>) -> Self {
        let remote_path = remote_path.into();
        let trimmed = remote_path.trim();
        if trimmed.is_empty() {
            warn!("Ignoring empty remote path override");
            return self;
        }
        if !trimmed.starts_with('/') {
            warn!(
                "Ignoring remote path override that is not absolute: {}",
                trimmed
            );
            return self;
        }
        if trimmed.contains('\n') || trimmed.contains('\r') || trimmed.contains('\0') {
            warn!("Ignoring unsafe remote path override containing control characters");
            return self;
        }

        let normalized = if trimmed.len() > 1 {
            trimmed.trim_end_matches('/').to_string()
        } else {
            "/".to_string()
        };
        self.remote_path_override = Some(normalized);
        self
    }

    fn env_value(&self, key: &str) -> Option<String> {
        if let Some(ref overrides) = self.env_overrides
            && let Some(value) = overrides.get(key)
        {
            return Some(value.clone());
        }
        std::env::var(key).ok()
    }

    fn rewrite_remote_env_value(
        &self,
        key: &str,
        value: &str,
        remote_path: &str,
    ) -> (String, Option<String>, bool) {
        match key {
            // Absolute or host-specific target directories are brittle on workers.
            // Force a remote-scoped target dir rooted in the synchronized project.
            "CARGO_TARGET_DIR" => {
                let target_dir = format!("{remote_path}/.rch-target");
                (
                    target_dir.clone(),
                    Some(target_dir.clone()),
                    target_dir != value,
                )
            }
            // Temporary directories may point to host-only volatile mounts (e.g. /data/tmp).
            // Keep temp files project-scoped on the worker for stability.
            "TMPDIR" | "TMP" | "TEMP" => {
                let temp_dir = format!("{remote_path}/.rch-tmp");
                (temp_dir.clone(), Some(temp_dir.clone()), temp_dir != value)
            }
            _ => (value.to_string(), None, false),
        }
    }

    fn build_remote_env_plan(&self, remote_path: &str) -> RemoteEnvPlan {
        let mut parts = Vec::new();
        let mut applied = Vec::new();
        let mut rejected = Vec::new();
        let mut ensure_dirs = Vec::new();

        for raw_key in &self.env_allowlist {
            let key = raw_key.trim();
            if key.is_empty() {
                continue;
            }
            if !is_valid_env_key(key) {
                info!(
                    "Rejecting env var '{}': invalid key name (must start with letter/underscore, contain only alphanumeric/underscore)",
                    key
                );
                rejected.push(key.to_string());
                continue;
            }

            let Some(original_value) = self.env_value(key) else {
                continue;
            };

            let (effective_value, ensure_dir, rewritten) =
                self.rewrite_remote_env_value(key, &original_value, remote_path);
            if rewritten {
                info!(
                    "Rewriting {} for remote execution (worker-scoped path): {} -> {}",
                    key, original_value, effective_value
                );
            }

            let Some(escaped) = shell_escape_value(&effective_value) else {
                info!(
                    "Rejecting env var '{}': value contains unsafe characters (newline, carriage return, or NUL)",
                    key
                );
                rejected.push(key.to_string());
                continue;
            };

            if let Some(dir) = ensure_dir
                && !ensure_dirs.iter().any(|existing| existing == &dir)
            {
                ensure_dirs.push(dir);
            }

            parts.push(format!("{key}={escaped}"));
            applied.push(key.to_string());
        }

        let prefix = if parts.is_empty() {
            String::new()
        } else {
            format!("{} ", parts.join(" "))
        };

        RemoteEnvPlan {
            env_prefix: EnvPrefix {
                prefix,
                applied,
                rejected,
            },
            ensure_dirs,
        }
    }

    #[cfg(test)]
    fn build_env_prefix(&self) -> EnvPrefix {
        self.build_remote_env_plan(&self.remote_path()).env_prefix
    }

    /// Get the effective exclude patterns by merging config defaults with .rchignore.
    ///
    /// Merge order (deterministic):
    /// 1. Default exclude patterns (from config)
    /// 2. User config exclude patterns (already in transfer_config)
    /// 3. Project-local .rchignore patterns (if present)
    fn get_effective_excludes(&self) -> Vec<String> {
        let mut excludes = self.transfer_config.exclude_patterns.clone();

        // Always protect remote-only runtime scratch/output directories from rsync --delete.
        // Without this, concurrent builds targeting the same remote root can remove each
        // other's in-flight compiler state (e.g. incremental dep-graph.part files).
        for pattern in REMOTE_RUNTIME_EXCLUDE_PATTERNS {
            if !excludes.iter().any(|existing| existing == pattern) {
                excludes.push((*pattern).to_string());
            }
        }

        // Read and merge .rchignore if present
        let rchignore_path = self.project_root.join(".rchignore");
        if let Ok(patterns) = parse_rchignore(&rchignore_path) {
            let original_count = excludes.len();
            for pattern in patterns {
                if !excludes.contains(&pattern) {
                    excludes.push(pattern);
                }
            }
            let added = excludes.len() - original_count;
            if added > 0 {
                info!(
                    "Loaded {} pattern(s) from .rchignore (total: {})",
                    added,
                    excludes.len()
                );
            }
        }

        excludes
    }

    fn compression_level_for_transfer(&self) -> u32 {
        self.transfer_config
            .select_compression_level(self.estimated_transfer_bytes)
    }

    /// Get the remote project path on the worker.
    pub fn remote_path(&self) -> String {
        if let Some(remote_path) = &self.remote_path_override {
            return remote_path.clone();
        }
        let base = self.transfer_config.remote_base.trim_end_matches('/');
        format!("{}/{}/{}", base, self.project_id, self.project_hash)
    }

    /// Build the full remote command string with all wrappers.
    fn build_remote_command(&self, command: &str, toolchain: Option<&ToolchainInfo>) -> String {
        let remote_path = self.remote_path();
        let escaped_remote_path = escape(Cow::from(&remote_path));
        let toolchain_command = wrap_command_with_toolchain(command, toolchain);

        let env_plan = self.build_remote_env_plan(&remote_path);
        if !env_plan.env_prefix.applied.is_empty() {
            debug!("Forwarding env vars: {:?}", env_plan.env_prefix.applied);
        }
        if !env_plan.env_prefix.rejected.is_empty() {
            warn!("Skipping env vars: {:?}", env_plan.env_prefix.rejected);
        }
        let env_command = if env_plan.env_prefix.prefix.is_empty() {
            toolchain_command
        } else {
            format!("{}{}", env_plan.env_prefix.prefix, toolchain_command)
        };

        // Apply color mode environment variables
        let colored_command = wrap_command_with_color(&env_command, self.color_mode);

        // Apply external process timeout wrapper for commands known to hang.
        // Bun tests have known issues where they can hang at 100% CPU indefinitely:
        // - https://github.com/oven-sh/bun/issues/21277 (sync loops block timeout)
        // - https://github.com/oven-sh/bun/issues/6751 (multiple test files cause hangs)
        // The `timeout` command provides a hard kill that works even for CPU-bound loops.
        let timeout_wrapped_command = self.wrap_with_external_timeout(&colored_command);

        // Ensure remote-scoped env directories exist before build execution.
        let ensure_dirs_command = if env_plan.ensure_dirs.is_empty() {
            String::new()
        } else {
            let escaped_dirs = env_plan
                .ensure_dirs
                .iter()
                .map(|dir| escape(Cow::from(dir.as_str())).to_string())
                .collect::<Vec<_>>()
                .join(" ");
            format!("mkdir -p {} && ", escaped_dirs)
        };

        // Force LC_ALL=C to ensure English output for error parsing.
        // Touching the remote root refreshes directory mtime so age-based cleanup
        // treats actively used caches as hot.
        // Wrap command to run in project directory.
        format!(
            "export LC_ALL=C; touch {} && cd {} && {}{}",
            escaped_remote_path, escaped_remote_path, ensure_dirs_command, timeout_wrapped_command
        )
    }

    /// Wrap a command with an external timeout to prevent zombie/stuck processes.
    ///
    /// All remote commands are wrapped with the `timeout` command to ensure they
    /// don't run indefinitely. Timeouts are configurable per command type via
    /// CompilationConfig:
    /// - Bun commands: bun_timeout_sec (default 600s = 10 min) - known hang issues
    /// - Test commands: test_timeout_sec (default 1800s = 30 min)
    /// - Build/other: build_timeout_sec (default 300s = 5 min)
    ///
    /// The timeout wrapper can be disabled entirely via `external_timeout_enabled`.
    ///
    /// Returns the original command unchanged if timeout wrapping is disabled.
    fn wrap_with_external_timeout(&self, command: &str) -> String {
        // Check if external timeout protection is enabled
        if !self.compilation_config.external_timeout_enabled() {
            debug!("External timeout protection disabled by config");
            return command.to_string();
        }

        // Get the appropriate timeout for this command type
        let timeout_duration = self
            .compilation_config
            .timeout_for_kind(self.compilation_kind);
        let timeout_secs = timeout_duration.as_secs();

        // Log the timeout being applied
        let kind_name = match self.compilation_kind {
            Some(CompilationKind::BunTest) => "bun test",
            Some(CompilationKind::BunTypecheck) => "bun typecheck",
            Some(CompilationKind::CargoTest) => "cargo test",
            Some(CompilationKind::CargoNextest) => "cargo nextest",
            Some(CompilationKind::CargoBuild) => "cargo build",
            Some(CompilationKind::CargoCheck) => "cargo check",
            Some(CompilationKind::CargoClippy) => "cargo clippy",
            Some(CompilationKind::CargoDoc) => "cargo doc",
            Some(CompilationKind::CargoBench) => "cargo bench",
            Some(CompilationKind::Rustc) => "rustc",
            Some(CompilationKind::Gcc) => "gcc",
            Some(CompilationKind::Gpp) => "g++",
            Some(CompilationKind::Clang) => "clang",
            Some(CompilationKind::Clangpp) => "clang++",
            Some(CompilationKind::Make) => "make",
            Some(CompilationKind::CmakeBuild) => "cmake build",
            Some(CompilationKind::Ninja) => "ninja",
            Some(CompilationKind::Meson) => "meson",
            None => "unknown",
        };

        info!(
            kind = %kind_name,
            timeout_secs = %timeout_secs,
            "Wrapping command with external timeout protection"
        );

        // Use --signal=KILL to ensure the process dies even if stuck in a CPU loop.
        // The --foreground flag ensures timeout works properly in non-interactive shells.
        // --preserve-status ensures the exit code reflects whether timeout killed it.
        // Exit code 137 (128 + 9) indicates SIGKILL was sent.
        format!(
            "timeout --signal=KILL --foreground --preserve-status {} {}",
            timeout_secs, command
        )
    }

    // =========================================================================
    // Transfer Size Estimation (bd-3hho)
    // =========================================================================

    /// Estimate transfer size using rsync dry-run.
    ///
    /// Returns `None` if estimation fails (e.g., rsync unavailable). Fail-open:
    /// if estimation fails, proceed with transfer rather than blocking.
    #[allow(dead_code)]
    pub async fn estimate_transfer_size(&self, worker: &WorkerConfig) -> Option<TransferEstimate> {
        let effective_excludes = self.get_effective_excludes();
        let start = std::time::Instant::now();

        let mut cmd = Command::new("rsync");
        cmd.env("LC_ALL", "C");

        let identity_file = shellexpand::tilde(&worker.identity_file);
        let escaped_identity = escape(Cow::from(identity_file.as_ref()));

        cmd.arg("-az")
            .arg("--dry-run")
            .arg("--stats")
            .arg("-e")
            .arg(format!(
                "ssh -i {} -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=5",
                escaped_identity
            ));

        for pattern in &effective_excludes {
            cmd.arg("--exclude").arg(pattern);
        }

        let remote_path = self.remote_path();
        let escaped_remote_path = escape(Cow::from(&remote_path));
        let destination = format!("{}@{}:{}", worker.user, worker.host, escaped_remote_path);

        cmd.arg(format!("{}/", self.project_root.display()))
            .arg(&destination);

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = match cmd.output().await {
            Ok(output) => output,
            Err(e) => {
                debug!("Transfer estimation failed (rsync error): {}", e);
                return None;
            }
        };

        let estimation_ms = start.elapsed().as_millis() as u64;
        let stdout = String::from_utf8_lossy(&output.stdout);

        if !output.status.success() {
            debug!(
                "Transfer estimation failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr)
            );
            return None;
        }

        let bytes = crate::transfer::parse_rsync_total_size(&stdout).unwrap_or(0);
        let files = crate::transfer::parse_rsync_total_files(&stdout).unwrap_or(0);

        // Calculate estimated transfer time using configured or default bandwidth
        // Default: 10 MB/s (reasonable for local network)
        let bandwidth_bps = self
            .transfer_config
            .estimated_bandwidth_bps
            .unwrap_or(10 * 1024 * 1024);

        let estimated_time_ms = if bandwidth_bps > 0 {
            (bytes as f64 / bandwidth_bps as f64 * 1000.0).round() as u64
        } else {
            0
        };

        Some(TransferEstimate {
            bytes,
            files,
            estimated_time_ms,
            estimation_ms,
        })
    }

    /// Check if transfer should be skipped based on size/time thresholds.
    ///
    /// Returns `Some(reason)` if transfer should be skipped, `None` if it should proceed.
    #[allow(dead_code)]
    pub async fn should_skip_transfer(&mut self, worker: &WorkerConfig) -> Option<String> {
        // Check if any thresholds are configured
        let max_mb = self.transfer_config.max_transfer_mb;
        let max_time_ms = self.transfer_config.max_transfer_time_ms;

        let needs_estimate =
            self.transfer_config.adaptive_compression || max_mb.is_some() || max_time_ms.is_some();

        if !needs_estimate {
            return None; // No thresholds configured
        }

        // Run estimation
        let estimate = match self.estimate_transfer_size(worker).await {
            Some(e) => e,
            None => {
                self.estimated_transfer_bytes = None;
                debug!("Transfer estimation failed, proceeding with transfer (fail-open)");
                return None;
            }
        };
        self.estimated_transfer_bytes = Some(estimate.bytes);

        // Check size threshold
        if let Some(max_mb) = max_mb {
            let max_bytes = max_mb.saturating_mul(1024 * 1024);
            if estimate.bytes > max_bytes {
                let estimated_mb = estimate.bytes as f64 / (1024.0 * 1024.0);
                return Some(format!(
                    "Transfer size ({:.2} MB) exceeds threshold ({:.2} MB)",
                    estimated_mb, max_mb as f64
                ));
            }
        }

        // Check time threshold
        if let Some(max_time) = max_time_ms
            && estimate.estimated_time_ms > max_time
        {
            return Some(format!(
                "Estimated transfer time ({} ms) exceeds threshold ({} ms)",
                estimate.estimated_time_ms, max_time
            ));
        }

        None
    }

    /// Build rsync command for sync_to_remote.
    fn build_sync_command(
        &self,
        worker: &WorkerConfig,
        destination: &str,
        escaped_remote_path: &str,
        effective_excludes: &[String],
    ) -> Command {
        let mut cmd = Command::new("rsync");
        // Force C locale for consistent output parsing
        cmd.env("LC_ALL", "C");

        let identity_file = shellexpand::tilde(&worker.identity_file);
        let escaped_identity = escape(Cow::from(identity_file.as_ref()));
        let ssh_command = self.build_rsync_ssh_command(escaped_identity.as_ref());

        cmd.arg("-az") // Archive mode + compression
            .arg("--stats") // Structured output for parse_rsync_bytes/files
            .arg("--delete") // Remove extraneous files from destination
            .arg("-e")
            .arg(ssh_command);

        // Create remote directory implicitly using rsync-path wrapper
        // This saves a separate SSH handshake for 'mkdir -p'
        cmd.arg("--rsync-path")
            .arg(format!("mkdir -p {} && rsync", escaped_remote_path));

        // Add exclude patterns (config defaults + .rchignore)
        for pattern in effective_excludes {
            cmd.arg("--exclude").arg(pattern);
        }

        // Add zstd compression if available (rsync 3.2.3+)
        let compression_level = self.compression_level_for_transfer();
        if compression_level > 0 {
            cmd.arg("--compress-choice=zstd");
            cmd.arg(format!("--compress-level={}", compression_level));
        }

        // Add bandwidth limit if configured (bd-3hho)
        if let Some(bwlimit) = self.transfer_config.bwlimit_kbps
            && bwlimit > 0
        {
            cmd.arg(format!("--bwlimit={}", bwlimit));
        }

        // Source and destination
        cmd.arg(format!("{}/", self.project_root.display())) // Trailing slash = contents only
            .arg(destination);

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd
    }

    /// Synchronize local project to remote worker.
    ///
    /// Uses retry logic with exponential backoff for transient network errors.
    pub async fn sync_to_remote(&self, worker: &WorkerConfig) -> Result<SyncResult> {
        let remote_path = self.remote_path();
        let escaped_remote_path = escape(Cow::from(&remote_path));
        let destination = format!("{}@{}:{}", worker.user, worker.host, escaped_remote_path);

        // Get effective excludes (config defaults + .rchignore)
        let effective_excludes = self.get_effective_excludes();

        if use_mock_transport(worker) {
            // Mock path also uses retry logic for consistent behavior
            // Create MockRsync ONCE and share via Arc so failure counters persist across retries
            let rsync = std::sync::Arc::new(MockRsync::new(MockRsyncConfig::from_env()));
            let project_root_str = self.project_root.display().to_string();
            let retry_config = self.transfer_config.retry.clone();
            let result = retry_with_backoff(&retry_config, "mock_sync_to_remote", || {
                let rsync = rsync.clone();
                let project_root = project_root_str.clone();
                let dest = destination.clone();
                let excludes = effective_excludes.clone();
                async move { rsync.sync_to_remote(&project_root, &dest, &excludes).await }
            })
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

        debug!("Effective exclude patterns: {:?}", effective_excludes);

        let start = std::time::Instant::now();

        // Execute rsync with retry logic for transient errors
        let output =
            execute_rsync_with_retry(&self.transfer_config.retry, "sync_to_remote", || {
                self.build_sync_command(
                    worker,
                    &destination,
                    &escaped_remote_path,
                    &effective_excludes,
                )
            })
            .await?;

        let duration = start.elapsed();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            // Check if the failure is retryable (it wasn't if we got here)
            if is_retryable_transport_error(&anyhow::anyhow!("{}", stderr)) {
                warn!(
                    "rsync failed with retryable error (retries exhausted): {}",
                    stderr
                );
            } else {
                warn!("rsync failed: {}", stderr);
            }
            return Err(TransferError::SyncFailed {
                reason: "rsync failed".to_string(),
                exit_code: output.status.code(),
                stderr: stderr.to_string(),
            }
            .into());
        }

        // Verify transfer completed successfully by checking for partial transfer indicators.
        // rsync can exit with code 0 even if interrupted mid-file in some edge cases.
        // Look for warning signs in stderr that indicate incomplete transfer.
        if !stderr.is_empty() {
            let stderr_lower = stderr.to_lowercase();
            let partial_indicators = [
                "partial transfer",
                "connection unexpectedly closed",
                "write error",
                "read error",
                "truncated file",
            ];
            if let Some(indicator) = partial_indicators
                .iter()
                .find(|ind| stderr_lower.contains(*ind))
            {
                warn!(
                    "rsync reported potential partial transfer (matched '{}'): {}",
                    indicator,
                    stderr.lines().next().unwrap_or(&stderr)
                );
            }
        }

        info!("Sync completed in {}ms", duration.as_millis());

        Ok(SyncResult {
            bytes_transferred: parse_rsync_bytes(&stdout),
            files_transferred: parse_rsync_files(&stdout),
            duration_ms: duration.as_millis() as u64,
        })
    }

    /// Synchronize local project to remote worker with streaming output.
    ///
    /// The `on_line` callback receives rsync progress lines for UI rendering.
    pub async fn sync_to_remote_streaming<F>(
        &self,
        worker: &WorkerConfig,
        mut on_line: F,
    ) -> Result<SyncResult>
    where
        F: FnMut(&str),
    {
        let remote_path = self.remote_path();
        let escaped_remote_path = escape(Cow::from(&remote_path));
        let destination = format!("{}@{}:{}", worker.user, worker.host, escaped_remote_path);

        // Get effective excludes (config defaults + .rchignore)
        let effective_excludes = self.get_effective_excludes();

        if use_mock_transport(worker) {
            let rsync = MockRsync::new(MockRsyncConfig::from_env());
            let result = rsync
                .sync_to_remote(
                    &self.project_root.display().to_string(),
                    &destination,
                    &effective_excludes,
                )
                .await?;
            return Ok(SyncResult {
                bytes_transferred: result.bytes_transferred,
                files_transferred: result.files_transferred,
                duration_ms: result.duration_ms,
            });
        }

        info!(
            "Syncing {} -> {} on {} (streaming)",
            self.project_root.display(),
            remote_path,
            worker.id
        );

        debug!("Effective exclude patterns: {:?}", effective_excludes);

        let mut cmd = Command::new("rsync");
        // Force C locale for consistent output parsing
        cmd.env("LC_ALL", "C");

        let identity_file = shellexpand::tilde(&worker.identity_file);
        let escaped_identity = escape(Cow::from(identity_file.as_ref()));

        let ssh_command = self.build_rsync_ssh_command(escaped_identity.as_ref());

        cmd.arg("-az") // Archive mode + compression
            .arg("--delete") // Remove extraneous files from destination
            .arg("--info=progress2")
            .arg("--info=stats2")
            .arg("-e")
            .arg(ssh_command);

        // Create remote directory implicitly using rsync-path wrapper
        cmd.arg("--rsync-path")
            .arg(format!("mkdir -p {} && rsync", escaped_remote_path));

        // Add exclude patterns (config defaults + .rchignore)
        for pattern in &effective_excludes {
            cmd.arg("--exclude").arg(pattern);
        }

        // Add zstd compression if available (rsync 3.2.3+)
        let compression_level = self.compression_level_for_transfer();
        if compression_level > 0 {
            cmd.arg("--compress-choice=zstd");
            cmd.arg(format!("--compress-level={}", compression_level));
        }

        // Add bandwidth limit if configured (bd-3hho)
        if let Some(bwlimit) = self.transfer_config.bwlimit_kbps
            && bwlimit > 0
        {
            cmd.arg(format!("--bwlimit={}", bwlimit));
        }

        // Source and destination
        cmd.arg(format!("{}/", self.project_root.display())) // Trailing slash = contents only
            .arg(&destination);

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        debug!(
            "Running (streaming): rsync {:?}",
            cmd.as_std().get_args().collect::<Vec<_>>()
        );

        let (output, duration_ms) = run_command_streaming(cmd, |line| {
            on_line(line);
        })
        .await?;

        Ok(SyncResult {
            bytes_transferred: parse_rsync_bytes(&output),
            files_transferred: parse_rsync_files(&output),
            duration_ms,
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
        let wrapped_command = self.build_remote_command(command, toolchain);

        if use_mock_transport(worker) {
            let mut client = MockSshClient::new(worker.clone(), MockConfig::from_env());
            client.connect().await?;
            let result = client.execute(&wrapped_command).await;
            if let Err(e) = client.disconnect().await {
                warn!("Failed to disconnect mock SSH client: {}", e);
            }
            return result;
        }

        // Mask sensitive data (API keys, tokens) before logging
        info!(
            "Executing on {}: {}",
            worker.id,
            rch_common::util::mask_sensitive_command(command)
        );

        #[cfg(not(unix))]
        {
            return Err(crate::error::PlatformError::UnixOnly {
                feature: "SSH remote execution".to_string(),
            }
            .into());
        }

        #[cfg(unix)]
        {
            let result = self
                .execute_over_ssh_streaming(worker, &wrapped_command, |_| {}, |_| {})
                .await?;

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
    }

    #[cfg(unix)]
    async fn execute_over_ssh_streaming<F, G>(
        &self,
        worker: &WorkerConfig,
        remote_script: &str,
        mut on_stdout: F,
        mut on_stderr: G,
    ) -> Result<CommandResult>
    where
        F: FnMut(&str),
        G: FnMut(&str),
    {
        let destination = format!("{}@{}", worker.user, worker.host);
        let identity_file = shellexpand::tilde(&worker.identity_file);

        let mut cmd = Command::new("ssh");
        cmd.arg("-o").arg("BatchMode=yes");
        cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
        cmd.arg("-o").arg(format!(
            "ConnectTimeout={}",
            self.ssh_options.connect_timeout.as_secs().max(1)
        ));
        cmd.arg("-i").arg(identity_file.as_ref());

        if let Some(interval) = self.ssh_options.server_alive_interval {
            let secs = interval.as_secs();
            if secs > 0 {
                cmd.arg("-o").arg(format!("ServerAliveInterval={secs}"));
            }
        }

        // IMPORTANT: pass the script via stdin (`sh -s`) to avoid quoting issues with
        // newlines/comments in `remote_script`. This preserves the prior mux behavior
        // where the script is an argv payload, not re-parsed by the user's login shell.
        cmd.arg(&destination).arg("sh").arg("-s");

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let start = std::time::Instant::now();
        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn ssh to {}", destination))?;

        if let Some(mut stdin) = child.stdin.take() {
            // Feed the script, then close stdin so `sh -s` begins execution.
            stdin
                .write_all(remote_script.as_bytes())
                .await
                .context("Failed to write remote script to ssh stdin")?;
            stdin
                .write_all(b"\n")
                .await
                .context("Failed to finalize remote script")?;
            drop(stdin);
        }

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let (tx, mut rx) = tokio::sync::mpsc::channel(100);

        enum StreamEvent {
            Stdout(String),
            Stderr(String),
        }

        // Spawn stdout reader
        if let Some(out) = stdout {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(out);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) => break,
                        Ok(_) => {
                            if tx.send(StreamEvent::Stdout(line.clone())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        // Spawn stderr reader
        if let Some(err) = stderr {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(err);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) => break,
                        Ok(_) => {
                            if tx.send(StreamEvent::Stderr(line.clone())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        drop(tx);

        let mut stdout_acc = String::new();
        let mut stderr_acc = String::new();

        let command_timeout = self.ssh_options.command_timeout;
        const MAX_OUTPUT_SIZE: usize = 10 * 1024 * 1024;

        let status = match tokio::time::timeout(command_timeout, async {
            while let Some(event) = rx.recv().await {
                match event {
                    StreamEvent::Stdout(line) => {
                        on_stdout(&line);
                        if stdout_acc.len() < MAX_OUTPUT_SIZE {
                            stdout_acc.push_str(&line);
                            if stdout_acc.len() >= MAX_OUTPUT_SIZE {
                                stdout_acc.push_str("\n...[output truncated]...\n");
                            }
                        }
                    }
                    StreamEvent::Stderr(line) => {
                        on_stderr(&line);
                        if stderr_acc.len() < MAX_OUTPUT_SIZE {
                            stderr_acc.push_str(&line);
                            if stderr_acc.len() >= MAX_OUTPUT_SIZE {
                                stderr_acc.push_str("\n...[output truncated]...\n");
                            }
                        }
                    }
                }
            }

            child.wait().await.context("Failed to wait for ssh command")
        })
        .await
        {
            Ok(status) => status?,
            Err(_) => {
                // Best-effort: kill local ssh process so the remote command is terminated.
                let _ = child.kill().await;
                anyhow::bail!("SSH command timed out after {:?}", command_timeout);
            }
        };

        let duration = start.elapsed();
        Ok(CommandResult {
            exit_code: status.code().unwrap_or(-1),
            stdout: stdout_acc,
            stderr: stderr_acc,
            duration_ms: duration.as_millis() as u64,
        })
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
        let wrapped_command = self.build_remote_command(command, toolchain);

        if use_mock_transport(worker) {
            let mut client = MockSshClient::new(worker.clone(), MockConfig::from_env());
            client.connect().await?;
            let result = client
                .execute_streaming(&wrapped_command, on_stdout, on_stderr)
                .await;
            if let Err(e) = client.disconnect().await {
                warn!("Failed to disconnect mock SSH client: {}", e);
            }
            return result;
        }

        #[cfg(not(unix))]
        {
            return Err(crate::error::PlatformError::UnixOnly {
                feature: "SSH remote streaming".to_string(),
            }
            .into());
        }

        #[cfg(unix)]
        {
            self.execute_over_ssh_streaming(worker, &wrapped_command, on_stdout, on_stderr)
                .await
        }
    }

    /// Build rsync command for retrieve_artifacts.
    fn build_retrieve_command(
        &self,
        worker: &WorkerConfig,
        escaped_remote_path: &str,
        artifact_patterns: &[String],
    ) -> Command {
        let mut cmd = Command::new("rsync");
        // Force C locale for consistent output parsing
        cmd.env("LC_ALL", "C");

        let identity_file = shellexpand::tilde(&worker.identity_file);
        let escaped_identity = escape(Cow::from(identity_file.as_ref()));
        let ssh_command = self.build_rsync_ssh_command(escaped_identity.as_ref());

        // Use --safe-links to prevent symlink traversal attacks from malicious workers.
        // --stats is required so parse_rsync_bytes/parse_rsync_files can read transfer
        // counts from stdout; without it rsync produces no output and the parsers
        // return 0, causing a false "No artifacts retrieved" warning.
        cmd.arg("-az")
            .arg("--stats")
            .arg("--safe-links")
            .arg("-e")
            .arg(ssh_command);

        // Add zstd compression
        let compression_level = self.compression_level_for_transfer();
        if compression_level > 0 {
            cmd.arg("--compress-choice=zstd");
            cmd.arg(format!("--compress-level={}", compression_level));
        }

        // Add bandwidth limit if configured (bd-3hho)
        if let Some(bwlimit) = self.transfer_config.bwlimit_kbps
            && bwlimit > 0
        {
            cmd.arg(format!("--bwlimit={}", bwlimit));
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
        cmd
    }

    fn build_rsync_ssh_command(&self, escaped_identity: &str) -> String {
        let mut command = format!(
            "ssh -i {} -o StrictHostKeyChecking=accept-new -o BatchMode=yes",
            escaped_identity
        );

        #[cfg(unix)]
        {
            if let Some(interval) = self.ssh_options.server_alive_interval {
                let secs = interval.as_secs();
                if secs > 0 {
                    command.push_str(&format!(" -o ServerAliveInterval={secs}"));
                }
            }

            if let Some(idle) = self.ssh_options.control_persist_idle {
                let control_dir = self.rsync_control_dir();
                if let Err(e) = std::fs::create_dir_all(&control_dir) {
                    warn!(
                        "Failed to create rsync SSH control dir {:?}: {}",
                        control_dir, e
                    );
                } else {
                    // Set restrictive permissions (0700) to prevent symlink attacks
                    // and unauthorized access to SSH control sockets
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(e) = std::fs::set_permissions(
                        &control_dir,
                        std::fs::Permissions::from_mode(0o700),
                    ) {
                        warn!(
                            "Failed to set permissions on rsync SSH control dir {:?}: {}",
                            control_dir, e
                        );
                    }
                }

                let control_path = control_dir.join("rch-rsync-%C");
                let escaped_control_path = escape(control_path.to_string_lossy());
                command.push_str(" -o ControlMaster=auto");
                command.push_str(&format!(" -o ControlPath={}", escaped_control_path));

                if idle.is_zero() {
                    command.push_str(" -o ControlPersist=no");
                } else {
                    command.push_str(&format!(" -o ControlPersist={}s", idle.as_secs()));
                }
            }
        }

        command
    }

    fn rsync_control_dir(&self) -> PathBuf {
        // Prefer ~/.ssh/rch to avoid exceeding the Unix socket path limit
        // (104 bytes on macOS). See rch-common/src/ssh.rs for rationale.
        if let Some(home) = dirs::home_dir() {
            home.join(".ssh").join("rch")
        } else if let Some(runtime_dir) = dirs::runtime_dir() {
            runtime_dir.join("rch-ssh")
        } else {
            // Include username in fallback path to prevent cross-user conflicts
            let username = std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| "unknown".to_string());
            std::env::temp_dir().join(format!("rch-ssh-{}", username))
        }
    }

    /// Retrieve build artifacts from the remote worker.
    ///
    /// Uses retry logic with exponential backoff for transient network errors.
    pub async fn retrieve_artifacts(
        &self,
        worker: &WorkerConfig,
        artifact_patterns: &[String],
    ) -> Result<SyncResult> {
        let remote_path = self.remote_path();
        let escaped_remote_path = escape(Cow::from(&remote_path));

        if use_mock_transport(worker) {
            // Mock path also uses retry logic for consistent behavior
            // Create MockRsync ONCE and share via Arc so failure counters persist across retries
            let rsync = std::sync::Arc::new(MockRsync::new(MockRsyncConfig::from_env()));
            let source = format!("{}@{}:{}/", worker.user, worker.host, escaped_remote_path);
            let project_root_str = self.project_root.display().to_string();
            let patterns = artifact_patterns.to_vec();
            let retry_config = self.transfer_config.retry.clone();
            let result = retry_with_backoff(&retry_config, "mock_retrieve_artifacts", || {
                let rsync = rsync.clone();
                let src = source.clone();
                let dest = project_root_str.clone();
                let pats = patterns.clone();
                async move { rsync.retrieve_artifacts(&src, &dest, &pats).await }
            })
            .await?;
            return Ok(SyncResult {
                bytes_transferred: result.bytes_transferred,
                files_transferred: result.files_transferred,
                duration_ms: result.duration_ms,
            });
        }

        info!("Retrieving artifacts from {} on {}", remote_path, worker.id);

        let start = std::time::Instant::now();

        // Execute rsync with retry logic for transient errors
        let output =
            execute_rsync_with_retry(&self.transfer_config.retry, "retrieve_artifacts", || {
                self.build_retrieve_command(worker, &escaped_remote_path, artifact_patterns)
            })
            .await?;

        let duration = start.elapsed();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            warn!("Artifact retrieval failed: {}", stderr);
            return Err(TransferError::SyncFailed {
                reason: "rsync artifact retrieval failed".to_string(),
                exit_code: output.status.code(),
                stderr: stderr.clone(),
            }
            .into());
        }

        let bytes_transferred = parse_rsync_bytes(&stdout);
        let files_transferred = parse_rsync_files(&stdout);

        // Warn if no artifacts were retrieved - this may indicate a build failure
        // or misconfigured artifact patterns. We don't fail here because some
        // commands (e.g., cargo check) don't produce artifacts.
        if files_transferred == 0 && bytes_transferred == 0 {
            warn!(
                "No artifacts retrieved from {} - build may have failed or artifact patterns may be misconfigured",
                worker.id
            );
            debug!("Artifact patterns used: {:?}", artifact_patterns);
        }

        info!(
            "Artifacts retrieved in {}ms ({} files, {} bytes)",
            duration.as_millis(),
            files_transferred,
            bytes_transferred
        );

        Ok(SyncResult {
            bytes_transferred,
            files_transferred,
            duration_ms: duration.as_millis() as u64,
        })
    }

    /// Retrieve build artifacts with streaming progress output.
    pub async fn retrieve_artifacts_streaming<F>(
        &self,
        worker: &WorkerConfig,
        artifact_patterns: &[String],
        mut on_line: F,
    ) -> Result<SyncResult>
    where
        F: FnMut(&str),
    {
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

        info!(
            "Retrieving artifacts from {} on {} (streaming)",
            remote_path, worker.id
        );

        let mut cmd = Command::new("rsync");
        // Force C locale for consistent output parsing
        cmd.env("LC_ALL", "C");

        let identity_file = shellexpand::tilde(&worker.identity_file);
        let escaped_identity = escape(Cow::from(identity_file.as_ref()));

        let ssh_command = self.build_rsync_ssh_command(escaped_identity.as_ref());

        cmd.arg("-az")
            .arg("--info=progress2")
            .arg("--info=stats2")
            .arg("-e")
            .arg(ssh_command);

        // Add zstd compression
        let compression_level = self.compression_level_for_transfer();
        if compression_level > 0 {
            cmd.arg("--compress-choice=zstd");
            cmd.arg(format!("--compress-level={}", compression_level));
        }

        // Add bandwidth limit if configured (bd-3hho)
        if let Some(bwlimit) = self.transfer_config.bwlimit_kbps
            && bwlimit > 0
        {
            cmd.arg(format!("--bwlimit={}", bwlimit));
        }

        // Prune empty directories to prevent cluttering local project
        cmd.arg("--prune-empty-dirs");

        // Essential: Include all directories so rsync can traverse to match patterns.
        cmd.arg("--include").arg("*/");

        for pattern in artifact_patterns {
            cmd.arg("--include").arg(pattern);
        }
        cmd.arg("--exclude").arg("*");

        let source = format!("{}@{}:{}/", worker.user, worker.host, escaped_remote_path);
        cmd.arg(&source)
            .arg(format!("{}/", self.project_root.display()));

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        debug!(
            "Running artifact retrieval (streaming): rsync {:?}",
            cmd.as_std().get_args().collect::<Vec<_>>()
        );

        let (output, duration_ms) = run_command_streaming(cmd, |line| {
            on_line(line);
        })
        .await?;

        Ok(SyncResult {
            bytes_transferred: parse_rsync_bytes(&output),
            files_transferred: parse_rsync_files(&output),
            duration_ms,
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

        #[cfg(not(unix))]
        {
            return Err(crate::error::PlatformError::UnixOnly {
                feature: "SSH remote cleanup".to_string(),
            }
            .into());
        }

        #[cfg(unix)]
        {
            let mut client = SshClient::new(worker.clone(), self.ssh_options.clone());
            client.connect().await?;

            let result = client
                .execute(&format!("rm -rf {}", escaped_remote_path))
                .await;

            if let Err(e) = client.disconnect().await {
                warn!("Failed to disconnect SSH client after cleanup: {}", e);
            }

            let result = result?;

            if !result.success() {
                warn!("Cleanup failed: {}", result.stderr);
            }

            Ok(())
        }
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

/// Estimate of transfer size from rsync dry-run (bd-3hho).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TransferEstimate {
    /// Total bytes that would be transferred.
    pub bytes: u64,
    /// Total files that would be transferred.
    pub files: u32,
    /// Estimated transfer time in milliseconds (based on configured bandwidth).
    pub estimated_time_ms: u64,
    /// Time taken to run the estimation in milliseconds.
    pub estimation_ms: u64,
}

/// Parse bytes transferred from rsync output.
fn parse_rsync_bytes(output: &str) -> u64 {
    // rsync output contains "sent X bytes  received Y bytes"
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("Total bytes sent:")
            && let Some(bytes_str) = rest.split_whitespace().next()
            && let Ok(bytes) = bytes_str.replace(',', "").parse()
        {
            return bytes;
        }
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
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("Number of files transferred:")
            && let Some(count) = rest.split_whitespace().next()
            && let Ok(parsed) = count.replace(',', "").parse::<u32>()
        {
            return parsed;
        }
        if let Some(rest) = line.strip_prefix("Number of files:")
            && let Some(count) = rest.split_whitespace().next()
            && let Ok(parsed) = count.replace(',', "").parse::<u32>()
        {
            return parsed;
        }
    }

    // If we couldn't parse structured stats, return 0 rather than guessing.
    // The previous heuristic of counting non-empty lines was unreliable as it
    // would count progress lines, stats, and error messages as files.
    0
}

// =============================================================================
// Transfer Estimation Parsers (bd-3hho)
// =============================================================================

/// Parse total file size from rsync --dry-run --stats output.
///
/// Looks for "Total file size:" line which shows the total bytes that would
/// be transferred (not the delta, but the full file size).
#[allow(dead_code)]
fn parse_rsync_total_size(output: &str) -> Option<u64> {
    for line in output.lines() {
        // "Total file size: 1,234,567 bytes"
        if let Some(rest) = line.strip_prefix("Total file size:") {
            let cleaned = rest.trim().replace(',', "");
            if let Some(bytes_str) = cleaned.split_whitespace().next() {
                return bytes_str.parse().ok();
            }
        }
        // Also check "Total transferred file size:" for delta transfers
        if let Some(rest) = line.strip_prefix("Total transferred file size:") {
            let cleaned = rest.trim().replace(',', "");
            if let Some(bytes_str) = cleaned.split_whitespace().next() {
                return bytes_str.parse().ok();
            }
        }
    }
    None
}

/// Parse total file count from rsync --dry-run --stats output.
///
/// Looks for "Number of files:" or "Number of regular files:" line.
#[allow(dead_code)]
fn parse_rsync_total_files(output: &str) -> Option<u32> {
    for line in output.lines() {
        // "Number of files: 1,234 (reg: 1,000, dir: 234)"
        if let Some(rest) = line.strip_prefix("Number of files:") {
            let cleaned = rest.trim().replace(',', "");
            if let Some(count_str) = cleaned.split_whitespace().next() {
                return count_str.parse().ok();
            }
        }
        // "Number of regular files transferred: 500"
        if let Some(rest) = line.strip_prefix("Number of regular files transferred:") {
            let cleaned = rest.trim().replace(',', "");
            if let Some(count_str) = cleaned.split_whitespace().next() {
                return count_str.parse().ok();
            }
        }
    }
    None
}

async fn run_command_streaming<F>(mut cmd: Command, mut on_line: F) -> Result<(String, u64)>
where
    F: FnMut(&str),
{
    let start = TokioInstant::now();
    let mut child = cmd.spawn().context("Failed to execute rsync")?;

    let stdout = child.stdout.take().context("Failed to capture stdout")?;
    let stderr = child.stderr.take().context("Failed to capture stderr")?;

    // Use a channel to aggregate lines from both streams
    // Capacity 100 ensures we don't consume too much memory if on_line is slow,
    // but allows some buffering.
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let tx_stderr = tx.clone();

    let tx_stdout = tx.clone();

    // Spawn task for stdout
    tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if tx_stdout.send(line).await.is_err() {
                break;
            }
        }
    });

    // Spawn task for stderr
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if tx_stderr.send(line).await.is_err() {
                break;
            }
        }
    });

    // Drop the original tx so rx will close when both tasks are done
    drop(tx);

    let mut combined = String::new();
    const MAX_RSYNC_OUTPUT: usize = 10 * 1024 * 1024;
    while let Some(text) = rx.recv().await {
        on_line(&text);
        if combined.len() < MAX_RSYNC_OUTPUT {
            combined.push_str(&text);
            combined.push('\n');
            if combined.len() >= MAX_RSYNC_OUTPUT {
                combined.push_str("...[output truncated]...\n");
            }
        }
    }

    let status = child.wait().await.context("Failed to wait on rsync")?;
    if !status.success() {
        return Err(TransferError::SyncFailed {
            reason: "rsync failed".to_string(),
            exit_code: status.code(),
            stderr: combined.trim().to_string(),
        }
        .into());
    }

    Ok((combined, start.elapsed().as_millis() as u64))
}

fn normalize_hash_root(path: &Path) -> PathBuf {
    normalize_project_path_with_policy(path, &PathTopologyPolicy::default())
        .map(|normalized| normalized.canonical_path().to_path_buf())
        .or_else(|_| std::fs::canonicalize(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn update_hasher_with_file_fingerprint(hasher: &mut blake3::Hasher, file_path: &Path, label: &str) {
    let Ok(metadata) = std::fs::metadata(file_path) else {
        return;
    };

    hasher.update(label.as_bytes());
    hasher.update(&metadata.len().to_le_bytes());
    if let Ok(modified) = metadata.modified()
        && let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH)
    {
        hasher.update(&duration.as_nanos().to_le_bytes());
    }

    if metadata.len() <= PROJECT_HASH_CONTENT_LIMIT_BYTES
        && let Ok(bytes) = std::fs::read(file_path)
    {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
}

fn collect_hash_roots(project_path: &Path, dependency_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();
    roots.insert(normalize_hash_root(project_path));
    for root in dependency_roots {
        roots.insert(normalize_hash_root(root));
    }
    roots.into_iter().collect()
}

/// Compute a project hash that includes dependency-closure fingerprints.
///
/// The resulting value is deterministic across `/dp` vs `/data/projects` alias
/// forms and changes when any tracked key file for any closure member changes.
pub fn compute_project_hash_with_dependency_roots(
    project_path: &Path,
    dependency_roots: &[PathBuf],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"rch-project-hash-v2");

    for root in collect_hash_roots(project_path, dependency_roots) {
        hasher.update(b"\0root\0");
        hasher.update(root.to_string_lossy().as_bytes());
        for filename in PROJECT_HASH_KEY_FILES {
            update_hasher_with_file_fingerprint(&mut hasher, &root.join(filename), filename);
        }
    }

    hasher.finalize().to_hex()[..16].to_string()
}

/// Compute a hash of the project for cache invalidation.
pub fn compute_project_hash(project_path: &Path) -> String {
    compute_project_hash_with_dependency_roots(project_path, &[])
}

/// Validate a project identifier for safe use in file paths.
///
/// Rejects:
/// - Path traversal sequences (.., ./)
/// - Null bytes
/// - Shell metacharacters that could cause injection
/// - Names starting with hyphen (could be interpreted as flags)
///
/// Returns the sanitized name or "unknown" if invalid.
fn sanitize_project_id(name: &str) -> String {
    // Reject obviously dangerous patterns
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains("..")
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.starts_with('-')
    {
        return "unknown".to_string();
    }

    // Reject shell metacharacters that could cause injection
    // Allow: alphanumeric, underscore, hyphen, dot (but not leading dot for hidden files)
    let is_safe = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        && !name.starts_with('.');

    if is_safe {
        name.to_string()
    } else {
        // Replace unsafe characters with underscores
        let sanitized: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        // Remove leading dots after sanitization
        let result = sanitized.trim_start_matches('.');
        // If result is empty after trimming, return "unknown"
        if result.is_empty() {
            "unknown".to_string()
        } else {
            result.to_string()
        }
    }
}

/// Get the project identifier from a path.
///
/// Extracts the directory name and sanitizes it for safe use in remote paths.
/// Returns "unknown" if the path is invalid or the name contains dangerous characters.
pub fn project_id_from_path(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    sanitize_project_id(name)
}

/// Default artifact patterns for Rust projects.
pub fn default_rust_artifact_patterns() -> Vec<String> {
    vec![
        "target/debug/**".to_string(),
        "target/release/**".to_string(),
        "target/doc/**".to_string(),
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
    use rch_common::WorkerId;
    use rch_common::mock::Phase;
    use rch_common::test_guard;
    use serial_test::serial;

    #[test]
    fn test_remote_path() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        let output = "sent 1,234 bytes  received 567 bytes  1800.50 bytes/sec";
        assert_eq!(parse_rsync_bytes(output), 1234);

        let empty = "";
        assert_eq!(parse_rsync_bytes(empty), 0);
    }

    #[test]
    fn test_parse_rsync_bytes_total_format() {
        let _guard = test_guard!();
        // Test "Total bytes sent:" format (newer rsync versions)
        let output = "Total bytes sent: 45,678\nTotal bytes received: 123";
        assert_eq!(parse_rsync_bytes(output), 45678);
    }

    #[test]
    fn test_parse_rsync_bytes_no_commas() {
        let _guard = test_guard!();
        let output = "sent 999 bytes  received 100 bytes  1000.00 bytes/sec";
        assert_eq!(parse_rsync_bytes(output), 999);
    }

    #[test]
    fn test_parse_rsync_bytes_large_number() {
        let _guard = test_guard!();
        let output = "sent 1,234,567,890 bytes  received 100 bytes  total";
        assert_eq!(parse_rsync_bytes(output), 1234567890);
    }

    #[test]
    fn test_parse_rsync_files() {
        let _guard = test_guard!();
        // Test "Number of files transferred:" format
        let output = "Number of files transferred: 42";
        assert_eq!(parse_rsync_files(output), 42);
    }

    #[test]
    fn test_parse_rsync_files_with_comma() {
        let _guard = test_guard!();
        let output = "Number of files transferred: 1,234";
        assert_eq!(parse_rsync_files(output), 1234);
    }

    #[test]
    fn test_parse_rsync_files_number_of_files_format() {
        let _guard = test_guard!();
        // Test "Number of files:" format (alternate rsync output)
        let output = "Number of files: 100\nsome other line";
        assert_eq!(parse_rsync_files(output), 100);
    }

    #[test]
    fn test_parse_rsync_files_empty() {
        let _guard = test_guard!();
        let empty = "";
        assert_eq!(parse_rsync_files(empty), 0);
    }

    #[test]
    fn test_parse_rsync_files_no_structured_stats_returns_zero() {
        let _guard = test_guard!();
        // When no "Number of files" line exists, return 0 rather than guessing.
        let output = "file1.txt\nfile2.txt\nfile3.txt";
        assert_eq!(parse_rsync_files(output), 0);
    }

    #[test]
    fn test_parse_rsync_files_no_structured_stats_ignores_sent_line() {
        let _guard = test_guard!();
        // No structured stats: still return 0, even if "sent" appears.
        let output = "file1.txt\nfile2.txt\nsent 100 bytes";
        assert_eq!(parse_rsync_files(output), 0);
    }

    #[test]
    fn test_default_artifact_patterns() {
        let _guard = test_guard!();
        let patterns = default_rust_artifact_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.contains("debug")));
        assert!(patterns.iter().any(|p| p.contains("release")));
    }

    #[test]
    fn test_default_bun_artifact_patterns() {
        let _guard = test_guard!();
        let patterns = default_bun_artifact_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.contains("coverage")));
        assert!(patterns.iter().any(|p| p.contains("tsbuildinfo")));
    }

    #[test]
    fn test_default_rust_test_artifact_patterns() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
    fn test_compute_project_hash_basic() {
        let _guard = test_guard!();
        use std::fs;
        use tempfile::tempdir;

        let dir = tempdir().expect("create temp dir");
        let path = dir.path();

        // Create a Cargo.toml file
        fs::write(path.join("Cargo.toml"), "[package]\nname = \"test\"").expect("write cargo");

        let hash1 = compute_project_hash(path);
        assert!(!hash1.is_empty());
        assert_eq!(hash1.len(), 16); // Should be 16 hex chars
    }

    #[test]
    fn test_compute_project_hash_different_paths() {
        let _guard = test_guard!();
        use tempfile::tempdir;

        let dir1 = tempdir().expect("create temp dir 1");
        let dir2 = tempdir().expect("create temp dir 2");

        let hash1 = compute_project_hash(dir1.path());
        let hash2 = compute_project_hash(dir2.path());

        // Different paths should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_project_hash_includes_key_files() {
        let _guard = test_guard!();
        use std::fs;
        use std::thread::sleep;
        use std::time::Duration;
        use tempfile::tempdir;

        let dir = tempdir().expect("create temp dir");
        let path = dir.path();

        let hash_before = compute_project_hash(path);

        // Add a key file (Cargo.toml)
        sleep(Duration::from_millis(10)); // Ensure mtime differs
        fs::write(path.join("Cargo.toml"), "[package]\nname = \"test\"").expect("write cargo");

        let hash_after = compute_project_hash(path);

        // Hash should change when key file is added
        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn test_compute_project_hash_with_dependency_roots_changes_on_dependency_manifest_change() {
        let _guard = test_guard!();
        use std::fs;
        use tempfile::tempdir;

        let root = tempdir().expect("create root dir");
        let dep = tempdir().expect("create dep dir");
        fs::write(root.path().join("Cargo.toml"), "[package]\nname = \"root\"")
            .expect("write root cargo");
        fs::write(dep.path().join("Cargo.toml"), "[package]\nname = \"dep\"")
            .expect("write dep cargo");

        let hash_before =
            compute_project_hash_with_dependency_roots(root.path(), &[dep.path().to_path_buf()]);

        fs::write(
            dep.path().join("Cargo.toml"),
            "[package]\nname = \"dep\"\nversion = \"0.2.0\"",
        )
        .expect("rewrite dep cargo");
        let hash_after =
            compute_project_hash_with_dependency_roots(root.path(), &[dep.path().to_path_buf()]);

        assert_ne!(
            hash_before, hash_after,
            "dependency manifest changes must invalidate closure hash"
        );
    }

    #[test]
    fn test_compute_project_hash_with_dependency_roots_ignores_non_key_noise_changes() {
        let _guard = test_guard!();
        use std::fs;
        use tempfile::tempdir;

        let root = tempdir().expect("create root dir");
        let dep = tempdir().expect("create dep dir");
        fs::write(root.path().join("Cargo.toml"), "[package]\nname = \"root\"")
            .expect("write root cargo");
        fs::write(dep.path().join("Cargo.toml"), "[package]\nname = \"dep\"")
            .expect("write dep cargo");

        let hash_before =
            compute_project_hash_with_dependency_roots(root.path(), &[dep.path().to_path_buf()]);

        fs::create_dir_all(dep.path().join("src")).expect("create dep src");
        fs::write(
            dep.path().join("src/lib.rs"),
            "pub fn unchanged_policy() {}",
        )
        .expect("write dep source");
        let hash_after =
            compute_project_hash_with_dependency_roots(root.path(), &[dep.path().to_path_buf()]);

        assert_eq!(
            hash_before, hash_after,
            "non-key file noise should not perturb closure hash policy"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_compute_project_hash_with_dependency_roots_normalizes_alias_equivalence() {
        let _guard = test_guard!();
        use std::fs;
        use tempfile::tempdir;

        let base = tempdir().expect("create temp base");
        let root = base.path().join("root");
        let dep = base.path().join("dep");
        let dep_alias = base.path().join("dep_alias");
        fs::create_dir_all(&root).expect("create root");
        fs::create_dir_all(&dep).expect("create dep");
        fs::write(root.join("Cargo.toml"), "[package]\nname = \"root\"").expect("write root cargo");
        fs::write(dep.join("Cargo.toml"), "[package]\nname = \"dep\"").expect("write dep cargo");
        std::os::unix::fs::symlink(&dep, &dep_alias).expect("create dep alias symlink");

        let canonical_hash =
            compute_project_hash_with_dependency_roots(&root, std::slice::from_ref(&dep));
        let alias_hash = compute_project_hash_with_dependency_roots(&root, &[dep_alias]);

        assert_eq!(
            canonical_hash, alias_hash,
            "alias and canonical dependency roots must produce identical closure hash"
        );
    }

    #[test]
    fn test_compute_project_hash_with_dependency_roots_perf_budget_smoke() {
        let _guard = test_guard!();
        use std::fs;
        use std::time::{Duration, Instant};
        use tempfile::tempdir;

        let base = tempdir().expect("create perf temp base");
        let root = base.path().join("root");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("Cargo.toml"), "[package]\nname = \"root\"").expect("write root cargo");

        let mut deps = Vec::new();
        for idx in 0..4 {
            let dep = base.path().join(format!("dep-{idx}"));
            fs::create_dir_all(&dep).expect("create dep root");
            fs::write(
                dep.join("Cargo.toml"),
                format!("[package]\nname = \"dep-{idx}\"\nversion = \"0.1.{idx}\""),
            )
            .expect("write dep cargo");
            deps.push(dep);
        }

        let start = Instant::now();
        for _ in 0..100 {
            let _ = compute_project_hash_with_dependency_roots(&root, &deps);
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "closure hash computation too slow: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_project_id_from_path_root() {
        let _guard = test_guard!();
        // Test with root path - falls back to "unknown" since "/" has no file_name
        assert_eq!(project_id_from_path(Path::new("/")), "unknown");
    }

    #[test]
    fn test_project_id_from_path_with_special_chars() {
        let _guard = test_guard!();
        // Test with path containing underscores and dashes
        assert_eq!(
            project_id_from_path(Path::new("/home/user/my_project-v2")),
            "my_project-v2"
        );
    }

    #[test]
    fn test_default_c_cpp_artifact_patterns() {
        let _guard = test_guard!();
        let patterns = default_c_cpp_artifact_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.contains("build")));
        assert!(patterns.iter().any(|p| p.contains(".o")));
        assert!(patterns.iter().any(|p| p.contains(".so")));
    }

    #[test]
    fn test_transfer_pipeline_builder_methods() {
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        )
        .with_color_mode(ColorMode::Always)
        .with_env_allowlist(vec!["RUSTFLAGS".to_string(), "CC".to_string()]);

        assert_eq!(pipeline.remote_path(), "/tmp/rch/test-project/abc123");
    }

    #[test]
    fn test_transfer_pipeline_with_ssh_options() {
        let _guard = test_guard!();
        let custom_options = SshOptions {
            connect_timeout: std::time::Duration::from_secs(30),
            command_timeout: std::time::Duration::from_secs(120),
            ..Default::default()
        };

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        )
        .with_ssh_options(custom_options)
        .with_command_timeout(std::time::Duration::from_secs(300));

        // Just verify it builds without panic
        assert_eq!(pipeline.remote_path(), "/tmp/rch/test-project/abc123");
    }

    #[test]
    fn test_bun_test_external_timeout_wrapper() {
        let _guard = test_guard!();
        // Test that BunTest commands get wrapped with timeout
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        )
        .with_compilation_kind(Some(CompilationKind::BunTest));

        let wrapped = pipeline.wrap_with_external_timeout("bun test");
        assert!(wrapped.contains("timeout"));
        assert!(wrapped.contains("--signal=KILL"));
        assert!(wrapped.contains("--foreground"));
        assert!(wrapped.contains("600")); // Default timeout
        assert!(wrapped.contains("bun test"));
    }

    #[test]
    fn test_bun_typecheck_external_timeout_wrapper() {
        let _guard = test_guard!();
        // Test that BunTypecheck commands also get wrapped
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        )
        .with_compilation_kind(Some(CompilationKind::BunTypecheck));

        let wrapped = pipeline.wrap_with_external_timeout("bun typecheck");
        assert!(wrapped.contains("timeout"));
        assert!(wrapped.contains("bun typecheck"));
    }

    #[test]
    fn test_cargo_build_wrapped_with_build_timeout() {
        let _guard = test_guard!();
        // All commands now wrapped with appropriate timeout (bd-1nmv)
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        )
        .with_compilation_kind(Some(CompilationKind::CargoBuild));

        let wrapped = pipeline.wrap_with_external_timeout("cargo build");
        assert!(wrapped.contains("timeout"));
        assert!(wrapped.contains("--signal=KILL"));
        assert!(wrapped.contains("--foreground"));
        assert!(wrapped.contains("300")); // Default build_timeout_sec
        assert!(wrapped.contains("cargo build"));
    }

    #[test]
    fn test_unknown_compilation_kind_uses_build_timeout() {
        let _guard = test_guard!();
        // Commands without compilation kind use build_timeout (bd-1nmv)
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        ); // No with_compilation_kind() call

        let wrapped = pipeline.wrap_with_external_timeout("some command");
        assert!(wrapped.contains("timeout"));
        assert!(wrapped.contains("300")); // Default build_timeout_sec
        assert!(wrapped.contains("some command"));
    }

    #[test]
    fn test_cargo_test_wrapped_with_test_timeout() {
        let _guard = test_guard!();
        // Test commands use test_timeout_sec (bd-1nmv)
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        )
        .with_compilation_kind(Some(CompilationKind::CargoTest));

        let wrapped = pipeline.wrap_with_external_timeout("cargo test");
        assert!(wrapped.contains("timeout"));
        assert!(wrapped.contains("1800")); // Default test_timeout_sec
        assert!(wrapped.contains("cargo test"));
    }

    #[test]
    fn test_external_timeout_disabled() {
        let _guard = test_guard!();
        use rch_common::CompilationConfig;

        // External timeout can be disabled via config (bd-1nmv)
        let config = CompilationConfig {
            external_timeout_enabled: false,
            ..CompilationConfig::default()
        };

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        )
        .with_compilation_kind(Some(CompilationKind::BunTest))
        .with_compilation_config(config);

        let wrapped = pipeline.wrap_with_external_timeout("bun test");
        assert!(!wrapped.contains("timeout"));
        assert_eq!(wrapped, "bun test");
    }

    #[test]
    fn test_custom_timeout_values() {
        let _guard = test_guard!();
        use rch_common::CompilationConfig;

        // Custom timeout values can be configured (bd-1nmv)
        let config = CompilationConfig {
            build_timeout_sec: 120,
            test_timeout_sec: 900,
            bun_timeout_sec: 180,
            external_timeout_enabled: true,
            ..CompilationConfig::default()
        };

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        )
        .with_compilation_kind(Some(CompilationKind::BunTest))
        .with_compilation_config(config);

        let wrapped = pipeline.wrap_with_external_timeout("bun test");
        assert!(wrapped.contains("180")); // Custom bun_timeout_sec
        assert!(wrapped.contains("bun test"));
    }

    #[test]
    fn test_build_sync_command_includes_keepalive_and_controlpersist_when_set() {
        let _guard = test_guard!();
        let custom_options = SshOptions {
            server_alive_interval: Some(std::time::Duration::from_secs(30)),
            control_persist_idle: Some(std::time::Duration::from_secs(60)),
            ..Default::default()
        };

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        )
        .with_ssh_options(custom_options);

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://worker".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        };

        let cmd = pipeline.build_sync_command(
            &worker,
            "mockuser@mock://worker:/tmp/rch/test-project/abc123",
            "/tmp/rch/test-project/abc123",
            &[],
        );

        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();

        let e_index = args.iter().position(|arg| arg == "-e").expect("-e arg");
        let ssh_arg = args.get(e_index + 1).expect("ssh -e value");

        assert!(ssh_arg.contains("ServerAliveInterval=30"));
        assert!(ssh_arg.contains("ControlMaster=auto"));
        assert!(ssh_arg.contains("ControlPath="));
        assert!(ssh_arg.contains("rch-rsync-%C"));
        assert!(ssh_arg.contains("ControlPersist=60s"));
    }

    #[test]
    fn test_build_sync_command_adaptive_compression_uses_estimate() {
        let _guard = test_guard!();
        let transfer_config = TransferConfig {
            adaptive_compression: true,
            compression_level: 3,
            min_compression_level: 1,
            max_compression_level: 9,
            ..TransferConfig::default()
        };

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            transfer_config,
        )
        .with_estimated_transfer_bytes(Some(500_000_000));

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://worker".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        };

        let cmd = pipeline.build_sync_command(
            &worker,
            "mockuser@mock://worker:/tmp/rch/test-project/abc123",
            "/tmp/rch/test-project/abc123",
            &[],
        );

        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();

        assert!(args.iter().any(|arg| arg == "--compress-choice=zstd"));
        assert!(args.iter().any(|arg| arg == "--compress-level=7"));
    }

    #[test]
    fn test_sync_result_struct() {
        let _guard = test_guard!();
        let result = SyncResult {
            bytes_transferred: 1024,
            files_transferred: 10,
            duration_ms: 500,
        };

        assert_eq!(result.bytes_transferred, 1024);
        assert_eq!(result.files_transferred, 10);
        assert_eq!(result.duration_ms, 500);

        // Test Clone
        let cloned = result.clone();
        assert_eq!(cloned.bytes_transferred, result.bytes_transferred);
    }

    #[test]
    #[serial(mock_global)]
    fn test_execute_remote_applies_env_allowlist() {
        let _guard = test_guard!();
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

        let env_prefix = pipeline.build_env_prefix();
        assert!(env_prefix.applied.contains(&"RUSTFLAGS".to_string()));
        assert!(env_prefix.applied.contains(&"QUOTED".to_string()));
        assert!(env_prefix.rejected.contains(&"BADVAL".to_string()));
        assert!(env_prefix.rejected.contains(&"BAD=KEY".to_string()));

        assert!(command.contains("RUSTFLAGS="));
        assert!(command.contains("target-cpu=native"));
        // shell_escape uses '\'' style (end string, escaped quote, start string)
        assert!(command.contains("QUOTED='a'\\''b'"));
        assert!(!command.contains("BADVAL="));
        assert!(!command.contains("BAD=KEY"));
        assert!(command.contains("cargo build"));

        mock::clear_mock_overrides();
        mock::clear_global_invocations();
    }

    #[test]
    fn test_build_remote_command_rewrites_cargo_target_dir_and_tmpdir() {
        let _guard = test_guard!();
        let mut overrides = HashMap::new();
        overrides.insert(
            "CARGO_TARGET_DIR".to_string(),
            "/data/tmp/pi_agent_rust/pearleagle".to_string(),
        );
        overrides.insert(
            "TMPDIR".to_string(),
            "/data/tmp/pi_agent_rust/pearleagle/tmp".to_string(),
        );

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/project"),
            "project".to_string(),
            "hash".to_string(),
            TransferConfig::default(),
        )
        .with_env_allowlist(vec!["CARGO_TARGET_DIR".to_string(), "TMPDIR".to_string()])
        .with_env_overrides(overrides);

        let worker_scoped_root = pipeline.remote_path();
        let command = pipeline.build_remote_command("cargo test --no-run", None);
        assert!(command.contains(&format!(
            "CARGO_TARGET_DIR='{}/.rch-target'",
            worker_scoped_root
        )));
        assert!(command.contains(&format!("TMPDIR='{}/.rch-tmp'", worker_scoped_root)));
        assert!(command.contains("mkdir -p"));
        assert!(command.contains(&format!("{}/.rch-target", worker_scoped_root)));
        assert!(command.contains(&format!("{}/.rch-tmp", worker_scoped_root)));
        assert!(command.contains("touch "));
        assert!(
            !command.contains("/data/tmp/pi_agent_rust/pearleagle"),
            "host-local tmpfs path should not be forwarded to worker"
        );
        assert!(command.contains(&worker_scoped_root));
    }

    #[test]
    fn test_build_remote_command_keeps_non_special_env_values() {
        let _guard = test_guard!();
        let mut overrides = HashMap::new();
        overrides.insert("RUSTFLAGS".to_string(), "-C target-cpu=native".to_string());

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/project"),
            "project".to_string(),
            "hash".to_string(),
            TransferConfig::default(),
        )
        .with_env_allowlist(vec!["RUSTFLAGS".to_string()])
        .with_env_overrides(overrides);

        let command = pipeline.build_remote_command("cargo build", None);
        assert!(command.contains("RUSTFLAGS='-C target-cpu=native'"));
        assert!(command.contains("cargo build"));
    }

    #[test]
    fn test_remote_path_with_custom_remote_base() {
        let _guard = test_guard!();
        let config = TransferConfig {
            remote_base: "/var/rch-builds".to_string(),
            ..Default::default()
        };

        let pipeline = TransferPipeline::new(
            PathBuf::from("/home/user/project"),
            "myproject".to_string(),
            "abc123".to_string(),
            config,
        );

        assert_eq!(pipeline.remote_path(), "/var/rch-builds/myproject/abc123");
    }

    #[test]
    fn test_remote_path_with_home_directory_base() {
        let _guard = test_guard!();
        let config = TransferConfig {
            remote_base: "/home/builder/.rch".to_string(),
            ..Default::default()
        };

        let pipeline = TransferPipeline::new(
            PathBuf::from("/workspace/project"),
            "project".to_string(),
            "def456".to_string(),
            config,
        );

        assert_eq!(pipeline.remote_path(), "/home/builder/.rch/project/def456");
    }

    #[test]
    fn test_remote_path_override_absolute() {
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            PathBuf::from("/workspace/project"),
            "project".to_string(),
            "def456".to_string(),
            TransferConfig::default(),
        )
        .with_remote_path_override("/data/projects/project");

        assert_eq!(pipeline.remote_path(), "/data/projects/project");
    }

    #[test]
    fn test_remote_path_override_rejects_relative() {
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            PathBuf::from("/workspace/project"),
            "project".to_string(),
            "def456".to_string(),
            TransferConfig::default(),
        )
        .with_remote_path_override("relative/path");

        assert_eq!(pipeline.remote_path(), "/tmp/rch/project/def456");
    }

    // ==========================================================================
    // .rchignore Parser Tests
    // ==========================================================================

    #[test]
    fn test_parse_rchignore_content_basic() {
        let _guard = test_guard!();
        let content = "target/\n.git/objects/\nnode_modules/";
        let patterns = parse_rchignore_content(content);
        assert_eq!(patterns, vec!["target/", ".git/objects/", "node_modules/"]);
    }

    #[test]
    fn test_parse_rchignore_content_with_comments() {
        let _guard = test_guard!();
        let content = r#"# Build artifacts
target/
# Git internals
.git/objects/
# Node stuff
node_modules/"#;
        let patterns = parse_rchignore_content(content);
        assert_eq!(patterns, vec!["target/", ".git/objects/", "node_modules/"]);
    }

    #[test]
    fn test_parse_rchignore_content_with_blank_lines() {
        let _guard = test_guard!();
        let content = r#"
target/

.git/objects/


node_modules/
"#;
        let patterns = parse_rchignore_content(content);
        assert_eq!(patterns, vec!["target/", ".git/objects/", "node_modules/"]);
    }

    #[test]
    fn test_parse_rchignore_content_trims_whitespace() {
        let _guard = test_guard!();
        let content = "  target/  \n\t.git/objects/\t\n   node_modules/   ";
        let patterns = parse_rchignore_content(content);
        assert_eq!(patterns, vec!["target/", ".git/objects/", "node_modules/"]);
    }

    #[test]
    fn test_parse_rchignore_content_empty() {
        let _guard = test_guard!();
        let content = "";
        let patterns = parse_rchignore_content(content);
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_parse_rchignore_content_only_comments() {
        let _guard = test_guard!();
        let content = "# This is a comment\n# Another comment";
        let patterns = parse_rchignore_content(content);
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_parse_rchignore_content_preserves_negation_literal() {
        let _guard = test_guard!();
        // Note: Unlike .gitignore, negation is not supported, ! is literal
        let content = "target/\n!important.txt\n.git/";
        let patterns = parse_rchignore_content(content);
        assert_eq!(patterns, vec!["target/", "!important.txt", ".git/"]);
    }

    #[test]
    fn test_parse_rchignore_file_not_found() {
        let _guard = test_guard!();
        let result = parse_rchignore(Path::new("/nonexistent/.rchignore"));
        assert!(result.is_err());
    }

    #[test]
    fn test_get_effective_excludes_without_rchignore() {
        let _guard = test_guard!();
        // When no .rchignore exists, should return config defaults + remote runtime guards.
        let config = TransferConfig::default();
        let default_excludes = config.exclude_patterns.clone();

        let pipeline = TransferPipeline::new(
            PathBuf::from("/nonexistent/project"),
            "project".to_string(),
            "hash".to_string(),
            config,
        );

        let effective = pipeline.get_effective_excludes();
        for pattern in &default_excludes {
            assert!(effective.contains(pattern));
        }
        assert!(effective.contains(&".rch-target/".to_string()));
        assert!(effective.contains(&".rch-tmp/".to_string()));
    }

    #[test]
    fn test_get_effective_excludes_with_rchignore() {
        let _guard = test_guard!();
        // Create a temp dir with .rchignore
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let rchignore_path = temp_dir.path().join(".rchignore");
        std::fs::write(&rchignore_path, "large_data/\nsecrets/").expect("write .rchignore");

        let config = TransferConfig::default();
        let default_excludes = config.exclude_patterns.clone();

        let pipeline = TransferPipeline::new(
            temp_dir.path().to_path_buf(),
            "project".to_string(),
            "hash".to_string(),
            config,
        );

        let effective = pipeline.get_effective_excludes();
        for pattern in &default_excludes {
            assert!(effective.contains(pattern));
        }
        assert!(effective.contains(&".rch-target/".to_string()));
        assert!(effective.contains(&".rch-tmp/".to_string()));
        assert!(effective.contains(&"large_data/".to_string()));
        assert!(effective.contains(&"secrets/".to_string()));
    }

    #[test]
    fn test_get_effective_excludes_deduplicates() {
        let _guard = test_guard!();
        // Create a temp dir with .rchignore that overlaps with defaults
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let rchignore_path = temp_dir.path().join(".rchignore");
        // "target/" is already in defaults
        std::fs::write(&rchignore_path, "target/\ncustom/").expect("write .rchignore");

        let config = TransferConfig::default();
        let default_excludes = config.exclude_patterns.clone();

        let pipeline = TransferPipeline::new(
            temp_dir.path().to_path_buf(),
            "project".to_string(),
            "hash".to_string(),
            config,
        );

        let effective = pipeline.get_effective_excludes();
        for pattern in &default_excludes {
            assert!(effective.contains(pattern));
        }
        assert!(effective.contains(&".rch-target/".to_string()));
        assert!(effective.contains(&".rch-tmp/".to_string()));
        assert!(effective.contains(&"custom/".to_string()));
        // target/ should appear only once
        let target_count = effective.iter().filter(|p| *p == "target/").count();
        assert_eq!(target_count, 1);
        // Runtime guards should appear only once too.
        let runtime_target_count = effective.iter().filter(|p| *p == ".rch-target/").count();
        assert_eq!(runtime_target_count, 1);
        let runtime_tmp_count = effective.iter().filter(|p| *p == ".rch-tmp/").count();
        assert_eq!(runtime_tmp_count, 1);
    }

    // ==========================================================================
    // Transfer Optimization Tests (bd-3hho)
    // ==========================================================================

    #[test]
    fn test_parse_rsync_total_size_standard() {
        let _guard = test_guard!();
        let output = "Number of files: 1,234
Total file size: 56,789,012 bytes
Total transferred file size: 1,234,567 bytes";
        assert_eq!(parse_rsync_total_size(output), Some(56789012));
    }

    #[test]
    fn test_parse_rsync_total_size_no_commas() {
        let _guard = test_guard!();
        let output = "Total file size: 123456 bytes";
        assert_eq!(parse_rsync_total_size(output), Some(123456));
    }

    #[test]
    fn test_parse_rsync_total_size_transferred() {
        let _guard = test_guard!();
        let output = "Total transferred file size: 9,876,543 bytes";
        assert_eq!(parse_rsync_total_size(output), Some(9876543));
    }

    #[test]
    fn test_parse_rsync_total_size_missing() {
        let _guard = test_guard!();
        let output = "sent 100 bytes received 200 bytes";
        assert_eq!(parse_rsync_total_size(output), None);
    }

    #[test]
    fn test_parse_rsync_total_files_standard() {
        let _guard = test_guard!();
        let output = "Number of files: 1,234 (reg: 1,000, dir: 234)
Total file size: 56,789,012 bytes";
        assert_eq!(parse_rsync_total_files(output), Some(1234));
    }

    #[test]
    fn test_parse_rsync_total_files_no_commas() {
        let _guard = test_guard!();
        let output = "Number of files: 456
Total file size: 123 bytes";
        assert_eq!(parse_rsync_total_files(output), Some(456));
    }

    #[test]
    fn test_parse_rsync_total_files_transferred() {
        let _guard = test_guard!();
        let output = "Number of regular files transferred: 789";
        assert_eq!(parse_rsync_total_files(output), Some(789));
    }

    #[test]
    fn test_parse_rsync_total_files_missing() {
        let _guard = test_guard!();
        let output = "Total file size: 100 bytes";
        assert_eq!(parse_rsync_total_files(output), None);
    }

    #[test]
    fn test_transfer_config_optimization_defaults() {
        let _guard = test_guard!();
        let config = TransferConfig::default();
        assert!(config.max_transfer_mb.is_none());
        assert!(config.max_transfer_time_ms.is_none());
        assert!(config.bwlimit_kbps.is_none());
        assert!(config.estimated_bandwidth_bps.is_none());
    }

    #[test]
    fn test_transfer_config_with_optimization_options() {
        let _guard = test_guard!();
        let config = TransferConfig {
            max_transfer_mb: Some(500),
            max_transfer_time_ms: Some(5000),
            bwlimit_kbps: Some(10000),
            estimated_bandwidth_bps: Some(10 * 1024 * 1024),
            ..Default::default()
        };
        assert_eq!(config.max_transfer_mb, Some(500));
        assert_eq!(config.max_transfer_time_ms, Some(5000));
        assert_eq!(config.bwlimit_kbps, Some(10000));
        assert_eq!(config.estimated_bandwidth_bps, Some(10 * 1024 * 1024));
    }

    #[test]
    fn test_transfer_estimate_struct() {
        let _guard = test_guard!();
        let estimate = TransferEstimate {
            bytes: 1024 * 1024 * 50, // 50 MB
            files: 100,
            estimated_time_ms: 5000, // 5 seconds
            estimation_ms: 150,      // 150ms to estimate
        };
        assert_eq!(estimate.bytes, 52428800);
        assert_eq!(estimate.files, 100);
        assert_eq!(estimate.estimated_time_ms, 5000);
        assert_eq!(estimate.estimation_ms, 150);
    }

    #[test]
    fn test_build_sync_command_with_bwlimit() {
        let _guard = test_guard!();
        let config = TransferConfig {
            bwlimit_kbps: Some(5000),
            ..Default::default()
        };

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            config,
        );

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://worker".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        };

        let cmd = pipeline.build_sync_command(
            &worker,
            "mockuser@mock://worker:/tmp/rch/test-project/abc123",
            "/tmp/rch/test-project/abc123",
            &[],
        );

        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();

        assert!(args.contains(&"--bwlimit=5000".to_string()));
    }

    #[test]
    fn test_build_sync_command_without_bwlimit() {
        let _guard = test_guard!();
        let config = TransferConfig::default();

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            config,
        );

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://worker".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        };

        let cmd = pipeline.build_sync_command(
            &worker,
            "mockuser@mock://worker:/tmp/rch/test-project/abc123",
            "/tmp/rch/test-project/abc123",
            &[],
        );

        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();

        // Should not have any --bwlimit arg when not configured
        assert!(!args.iter().any(|arg| arg.starts_with("--bwlimit")));
    }

    #[test]
    fn test_build_sync_command_bwlimit_zero_disabled() {
        let _guard = test_guard!();
        let config = TransferConfig {
            bwlimit_kbps: Some(0), // Explicitly 0 = disabled
            ..Default::default()
        };

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            config,
        );

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://worker".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        };

        let cmd = pipeline.build_sync_command(
            &worker,
            "mockuser@mock://worker:/tmp/rch/test-project/abc123",
            "/tmp/rch/test-project/abc123",
            &[],
        );

        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();

        // bwlimit=0 should be treated as disabled (no flag)
        assert!(!args.iter().any(|arg| arg.starts_with("--bwlimit")));
    }
}
