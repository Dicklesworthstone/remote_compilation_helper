//! File transfer and remote execution pipeline.
//!
//! Handles synchronizing project files to remote workers, executing compilation
//! commands, and retrieving build artifacts.

use crate::error::TransferError;
use anyhow::{Context, Result};
use glob::Pattern;
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
const REMOTE_RUNTIME_EXCLUDE_PATTERNS: &[&str] = &[
    ".rch-target/",
    ".rch-target-*/",
    ".rch-tmp/",
    ".franken_whisper/tools/ffmpeg/",
];
const DEFAULT_REMOTE_CARGO_TARGET_DIR_NAME: &str = ".rch-target";
const CONFIG_EXCLUDE_REWRITES: &[(&str, &str)] = &[
    ("core.*", "core.[0-9]*"),
    (".core.*", ".core.[0-9]*"),
    (".git/objects/", ".git/"),
];

fn normalize_config_exclude_pattern(pattern: &str) -> &str {
    CONFIG_EXCLUDE_REWRITES
        .iter()
        .find_map(|(legacy, replacement)| (*legacy == pattern).then_some(*replacement))
        .unwrap_or(pattern)
}

fn add_portable_rsync_archive_args(cmd: &mut Command) {
    // `-a` includes owner/group preservation. Across independently provisioned
    // workers those metadata IDs are not portable and can turn an otherwise
    // writable sync into a fail-open chgrp failure.
    cmd.arg("--no-owner").arg("--no-group");
}

/// Anchor an artifact retrieval pattern so rsync only matches it at the
/// transfer source root, NOT at any arbitrary depth in the source tree.
/// Closes RCH bug `d7xc3` ("Artifact retrieval must not dirty local source
/// checkout"). Unanchored patterns like `target/debug/**` would match
/// `<root>/target/debug/foo` AND `<root>/anything/target/debug/foo` — the
/// second branch lets a hostile or stale remote layout (e.g., another
/// agent's build tree at `<root>/some-crate/target/...`) drift into the
/// retrieval set and overwrite a local file.
///
/// Rules (rsync filter semantics):
///   * pattern already starts with `/`  → leave as-is (already anchored)
///   * pattern starts with `**/`        → leave as-is (explicit recursion)
///   * otherwise                        → prepend `/` to anchor
///
/// Empty / whitespace-only patterns are returned unchanged so the caller
/// can decide whether to drop them; we do not silently mutate junk input.
fn anchor_retrieval_pattern(pattern: &str) -> String {
    let trimmed = pattern.trim_start();
    if trimmed.is_empty() {
        return pattern.to_string();
    }
    if trimmed.starts_with('/') || trimmed.starts_with("**/") {
        return pattern.to_string();
    }
    format!("/{}", pattern)
}

/// Compute the set of "allowed top-level roots" implied by anchored
/// artifact patterns. Used to build the `--exclude` belt-and-suspenders
/// for retrieval: anything at the rsync transfer root that ISN'T in this
/// set gets explicitly excluded, regardless of pattern matching quirks.
///
/// For each anchored pattern, the first path component after the leading
/// `/` is the implied root. Glob metacharacters in that component (e.g.,
/// `*.tsbuildinfo`) disable the implication for that pattern — we can't
/// safely derive a single root from a glob, so we conservatively allow
/// the rsync source root to be scanned for that pattern.
fn allowed_artifact_roots(artifact_patterns: &[String]) -> std::collections::BTreeSet<String> {
    let mut roots = std::collections::BTreeSet::new();
    for pattern in artifact_patterns {
        let anchored = anchor_retrieval_pattern(pattern);
        let after_slash = anchored.trim_start_matches('/');
        let first = after_slash.split('/').next().unwrap_or("");
        if first.is_empty() {
            continue;
        }
        if has_rsync_glob_meta(first) {
            // Top-level glob (e.g., `*.tsbuildinfo`) — can't derive a
            // single allowed root. The caller's `--include` rule will
            // accept matching files at the source root; we don't add a
            // root exclusion that would block them.
            continue;
        }
        roots.insert(first.to_string());
    }
    roots
}

fn has_rsync_glob_meta(pattern: &str) -> bool {
    pattern
        .chars()
        .any(|ch| matches!(ch, '*' | '?' | '[' | ']'))
}

fn top_level_artifact_pattern_matches_entry(pattern: &str, entry_name: &str) -> bool {
    let anchored = anchor_retrieval_pattern(pattern);
    if anchored.starts_with("**/") {
        return false;
    }

    let after_slash = anchored.trim_start_matches('/');
    let first = after_slash.split('/').next().unwrap_or("");
    if first.is_empty() {
        return false;
    }
    if first == "*" {
        // `*` is used by the C/C++ defaults as a best-effort way to fetch
        // newly-created root-level outputs. It is too broad to prove that an
        // existing local top-level entry is an artifact, so it must not disable
        // the source-integrity exclude guard for source files/directories.
        return false;
    }
    if first == entry_name {
        return true;
    }
    has_rsync_glob_meta(first)
        && Pattern::new(first)
            .map(|pattern| pattern.matches(entry_name))
            .unwrap_or(false)
}

fn escape_rsync_filter_literal_component(name: &str) -> Cow<'_, str> {
    if !has_rsync_glob_meta(name) {
        return Cow::Borrowed(name);
    }

    let mut escaped = String::with_capacity(name.len());
    for ch in name.chars() {
        match ch {
            '\\' => escaped.push_str(r"\\"),
            '*' | '?' | '[' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    Cow::Owned(escaped)
}

fn artifact_patterns_allow_top_level_entry(artifact_patterns: &[String], entry_name: &str) -> bool {
    artifact_patterns
        .iter()
        .any(|pattern| top_level_artifact_pattern_matches_entry(pattern, entry_name))
}

fn first_path_component(pattern: &str) -> Option<&str> {
    let trimmed = pattern.trim_start_matches('/');
    let trimmed = trimmed.trim_end_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.split('/').next().unwrap_or(trimmed))
    }
}

fn retrieval_exclude_can_block_artifacts(pattern: &str, artifact_patterns: &[String]) -> bool {
    let trimmed = pattern.trim();
    if !trimmed.ends_with('/') {
        return true;
    }

    let Some(exclude_root) = first_path_component(trimmed) else {
        return true;
    };
    if has_rsync_glob_meta(exclude_root) {
        return true;
    }

    artifact_patterns.iter().any(|artifact| {
        first_path_component(artifact)
            .map(|artifact_root| artifact_root == exclude_root)
            .unwrap_or(false)
    })
}

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

        let elapsed_ms = start.elapsed().as_millis();
        let remaining_ms = if elapsed_ms >= config.total_timeout_ms as u128 {
            0
        } else {
            config.total_timeout_ms - elapsed_ms as u64
        };
        let attempt_timeout = std::time::Duration::from_millis(remaining_ms.max(1));

        let operation_result = match tokio::time::timeout(attempt_timeout, operation()).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "{}: timed out after {}ms",
                operation_name,
                config.total_timeout_ms
            )),
        };

        match operation_result {
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
/// rsync/SSH errors. The retry timeout bounds each attempt; timed-out child
/// processes are killed on drop so rsync/SSH cannot keep running in the
/// background.
async fn execute_rsync_with_retry(
    config: &RetryConfig,
    operation_name: &str,
    build_command: impl Fn() -> Command,
) -> Result<std::process::Output> {
    retry_with_backoff(config, operation_name, || async {
        let mut cmd = build_command();
        cmd.kill_on_drop(true);
        let child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("rsync I/O error: {}", e))?;
        child
            .wait_with_output()
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
    /// Remote Cargo target directory basename.
    ///
    /// Defaults to `.rch-target` for direct `TransferPipeline` users. The rch
    /// hook sets a unique value per remote job to prevent parallel Cargo runs
    /// in the same synchronized project from contending on Cargo's artifact
    /// directory lock.
    remote_cargo_target_dir_name: String,
    /// Optional include-only patterns for sync-to-remote uploads.
    sync_include_patterns: Option<Vec<String>>,
    /// Whether sync-to-remote should delete extraneous files remotely.
    sync_delete: bool,
    /// Build ID for tracking and cancellation.
    build_id: Option<u64>,
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
            control_master: transfer_config.ssh_control_persist_secs.is_some(),
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
            remote_cargo_target_dir_name: DEFAULT_REMOTE_CARGO_TARGET_DIR_NAME.to_string(),
            sync_include_patterns: None,
            sync_delete: true,
            build_id: None,
        }
    }

    /// Set build id for remote execution.
    pub fn with_build_id(mut self, build_id: Option<u64>) -> Self {
        self.build_id = build_id;
        self
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

    /// Restrict sync-to-remote uploads to a small include-only set.
    pub fn with_sync_include_patterns(mut self, patterns: Vec<String>) -> Self {
        self.sync_include_patterns = Some(patterns);
        self
    }

    /// Control whether sync-to-remote deletes extraneous remote files.
    pub fn with_sync_delete(mut self, delete: bool) -> Self {
        self.sync_delete = delete;
        self
    }

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
    pub fn with_compilation_config(mut self, config: rch_common::CompilationConfig) -> Self {
        self.compilation_config = config;
        self
    }

    #[cfg(test)]
    pub fn with_estimated_transfer_bytes(mut self, bytes: Option<u64>) -> Self {
        self.estimated_transfer_bytes = bytes;
        self
    }

    fn effective_rsync_retry_config(&self) -> RetryConfig {
        let mut retry = self.transfer_config.retry.clone();
        if let Some(max_transfer_time_ms) = self.transfer_config.max_transfer_time_ms
            && max_transfer_time_ms > 0
        {
            retry.total_timeout_ms = max_transfer_time_ms;
        }
        retry
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

    /// Set the remote Cargo target directory basename.
    ///
    /// The value must be a single relative path segment because it is appended
    /// to the worker-side project root. Invalid names are ignored so callers
    /// fail closed to the default path rather than creating surprising remote
    /// paths.
    pub fn with_remote_cargo_target_dir_name(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        let trimmed = name.trim();
        if trimmed.is_empty()
            || trimmed == "."
            || trimmed == ".."
            || trimmed.contains('/')
            || trimmed.contains('\\')
            || trimmed.contains('\n')
            || trimmed.contains('\r')
            || trimmed.contains('\0')
        {
            warn!(
                "Ignoring invalid remote Cargo target directory name: {:?}",
                name
            );
            return self;
        }

        self.remote_cargo_target_dir_name = trimmed.to_string();
        self
    }

    fn remote_cargo_target_dir_for_remote_path(&self, remote_path: &str) -> String {
        format!(
            "{}/{}",
            remote_path.trim_end_matches('/'),
            self.remote_cargo_target_dir_name
        )
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
                let target_dir = self.remote_cargo_target_dir_for_remote_path(remote_path);
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
        let mut excludes = Vec::new();
        for pattern in &self.transfer_config.exclude_patterns {
            let normalized = normalize_config_exclude_pattern(pattern);
            if normalized != pattern {
                debug!(
                    "Rewriting legacy broad exclude pattern '{}' to '{}'",
                    pattern, normalized
                );
            }
            if !excludes.iter().any(|existing| existing == normalized) {
                excludes.push(normalized.to_string());
            }
        }

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

    /// Belt-and-suspenders source-integrity guard for retrieval (RCH bug
    /// `d7xc3`). Scans the LOCAL project root's top-level entries and
    /// returns a list of explicit `--exclude /<entry>` rules for every
    /// entry that ISN'T in the allowed-artifact-roots set. Rsync's filter
    /// semantics: anchored excludes match only at the rsync transfer
    /// root, so this rules out an entire class of source-overwrite bugs
    /// (unanchored artifact patterns, malformed includes, hostile remote
    /// layouts) by stopping rsync from even descending into known-source
    /// top-level directories like `rch/`, `rch-common/`, etc.
    ///
    /// Why scan LOCAL not remote: the local project root mirrors the
    /// remote source tree (we uploaded it). Listing local is fast (one
    /// `read_dir`) and avoids an extra SSH round-trip. The threat model
    /// is "stale or hostile remote tree dirties local source"; if our
    /// LOCAL layout is being tampered with, the operator has bigger
    /// problems than this retrieve.
    fn local_source_roots_to_exclude(
        &self,
        allowed_roots: &BTreeSet<String>,
        artifact_patterns: &[String],
    ) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.project_root) else {
            // Project root unreadable → nothing to exclude here. Other
            // retrieval excludes (REMOTE_RUNTIME_EXCLUDE_PATTERNS, the
            // final `--exclude "*"`) still apply, so retrieval remains
            // safe; we just lose the explicit belt-and-suspenders layer.
            return Vec::new();
        };
        let mut excludes: Vec<String> = Vec::new();
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            if allowed_roots.contains(name) {
                // Permit descent into this artifact root.
                continue;
            }
            if artifact_patterns_allow_top_level_entry(artifact_patterns, name) {
                // Permit exact top-level artifact files and top-level artifact
                // globs such as `*.tsbuildinfo`. Otherwise an existing local
                // artifact file would be excluded before the later include rule
                // can refresh it from the worker.
                continue;
            }
            // Anchor with leading `/` so the exclude matches ONLY at the
            // rsync transfer root, not at any nested depth.
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let name = escape_rsync_filter_literal_component(name);
            let exclude = if is_dir {
                format!("/{name}/")
            } else {
                format!("/{name}")
            };
            excludes.push(exclude);
        }
        // Deterministic order so test assertions and tracing logs are stable.
        excludes.sort();
        excludes
    }

    /// Retrieval-side excludes used when pulling artifacts back from the worker.
    ///
    /// This is intentionally narrower than upload filtering. Upload wants broad
    /// project hygiene exclusions (`target/`, `dist/`, coverage caches, etc.),
    /// but retrieval still needs to descend into artifact roots like `target/`
    /// and `build/`. The retrieval pass applies runtime scratch guards plus
    /// project-local `.rchignore` directory patterns that cannot hide the
    /// requested artifacts. File globs and artifact-root directories are skipped
    /// because rsync evaluates these excludes before the artifact includes.
    fn get_retrieval_excludes(&self, artifact_patterns: &[String]) -> Vec<String> {
        let mut excludes = Vec::new();

        for pattern in REMOTE_RUNTIME_EXCLUDE_PATTERNS {
            if !excludes.iter().any(|existing| existing == pattern) {
                excludes.push((*pattern).to_string());
            }
        }

        let rchignore_path = self.project_root.join(".rchignore");
        if let Ok(patterns) = parse_rchignore(&rchignore_path) {
            let original_count = excludes.len();
            for pattern in patterns {
                if retrieval_exclude_can_block_artifacts(&pattern, artifact_patterns) {
                    debug!(
                        "Skipping retrieval exclude pattern '{}' because it may hide requested artifacts",
                        pattern
                    );
                    continue;
                }
                if !excludes.contains(&pattern) {
                    excludes.push(pattern);
                }
            }
            let added = excludes.len() - original_count;
            if added > 0 {
                info!(
                    "Loaded {} retrieval exclude pattern(s) from .rchignore (total: {})",
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

    /// Get the remote Cargo target directory path on the worker.
    pub fn remote_cargo_target_dir(&self) -> String {
        self.remote_cargo_target_dir_for_remote_path(&self.remote_path())
    }

    #[cfg(test)]
    pub fn remote_pgid_file_path(&self) -> Option<String> {
        self.build_id
            .map(|build_id| Self::remote_pgid_file_path_for_root(&self.remote_path(), build_id))
    }

    pub fn remote_run_dir_for_root(remote_root: &str) -> String {
        let project_id = project_id_from_path(Path::new(remote_root));
        let hash = blake3::hash(remote_root.as_bytes()).to_hex();
        format!("/tmp/rch-run/{}-{}", project_id, &hash[..16])
    }

    pub fn remote_pgid_file_path_for_root(remote_root: &str, build_id: u64) -> String {
        format!(
            "{}/{build_id}.pgid",
            Self::remote_run_dir_for_root(remote_root)
        )
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
        // Wall-clock cap in seconds for the pgid-tracked path's watchdog (0 = disabled).
        // Same source of truth as `wrap_with_external_timeout`, applied via an
        // in-session group-kill watchdog instead of `timeout(1)` (see build_id branch).
        let external_timeout_secs = if self.compilation_config.external_timeout_enabled() {
            self.compilation_config
                .timeout_for_kind(self.compilation_kind)
                .as_secs()
        } else {
            0
        };

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
        let execution_command = if let Some(build_id) = self.build_id {
            let remote_pgid_file = Self::remote_pgid_file_path_for_root(&remote_path, build_id);
            let remote_run_dir = Self::remote_run_dir_for_root(&remote_path);
            let escaped_pgid_file = escape(Cow::from(remote_pgid_file));
            let escaped_run_dir = escape(Cow::from(remote_run_dir));
            // For the pgid-tracked path we do NOT use the `timeout(1)` wrapper:
            // `timeout --foreground` only signals its direct child, so a livelocked
            // test binary (and its fixtures) that the test harness spawned survive
            // the cap and reparent to init as 20-45h PPID-1 orphans. Instead we run
            // the raw command and arm an in-session watchdog that, at the wall-clock
            // cap, SIGKILLs the whole process group (`-$pgid`) — the SAME group the
            // daemon's stuck-detector kills (`cancellation.rs`). One group, both
            // reapers, entire tree. Killing the group includes the leader `sh -c`,
            // but that is a child of the ssh `sh -s`, so the outer shell still
            // reports 137 (128+SIGKILL) for clean timeout exit semantics.
            let escaped_command = escape(Cow::from(colored_command.as_str()));
            // The watchdog program (single-quoted, no inner single quotes):
            //   $1 = pgid file, $2 = timeout secs (0 disables), $3.. = command.
            // Record $$ (session-leader pgid) so the daemon kill path keeps working.
            // NOTE: group kill is `kill -KILL -PGID` with NO `--`. dash's (/bin/sh)
            // kill builtin mishandles `kill -KILL -- -PGID` (the `--` makes it a
            // no-op), so `--` would silently fail to reap on the Ubuntu fleet. The
            // `-PGID` form works in both dash and bash.
            let watchdog = "echo $$ > \"$1\"; __p=$$; __t=\"$2\"; shift 2; \"$@\" & __c=$!; \
if [ \"$__t\" -gt 0 ] 2>/dev/null; then ( sleep \"$__t\"; kill -KILL -\"$__p\" 2>/dev/null ) & __w=$!; fi; \
wait \"$__c\"; __s=$?; if [ -n \"$__w\" ]; then kill \"$__w\" 2>/dev/null; fi; exit \"$__s\"";

            format!(
                "mkdir -p {} && rm -f {} && \
if command -v setsid >/dev/null 2>&1; then \
setsid sh -c '{}' rch-build {} {} sh -lc {}; \
else \
sh -c '{}' rch-build {} {} sh -lc {}; \
fi",
                escaped_run_dir,
                escaped_pgid_file,
                watchdog,
                escaped_pgid_file,
                external_timeout_secs,
                escaped_command,
                watchdog,
                escaped_pgid_file,
                external_timeout_secs,
                escaped_command,
            )
        } else {
            timeout_wrapped_command
        };

        format!(
            "export LC_ALL=C; touch {} && cd {} && {}{}",
            escaped_remote_path, escaped_remote_path, ensure_dirs_command, execution_command
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
        // Run through env so leading VAR=value assignments remain environment
        // assignments after the timeout wrapper is prepended.
        // Exit code 137 (128 + 9) indicates SIGKILL was sent.
        format!(
            "timeout --signal=KILL --foreground --preserve-status {} env {}",
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

        cmd.arg("-az");
        add_portable_rsync_archive_args(&mut cmd);
        cmd.arg("--dry-run").arg("--stats").arg("-e").arg(format!(
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

        cmd.arg("-az"); // Archive mode + compression
        add_portable_rsync_archive_args(&mut cmd);
        cmd.arg("--stats") // Structured output for parse_rsync_bytes/files
            .arg("-e")
            .arg(ssh_command);

        if self.sync_delete {
            cmd.arg("--delete"); // Remove extraneous files from destination
        }

        // Create remote directory implicitly using rsync-path wrapper
        // This saves a separate SSH handshake for 'mkdir -p'
        cmd.arg("--rsync-path")
            .arg(format!("mkdir -p {} && rsync", escaped_remote_path));

        if let Some(include_patterns) = &self.sync_include_patterns {
            cmd.arg("--prune-empty-dirs");
            for pattern in include_patterns {
                cmd.arg("--include").arg(pattern);
            }
            cmd.arg("--exclude").arg("*");
        } else {
            // Add exclude patterns (config defaults + .rchignore)
            for pattern in effective_excludes {
                cmd.arg("--exclude").arg(pattern);
            }
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

    /// Build rsync command for sync_to_remote_streaming.
    fn build_sync_streaming_command(
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

        cmd.arg("-az"); // Archive mode + compression
        add_portable_rsync_archive_args(&mut cmd);
        cmd.arg("--info=progress2")
            .arg("--info=stats2")
            .arg("-e")
            .arg(ssh_command);

        if self.sync_delete {
            cmd.arg("--delete"); // Remove extraneous files from destination
        }

        // Create remote directory implicitly using rsync-path wrapper
        cmd.arg("--rsync-path")
            .arg(format!("mkdir -p {} && rsync", escaped_remote_path));

        if let Some(include_patterns) = &self.sync_include_patterns {
            cmd.arg("--prune-empty-dirs");
            for pattern in include_patterns {
                cmd.arg("--include").arg(pattern);
            }
            cmd.arg("--exclude").arg("*");
        } else {
            // Add exclude patterns (config defaults + .rchignore)
            for pattern in effective_excludes {
                cmd.arg("--exclude").arg(pattern);
            }
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
        let retry_config = self.effective_rsync_retry_config();
        let output = execute_rsync_with_retry(&retry_config, "sync_to_remote", || {
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

        let cmd = self.build_sync_streaming_command(
            worker,
            &destination,
            &escaped_remote_path,
            &effective_excludes,
        );

        debug!(
            "Running (streaming): rsync {:?}",
            cmd.as_std().get_args().collect::<Vec<_>>()
        );

        let retry_config = self.effective_rsync_retry_config();
        let transfer_timeout =
            std::time::Duration::from_millis(retry_config.total_timeout_ms.max(1));
        let (output, duration_ms) =
            run_command_streaming(cmd, "sync_to_remote_streaming", transfer_timeout, |line| {
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
        cmd.arg("-az");
        add_portable_rsync_archive_args(&mut cmd);
        cmd.arg("--stats")
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

        // Apply retrieval-safe excludes before the directory include so rsync
        // never descends into known junk trees like `.beads/recovery_*` on the
        // worker, while still allowing traversal into declared artifact roots.
        for pattern in self.get_retrieval_excludes(artifact_patterns) {
            cmd.arg("--exclude").arg(pattern);
        }

        // Source-integrity guard (RCH bug d7xc3): explicitly exclude every
        // top-level entry in the local project root that ISN'T an allowed
        // artifact root. Defends against unanchored pattern matching, malformed
        // includes, or a stale remote tree pulling source files into the local
        // checkout. The excludes are emitted BEFORE the directory include so
        // rsync evaluates them first and refuses to descend into source dirs.
        let allowed_roots = allowed_artifact_roots(artifact_patterns);
        for exclude in self.local_source_roots_to_exclude(&allowed_roots, artifact_patterns) {
            cmd.arg("--exclude").arg(exclude);
        }

        // Essential: Include all directories so rsync can traverse to match patterns.
        // Without this, the final --exclude "*" prevents rsync from entering directories
        // like "target/" to check for matches.
        cmd.arg("--include").arg("*/");

        // Include only specified artifact patterns, anchored at the rsync
        // transfer root via `anchor_retrieval_pattern` (RCH bug d7xc3) so
        // a pattern like `target/debug/**` cannot match `<root>/anything/
        // target/debug/...` at arbitrary depth.
        for pattern in artifact_patterns {
            cmd.arg("--include").arg(anchor_retrieval_pattern(pattern));
        }
        cmd.arg("--exclude").arg("*"); // Exclude everything else

        let source = format!("{}@{}:{}/", worker.user, worker.host, escaped_remote_path);
        cmd.arg(&source)
            .arg(format!("{}/", self.project_root.display()));

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd
    }

    /// Build rsync command for streaming artifact retrieval.
    fn build_retrieve_streaming_command(
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

        cmd.arg("-az");
        add_portable_rsync_archive_args(&mut cmd);
        cmd.arg("--info=progress2")
            .arg("--info=stats2")
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

        // Prune empty directories to prevent cluttering local project
        cmd.arg("--prune-empty-dirs");

        // Reuse the retrieval-safe excludes so streaming downloads skip stale
        // worker-local junk trees without excluding legitimate artifact roots.
        for pattern in self.get_retrieval_excludes(artifact_patterns) {
            cmd.arg("--exclude").arg(pattern);
        }

        // Source-integrity guard (RCH bug d7xc3): see build_retrieve_command.
        // Same belt-and-suspenders defense applied to the streaming variant.
        let allowed_roots = allowed_artifact_roots(artifact_patterns);
        for exclude in self.local_source_roots_to_exclude(&allowed_roots, artifact_patterns) {
            cmd.arg("--exclude").arg(exclude);
        }

        // Essential: Include all directories so rsync can traverse to match patterns.
        cmd.arg("--include").arg("*/");

        // Artifact include patterns are anchored (RCH bug d7xc3) so they can
        // only match at the rsync transfer root.
        for pattern in artifact_patterns {
            cmd.arg("--include").arg(anchor_retrieval_pattern(pattern));
        }
        cmd.arg("--exclude").arg("*");

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

            if self.ssh_options.control_master
                && let Some(idle) = self.ssh_options.control_persist_idle
            {
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
        let retry_config = self.effective_rsync_retry_config();
        let output = execute_rsync_with_retry(&retry_config, "retrieve_artifacts", || {
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

        let cmd =
            self.build_retrieve_streaming_command(worker, &escaped_remote_path, artifact_patterns);

        debug!(
            "Running artifact retrieval (streaming): rsync {:?}",
            cmd.as_std().get_args().collect::<Vec<_>>()
        );

        let retry_config = self.effective_rsync_retry_config();
        let transfer_timeout =
            std::time::Duration::from_millis(retry_config.total_timeout_ms.max(1));
        let (output, duration_ms) = run_command_streaming(
            cmd,
            "retrieve_artifacts_streaming",
            transfer_timeout,
            |line| {
                on_line(line);
            },
        )
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

    /// Best-effort reaping of *stale* sibling per-job target dirs for this
    /// project on the worker.
    ///
    /// rch gives every forwarded-`CARGO_TARGET_DIR` build a per-job target dir
    /// (`.rch-target-<worker>-job-<id>-<ts>-<seq>`). Such a dir can stay in active
    /// use far beyond a single command — a long-running build keeps writing into
    /// it, and one was observed accumulating ~11.5h of build artifacts. So a
    /// per-job dir must *never* be removed merely because some build finished; that
    /// could clip a build still in flight. Instead we remove only dirs that
    /// have seen **no file activity for `idle_hours`** — i.e. finished/abandoned
    /// ones. A dir idle that long cannot be a live job (an active build touches its
    /// dir continuously), so this never races a concurrent build on the same
    /// project, even when multiple agents build it on the same worker at once.
    ///
    /// The sweep is confined to the *single current project dir* (`remote_path()`),
    /// reaping only its abandoned sibling per-job dirs. The expensive cross-project
    /// full-tree scan has moved OFF this per-dispatch path into the durable
    /// daemon-side worker sweep (`rchd::stale_target_reap`), which scans every
    /// project under the worker's `remote_base` on a background interval. Both
    /// share the idle predicate via `rch_common::stale_target_reap` so they cannot
    /// drift; this orchestrator side stays cheap (one `cd` + a two-glob loop).
    ///
    /// The staleness check looks at the dir itself *and* any descendant (file or
    /// subdir): a recent deep file means an active build (a top-dir-mtime-only
    /// check would miss it, because the top dir mtime can go stale while deep
    /// incremental artifacts keep changing), while a recent *dir* mtime means a
    /// freshly-created target — e.g. a concurrent build that has `mkdir`'d its dir
    /// but not yet written a file (a files-only check would wrongly reap it). The
    /// removal *itself* is detached on the worker (a backgrounded `rm`), so the
    /// potentially-large reclaim runs concurrently with the build — only a quick
    /// SSH dispatch is awaited here. Failures are swallowed — reaping is
    /// opportunistic, never load-bearing.
    pub async fn reap_stale_sibling_per_job_target_dirs(
        &self,
        worker: &WorkerConfig,
        idle_hours: u32,
    ) {
        let project_dir = self.remote_path();
        let current = self.remote_cargo_target_dir_name.clone();

        // Hard safety guards. Both values are rch-generated and should be simple
        // path tokens; refuse anything that could escape the intended
        // `<project_dir>/.rch-target-*` scope or inject shell syntax. The reap
        // script embeds these unescaped (inside double quotes), so this guard is
        // the security boundary. The predicate + safety checks are shared with the
        // daemon-side worker sweep (`rchd::stale_target_reap`) via
        // `rch_common::stale_target_reap` so the two can't drift.
        if !rch_common::stale_target_reap::is_safe_reap_path(&project_dir)
            || !rch_common::stale_target_reap::is_safe_reap_token(&current)
        {
            warn!(
                "stale-target reap: refusing unsafe inputs (project_dir={:?}, current={:?})",
                project_dir, current
            );
            return;
        }
        // Never below a 1h floor, no matter how the threshold was configured.
        let idle_minutes = rch_common::stale_target_reap::idle_minutes_from_hours(idle_hours);

        if use_mock_transport(worker) {
            debug!(
                "Mock stale-target reap in {} on {} (idle>{}h)",
                project_dir, worker.id, idle_hours
            );
            return;
        }

        #[cfg(not(unix))]
        {
            let _ = (worker, idle_minutes);
        }

        #[cfg(unix)]
        {
            // For each per-job sibling dir apply the SHARED reap predicate
            // (`rch_common::stale_target_reap::reap_loop_body`): keep it if the dir
            // OR any descendant was modified within the idle window (an active or
            // just-created build); otherwise remove it. This job's own dir is
            // always excluded. The glob list is the shared `REAP_GLOBS`.
            let globs = rch_common::stale_target_reap::REAP_GLOBS.join(" ");
            let loop_body =
                rch_common::stale_target_reap::reap_loop_body(idle_minutes, Some(&current), "", "");
            let script = format!(
                "cd \"{project_dir}\" 2>/dev/null || exit 0; \
                 for d in {globs}; do {loop_body} done"
            );
            // Detach on the worker so a large reclaim runs concurrently with the
            // build rather than blocking it. The script contains no single quotes
            // (inputs are charset-restricted above), so single-quoting is safe.
            let remote_command = format!("nohup sh -c '{script}' >/dev/null 2>&1 &");

            let mut client = SshClient::new(worker.clone(), self.ssh_options.clone());
            if let Err(e) = client.connect().await {
                debug!(
                    "stale-target reap skipped (ssh connect failed on {}): {}",
                    worker.id, e
                );
                return;
            }
            if let Err(e) = client.execute(&remote_command).await {
                debug!("stale-target reap dispatch failed on {}: {}", worker.id, e);
            }
            if let Err(e) = client.disconnect().await {
                debug!(
                    "stale-target reap: ssh disconnect warning on {}: {}",
                    worker.id, e
                );
            }
        }
    }
}

// The stale-target reap safety predicates now live in
// `rch_common::stale_target_reap` so the orchestrator reaper (here) and the
// daemon-side worker sweep (`rchd::stale_target_reap`) share a single source of
// truth and cannot drift. These thin wrappers preserve the local test surface.

/// See [`rch_common::stale_target_reap::is_safe_reap_path`].
#[cfg(test)]
fn is_safe_reap_path(s: &str) -> bool {
    rch_common::stale_target_reap::is_safe_reap_path(s)
}

/// See [`rch_common::stale_target_reap::is_safe_reap_token`].
#[cfg(test)]
fn is_safe_reap_token(s: &str) -> bool {
    rch_common::stale_target_reap::is_safe_reap_token(s)
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
    let mut total_files = None;

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
            total_files = Some(parsed);
        }
    }

    // If we couldn't parse structured stats, return 0 rather than guessing.
    // The previous heuristic of counting non-empty lines was unreliable as it
    // would count progress lines, stats, and error messages as files.
    total_files.unwrap_or(0)
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

async fn run_command_streaming<F>(
    mut cmd: Command,
    operation_name: &str,
    operation_timeout: std::time::Duration,
    mut on_line: F,
) -> Result<(String, u64)>
where
    F: FnMut(&str),
{
    let start = TokioInstant::now();
    cmd.kill_on_drop(true);
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
    let status = match tokio::time::timeout(operation_timeout, async {
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

        child.wait().await.context("Failed to wait on rsync")
    })
    .await
    {
        Ok(status) => status?,
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!(
                "{}: timed out after {}ms",
                operation_name,
                operation_timeout.as_millis()
            );
        }
    };
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

fn normalize_hash_root(path: &Path, policy: &PathTopologyPolicy) -> PathBuf {
    normalize_project_path_with_policy(path, policy)
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

fn collect_hash_roots(
    project_path: &Path,
    dependency_roots: &[PathBuf],
    policy: &PathTopologyPolicy,
) -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();
    roots.insert(normalize_hash_root(project_path, policy));
    for root in dependency_roots {
        roots.insert(normalize_hash_root(root, policy));
    }
    roots.into_iter().collect()
}

/// Compute a project hash that includes dependency-closure fingerprints.
///
/// The resulting value is deterministic across `/dp` vs `/data/projects` alias
/// forms and changes when any tracked key file for any closure member changes.
///
/// Convenience wrapper using the default topology policy; production code
/// should prefer [`compute_project_hash_with_dependency_roots_and_policy`].
#[cfg(test)]
pub fn compute_project_hash_with_dependency_roots(
    project_path: &Path,
    dependency_roots: &[PathBuf],
) -> String {
    compute_project_hash_with_dependency_roots_and_policy(
        project_path,
        dependency_roots,
        &PathTopologyPolicy::default(),
    )
}

/// Compute a project hash using an explicit topology policy.
pub fn compute_project_hash_with_dependency_roots_and_policy(
    project_path: &Path,
    dependency_roots: &[PathBuf],
    policy: &PathTopologyPolicy,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"rch-project-hash-v2");

    for root in collect_hash_roots(project_path, dependency_roots, policy) {
        hasher.update(b"\0root\0");
        hasher.update(root.to_string_lossy().as_bytes());
        for filename in PROJECT_HASH_KEY_FILES {
            update_hasher_with_file_fingerprint(&mut hasher, &root.join(filename), filename);
        }
    }

    hasher.finalize().to_hex()[..16].to_string()
}

/// Compute a hash of the project for cache invalidation.
///
/// Convenience wrapper using the default topology policy; production code
/// should prefer [`compute_project_hash_with_dependency_roots_and_policy`].
#[cfg(test)]
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
        // Best-effort root-level outputs (like `a.out`) when they are newly
        // created remotely. Existing local top-level entries stay protected by
        // the retrieval source-integrity guard.
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

    fn arg_pair_position(args: &[String], flag: &str, value: &str) -> Option<usize> {
        args.windows(2).position(|window| {
            matches!(window, [observed_flag, observed_value]
                if observed_flag.as_str() == flag && observed_value.as_str() == value)
        })
    }

    fn command_args(cmd: &Command) -> Vec<String> {
        cmd.as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect()
    }

    fn assert_portable_rsync_archive_args(args: &[String]) {
        assert!(
            args.iter().any(|arg| arg == "--no-owner"),
            "rsync archive mode must not preserve owner metadata across workers"
        );
        assert!(
            args.iter().any(|arg| arg == "--no-group"),
            "rsync archive mode must not preserve group metadata across workers"
        );
    }

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
    fn test_is_safe_reap_path_accepts_real_project_dirs() {
        // The two shapes remote_path() actually produces.
        assert!(is_safe_reap_path("/tmp/rch/myproject/abc123"));
        assert!(is_safe_reap_path(
            "/data/projects/coding_agent_session_search/9f8e7d6c"
        ));
    }

    #[test]
    fn test_is_safe_reap_path_rejects_dangerous_inputs() {
        assert!(!is_safe_reap_path(""));
        assert!(!is_safe_reap_path("/"));
        assert!(!is_safe_reap_path("relative/path")); // not absolute
        assert!(!is_safe_reap_path("/toplevel")); // < 2 segments
        assert!(!is_safe_reap_path("/data/../etc")); // parent traversal
        // Shell metacharacters / quotes / globs / spaces must all be rejected so
        // the unescaped embedding in the reap script cannot be subverted.
        for bad in [
            "/data/projects/a b",
            "/data/projects/a'b",
            "/data/projects/a\"b",
            "/data/projects/a$b",
            "/data/projects/a`b",
            "/data/projects/a;b",
            "/data/projects/a|b",
            "/data/projects/a*b",
            "/data/projects/a&b",
        ] {
            assert!(!is_safe_reap_path(bad), "must reject {bad:?}");
        }
    }

    #[test]
    fn test_is_safe_reap_token_guards_basenames() {
        // A real per-job dir basename is accepted.
        assert!(is_safe_reap_token(
            ".rch-target-ts2-job-29863360510034113-1780109474952075077-0"
        ));
        // Path separators, traversal, and shell metacharacters are rejected.
        assert!(!is_safe_reap_token(""));
        assert!(!is_safe_reap_token("."));
        assert!(!is_safe_reap_token(".."));
        assert!(!is_safe_reap_token("a/b"));
        assert!(!is_safe_reap_token("a b"));
        assert!(!is_safe_reap_token("a'b"));
        assert!(!is_safe_reap_token("a$b"));
        assert!(!is_safe_reap_token("a*b"));
    }

    /// End-to-end behavioral test for the cheap CURRENT-PROJECT-ONLY orchestrator
    /// reaper: actually run the generated script (under POSIX `sh`, single-quote
    /// wrapped exactly like the dispatch site) against a fake repo dir holding
    /// idle, live, current-job, and empty sibling per-job dirs and assert which
    /// survive. The expensive cross-project full-tree sweep moved to the daemon;
    /// the orchestrator now only `cd`s into the one repo dir and globs its
    /// siblings, always excluding the current job's own dir.
    #[cfg(unix)]
    #[test]
    fn test_current_project_reap_script_reaps_idle_keeps_live_current_and_empty() {
        use std::fs;
        use std::process::Command;
        use tempfile::tempdir;

        let tmp = tempdir().expect("create repo root");
        // The single repo dir the orchestrator `cd`s into (>=2 segments deep so it
        // passes is_safe_reap_path; the script itself just `cd`s into it verbatim).
        let project_dir = tmp.path().join("repo");
        fs::create_dir_all(&project_dir).expect("mkdir repo dir");

        // Helper: a per-job sibling dir with one artifact, optionally aged past the
        // idle window via `touch -t` (portable GNU/BSD).
        let make = |name: &str, aged: bool| -> std::path::PathBuf {
            let d = project_dir.join(name);
            fs::create_dir_all(d.join("deps")).expect("mkdir per-job dir");
            fs::write(d.join("deps/a.rlib"), b"x").expect("write artifact");
            if aged {
                let ok = Command::new("find")
                    .arg(&d)
                    .args(["-exec", "touch", "-t", "202601010000", "{}", ";"])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                assert!(ok, "aging {name} should succeed");
            }
            d
        };

        let current = ".rch-target-host-job-9-999-1";
        let idle = make(".rch-target-host-job-1-111-0", true);
        let idle_pid = make(".rch-target-host-pid-2-222-0", true);
        let live = make(".rch-target-host-job-3-333-0", false);
        let current_dir = make(current, true); // aged but must be EXCLUDED by name
        // Empty just-created dir (mkdir, no first write) must be kept.
        let empty = project_dir.join(".rch-target-host-job-4-444-0");
        fs::create_dir_all(&empty).expect("mkdir empty dir");
        // A non-rch sibling must never match the glob.
        let bystander = project_dir.join("target");
        fs::create_dir_all(&bystander).expect("mkdir bystander");

        // Build the script EXACTLY as the reaper does (shared globs + loop body,
        // excluding the current job dir), then run it single-quote wrapped.
        let globs = rch_common::stale_target_reap::REAP_GLOBS.join(" ");
        let loop_body = rch_common::stale_target_reap::reap_loop_body(720, Some(current), "", "");
        let project_dir_str = project_dir.to_str().unwrap();
        let script = format!(
            "cd \"{project_dir_str}\" 2>/dev/null || exit 0; \
             for d in {globs}; do {loop_body} done"
        );
        // Guard: no single quote of its own (it is single-quote wrapped at dispatch
        // — `reap_loop_body`'s `awk '{{print $1}}'` is only emitted in the METRICS
        // variant; the orchestrator passes empty counters so no awk/quotes appear).
        assert!(
            !script.contains('\''),
            "orchestrator script must contain no single quotes: {script}"
        );
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("sh -c '{script}'"))
            .status()
            .expect("run reap script");
        assert!(status.success(), "reap script should exit 0");

        assert!(!idle.exists(), "idle -job- sibling must be reaped");
        assert!(!idle_pid.exists(), "idle -pid- sibling must be reaped");
        assert!(live.exists(), "freshly-touched sibling must be kept");
        assert!(
            current_dir.exists(),
            "the current job's own dir must NEVER be reaped (excluded by name)"
        );
        assert!(empty.exists(), "empty just-created dir must be kept");
        assert!(bystander.exists(), "non-rch `target` must never be touched");
    }

    /// The orchestrator `cd`s into the repo dir verbatim, so a SYMLINKED project
    /// dir is followed transparently by `cd` (no `pwd -P` needed) and its idle
    /// siblings are still reaped while the live one survives.
    #[cfg(unix)]
    #[test]
    fn test_current_project_reap_script_follows_symlinked_project_dir() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::process::Command;
        use tempfile::tempdir;

        let base = tempdir().expect("create base");
        let physical = base.path().join("data_repo");
        fs::create_dir_all(&physical).expect("mkdir physical repo dir");
        let link = base.path().join("home_repo");
        symlink(&physical, &link).expect("create symlink to physical repo dir");

        let make = |name: &str, aged: bool| -> std::path::PathBuf {
            let d = physical.join(name);
            fs::create_dir_all(d.join("deps")).expect("mkdir per-job dir");
            fs::write(d.join("deps/a.rlib"), b"x").expect("write artifact");
            if aged {
                let ok = Command::new("find")
                    .arg(&d)
                    .args(["-exec", "touch", "-t", "202601010000", "{}", ";"])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                assert!(ok, "aging {name} should succeed");
            }
            d
        };

        let idle = make(".rch-target-host-job-1-111-0", true);
        let live = make(".rch-target-host-job-2-222-1", false);

        // Pass the SYMLINK path as the project dir — `cd <symlink>` follows it.
        let link_str = link.to_str().unwrap();
        let globs = rch_common::stale_target_reap::REAP_GLOBS.join(" ");
        let loop_body = rch_common::stale_target_reap::reap_loop_body(720, None, "", "");
        let script = format!(
            "cd \"{link_str}\" 2>/dev/null || exit 0; \
             for d in {globs}; do {loop_body} done"
        );
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("sh -c '{script}'"))
            .status()
            .expect("run reap script");
        assert!(status.success(), "reap script should exit 0");

        assert!(
            !idle.exists(),
            "idle sibling behind a SYMLINKED project dir must be reaped"
        );
        assert!(
            live.exists(),
            "live sibling must be preserved via the symlinked project dir"
        );
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
    fn test_parse_rsync_files_prefers_transferred_count_over_total_tree_count() {
        let _guard = test_guard!();
        let output = "Number of files: 28,779 (reg: 20,000, dir: 8,779)\nNumber of files transferred: 42\nTotal bytes sent: 1,271,299";
        assert_eq!(parse_rsync_files(output), 42);
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
    fn test_transfer_pipeline_defaults_to_plain_ssh_sessions() {
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        );

        assert!(!pipeline.ssh_options.control_master);
        assert!(pipeline.ssh_options.control_persist_idle.is_none());
    }

    #[test]
    fn test_transfer_pipeline_enables_control_master_when_persist_configured() {
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig {
                ssh_control_persist_secs: Some(60),
                ..TransferConfig::default()
            },
        );

        assert!(pipeline.ssh_options.control_master);
        assert_eq!(
            pipeline.ssh_options.control_persist_idle,
            Some(std::time::Duration::from_secs(60))
        );
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
    fn test_external_timeout_preserves_leading_env_assignments() {
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        )
        .with_compilation_kind(Some(CompilationKind::CargoTest));

        let wrapped = pipeline.wrap_with_external_timeout(
            "CARGO_TARGET_DIR='/tmp/rch target' RUSTFLAGS='-C target-cpu=native' cargo test",
        );

        assert!(wrapped.contains("timeout"));
        assert!(wrapped.contains(" env CARGO_TARGET_DIR="));
        assert!(!wrapped.contains("1800 CARGO_TARGET_DIR="));
        assert!(wrapped.contains("RUSTFLAGS='-C target-cpu=native' cargo test"));
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
            control_master: true,
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
    fn test_rsync_commands_disable_owner_and_group_preservation() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let pipeline = TransferPipeline::new(
            temp_dir.path().to_path_buf(),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
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

        let sync = pipeline.build_sync_command(
            &worker,
            "mockuser@mock://worker:/tmp/rch/test-project/abc123",
            "/tmp/rch/test-project/abc123",
            &[],
        );
        assert_portable_rsync_archive_args(&command_args(&sync));

        let sync_streaming = pipeline.build_sync_streaming_command(
            &worker,
            "mockuser@mock://worker:/tmp/rch/test-project/abc123",
            "/tmp/rch/test-project/abc123",
            &[],
        );
        assert_portable_rsync_archive_args(&command_args(&sync_streaming));

        let retrieve =
            pipeline.build_retrieve_command(&worker, "/tmp/rch/test-project/abc123", &[]);
        assert_portable_rsync_archive_args(&command_args(&retrieve));

        let retrieve_streaming =
            pipeline.build_retrieve_streaming_command(&worker, "/tmp/rch/test-project/abc123", &[]);
        assert_portable_rsync_archive_args(&command_args(&retrieve_streaming));
    }

    #[test]
    fn test_build_retrieve_command_applies_rchignore_excludes_before_directory_include() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(
            temp_dir.path().join(".rchignore"),
            ".beads/\n.beads/recovery_*/\ncustom-cache/\ntarget/\n*.rlib\n",
        )
        .expect("write .rchignore");

        let pipeline = TransferPipeline::new(
            temp_dir.path().to_path_buf(),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
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

        let cmd = pipeline.build_retrieve_command(
            &worker,
            "/tmp/rch/test-project/abc123",
            &["target/debug/**".to_string()],
        );

        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();

        let beads_exclude =
            arg_pair_position(&args, "--exclude", ".beads/").expect("missing .beads exclude");
        let recovery_exclude = arg_pair_position(&args, "--exclude", ".beads/recovery_*/")
            .expect("missing .beads recovery exclude");
        let custom_exclude = arg_pair_position(&args, "--exclude", "custom-cache/")
            .expect("missing custom cache exclude");
        let target_exclude = arg_pair_position(&args, "--exclude", "target/");
        let rlib_exclude = args
            .windows(2)
            .position(|window| window == ["--exclude", "*.rlib"]);
        let include_dirs = args
            .windows(2)
            .position(|window| window == ["--include", "*/"])
            .expect("missing directory include");
        // RCH bug d7xc3: artifact patterns are now anchored at the rsync
        // source root via `anchor_retrieval_pattern`, so `target/debug/**`
        // is emitted as `/target/debug/**` to prevent it from floating
        // and matching e.g. `<root>/anything/target/debug/...`.
        let target_include = args
            .windows(2)
            .position(|window| window == ["--include", "/target/debug/**"])
            .expect("missing artifact include");

        assert!(beads_exclude < include_dirs);
        assert!(recovery_exclude < include_dirs);
        assert!(custom_exclude < include_dirs);
        assert_eq!(target_exclude, None);
        assert_eq!(rlib_exclude, None);
        assert!(include_dirs < target_include);
        assert!(
            !args
                .windows(2)
                .any(|window| window == ["--exclude", "target/"]),
            "retrieve filters must not inherit upload-only target/ exclusion"
        );
        assert!(args.windows(2).any(|window| window == ["--exclude", "*"]));
    }

    #[test]
    fn test_build_retrieve_streaming_command_does_not_exclude_artifact_root_from_rchignore() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(temp_dir.path().join(".rchignore"), "build/\n.cache/\n")
            .expect("write .rchignore");

        let pipeline = TransferPipeline::new(
            temp_dir.path().to_path_buf(),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
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

        let cmd = pipeline.build_retrieve_streaming_command(
            &worker,
            "/tmp/rch/test-project/abc123",
            &["build/**".to_string()],
        );

        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();

        assert!(
            !args
                .windows(2)
                .any(|window| window == ["--exclude", "build/"]),
            "streaming retrieval must not exclude the requested artifact root"
        );
        assert!(
            args.windows(2)
                .any(|window| window == ["--exclude", ".cache/"]),
            "unrelated directory-only .rchignore entries should still prune traversal"
        );
        assert!(
            args.windows(2)
                .any(|window| window == ["--include", "/build/**"]),
            "streaming retrieval should include the anchored form of requested artifact patterns (RCH bug d7xc3)"
        );
    }

    #[test]
    fn test_build_retrieve_streaming_command_uses_safe_links() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let pipeline = TransferPipeline::new(
            temp_dir.path().to_path_buf(),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
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

        let cmd = pipeline.build_retrieve_streaming_command(
            &worker,
            "/tmp/rch/test-project/abc123",
            &["target/release/**".to_string()],
        );

        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();

        assert!(
            args.iter().any(|arg| arg == "--safe-links"),
            "streaming artifact retrieval must keep symlink traversal protection"
        );
        assert!(
            args.windows(2)
                .any(|window| window == ["--include", "/target/release/**"]),
            "streaming retrieval should still include requested artifact patterns (anchored per RCH bug d7xc3)"
        );
        assert!(args.windows(2).any(|window| window == ["--exclude", "*"]));
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
    fn test_build_remote_command_uses_custom_remote_cargo_target_dir_name() {
        let _guard = test_guard!();
        let mut overrides = HashMap::new();
        overrides.insert(
            "CARGO_TARGET_DIR".to_string(),
            "/data/tmp/pi_agent_rust/pearleagle".to_string(),
        );

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/project"),
            "project".to_string(),
            "hash".to_string(),
            TransferConfig::default(),
        )
        .with_env_allowlist(vec!["CARGO_TARGET_DIR".to_string()])
        .with_env_overrides(overrides)
        .with_remote_cargo_target_dir_name(".rch-target-worker-job-42");

        let worker_scoped_root = pipeline.remote_path();
        let command = pipeline.build_remote_command("cargo test --no-run", None);
        assert!(command.contains(&format!(
            "CARGO_TARGET_DIR='{}/.rch-target-worker-job-42'",
            worker_scoped_root
        )));
        assert!(command.contains(&format!("{}/.rch-target-worker-job-42", worker_scoped_root)));
        assert!(!command.contains(&format!("{}/.rch-target'", worker_scoped_root)));
    }

    #[test]
    fn test_invalid_remote_cargo_target_dir_name_falls_back_to_default() {
        let _guard = test_guard!();
        let mut overrides = HashMap::new();
        overrides.insert(
            "CARGO_TARGET_DIR".to_string(),
            "/data/tmp/pi_agent_rust/pearleagle".to_string(),
        );

        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/project"),
            "project".to_string(),
            "hash".to_string(),
            TransferConfig::default(),
        )
        .with_env_allowlist(vec!["CARGO_TARGET_DIR".to_string()])
        .with_env_overrides(overrides)
        .with_remote_cargo_target_dir_name("../bad");

        assert!(
            pipeline
                .build_remote_command("cargo test --no-run", None)
                .contains(".rch-target")
        );
        assert_eq!(
            pipeline.remote_cargo_target_dir(),
            format!("{}/.rch-target", pipeline.remote_path())
        );
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
    fn test_build_remote_command_preserves_inline_env_before_toolchain_runner() {
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/project"),
            "project".to_string(),
            "hash".to_string(),
            TransferConfig::default(),
        )
        .with_compilation_kind(Some(CompilationKind::CargoBuild));

        let command = pipeline.build_remote_command(
            "RUSTFLAGS='-C target-cpu=native' cargo build",
            Some(&ToolchainInfo::new("nightly", None, "")),
        );

        assert!(
            command.contains("RUSTFLAGS='-C target-cpu=native' rustup run nightly cargo build")
        );
        assert!(!command.contains("rustup run nightly RUSTFLAGS="));
    }

    #[test]
    fn test_build_remote_command_records_remote_pgid_for_cancellation() {
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/project"),
            "project".to_string(),
            "hash".to_string(),
            TransferConfig::default(),
        )
        .with_build_id(Some(42));

        let command = pipeline.build_remote_command("cargo test --no-run", None);
        let remote_pgid_file = pipeline
            .remote_pgid_file_path()
            .expect("build_id should enable remote pgid tracking");

        assert!(command.contains("/tmp/rch-run/"));
        assert!(!command.contains("/.rch-run/"));
        assert!(command.contains("echo $$ > \"$1\""));
        assert!(command.contains("setsid sh -c"));
        assert!(command.contains(&remote_pgid_file));
    }

    #[test]
    fn test_build_id_path_uses_group_kill_watchdog_not_foreground_timeout() {
        // The pgid-tracked path must group-kill the whole session at the wall-clock
        // cap (so a livelocked test binary + fixtures are reaped together), NOT use
        // `timeout --foreground` (which only kills its direct child -> 20-45h orphans).
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/project"),
            "project".to_string(),
            "hash".to_string(),
            TransferConfig::default(),
        )
        .with_build_id(Some(7))
        .with_compilation_kind(Some(CompilationKind::CargoTest));

        let command = pipeline.build_remote_command("cargo test", None);

        // Watchdog group-kill of the recorded pgid (no `--`: dash mishandles it).
        assert!(
            command.contains("kill -KILL -\"$__p\""),
            "build_id path must SIGKILL the whole process group: {command}"
        );
        assert!(
            !command.contains("kill -KILL -- -"),
            "must not use the `--` form (broken in dash): {command}"
        );
        // The default cargo-test cap (1800s) is passed to the watchdog as an arg.
        assert!(
            command.contains("1800 sh -lc"),
            "watchdog must receive the test timeout (1800s): {command}"
        );
        assert!(
            command.contains("wait \"$__c\""),
            "watchdog must wait on the job"
        );
        // The build_id path must NOT shell out to `timeout --foreground` (the bug).
        assert!(
            !command.contains("--foreground"),
            "build_id path must not use timeout --foreground: {command}"
        );
    }

    /// Functional proof: a SIGTERM-ignoring grandchild that the test harness forked
    /// is fully reaped by the watchdog at the cap. Under the old `timeout
    /// --foreground` behavior the grandchild would orphan and survive. Linux-only
    /// (needs setsid + process-group signaling); the build/CI workers are Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_watchdog_reaps_forking_orphan_at_cap() {
        use std::process::Command;
        use std::time::{Duration, Instant};

        if !Command::new("sh")
            .arg("-c")
            .arg("command -v setsid")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            eprintln!("setsid unavailable; skipping functional watchdog test");
            return;
        }

        let dir = std::env::temp_dir().join(format!("rch-wd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pgf = dir.join("job.pgid");
        let marker = dir.join("grandchild-alive");
        let _ = std::fs::remove_file(&pgf);
        let _ = std::fs::remove_file(&marker);

        // Exactly the production watchdog program (build_id branch).
        let watchdog = "echo $$ > \"$1\"; __p=$$; __t=\"$2\"; shift 2; \"$@\" & __c=$!; \
if [ \"$__t\" -gt 0 ] 2>/dev/null; then ( sleep \"$__t\"; kill -KILL -\"$__p\" 2>/dev/null ) & __w=$!; fi; \
wait \"$__c\"; __s=$?; if [ -n \"$__w\" ]; then kill \"$__w\" 2>/dev/null; fi; exit \"$__s\"";

        // Job forks a grandchild that IGNORES SIGTERM and loops forever (a livelock
        // that only a group SIGKILL can stop), then waits on it.
        let inner = format!(
            "( trap '' TERM; touch '{}'; while true; do sleep 1; done ) & gc=$!; trap '' TERM; wait $gc",
            marker.display()
        );

        let mut child = Command::new("setsid")
            .arg("sh")
            .arg("-c")
            .arg(watchdog)
            .arg("rch-build")
            .arg(pgf.to_str().unwrap())
            .arg("2") // 2-second cap
            .arg("sh")
            .arg("-lc")
            .arg(&inner)
            // Detach all stdio: otherwise the forked grandchild inherits libtest's
            // captured stdout pipe and the harness blocks waiting for EOF.
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();

        // Grandchild must come up.
        let start = Instant::now();
        while !marker.exists() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(marker.exists(), "grandchild should have started");
        let pgid = std::fs::read_to_string(&pgf).unwrap().trim().to_string();
        assert!(pgid.parse::<i64>().unwrap() > 1, "recorded a real pgid");

        // The session leader must die from the cap within a few seconds.
        let mut exited = false;
        let wstart = Instant::now();
        while wstart.elapsed() < Duration::from_secs(8) {
            if matches!(child.try_wait(), Ok(Some(_))) {
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // Safety net: ensure nothing leaks regardless of assertions.
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!("kill -KILL -- -{pgid} 2>/dev/null"))
            .status();
        let _ = child.wait();

        assert!(
            exited,
            "watchdog should have killed the session at the ~2s cap"
        );

        // The whole process group (incl. the TERM-ignoring grandchild) must be gone.
        std::thread::sleep(Duration::from_millis(300));
        let group_alive = Command::new("sh")
            .arg("-c")
            .arg(format!("kill -0 -- -{pgid} 2>/dev/null"))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            !group_alive,
            "process group {pgid} (with the SIGTERM-ignoring grandchild) must be fully reaped"
        );
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
        let content = "target/\n.git/\nnode_modules/";
        let patterns = parse_rchignore_content(content);
        assert_eq!(patterns, vec!["target/", ".git/", "node_modules/"]);
    }

    #[test]
    fn test_parse_rchignore_content_with_comments() {
        let _guard = test_guard!();
        let content = r#"# Build artifacts
target/
# Git metadata
.git/
# Node stuff
node_modules/"#;
        let patterns = parse_rchignore_content(content);
        assert_eq!(patterns, vec!["target/", ".git/", "node_modules/"]);
    }

    #[test]
    fn test_parse_rchignore_content_with_blank_lines() {
        let _guard = test_guard!();
        let content = r#"
target/

.git/


node_modules/
"#;
        let patterns = parse_rchignore_content(content);
        assert_eq!(patterns, vec!["target/", ".git/", "node_modules/"]);
    }

    #[test]
    fn test_parse_rchignore_content_trims_whitespace() {
        let _guard = test_guard!();
        let content = "  target/  \n\t.git/\t\n   node_modules/   ";
        let patterns = parse_rchignore_content(content);
        assert_eq!(patterns, vec!["target/", ".git/", "node_modules/"]);
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
        assert!(effective.contains(&".git/".to_string()));
        assert!(
            !effective.contains(&".git/objects/".to_string()),
            "default upload excludes must avoid syncing a partial .git tree"
        );
        assert!(effective.contains(&".rch-target/".to_string()));
        assert!(effective.contains(&".rch-tmp/".to_string()));
        assert!(effective.contains(&".franken_whisper/tools/ffmpeg/".to_string()));
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
        assert!(effective.contains(&".franken_whisper/tools/ffmpeg/".to_string()));
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
        assert!(effective.contains(&".franken_whisper/tools/ffmpeg/".to_string()));
        assert!(effective.contains(&"custom/".to_string()));
        // target/ should appear only once
        let target_count = effective.iter().filter(|p| *p == "target/").count();
        assert_eq!(target_count, 1);
        // Runtime guards should appear only once too.
        let runtime_target_count = effective.iter().filter(|p| *p == ".rch-target/").count();
        assert_eq!(runtime_target_count, 1);
        let runtime_tmp_count = effective.iter().filter(|p| *p == ".rch-tmp/").count();
        assert_eq!(runtime_tmp_count, 1);
        let runtime_ffmpeg_count = effective
            .iter()
            .filter(|p| *p == ".franken_whisper/tools/ffmpeg/")
            .count();
        assert_eq!(runtime_ffmpeg_count, 1);
    }

    #[test]
    fn test_get_effective_excludes_rewrites_legacy_core_dump_globs() {
        let _guard = test_guard!();
        let config = TransferConfig {
            exclude_patterns: vec![
                "target/".to_string(),
                "core.*".to_string(),
                ".core.*".to_string(),
                "core.[0-9]*".to_string(),
            ],
            ..TransferConfig::default()
        };

        let pipeline = TransferPipeline::new(
            PathBuf::from("/nonexistent/project"),
            "project".to_string(),
            "hash".to_string(),
            config,
        );

        let effective = pipeline.get_effective_excludes();

        assert!(!effective.contains(&"core.*".to_string()));
        assert!(!effective.contains(&".core.*".to_string()));
        assert!(effective.contains(&"core.[0-9]*".to_string()));
        assert!(effective.contains(&".core.[0-9]*".to_string()));
        assert_eq!(effective.iter().filter(|p| *p == "core.[0-9]*").count(), 1);
    }

    #[test]
    fn test_get_effective_excludes_rewrites_legacy_git_objects_exclude() {
        let _guard = test_guard!();
        let config = TransferConfig {
            exclude_patterns: vec![
                "target/".to_string(),
                ".git/objects/".to_string(),
                "node_modules/".to_string(),
            ],
            ..TransferConfig::default()
        };

        let pipeline = TransferPipeline::new(
            PathBuf::from("/nonexistent/project"),
            "project".to_string(),
            "hash".to_string(),
            config,
        );

        let effective = pipeline.get_effective_excludes();

        assert!(effective.contains(&".git/".to_string()));
        assert!(!effective.contains(&".git/objects/".to_string()));
        assert_eq!(effective.iter().filter(|p| *p == ".git/").count(), 1);
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
    fn test_effective_rsync_retry_config_uses_transfer_time_override() {
        let _guard = test_guard!();
        let transfer_config = TransferConfig {
            max_transfer_time_ms: Some(5000),
            retry: RetryConfig {
                total_timeout_ms: 30000,
                ..RetryConfig::default()
            },
            ..TransferConfig::default()
        };
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/test"),
            "test-project".to_string(),
            "abc123".to_string(),
            transfer_config,
        );

        assert_eq!(
            pipeline.effective_rsync_retry_config().total_timeout_ms,
            5000
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_execute_rsync_with_retry_times_out_hanging_child() {
        let _guard = test_guard!();
        let retry_config = RetryConfig {
            max_attempts: 1,
            total_timeout_ms: 25,
            jitter_factor: 0.0,
            ..RetryConfig::default()
        };
        let start = std::time::Instant::now();

        let err = execute_rsync_with_retry(&retry_config, "test_hanging_rsync", || {
            let mut cmd = Command::new("sleep");
            cmd.arg("5");
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());
            cmd
        })
        .await
        .expect_err("hanging child should time out");

        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "timeout should stop the child promptly"
        );
        assert!(
            err.to_string()
                .contains("test_hanging_rsync: timed out after 25ms")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_run_command_streaming_times_out_hanging_child() {
        let _guard = test_guard!();
        let mut cmd = Command::new("sleep");
        cmd.arg("5");
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let start = std::time::Instant::now();

        let err = run_command_streaming(
            cmd,
            "test_streaming_rsync",
            std::time::Duration::from_millis(25),
            |_| {},
        )
        .await
        .expect_err("streaming child should time out");

        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "timeout should stop the streaming child promptly"
        );
        assert!(
            err.to_string()
                .contains("test_streaming_rsync: timed out after 25ms")
        );
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

    #[test]
    fn test_build_sync_command_metadata_only_sync_omits_delete_and_uses_includes() {
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/workspace-root"),
            "workspace-root".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        )
        .with_sync_include_patterns(vec![
            "Cargo.toml".to_string(),
            "Cargo.lock".to_string(),
            ".cargo/".to_string(),
            ".cargo/**".to_string(),
        ])
        .with_sync_delete(false);

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

        assert!(
            !args.iter().any(|arg| arg == "--delete"),
            "metadata-only syncs must not delete unrelated remote files"
        );
        assert!(
            args.windows(2)
                .any(|window| window == ["--include", "Cargo.toml"]),
            "metadata-only syncs should include Cargo.toml"
        );
        assert!(
            args.windows(2)
                .any(|window| window == ["--include", ".cargo/**"]),
            "metadata-only syncs should include workspace .cargo metadata"
        );
        assert!(
            args.windows(2).any(|window| window == ["--exclude", "*"]),
            "metadata-only syncs should exclude everything else"
        );
    }

    #[test]
    fn test_build_sync_streaming_command_metadata_only_sync_omits_delete_and_uses_includes() {
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/workspace-root"),
            "workspace-root".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        )
        .with_sync_include_patterns(vec![
            "Cargo.toml".to_string(),
            "Cargo.lock".to_string(),
            ".cargo/".to_string(),
            ".cargo/**".to_string(),
        ])
        .with_sync_delete(false);

        let worker = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock://worker".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        };

        let cmd = pipeline.build_sync_streaming_command(
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

        assert!(
            !args.iter().any(|arg| arg == "--delete"),
            "streaming metadata-only syncs must not delete unrelated remote files"
        );
        assert!(
            args.windows(2)
                .any(|window| window == ["--include", "Cargo.toml"]),
            "streaming metadata-only syncs should include Cargo.toml"
        );
        assert!(
            args.windows(2)
                .any(|window| window == ["--include", ".cargo/**"]),
            "streaming metadata-only syncs should include workspace .cargo metadata"
        );
        assert!(
            args.windows(2).any(|window| window == ["--exclude", "*"]),
            "streaming metadata-only syncs should exclude everything else"
        );
    }

    #[test]
    fn test_build_sync_streaming_command_default_sync_includes_delete() {
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            PathBuf::from("/tmp/workspace-root"),
            "workspace-root".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
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

        let cmd = pipeline.build_sync_streaming_command(
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

        assert!(
            args.iter().any(|arg| arg == "--delete"),
            "normal streaming syncs should retain delete semantics"
        );
    }

    // =========================================================================
    // Source-Integrity Hardening Tests (RCH bug d7xc3)
    // =========================================================================
    //
    // These tests pin the contract that artifact retrieval cannot dirty the
    // local source checkout, regardless of the pattern shape or what other
    // agents may have left on the remote worker. The fix has three layers:
    //
    //   1. anchor_retrieval_pattern: every artifact pattern is anchored at
    //      the rsync source root with leading `/`.
    //   2. allowed_artifact_roots: derive the implied top-level allowed roots
    //      from anchored patterns; non-glob top-level components only.
    //   3. local_source_roots_to_exclude: emit explicit `--exclude /<entry>`
    //      rules for every top-level entry in the local project root that
    //      isn't an allowed artifact root.
    //
    // Together these mean: even if rsync's filter semantics had a subtle
    // bug, AND a malicious/stale remote tree contained source files at
    // unexpected paths, AND the artifact patterns were too permissive,
    // rsync STILL refuses to descend into local source roots.

    #[test]
    fn anchor_retrieval_pattern_prepends_slash_when_unanchored() {
        // TEST START: bare patterns get anchored
        assert_eq!(
            anchor_retrieval_pattern("target/debug/**"),
            "/target/debug/**"
        );
        assert_eq!(
            anchor_retrieval_pattern("target/release/**"),
            "/target/release/**"
        );
        assert_eq!(anchor_retrieval_pattern("coverage/**"), "/coverage/**");
        assert_eq!(
            anchor_retrieval_pattern("*.tsbuildinfo"),
            "/*.tsbuildinfo",
            "top-level glob files must still be anchored"
        );
        // TEST PASS: unanchored patterns get a leading `/`
    }

    #[test]
    fn anchor_retrieval_pattern_preserves_already_anchored() {
        // TEST START: patterns starting with `/` are passthrough
        assert_eq!(
            anchor_retrieval_pattern("/target/debug/**"),
            "/target/debug/**"
        );
        assert_eq!(anchor_retrieval_pattern("/coverage/**"), "/coverage/**");
        // TEST PASS: already-anchored patterns are returned unchanged
    }

    #[test]
    fn anchor_retrieval_pattern_preserves_recursive_globstar() {
        // TEST START: explicit recursion via `**/` is intentional, leave alone
        assert_eq!(
            anchor_retrieval_pattern("**/junit.xml"),
            "**/junit.xml",
            "explicit recursive globstar must be preserved"
        );
        // TEST PASS: explicit `**/` patterns pass through
    }

    #[test]
    fn anchor_retrieval_pattern_handles_edge_cases() {
        // TEST START: empty and whitespace patterns are returned unchanged
        assert_eq!(anchor_retrieval_pattern(""), "");
        assert_eq!(anchor_retrieval_pattern("   "), "   ");
        // TEST PASS: caller decides what to do with junk input
    }

    #[test]
    fn allowed_artifact_roots_derives_first_component() {
        // TEST START: implied allowed roots = first path component of each
        // anchored pattern, glob components excluded.
        let patterns = vec![
            "target/debug/**".to_string(),
            "target/release/**".to_string(),
            "coverage/**".to_string(),
            "*.tsbuildinfo".to_string(),
            "/build/output/**".to_string(),
        ];
        let roots = allowed_artifact_roots(&patterns);
        assert!(roots.contains("target"));
        assert!(roots.contains("coverage"));
        assert!(roots.contains("build"));
        // Top-level glob patterns cannot contribute a single allowed root.
        assert!(!roots.iter().any(|r| r.contains('*')));
        // TEST PASS: derived allowed roots
    }

    #[test]
    fn allowed_artifact_roots_handles_empty_input() {
        // TEST START: defensive — empty patterns yields empty set
        let roots = allowed_artifact_roots(&[]);
        assert!(roots.is_empty());
        // TEST PASS: empty input is safe
    }

    #[test]
    fn local_source_roots_to_exclude_emits_explicit_rules_for_each_top_level_source_entry() {
        // TEST START: scan local project root, emit `--exclude /<entry>/`
        // for every top-level dir that ISN'T an allowed artifact root.
        // This is the belt-and-suspenders defense — even if rsync filters
        // are subtly wrong, these explicit anchored excludes pin source
        // roots out of the retrieval set.
        let _guard = test_guard!();
        let temp = tempfile::tempdir().expect("create temp dir");
        std::fs::create_dir(temp.path().join("rch")).expect("mkdir rch");
        std::fs::create_dir(temp.path().join("rch-common")).expect("mkdir rch-common");
        std::fs::create_dir(temp.path().join("rchd")).expect("mkdir rchd");
        std::fs::create_dir(temp.path().join("target")).expect("mkdir target");
        std::fs::write(temp.path().join("Cargo.toml"), b"[workspace]\n").expect("write toml");
        let pipeline = TransferPipeline::new(
            temp.path().to_path_buf(),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        );
        let artifact_patterns = ["target/debug/**".to_string()];
        let allowed = allowed_artifact_roots(&artifact_patterns);
        let excludes = pipeline.local_source_roots_to_exclude(&allowed, &artifact_patterns);

        // target/ MUST NOT be excluded — it's the artifact root.
        assert!(
            !excludes.iter().any(|e| e == "/target/"),
            "target/ is an allowed artifact root and must NOT be in the exclude set"
        );
        // Every other source dir MUST be excluded (anchored with leading `/`).
        assert!(
            excludes.iter().any(|e| e == "/rch/"),
            "rch/ source dir must be excluded; got {excludes:?}"
        );
        assert!(
            excludes.iter().any(|e| e == "/rch-common/"),
            "rch-common/ source dir must be excluded; got {excludes:?}"
        );
        assert!(
            excludes.iter().any(|e| e == "/rchd/"),
            "rchd/ source dir must be excluded; got {excludes:?}"
        );
        // Top-level files also excluded, with no trailing slash.
        assert!(
            excludes.iter().any(|e| e == "/Cargo.toml"),
            "top-level files must be excluded (no trailing slash); got {excludes:?}"
        );
        // Excludes are sorted for stability.
        let mut sorted = excludes.clone();
        sorted.sort();
        assert_eq!(excludes, sorted, "excludes must be sorted for determinism");
        // TEST PASS: source-root exclusion contract
    }

    #[test]
    fn local_source_roots_to_exclude_does_not_hide_top_level_glob_artifacts() {
        // TEST START: Bun/typecheck retrieval includes top-level globs such
        // as `*.tsbuildinfo`. If the local file already exists, the
        // source-integrity guard must not emit a prior exclude that prevents
        // rsync from refreshing it.
        let _guard = test_guard!();
        let temp = tempfile::tempdir().expect("create temp dir");
        std::fs::create_dir(temp.path().join("src")).expect("mkdir src");
        std::fs::write(temp.path().join("Cargo.toml"), b"[workspace]\n").expect("write toml");
        std::fs::write(temp.path().join("tsconfig.tsbuildinfo"), b"old").expect("write artifact");
        let pipeline = TransferPipeline::new(
            temp.path().to_path_buf(),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        );
        let artifact_patterns = ["*.tsbuildinfo".to_string()];
        let allowed = allowed_artifact_roots(&artifact_patterns);
        let excludes = pipeline.local_source_roots_to_exclude(&allowed, &artifact_patterns);

        assert!(
            !excludes.iter().any(|e| e == "/tsconfig.tsbuildinfo"),
            "declared top-level glob artifact must not be source-excluded; got {excludes:?}"
        );
        assert!(
            excludes.iter().any(|e| e == "/Cargo.toml"),
            "unrelated top-level files must still be source-excluded; got {excludes:?}"
        );
        assert!(
            excludes.iter().any(|e| e == "/src/"),
            "source directories must still be source-excluded; got {excludes:?}"
        );
        // TEST PASS: top-level artifact glob stays retrievable without
        // opening unrelated source entries.
    }

    #[test]
    fn catch_all_pattern_does_not_prove_literal_star_entry_is_artifact() {
        // TEST START: a catch-all retrieval pattern may fetch newly-created
        // root outputs, but it must not prove that a local source entry named
        // `*` is safe to overwrite.
        assert!(!top_level_artifact_pattern_matches_entry("*", "*"));
        assert_eq!(escape_rsync_filter_literal_component("*").as_ref(), r"\*");
        assert_eq!(
            escape_rsync_filter_literal_component("question?mark.c").as_ref(),
            r"question\?mark.c"
        );
        assert_eq!(
            escape_rsync_filter_literal_component("array[0].c").as_ref(),
            r"array\[0].c"
        );
        // TEST PASS: wildcard-looking local names stay literal in filter rules.
    }

    #[cfg(unix)]
    #[test]
    fn local_source_roots_to_exclude_keeps_catch_all_from_unprotecting_source_entries() {
        // TEST START: C/C++ retrieval includes a catch-all `*` for newly
        // created root-level outputs. That pattern must not make every
        // existing local source entry look safe to overwrite.
        let _guard = test_guard!();
        let temp = tempfile::tempdir().expect("create temp dir");
        std::fs::create_dir(temp.path().join("src")).expect("mkdir src");
        std::fs::write(
            temp.path().join("main.c"),
            b"int main(void) { return 0; }\n",
        )
        .expect("write source file");
        std::fs::write(temp.path().join("*"), b"literal star source\n")
            .expect("write literal star source file");
        std::fs::write(temp.path().join("question?mark.c"), b"int q(void);\n")
            .expect("write literal question source file");
        std::fs::write(temp.path().join("array[0].c"), b"int a(void);\n")
            .expect("write literal bracket source file");
        std::fs::write(temp.path().join("Makefile"), b"all:\n\tcc main.c\n")
            .expect("write makefile");
        let pipeline = TransferPipeline::new(
            temp.path().to_path_buf(),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        );
        let artifact_patterns = ["*".to_string()];
        let allowed = allowed_artifact_roots(&artifact_patterns);
        let excludes = pipeline.local_source_roots_to_exclude(&allowed, &artifact_patterns);

        assert!(
            excludes.iter().any(|e| e == "/src/"),
            "catch-all artifact pattern must not unprotect source directories; got {excludes:?}"
        );
        assert!(
            excludes.iter().any(|e| e == "/main.c"),
            "catch-all artifact pattern must not unprotect existing source files; got {excludes:?}"
        );
        assert!(
            excludes.iter().any(|e| e == "/Makefile"),
            "catch-all artifact pattern must not unprotect existing build files; got {excludes:?}"
        );
        assert!(
            excludes.iter().any(|e| e == r"/\*"),
            "literal local filenames with rsync glob syntax must be excluded literally; got {excludes:?}"
        );
        assert!(
            excludes.iter().any(|e| e == r"/question\?mark.c"),
            "literal question-mark filenames must not become rsync wildcards; got {excludes:?}"
        );
        assert!(
            excludes.iter().any(|e| e == r"/array\[0].c"),
            "literal bracket filenames must not become rsync character classes; got {excludes:?}"
        );
        // TEST PASS: catch-all retrieval stays subordinate to source protection.
    }

    #[test]
    fn local_source_roots_to_exclude_handles_unreadable_project_root() {
        // TEST START: defensive — if project_root is unreadable, we get an
        // empty exclude list (not a panic). Other retrieval guards still
        // apply, so retrieval remains safe.
        let _guard = test_guard!();
        let pipeline = TransferPipeline::new(
            std::path::PathBuf::from("/this/path/does/not/exist/anywhere/d7xc3-test"),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
        );
        let allowed = std::collections::BTreeSet::new();
        let excludes = pipeline.local_source_roots_to_exclude(&allowed, &[]);
        assert!(
            excludes.is_empty(),
            "unreadable project_root must yield empty excludes (got {excludes:?})"
        );
        // TEST PASS: unreadable root is non-fatal
    }

    #[test]
    fn build_retrieve_command_excludes_local_source_dirs_at_anchored_paths() {
        // TEST START: integration test — build the retrieve command for a
        // workspace-shaped local project and verify both layers fire:
        //
        //   (a) The artifact pattern is anchored.
        //   (b) Every top-level source dir gets an explicit anchored exclude
        //       BEFORE the directory `--include "*/"`.
        let _guard = test_guard!();
        let temp = tempfile::tempdir().expect("create temp dir");
        std::fs::create_dir(temp.path().join("rch")).expect("mkdir rch");
        std::fs::create_dir(temp.path().join("rch-common")).expect("mkdir rch-common");
        std::fs::create_dir(temp.path().join("rchd")).expect("mkdir rchd");
        std::fs::create_dir(temp.path().join("rch-wkr")).expect("mkdir rch-wkr");
        std::fs::create_dir(temp.path().join("target")).expect("mkdir target");
        let pipeline = TransferPipeline::new(
            temp.path().to_path_buf(),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
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
        let cmd = pipeline.build_retrieve_command(
            &worker,
            "/tmp/rch/test-project/abc123",
            &["target/debug/**".to_string()],
        );
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();

        // (a) Artifact pattern anchored.
        assert!(
            args.windows(2)
                .any(|w| w == ["--include", "/target/debug/**"]),
            "artifact pattern must be emitted in anchored form (RCH bug d7xc3); got args = {args:?}"
        );
        assert!(
            !args
                .windows(2)
                .any(|w| w == ["--include", "target/debug/**"]),
            "unanchored pattern form must NOT be emitted (RCH bug d7xc3)"
        );

        // (b) All four workspace source dirs explicitly excluded with anchored form.
        for src in ["/rch/", "/rch-common/", "/rchd/", "/rch-wkr/"] {
            assert!(
                args.windows(2).any(|w| w == ["--exclude", src]),
                "{src} must be in the exclude set (source-integrity guard); got args = {args:?}"
            );
        }

        // The artifact root MUST NOT be in the source-exclude set.
        assert!(
            !args.windows(2).any(|w| w == ["--exclude", "/target/"]),
            "target/ is the allowed artifact root and must NOT be source-excluded"
        );

        // Ordering: source-excludes are emitted BEFORE the `--include "*/"`
        // directive so rsync evaluates them first and refuses to descend.
        let include_dirs_pos = args
            .windows(2)
            .position(|w| w == ["--include", "*/"])
            .expect("missing directory include");
        let first_source_exclude_pos = args
            .windows(2)
            .position(|w| w == ["--exclude", "/rch/"])
            .expect("missing /rch/ exclude");
        assert!(
            first_source_exclude_pos < include_dirs_pos,
            "source-integrity excludes must be applied BEFORE --include */"
        );
        // TEST PASS: source-integrity guard wired through both helpers
    }

    #[test]
    fn build_retrieve_command_keeps_existing_top_level_glob_artifact_retrievable() {
        // TEST START: command-level proof for the Bun/default artifact case.
        // A local tsbuildinfo file must not be excluded before the artifact
        // include can match it.
        let _guard = test_guard!();
        let temp = tempfile::tempdir().expect("create temp dir");
        std::fs::create_dir(temp.path().join("src")).expect("mkdir src");
        std::fs::write(temp.path().join("tsconfig.tsbuildinfo"), b"old").expect("write artifact");
        let pipeline = TransferPipeline::new(
            temp.path().to_path_buf(),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
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
        let cmd = pipeline.build_retrieve_command(
            &worker,
            "/tmp/rch/test-project/abc123",
            &["*.tsbuildinfo".to_string()],
        );
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        assert!(
            args.windows(2)
                .any(|w| w == ["--include", "/*.tsbuildinfo"]),
            "top-level glob artifact must be emitted in anchored form; got args = {args:?}"
        );
        assert!(
            !args
                .windows(2)
                .any(|w| w == ["--exclude", "/tsconfig.tsbuildinfo"]),
            "existing top-level artifact must not be excluded before its include; got args = {args:?}"
        );
        assert!(
            args.windows(2).any(|w| w == ["--exclude", "/src/"]),
            "source directories must remain protected; got args = {args:?}"
        );
        // TEST PASS: command preserves both source guard and top-level glob retrieval.
    }

    #[cfg(unix)]
    #[test]
    fn build_retrieve_command_with_catch_all_still_excludes_existing_source_entries() {
        // TEST START: command-level proof for the C/C++ catch-all artifact
        // pattern. The broad include may fetch new root outputs, but it must
        // not run before source excludes for existing entries.
        let _guard = test_guard!();
        let temp = tempfile::tempdir().expect("create temp dir");
        std::fs::create_dir(temp.path().join("src")).expect("mkdir src");
        std::fs::write(
            temp.path().join("main.c"),
            b"int main(void) { return 0; }\n",
        )
        .expect("write source file");
        std::fs::write(temp.path().join("*"), b"literal star source\n")
            .expect("write literal star source file");
        let pipeline = TransferPipeline::new(
            temp.path().to_path_buf(),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
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
        let cmd =
            pipeline.build_retrieve_command(&worker, "/tmp/rch/test-project/abc123", &["*".into()]);
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();

        let include_dirs_pos = args
            .windows(2)
            .position(|w| w == ["--include", "*/"])
            .expect("missing directory include");
        let catch_all_include_pos = args
            .windows(2)
            .position(|w| w == ["--include", "/*"])
            .expect("missing anchored catch-all include");
        let src_exclude_pos = args
            .windows(2)
            .position(|w| w == ["--exclude", "/src/"])
            .expect("missing /src/ exclude");
        let main_exclude_pos = args
            .windows(2)
            .position(|w| w == ["--exclude", "/main.c"])
            .expect("missing /main.c exclude");
        let literal_star_exclude_pos = args
            .windows(2)
            .position(|w| w == ["--exclude", r"/\*"])
            .expect("missing escaped literal star exclude");

        assert!(src_exclude_pos < include_dirs_pos);
        assert!(main_exclude_pos < include_dirs_pos);
        assert!(literal_star_exclude_pos < include_dirs_pos);
        assert!(include_dirs_pos < catch_all_include_pos);
        assert!(
            !args.windows(2).any(|w| w == ["--exclude", "/*"]),
            "literal local star source must not become a broad /* exclude; got args = {args:?}"
        );
        // TEST PASS: broad include remains behind source-integrity excludes.
    }

    #[test]
    fn build_retrieve_streaming_command_also_applies_source_integrity_guard() {
        // TEST START: parity check — the streaming variant must apply the
        // same guard. If they drift, the bug returns under one code path.
        let _guard = test_guard!();
        let temp = tempfile::tempdir().expect("create temp dir");
        std::fs::create_dir(temp.path().join("src")).expect("mkdir src");
        std::fs::create_dir(temp.path().join("target")).expect("mkdir target");
        let pipeline = TransferPipeline::new(
            temp.path().to_path_buf(),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
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
        let cmd = pipeline.build_retrieve_streaming_command(
            &worker,
            "/tmp/rch/test-project/abc123",
            &["target/release/**".to_string()],
        );
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        assert!(
            args.windows(2)
                .any(|w| w == ["--include", "/target/release/**"]),
            "streaming variant must anchor patterns (RCH bug d7xc3)"
        );
        assert!(
            args.windows(2).any(|w| w == ["--exclude", "/src/"]),
            "streaming variant must apply source-integrity excludes (RCH bug d7xc3)"
        );
        // TEST PASS: streaming + non-streaming have identical safety contract
    }

    #[test]
    fn build_retrieve_command_with_absolute_cargo_target_dir_still_safe() {
        // TEST START: simulate the original d7xc3 scenario — operator set
        // CARGO_TARGET_DIR to an ABSOLUTE path outside the project (e.g.,
        // /tmp/rch-target-foo). The artifact pattern is still `target/...`
        // (relative to project), but no target/ exists locally. Our guard
        // must STILL prevent any local source dir from being a retrieval
        // candidate.
        let _guard = test_guard!();
        let temp = tempfile::tempdir().expect("create temp dir");
        std::fs::create_dir(temp.path().join("rch")).expect("mkdir rch");
        std::fs::create_dir(temp.path().join("rch-common")).expect("mkdir rch-common");
        // NO target/ dir locally — simulates absolute CARGO_TARGET_DIR.
        let pipeline = TransferPipeline::new(
            temp.path().to_path_buf(),
            "test-project".to_string(),
            "abc123".to_string(),
            TransferConfig::default(),
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
        let cmd = pipeline.build_retrieve_command(
            &worker,
            "/tmp/rch/test-project/abc123",
            &["target/debug/**".to_string()],
        );
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        assert!(
            args.windows(2).any(|w| w == ["--exclude", "/rch/"]),
            "source-integrity excludes must fire even when local target/ is absent"
        );
        assert!(
            args.windows(2).any(|w| w == ["--exclude", "/rch-common/"]),
            "all local top-level source dirs must be excluded"
        );
        // TEST PASS: absolute CARGO_TARGET_DIR case
    }
}
