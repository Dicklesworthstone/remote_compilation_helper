//! Worker setup and toolchain synchronization commands.
//!
//! This module contains commands for setting up workers including
//! binary deployment and Rust toolchain synchronization.

use crate::error::SshError;
use crate::ui::context::OutputContext;
use crate::ui::progress::Spinner;
use crate::ui::theme::StatusIndicator;
use anyhow::{Context, Result};
use rch_common::{ApiError, ApiResponse, ErrorCode, WorkerConfig};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::process::Command;
use tracing::{info, warn};

use super::helpers::load_workers_from_config;
use super::workers_deploy::{
    deploy_via_scp, find_local_binary, get_binary_version, get_remote_version,
};

// =============================================================================
// Workers Sync Toolchain Command
// =============================================================================

/// Synchronize Rust toolchain to workers.
///
/// Detects the project's required toolchain from rust-toolchain.toml,
/// checks each worker's installed toolchains, and installs if missing.
pub async fn workers_sync_toolchain(
    worker_id: Option<String>,
    all: bool,
    dry_run: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();

    if worker_id.is_none() && !all {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers sync-toolchain",
                ApiError::new(
                    ErrorCode::ConfigValidationError,
                    "Specify either a worker ID or --all",
                ),
            ));
        } else {
            println!(
                "{} Specify either {} or {}",
                StatusIndicator::Error.display(style),
                style.highlight("<worker-id>"),
                style.highlight("--all")
            );
        }
        return Ok(());
    }

    // Detect project toolchain
    let toolchain = detect_project_toolchain()?;

    // Load workers configuration
    let workers = load_workers_from_config()?;
    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers sync-toolchain",
                ApiError::new(ErrorCode::ConfigNotFound, "No workers configured"),
            ));
        } else {
            println!(
                "{} No workers configured.",
                StatusIndicator::Error.display(style)
            );
        }
        return Ok(());
    }

    // Filter to target workers
    let target_workers: Vec<&WorkerConfig> = if all {
        workers.iter().collect()
    } else if let Some(ref id) = worker_id {
        workers.iter().filter(|w| w.id.0 == *id).collect()
    } else {
        vec![]
    };

    if target_workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers sync-toolchain",
                ApiError::new(
                    ErrorCode::ConfigInvalidWorker,
                    format!("Worker '{}' not found", worker_id.unwrap_or_default()),
                ),
            ));
        } else {
            println!(
                "{} Worker not found: {}",
                StatusIndicator::Error.display(style),
                worker_id.unwrap_or_default()
            );
        }
        return Ok(());
    }

    if !ctx.is_json() {
        println!("{}", style.format_header("Sync Rust Toolchain"));
        println!();
        println!(
            "  {} Required toolchain: {}",
            style.muted("→"),
            style.highlight(&toolchain)
        );
        if dry_run {
            println!(
                "  {} {}",
                style.muted("→"),
                style.warning("DRY RUN - no changes will be made")
            );
        }
        println!();
    }

    // Sync to each target worker
    let mut results: Vec<ToolchainSyncResult> = Vec::new();

    for worker in &target_workers {
        let result = sync_toolchain_to_worker(worker, &toolchain, dry_run, ctx).await;
        results.push(result);
    }

    // JSON output
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "workers sync-toolchain",
            serde_json::json!({
                "toolchain": toolchain,
                "results": results,
            }),
        ));
    } else {
        // Summary
        let success_count = results.iter().filter(|r| r.success).count();
        let already_count = results.iter().filter(|r| r.already_installed).count();
        let fail_count = results.len() - success_count;

        println!();
        println!(
            "  {} Installed: {}, Already present: {}, Failed: {}",
            style.muted("Summary:"),
            style.success(&(success_count - already_count).to_string()),
            style.muted(&already_count.to_string()),
            if fail_count > 0 {
                style.error(&fail_count.to_string())
            } else {
                style.muted("0")
            }
        );
    }

    Ok(())
}

// =============================================================================
// Workers Setup Command
// =============================================================================

/// Complete worker setup: deploy binary and sync toolchain.
///
/// This is the recommended command for setting up new workers.
/// It combines `rch workers deploy-binary` and `rch workers sync-toolchain`.
pub async fn workers_setup(
    worker_id: Option<String>,
    all: bool,
    dry_run: bool,
    skip_binary: bool,
    skip_toolchain: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();

    if worker_id.is_none() && !all {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers setup",
                ApiError::new(
                    ErrorCode::ConfigValidationError,
                    "Specify either a worker ID or --all",
                ),
            ));
        } else {
            println!(
                "{} Specify either {} or {}",
                StatusIndicator::Error.display(style),
                style.highlight("<worker-id>"),
                style.highlight("--all")
            );
        }
        return Ok(());
    }

    // Load workers configuration
    let workers = load_workers_from_config()?;
    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers setup",
                ApiError::new(ErrorCode::ConfigNotFound, "No workers configured"),
            ));
        } else {
            println!(
                "{} No workers configured. Run {}",
                StatusIndicator::Error.display(style),
                style.highlight("rch workers discover --add")
            );
        }
        return Ok(());
    }

    // Filter to target workers
    let target_workers: Vec<&WorkerConfig> = if all {
        workers.iter().collect()
    } else if let Some(ref id) = worker_id {
        workers.iter().filter(|w| w.id.0 == *id).collect()
    } else {
        vec![]
    };

    if target_workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers setup",
                ApiError::new(
                    ErrorCode::ConfigInvalidWorker,
                    format!("Worker '{}' not found", worker_id.unwrap_or_default()),
                ),
            ));
        } else {
            println!(
                "{} Worker not found: {}",
                StatusIndicator::Error.display(style),
                worker_id.unwrap_or_default()
            );
        }
        return Ok(());
    }

    // Detect project toolchain for sync
    let toolchain = if skip_toolchain {
        None
    } else {
        Some(detect_project_toolchain()?)
    };

    if !ctx.is_json() {
        println!("{}", style.format_header("Worker Setup"));
        println!();
        println!(
            "  {} Workers: {} ({})",
            style.muted("→"),
            target_workers.len(),
            if all {
                "all"
            } else {
                worker_id.as_deref().unwrap_or("?")
            }
        );
        if let Some(ref tc) = toolchain {
            println!("  {} Toolchain: {}", style.muted("→"), style.highlight(tc));
        }
        if dry_run {
            println!(
                "  {} {}",
                style.muted("→"),
                style.warning("DRY RUN - no changes will be made")
            );
        }
        println!();
    }

    // Track overall results
    let mut all_results: Vec<SetupResult> = Vec::new();

    // Resolve the configured path topology policy once and pass it to
    // every worker setup so the topology probes / mutations honour
    // operator overrides instead of the hardcoded `/data/projects`,
    // `/dp` constants. Falls back to the documented defaults when
    // config loading fails — keeps the existing behaviour for users
    // who haven't customized topology. See rch#12.
    let policy = match crate::config::load_config() {
        Ok(cfg) => cfg.path_topology.to_policy(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not load rch config for path_topology — using compiled-in defaults (rch#12)"
            );
            rch_common::path_topology::PathTopologyPolicy::default()
        }
    };

    // Setup each worker
    for worker in &target_workers {
        let result = setup_single_worker(
            worker,
            toolchain.as_deref(),
            dry_run,
            skip_binary,
            skip_toolchain,
            &policy,
            ctx,
        )
        .await;
        all_results.push(result);
    }

    // JSON output
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "workers setup",
            serde_json::json!({
                "toolchain": toolchain,
                "results": all_results,
            }),
        ));
    } else {
        // Summary
        println!();
        let success_count = all_results.iter().filter(|r| r.success).count();
        let fail_count = all_results.len() - success_count;

        println!(
            "  {} Successful: {}, Failed: {}",
            style.muted("Summary:"),
            style.success(&success_count.to_string()),
            if fail_count > 0 {
                style.error(&fail_count.to_string())
            } else {
                style.muted("0")
            }
        );
    }

    Ok(())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Result of setting up a single worker.
#[derive(Debug, Clone, Serialize)]
struct SetupResult {
    worker_id: String,
    success: bool,
    topology_enforced: bool,
    topology_changed: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    topology_audit: Vec<TopologyAuditEntry>,
    binary_deployed: bool,
    toolchain_synced: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

/// Setup a single worker: deploy binary and sync toolchain.
async fn setup_single_worker(
    worker: &WorkerConfig,
    toolchain: Option<&str>,
    dry_run: bool,
    skip_binary: bool,
    skip_toolchain: bool,
    policy: &rch_common::path_topology::PathTopologyPolicy,
    ctx: &OutputContext,
) -> SetupResult {
    let style = ctx.theme();
    let worker_id = &worker.id.0;

    if !ctx.is_json() {
        println!(
            "  {} Setting up {}...",
            StatusIndicator::Info.display(style),
            style.highlight(worker_id)
        );
    }

    let mut result = SetupResult {
        worker_id: worker_id.clone(),
        success: true,
        topology_enforced: false,
        topology_changed: false,
        topology_audit: Vec::new(),
        binary_deployed: false,
        toolchain_synced: false,
        errors: Vec::new(),
    };

    // Step 0: Ensure canonical project topology on remote worker.
    if !ctx.is_json() {
        print!("      {} Topology: ", style.muted("→"));
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }

    let topology = enforce_worker_bootstrap_topology(worker, dry_run, policy).await;
    result.topology_enforced = topology.success;
    result.topology_changed = topology.changed;
    result.topology_audit = topology.audit;

    if topology.success {
        if !ctx.is_json() {
            if topology.changed {
                println!("{}", style.success("repaired"));
            } else {
                println!("{}", style.muted("already compliant"));
            }
        }
    } else {
        result.success = false;
        result.errors.extend(topology.errors);
        if !ctx.is_json() {
            println!("{}", style.error("FAILED"));
        }
        return result;
    }

    // Step 1: Deploy binary
    if !skip_binary {
        if !ctx.is_json() {
            print!("      {} Binary: ", style.muted("→"));
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        // Find local binary and get version
        let binary_result: Result<bool> = async {
            let local_binary = find_local_binary("rch-wkr")?;
            let local_version = get_binary_version(&local_binary).await?;

            // Check remote version
            let remote_version = get_remote_version(worker).await.ok();

            // Skip if versions match
            if remote_version.as_ref() == Some(&local_version) {
                return Ok(false); // No deployment needed
            }

            if dry_run {
                return Ok(true); // Would deploy (for dry-run reporting)
            }

            // Deploy the binary
            deploy_via_scp(worker, &local_binary).await?;
            Ok(true)
        }
        .await;

        match binary_result {
            Ok(true) if dry_run => {
                if !ctx.is_json() {
                    println!("{}", style.muted("would deploy"));
                }
            }
            Ok(true) => {
                result.binary_deployed = true;
                if !ctx.is_json() {
                    println!("{}", style.success("deployed"));
                }
            }
            Ok(false) => {
                if !ctx.is_json() {
                    println!("{}", style.muted("already up to date"));
                }
            }
            Err(e) => {
                result.success = false;
                result.errors.push(format!("Binary deployment: {}", e));
                if !ctx.is_json() {
                    println!("{} ({})", style.error("FAILED"), e);
                }
            }
        }
    }

    // Step 2: Sync toolchain
    if !skip_toolchain && let Some(tc) = toolchain {
        if !ctx.is_json() {
            print!("      {} Toolchain: ", style.muted("→"));
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        if dry_run {
            // Check if already installed for dry-run reporting
            match check_remote_toolchain(worker, tc).await {
                Ok(true) => {
                    if !ctx.is_json() {
                        println!("{}", style.muted("already installed"));
                    }
                    result.toolchain_synced = true;
                }
                Ok(false) => {
                    if !ctx.is_json() {
                        println!("{}", style.muted("would install"));
                    }
                }
                Err(e) => {
                    if !ctx.is_json() {
                        println!("{} ({})", style.warning("check failed"), e);
                    }
                }
            }
        } else {
            // Check and install
            match check_remote_toolchain(worker, tc).await {
                Ok(true) => {
                    result.toolchain_synced = true;
                    if !ctx.is_json() {
                        println!("{}", style.muted("already installed"));
                    }
                }
                Ok(false) => {
                    // Install
                    match install_remote_toolchain(worker, tc).await {
                        Ok(()) => {
                            result.toolchain_synced = true;
                            if !ctx.is_json() {
                                println!("{}", style.success("installed"));
                            }
                        }
                        Err(e) => {
                            result.success = false;
                            result.errors.push(format!("Toolchain install: {}", e));
                            if !ctx.is_json() {
                                println!("{} ({})", style.error("FAILED"), e);
                            }
                        }
                    }
                }
                Err(e) => {
                    result.success = false;
                    result.errors.push(format!("Toolchain check: {}", e));
                    if !ctx.is_json() {
                        println!("{} ({})", style.error("FAILED"), e);
                    }
                }
            }
        }
    }

    // Step 3: Verify worker health (quick SSH ping)
    if !dry_run && result.success {
        if !ctx.is_json() {
            print!("      {} Health: ", style.muted("→"));
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        match verify_worker_health(worker).await {
            Ok(true) => {
                if !ctx.is_json() {
                    println!("{}", style.success("OK"));
                }
            }
            Ok(false) => {
                if !ctx.is_json() {
                    println!("{}", style.warning("degraded"));
                }
            }
            Err(e) => {
                result.errors.push(format!("Health check: {}", e));
                if !ctx.is_json() {
                    println!("{} ({})", style.error("FAILED"), e);
                }
            }
        }
    }

    result
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TopologyFailureKind {
    Permission,
    Filesystem,
    IntegrityMismatch,
    Unknown,
}

impl TopologyFailureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Permission => "permission",
            Self::Filesystem => "filesystem",
            Self::IntegrityMismatch => "integrity_mismatch",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TopologyAuditStatus {
    AlreadyCompliant,
    Created,
    Updated,
    DryRunWouldCreate,
    DryRunWouldUpdate,
    Failed,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct TopologyAuditEntry {
    step: String,
    status: TopologyAuditStatus,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_kind: Option<TopologyFailureKind>,
}

#[derive(Debug, Clone, Default)]
struct TopologyEnforcementResult {
    success: bool,
    changed: bool,
    audit: Vec<TopologyAuditEntry>,
    errors: Vec<String>,
}

struct TopologyFixContext<'a> {
    outcome: &'a mut TopologyEnforcementResult,
    worker_id: &'a str,
    canonical_root: &'a Path,
    alias_root: &'a Path,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CanonicalTopologyState {
    Missing,
    Directory,
    NotDirectory,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AliasTopologyState {
    Missing,
    Correct,
    WrongTarget(String),
    NotSymlink,
    Unknown(String),
}

/// Per-worker topology command builders (rch#12). The original
/// implementation hardcoded `/data/projects` and `/dp` in
/// `const &str` literals, so `[path_topology]` in `rch.toml` was
/// silently ignored on the worker-setup path. The four mutation
/// commands and two probe commands are now built at runtime from the
/// caller-supplied `PathTopologyPolicy` so they honour whatever the
/// operator configured.
///
/// **Security**: `shell_escape` quotes the path before splicing into
/// the shell command. Without it, a path containing a metacharacter
/// (`$`, backtick, `;`, etc.) would let the SSH-target shell
/// re-parse it as arbitrary command — a privilege escalation in
/// reverse (local-to-remote). We do not want any path from a config
/// file to land unescaped in a shell `printf`/`readlink` argument.
fn canonical_topology_check_cmd(canonical: &Path) -> String {
    let p = shell_escape(canonical);
    format!(
        "if [ ! -e {p} ] && [ ! -L {p} ]; then printf 'MISSING'; \
elif [ -d {p} ]; then printf 'DIRECTORY'; \
else printf 'NOT_DIRECTORY'; fi"
    )
}

fn alias_topology_check_cmd(alias: &Path, canonical: &Path) -> String {
    let a = shell_escape(alias);
    let c = shell_escape(canonical);
    // Accept both the raw symlink target and the canonicalized real path.
    // Some workers expose the configured canonical root as a symlink
    // (`/Users/.../projects -> /data/projects`) while `/dp` points to
    // the resolved target. Raw text differs, but the topology is correct.
    // Build the trailing-slash variant from the rendered display string
    // directly; `Path::join("")` returns a `PathBuf` whose serialization
    // differs across platforms.
    let canonical_display = canonical.display().to_string();
    let c_slash = shell_escape_str(&path_display_with_trailing_slash(&canonical_display));
    format!(
        "if [ ! -e {a} ] && [ ! -L {a} ]; then printf 'MISSING'; \
elif [ -L {a} ]; then target=$(readlink -- {a} 2>/dev/null || true); \
canonical_real=$(readlink -f -- {c} 2>/dev/null || printf '%s' {c}); \
target_real=$(readlink -f -- {a} 2>/dev/null || true); \
if [ \"$target\" = {c} ] || [ \"$target\" = {c_slash} ] || [ \"$target_real\" = \"$canonical_real\" ]; then printf 'CORRECT'; \
else printf 'WRONG_TARGET:%s' \"$target\"; fi; \
else printf 'NOT_SYMLINK'; fi"
    )
}

fn create_canonical_root_cmd(canonical: &Path) -> String {
    let c = shell_escape(canonical);
    format!(
        "mkdir_stderr=$(mkdir -p -- {c} 2>&1) || {{ printf 'RCH_TOPOLOGY_ERR_CANONICAL_CREATE_FAILED:path=%s:%s\\n' {c} \"$mkdir_stderr\" >&2; exit 45; }}"
    )
}

fn create_alias_symlink_cmd(alias: &Path, canonical: &Path) -> String {
    let a = shell_escape(alias);
    let c = shell_escape(canonical);
    let canonical_display = canonical.display().to_string();
    let c_slash = shell_escape_str(&path_display_with_trailing_slash(&canonical_display));
    format!(
        "canonical_real=$(readlink -f -- {c} 2>/dev/null || printf '%s' {c}); \
ensure_alias_symlink() {{ \
if [ -L {a} ]; then \
target=$(readlink -- {a} 2>/dev/null || true); \
target_real=$(readlink -f -- {a} 2>/dev/null || true); \
if [ \"$target\" = {c} ] || [ \"$target\" = {c_slash} ] || [ \"$target_real\" = \"$canonical_real\" ]; then return 0; fi; \
update_stderr=$(ln -sfn -- {c} {a} 2>&1) || {{ printf 'RCH_TOPOLOGY_ERR_ALIAS_UPDATE_FAILED:path=%s:target=%s:%s\\n' {a} {c} \"$update_stderr\" >&2; return 43; }}; \
elif [ -e {a} ]; then \
printf 'RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK:path=%s\\n' {a} >&2; return 42; \
else \
create_stderr=$(ln -s -- {c} {a} 2>&1) && return 0; \
if [ -L {a} ]; then ensure_alias_symlink; return $?; fi; \
if [ -e {a} ]; then printf 'RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK:path=%s\\n' {a} >&2; return 42; fi; \
printf 'RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED:path=%s:target=%s:%s\\n' {a} {c} \"$create_stderr\" >&2; return 44; \
fi; \
}}; ensure_alias_symlink"
    )
}

fn update_alias_symlink_cmd(alias: &Path, canonical: &Path) -> String {
    format!(
        "ln -sfn -- {} {}",
        shell_escape(canonical),
        shell_escape(alias)
    )
}

/// Single-quote a path for safe POSIX shell splicing. Anything in the
/// path containing `'` is rewritten to `'\''` (the canonical
/// end-quote-escape-quote-start trick) so the resulting argument is
/// always a single bash word.
fn shell_escape(path: &Path) -> String {
    shell_escape_str(&path.display().to_string())
}

fn path_display_with_trailing_slash(display: &str) -> String {
    format!("{}/", display.trim_end_matches('/'))
}

/// Same logic as `shell_escape` but operates on an already-rendered
/// string. Used for the trailing-slash canonical variant in the
/// alias-topology check, which can't be cleanly expressed as a
/// `Path` because `Path::join("")` has platform-specific
/// serialization semantics.
fn shell_escape_str(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    // Force quoting when the first char is `-` so the path remains
    // visually distinct in generated shell. Program-level option
    // parsing is handled by passing `--` before path operands in the
    // command builders below.
    let starts_with_dash = s.starts_with('-');
    if !starts_with_dash
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
    {
        // Safe ASCII-identifier-ish — no quoting needed.
        return s.to_string();
    }
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

#[cfg(test)]
fn remediation_for_failure(kind: TopologyFailureKind) -> String {
    remediation_for_failure_with_paths(
        kind,
        Path::new(rch_common::DEFAULT_CANONICAL_PROJECT_ROOT),
        Path::new(rch_common::DEFAULT_ALIAS_PROJECT_ROOT),
    )
}

fn remediation_for_failure_with_paths(
    kind: TopologyFailureKind,
    canonical_root: &Path,
    alias_root: &Path,
) -> String {
    match kind {
        TopologyFailureKind::Permission => format!(
            "Ensure the SSH user can write {} and create {} symlinks (sudo/chown may be required).",
            canonical_root.display(),
            alias_root.display()
        ),
        TopologyFailureKind::Filesystem => format!(
            "Verify remote filesystem health and that {} is writable before rerunning setup.",
            canonical_root.display()
        ),
        TopologyFailureKind::IntegrityMismatch => format!(
            "Resolve conflicting paths manually so {} is a directory and {} is a symlink to {}.",
            canonical_root.display(),
            alias_root.display(),
            canonical_root.display()
        ),
        TopologyFailureKind::Unknown => {
            "Inspect worker logs and rerun with --verbose for detailed diagnostics.".to_string()
        }
    }
}

fn classify_topology_failure(stderr: &str) -> TopologyFailureKind {
    let lowered = stderr.to_ascii_lowercase();
    if lowered.contains("permission denied") || lowered.contains("operation not permitted") {
        return TopologyFailureKind::Permission;
    }
    if lowered.contains("file exists")
        || lowered.contains("not a directory")
        || lowered.contains("too many levels of symbolic links")
    {
        return TopologyFailureKind::IntegrityMismatch;
    }
    if lowered.contains("read-only file system")
        || lowered.contains("no such file or directory")
        || lowered.contains("input/output error")
    {
        return TopologyFailureKind::Filesystem;
    }
    TopologyFailureKind::Unknown
}

fn parse_canonical_topology_state(stdout: &str) -> CanonicalTopologyState {
    match stdout.trim() {
        "MISSING" => CanonicalTopologyState::Missing,
        "DIRECTORY" => CanonicalTopologyState::Directory,
        "NOT_DIRECTORY" => CanonicalTopologyState::NotDirectory,
        other => CanonicalTopologyState::Unknown(other.to_string()),
    }
}

fn parse_alias_topology_state(stdout: &str) -> AliasTopologyState {
    let trimmed = stdout.trim();
    if trimmed == "MISSING" {
        return AliasTopologyState::Missing;
    }
    if trimmed == "CORRECT" {
        return AliasTopologyState::Correct;
    }
    if trimmed == "NOT_SYMLINK" {
        return AliasTopologyState::NotSymlink;
    }
    if let Some(target) = trimmed.strip_prefix("WRONG_TARGET:") {
        return AliasTopologyState::WrongTarget(target.to_string());
    }
    AliasTopologyState::Unknown(trimmed.to_string())
}

fn push_topology_audit(
    worker_id: &str,
    audit: &mut Vec<TopologyAuditEntry>,
    step: &str,
    status: TopologyAuditStatus,
    message: impl Into<String>,
    remediation: Option<String>,
    failure_kind: Option<TopologyFailureKind>,
) {
    let entry = TopologyAuditEntry {
        step: step.to_string(),
        status,
        message: message.into(),
        remediation,
        failure_kind,
    };

    if matches!(entry.status, TopologyAuditStatus::Failed) {
        warn!(
            worker = worker_id,
            step = entry.step,
            status = ?entry.status,
            failure_kind = ?entry.failure_kind,
            message = entry.message,
            remediation = ?entry.remediation,
            "worker bootstrap topology audit failure"
        );
    } else {
        info!(
            worker = worker_id,
            step = entry.step,
            status = ?entry.status,
            message = entry.message,
            remediation = ?entry.remediation,
            "worker bootstrap topology audit"
        );
    }

    audit.push(entry);
}

/// Run a one-shot SSH command on a worker for **setup / probing** flows
/// (reachability checks, canonical/alias topology probes and fixes). Uses a
/// fixed 10s connect timeout and a plain `cmd.output()`.
///
/// Distinct from the offload hot-path executor `run_offload_ssh_command` in
/// `hook::ssh`, which takes a caller-supplied timeout and is hardened with
/// `kill_on_drop` + concurrent stdout/stderr draining for the build pipeline.
pub(crate) async fn run_setup_ssh_command(
    worker: &WorkerConfig,
    remote_cmd: &str,
) -> Result<std::process::Output> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-i").arg(&worker.identity_file);
    cmd.arg(format!("{}@{}", worker.user, worker.host));
    cmd.arg(remote_cmd);

    cmd.output().await.with_context(|| {
        format!(
            "Failed to execute remote topology command on {}",
            worker.id.0
        )
    })
}

async fn query_canonical_topology_state(
    worker: &WorkerConfig,
    policy: &rch_common::path_topology::PathTopologyPolicy,
) -> Result<CanonicalTopologyState> {
    let cmd = canonical_topology_check_cmd(policy.canonical_root());
    let output = run_setup_ssh_command(worker, &cmd).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "canonical topology probe failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }

    Ok(parse_canonical_topology_state(
        String::from_utf8_lossy(&output.stdout).as_ref(),
    ))
}

async fn query_alias_topology_state(
    worker: &WorkerConfig,
    policy: &rch_common::path_topology::PathTopologyPolicy,
) -> Result<AliasTopologyState> {
    let cmd = alias_topology_check_cmd(policy.alias_root(), policy.canonical_root());
    let output = run_setup_ssh_command(worker, &cmd).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "alias topology probe failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }

    Ok(parse_alias_topology_state(
        String::from_utf8_lossy(&output.stdout).as_ref(),
    ))
}

async fn execute_topology_fix(
    worker: &WorkerConfig,
    command: &str,
    step: &str,
    success_status: TopologyAuditStatus,
    action_message: &str,
    ctx: &mut TopologyFixContext<'_>,
) -> bool {
    match run_setup_ssh_command(worker, command).await {
        Ok(output) if output.status.success() => {
            ctx.outcome.changed = true;
            push_topology_audit(
                ctx.worker_id,
                &mut ctx.outcome.audit,
                step,
                success_status,
                action_message,
                None,
                None,
            );
            true
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let failure_kind = classify_topology_failure(&stderr);
            let remediation = remediation_for_failure_with_paths(
                failure_kind,
                ctx.canonical_root,
                ctx.alias_root,
            );
            let message = format!(
                "{} failed (exit {}): {}",
                step,
                output.status.code().unwrap_or(-1),
                stderr.trim()
            );
            push_topology_audit(
                ctx.worker_id,
                &mut ctx.outcome.audit,
                step,
                TopologyAuditStatus::Failed,
                message.clone(),
                Some(remediation.clone()),
                Some(failure_kind),
            );
            ctx.outcome.success = false;
            ctx.outcome.errors.push(format!(
                "{} [{}] remediation: {}",
                message,
                failure_kind.as_str(),
                remediation
            ));
            false
        }
        Err(e) => {
            let failure_kind = classify_topology_failure(&e.to_string());
            let remediation = remediation_for_failure_with_paths(
                failure_kind,
                ctx.canonical_root,
                ctx.alias_root,
            );
            let message = format!("{} failed: {}", step, e);
            push_topology_audit(
                ctx.worker_id,
                &mut ctx.outcome.audit,
                step,
                TopologyAuditStatus::Failed,
                message.clone(),
                Some(remediation.clone()),
                Some(failure_kind),
            );
            ctx.outcome.success = false;
            ctx.outcome.errors.push(format!(
                "{} [{}] remediation: {}",
                message,
                failure_kind.as_str(),
                remediation
            ));
            false
        }
    }
}

async fn enforce_worker_bootstrap_topology(
    worker: &WorkerConfig,
    dry_run: bool,
    policy: &rch_common::path_topology::PathTopologyPolicy,
) -> TopologyEnforcementResult {
    let worker_id = worker.id.0.as_str();
    let canonical_root = policy.canonical_root();
    let alias_root = policy.alias_root();
    let mut outcome = TopologyEnforcementResult {
        success: true,
        ..TopologyEnforcementResult::default()
    };

    let canonical_state = match query_canonical_topology_state(worker, policy).await {
        Ok(state) => state,
        Err(e) => {
            let failure_kind = classify_topology_failure(&e.to_string());
            let remediation =
                remediation_for_failure_with_paths(failure_kind, canonical_root, alias_root);
            let message = format!("canonical topology probe failed: {}", e);
            push_topology_audit(
                worker_id,
                &mut outcome.audit,
                "canonical_root",
                TopologyAuditStatus::Failed,
                message.clone(),
                Some(remediation.clone()),
                Some(failure_kind),
            );
            outcome.success = false;
            outcome.errors.push(format!(
                "{} [{}] remediation: {}",
                message,
                failure_kind.as_str(),
                remediation
            ));
            return outcome;
        }
    };

    match canonical_state {
        CanonicalTopologyState::Directory => {
            push_topology_audit(
                worker_id,
                &mut outcome.audit,
                "canonical_root",
                TopologyAuditStatus::AlreadyCompliant,
                format!("{} exists as a directory", canonical_root.display()),
                None,
                None,
            );
        }
        CanonicalTopologyState::Missing => {
            if dry_run {
                push_topology_audit(
                    worker_id,
                    &mut outcome.audit,
                    "canonical_root",
                    TopologyAuditStatus::DryRunWouldCreate,
                    format!("Would create {}", canonical_root.display()),
                    None,
                    None,
                );
            } else {
                let command = create_canonical_root_cmd(canonical_root);
                let action_message = format!("Created {} directory", canonical_root.display());
                let mut fix_ctx = TopologyFixContext {
                    outcome: &mut outcome,
                    worker_id,
                    canonical_root,
                    alias_root,
                };
                if !execute_topology_fix(
                    worker,
                    &command,
                    "canonical_root",
                    TopologyAuditStatus::Created,
                    &action_message,
                    &mut fix_ctx,
                )
                .await
                {
                    return outcome;
                }
            }
        }
        CanonicalTopologyState::NotDirectory => {
            let failure_kind = TopologyFailureKind::IntegrityMismatch;
            let remediation =
                remediation_for_failure_with_paths(failure_kind, canonical_root, alias_root);
            let message = format!("{} exists but is not a directory", canonical_root.display());
            push_topology_audit(
                worker_id,
                &mut outcome.audit,
                "canonical_root",
                TopologyAuditStatus::Failed,
                message.clone(),
                Some(remediation.clone()),
                Some(failure_kind),
            );
            outcome.success = false;
            outcome.errors.push(format!(
                "{} [{}] remediation: {}",
                message,
                failure_kind.as_str(),
                remediation
            ));
            return outcome;
        }
        CanonicalTopologyState::Unknown(raw) => {
            let failure_kind = TopologyFailureKind::Filesystem;
            let remediation =
                remediation_for_failure_with_paths(failure_kind, canonical_root, alias_root);
            let message = format!("Unexpected canonical topology probe output: {}", raw);
            push_topology_audit(
                worker_id,
                &mut outcome.audit,
                "canonical_root",
                TopologyAuditStatus::Failed,
                message.clone(),
                Some(remediation.clone()),
                Some(failure_kind),
            );
            outcome.success = false;
            outcome.errors.push(format!(
                "{} [{}] remediation: {}",
                message,
                failure_kind.as_str(),
                remediation
            ));
            return outcome;
        }
    }

    let alias_state = match query_alias_topology_state(worker, policy).await {
        Ok(state) => state,
        Err(e) => {
            let failure_kind = classify_topology_failure(&e.to_string());
            let remediation =
                remediation_for_failure_with_paths(failure_kind, canonical_root, alias_root);
            let message = format!("alias topology probe failed: {}", e);
            push_topology_audit(
                worker_id,
                &mut outcome.audit,
                "alias_symlink",
                TopologyAuditStatus::Failed,
                message.clone(),
                Some(remediation.clone()),
                Some(failure_kind),
            );
            outcome.success = false;
            outcome.errors.push(format!(
                "{} [{}] remediation: {}",
                message,
                failure_kind.as_str(),
                remediation
            ));
            return outcome;
        }
    };

    match alias_state {
        AliasTopologyState::Correct => {
            push_topology_audit(
                worker_id,
                &mut outcome.audit,
                "alias_symlink",
                TopologyAuditStatus::AlreadyCompliant,
                format!(
                    "{} already points to {}",
                    alias_root.display(),
                    canonical_root.display()
                ),
                None,
                None,
            );
        }
        AliasTopologyState::Missing => {
            if dry_run {
                push_topology_audit(
                    worker_id,
                    &mut outcome.audit,
                    "alias_symlink",
                    TopologyAuditStatus::DryRunWouldCreate,
                    format!(
                        "Would create {} -> {}",
                        alias_root.display(),
                        canonical_root.display()
                    ),
                    None,
                    None,
                );
            } else {
                let command = create_alias_symlink_cmd(alias_root, canonical_root);
                let action_message = format!(
                    "Created {} symlink to {}",
                    alias_root.display(),
                    canonical_root.display()
                );
                let mut fix_ctx = TopologyFixContext {
                    outcome: &mut outcome,
                    worker_id,
                    canonical_root,
                    alias_root,
                };
                if !execute_topology_fix(
                    worker,
                    &command,
                    "alias_symlink",
                    TopologyAuditStatus::Created,
                    &action_message,
                    &mut fix_ctx,
                )
                .await
                {
                    return outcome;
                }
            }
        }
        AliasTopologyState::WrongTarget(target) => {
            if dry_run {
                push_topology_audit(
                    worker_id,
                    &mut outcome.audit,
                    "alias_symlink",
                    TopologyAuditStatus::DryRunWouldUpdate,
                    format!(
                        "Would repoint {} from '{}' to {}",
                        alias_root.display(),
                        target,
                        canonical_root.display()
                    ),
                    None,
                    None,
                );
            } else {
                let command = update_alias_symlink_cmd(alias_root, canonical_root);
                let action_message = format!(
                    "Updated {} symlink target to {}",
                    alias_root.display(),
                    canonical_root.display()
                );
                let mut fix_ctx = TopologyFixContext {
                    outcome: &mut outcome,
                    worker_id,
                    canonical_root,
                    alias_root,
                };
                if !execute_topology_fix(
                    worker,
                    &command,
                    "alias_symlink",
                    TopologyAuditStatus::Updated,
                    &action_message,
                    &mut fix_ctx,
                )
                .await
                {
                    return outcome;
                }
            }
        }
        AliasTopologyState::NotSymlink => {
            let failure_kind = TopologyFailureKind::IntegrityMismatch;
            let remediation =
                remediation_for_failure_with_paths(failure_kind, canonical_root, alias_root);
            let message = format!("{} exists but is not a symlink", alias_root.display());
            push_topology_audit(
                worker_id,
                &mut outcome.audit,
                "alias_symlink",
                TopologyAuditStatus::Failed,
                message.clone(),
                Some(remediation.clone()),
                Some(failure_kind),
            );
            outcome.success = false;
            outcome.errors.push(format!(
                "{} [{}] remediation: {}",
                message,
                failure_kind.as_str(),
                remediation
            ));
            return outcome;
        }
        AliasTopologyState::Unknown(raw) => {
            let failure_kind = TopologyFailureKind::Filesystem;
            let remediation =
                remediation_for_failure_with_paths(failure_kind, canonical_root, alias_root);
            let message = format!("Unexpected alias topology probe output: {}", raw);
            push_topology_audit(
                worker_id,
                &mut outcome.audit,
                "alias_symlink",
                TopologyAuditStatus::Failed,
                message.clone(),
                Some(remediation.clone()),
                Some(failure_kind),
            );
            outcome.success = false;
            outcome.errors.push(format!(
                "{} [{}] remediation: {}",
                message,
                failure_kind.as_str(),
                remediation
            ));
            return outcome;
        }
    }

    if !dry_run {
        let post_canonical = query_canonical_topology_state(worker, policy).await;
        let post_alias = query_alias_topology_state(worker, policy).await;
        let verified = matches!(post_canonical, Ok(CanonicalTopologyState::Directory))
            && matches!(post_alias, Ok(AliasTopologyState::Correct));

        if verified {
            push_topology_audit(
                worker_id,
                &mut outcome.audit,
                "topology_verify",
                TopologyAuditStatus::AlreadyCompliant,
                "Post-fix verification confirmed canonical root and alias topology",
                None,
                None,
            );
        } else {
            let failure_kind = TopologyFailureKind::IntegrityMismatch;
            let remediation =
                remediation_for_failure_with_paths(failure_kind, canonical_root, alias_root);
            let message = format!(
                "Post-fix verification failed: canonical={:?}, alias={:?}",
                post_canonical, post_alias
            );
            push_topology_audit(
                worker_id,
                &mut outcome.audit,
                "topology_verify",
                TopologyAuditStatus::Failed,
                message.clone(),
                Some(remediation.clone()),
                Some(failure_kind),
            );
            outcome.success = false;
            outcome.errors.push(format!(
                "{} [{}] remediation: {}",
                message,
                failure_kind.as_str(),
                remediation
            ));
        }
    }

    outcome
}

/// Quick health check: verify SSH works and rch-wkr responds.
async fn verify_worker_health(worker: &WorkerConfig) -> Result<bool> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-i").arg(&worker.identity_file);
    cmd.arg(format!("{}@{}", worker.user, worker.host));
    cmd.arg("rch-wkr capabilities >/dev/null 2>&1 && echo OK || echo DEGRADED");

    let output = cmd.output().await.context("Health check failed")?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    Ok(stdout == "OK")
}

#[derive(Debug, Deserialize)]
struct RustToolchainToml {
    toolchain: Option<RustToolchainSection>,
}

#[derive(Debug, Deserialize)]
struct RustToolchainSection {
    channel: Option<String>,
}

fn normalize_toolchain_channel(channel: &str) -> Result<String> {
    let trimmed = channel.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Rust toolchain channel is empty");
    }
    if trimmed.chars().any(|ch| matches!(ch, '\0' | '\n' | '\r')) {
        anyhow::bail!("Rust toolchain channel contains control characters");
    }
    Ok(trimmed.to_string())
}

fn parse_rust_toolchain_toml_channel(content: &str, path: &Path) -> Result<Option<String>> {
    let parsed: RustToolchainToml =
        toml::from_str(content).with_context(|| format!("Failed to parse {}", path.display()))?;
    parsed
        .toolchain
        .and_then(|toolchain| toolchain.channel)
        .map(|channel| normalize_toolchain_channel(&channel))
        .transpose()
}

fn check_toolchain_command(toolchain: &str) -> String {
    let toolchain = shell_escape_str(toolchain);
    format!(
        "rustup run -- {toolchain} rustc --version >/dev/null 2>&1 && echo FOUND || echo NOTFOUND"
    )
}

fn install_toolchain_command(toolchain: &str) -> String {
    let toolchain = shell_escape_str(toolchain);
    format!(
        "rustup install -- {toolchain} && rustup component add rust-src --toolchain={toolchain}"
    )
}

/// Detect the project's required toolchain from rust-toolchain.toml or rust-toolchain.
pub(super) fn detect_project_toolchain() -> Result<String> {
    use std::fs;

    // Check for rust-toolchain.toml first
    let toml_path = std::env::current_dir()?.join("rust-toolchain.toml");
    if toml_path.exists() {
        let content = fs::read_to_string(&toml_path)
            .with_context(|| format!("Failed to read {}", toml_path.display()))?;
        if let Some(channel) = parse_rust_toolchain_toml_channel(&content, &toml_path)? {
            return Ok(channel);
        }
    }

    // Check for rust-toolchain (plain text)
    let plain_path = std::env::current_dir()?.join("rust-toolchain");
    if plain_path.exists() {
        let content = fs::read_to_string(&plain_path)
            .with_context(|| format!("Failed to read {}", plain_path.display()))?;
        return normalize_toolchain_channel(&content);
    }

    // Default to stable if no toolchain file
    Ok("stable".to_string())
}

/// Sync toolchain to a single worker.
async fn sync_toolchain_to_worker(
    worker: &WorkerConfig,
    toolchain: &str,
    dry_run: bool,
    ctx: &OutputContext,
) -> ToolchainSyncResult {
    let worker_id = &worker.id.0;

    // Use a spinner for progress indication during toolchain sync
    let spinner = if !ctx.is_json() {
        let s = Spinner::new(ctx, &format!("{}: Checking toolchain...", worker_id));
        Some(s)
    } else {
        None
    };

    // Check if toolchain is already installed
    match check_remote_toolchain(worker, toolchain).await {
        Ok(true) => {
            if let Some(s) = spinner {
                s.finish_success(&format!("{}: Already installed", worker_id));
            }
            return ToolchainSyncResult {
                worker_id: worker_id.clone(),
                success: true,
                already_installed: true,
                installed_toolchain: Some(toolchain.to_string()),
                error: None,
            };
        }
        Ok(false) => {
            // Need to install - update spinner message
            if let Some(ref s) = spinner {
                s.set_message(&format!("{}: Installing {}...", worker_id, toolchain));
            }
        }
        Err(e) => {
            if let Some(s) = spinner {
                s.finish_error(&format!("{}: {}", worker_id, e));
            }
            return ToolchainSyncResult {
                worker_id: worker_id.clone(),
                success: false,
                already_installed: false,
                installed_toolchain: None,
                error: Some(e.to_string()),
            };
        }
    }

    if dry_run {
        if let Some(s) = spinner {
            s.finish_warning(&format!("{}: Would install {}", worker_id, toolchain));
        }
        return ToolchainSyncResult {
            worker_id: worker_id.clone(),
            success: true,
            already_installed: false,
            installed_toolchain: None,
            error: None,
        };
    }

    // Install the toolchain
    match install_remote_toolchain(worker, toolchain).await {
        Ok(()) => {
            if let Some(s) = spinner {
                s.finish_success(&format!("{}: Installed {}", worker_id, toolchain));
            }
            ToolchainSyncResult {
                worker_id: worker_id.clone(),
                success: true,
                already_installed: false,
                installed_toolchain: Some(toolchain.to_string()),
                error: None,
            }
        }
        Err(e) => {
            if let Some(s) = spinner {
                s.finish_error(&format!("{}: {}", worker_id, e));
            }
            ToolchainSyncResult {
                worker_id: worker_id.clone(),
                success: false,
                already_installed: false,
                installed_toolchain: None,
                error: Some(e.to_string()),
            }
        }
    }
}

/// Check if a toolchain is installed on a remote worker.
async fn check_remote_toolchain(worker: &WorkerConfig, toolchain: &str) -> Result<bool> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-i").arg(&worker.identity_file);
    cmd.arg(format!("{}@{}", worker.user, worker.host));
    cmd.arg(check_toolchain_command(toolchain));

    let output = cmd.output().await.context("Failed to SSH to worker")?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    Ok(stdout.trim() == "FOUND")
}

/// Install a toolchain on a remote worker.
async fn install_remote_toolchain(worker: &WorkerConfig, toolchain: &str) -> Result<()> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=60"); // Toolchain install can take a while
    cmd.arg("-i").arg(&worker.identity_file);
    cmd.arg(format!("{}@{}", worker.user, worker.host));
    cmd.arg(install_toolchain_command(toolchain));

    let output = cmd.output().await.context("Failed to install toolchain")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SshError::ToolchainInstallFailed {
            host: worker.host.clone(),
            toolchain: toolchain.to_string(),
            message: stderr.trim().to_string(),
        }
        .into());
    }

    Ok(())
}

// =============================================================================
// Response Types
// =============================================================================

/// Result of syncing toolchain to a single worker.
#[derive(Debug, Clone, Serialize)]
struct ToolchainSyncResult {
    worker_id: String,
    success: bool,
    already_installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_toolchain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;
    use tracing::info;

    #[cfg(unix)]
    use std::os::unix::fs as unix_fs;

    fn log_test_start(test_name: &str) {
        info!(test = test_name, "start");
    }

    fn log_test_pass(test_name: &str) {
        info!(test = test_name, "pass");
    }

    fn local_canonical_state(canonical_root: &Path) -> CanonicalTopologyState {
        if !canonical_root.exists() {
            CanonicalTopologyState::Missing
        } else if canonical_root.is_dir() {
            CanonicalTopologyState::Directory
        } else {
            CanonicalTopologyState::NotDirectory
        }
    }

    #[cfg(unix)]
    fn local_alias_state(alias_root: &Path, canonical_root: &Path) -> AliasTopologyState {
        let metadata = match fs::symlink_metadata(alias_root) {
            Ok(meta) => meta,
            Err(_) => return AliasTopologyState::Missing,
        };

        if !metadata.file_type().is_symlink() {
            return AliasTopologyState::NotSymlink;
        }

        let canonical_target = match fs::canonicalize(canonical_root) {
            Ok(path) => path,
            Err(err) => return AliasTopologyState::Unknown(err.to_string()),
        };

        match fs::canonicalize(alias_root) {
            Ok(target) if target == canonical_target => AliasTopologyState::Correct,
            Ok(target) => AliasTopologyState::WrongTarget(target.display().to_string()),
            Err(err) => AliasTopologyState::Unknown(err.to_string()),
        }
    }

    #[cfg(unix)]
    fn enforce_local_topology_for_tests(
        canonical_root: &Path,
        alias_root: &Path,
        dry_run: bool,
    ) -> TopologyEnforcementResult {
        let mut outcome = TopologyEnforcementResult {
            success: true,
            ..TopologyEnforcementResult::default()
        };

        match local_canonical_state(canonical_root) {
            CanonicalTopologyState::Directory => {
                outcome.audit.push(TopologyAuditEntry {
                    step: "canonical_root".to_string(),
                    status: TopologyAuditStatus::AlreadyCompliant,
                    message: "canonical root already present".to_string(),
                    remediation: None,
                    failure_kind: None,
                });
            }
            CanonicalTopologyState::Missing => {
                if dry_run {
                    outcome.audit.push(TopologyAuditEntry {
                        step: "canonical_root".to_string(),
                        status: TopologyAuditStatus::DryRunWouldCreate,
                        message: "would create canonical root".to_string(),
                        remediation: None,
                        failure_kind: None,
                    });
                } else if let Err(err) = fs::create_dir_all(canonical_root) {
                    outcome.success = false;
                    outcome.errors.push(err.to_string());
                    outcome.audit.push(TopologyAuditEntry {
                        step: "canonical_root".to_string(),
                        status: TopologyAuditStatus::Failed,
                        message: err.to_string(),
                        remediation: Some(remediation_for_failure(TopologyFailureKind::Filesystem)),
                        failure_kind: Some(TopologyFailureKind::Filesystem),
                    });
                    return outcome;
                } else {
                    outcome.changed = true;
                    outcome.audit.push(TopologyAuditEntry {
                        step: "canonical_root".to_string(),
                        status: TopologyAuditStatus::Created,
                        message: "created canonical root".to_string(),
                        remediation: None,
                        failure_kind: None,
                    });
                }
            }
            CanonicalTopologyState::NotDirectory | CanonicalTopologyState::Unknown(_) => {
                outcome.success = false;
                outcome
                    .errors
                    .push("canonical root is not a directory".to_string());
                outcome.audit.push(TopologyAuditEntry {
                    step: "canonical_root".to_string(),
                    status: TopologyAuditStatus::Failed,
                    message: "canonical root is not a directory".to_string(),
                    remediation: Some(remediation_for_failure(
                        TopologyFailureKind::IntegrityMismatch,
                    )),
                    failure_kind: Some(TopologyFailureKind::IntegrityMismatch),
                });
                return outcome;
            }
        }

        match local_alias_state(alias_root, canonical_root) {
            AliasTopologyState::Correct => {
                outcome.audit.push(TopologyAuditEntry {
                    step: "alias_symlink".to_string(),
                    status: TopologyAuditStatus::AlreadyCompliant,
                    message: "alias symlink already correct".to_string(),
                    remediation: None,
                    failure_kind: None,
                });
            }
            AliasTopologyState::Missing => {
                if dry_run {
                    outcome.audit.push(TopologyAuditEntry {
                        step: "alias_symlink".to_string(),
                        status: TopologyAuditStatus::DryRunWouldCreate,
                        message: "would create alias symlink".to_string(),
                        remediation: None,
                        failure_kind: None,
                    });
                } else if let Err(err) = unix_fs::symlink(canonical_root, alias_root) {
                    outcome.success = false;
                    outcome.errors.push(err.to_string());
                    outcome.audit.push(TopologyAuditEntry {
                        step: "alias_symlink".to_string(),
                        status: TopologyAuditStatus::Failed,
                        message: err.to_string(),
                        remediation: Some(remediation_for_failure(TopologyFailureKind::Filesystem)),
                        failure_kind: Some(TopologyFailureKind::Filesystem),
                    });
                    return outcome;
                } else {
                    outcome.changed = true;
                    outcome.audit.push(TopologyAuditEntry {
                        step: "alias_symlink".to_string(),
                        status: TopologyAuditStatus::Created,
                        message: "created alias symlink".to_string(),
                        remediation: None,
                        failure_kind: None,
                    });
                }
            }
            AliasTopologyState::WrongTarget(_) => {
                if dry_run {
                    outcome.audit.push(TopologyAuditEntry {
                        step: "alias_symlink".to_string(),
                        status: TopologyAuditStatus::DryRunWouldUpdate,
                        message: "would repoint alias symlink".to_string(),
                        remediation: None,
                        failure_kind: None,
                    });
                } else if fs::remove_file(alias_root).is_ok()
                    && unix_fs::symlink(canonical_root, alias_root).is_ok()
                {
                    outcome.changed = true;
                    outcome.audit.push(TopologyAuditEntry {
                        step: "alias_symlink".to_string(),
                        status: TopologyAuditStatus::Updated,
                        message: "updated alias symlink target".to_string(),
                        remediation: None,
                        failure_kind: None,
                    });
                } else {
                    outcome.success = false;
                    outcome
                        .errors
                        .push("failed to repoint alias symlink".to_string());
                    outcome.audit.push(TopologyAuditEntry {
                        step: "alias_symlink".to_string(),
                        status: TopologyAuditStatus::Failed,
                        message: "failed to repoint alias symlink".to_string(),
                        remediation: Some(remediation_for_failure(TopologyFailureKind::Filesystem)),
                        failure_kind: Some(TopologyFailureKind::Filesystem),
                    });
                    return outcome;
                }
            }
            AliasTopologyState::NotSymlink | AliasTopologyState::Unknown(_) => {
                outcome.success = false;
                outcome
                    .errors
                    .push("alias path is not a symlink".to_string());
                outcome.audit.push(TopologyAuditEntry {
                    step: "alias_symlink".to_string(),
                    status: TopologyAuditStatus::Failed,
                    message: "alias path is not a symlink".to_string(),
                    remediation: Some(remediation_for_failure(
                        TopologyFailureKind::IntegrityMismatch,
                    )),
                    failure_kind: Some(TopologyFailureKind::IntegrityMismatch),
                });
                return outcome;
            }
        }

        outcome
    }

    #[test]
    fn topology_bootstrap_parse_canonical_states() {
        log_test_start("topology_bootstrap_parse_canonical_states");
        assert_eq!(
            parse_canonical_topology_state("MISSING"),
            CanonicalTopologyState::Missing
        );
        assert_eq!(
            parse_canonical_topology_state("DIRECTORY"),
            CanonicalTopologyState::Directory
        );
        assert_eq!(
            parse_canonical_topology_state("NOT_DIRECTORY"),
            CanonicalTopologyState::NotDirectory
        );
        log_test_pass("topology_bootstrap_parse_canonical_states");
    }

    #[test]
    fn topology_bootstrap_parse_alias_states() {
        log_test_start("topology_bootstrap_parse_alias_states");
        assert_eq!(
            parse_alias_topology_state("MISSING"),
            AliasTopologyState::Missing
        );
        assert_eq!(
            parse_alias_topology_state("CORRECT"),
            AliasTopologyState::Correct
        );
        assert_eq!(
            parse_alias_topology_state("NOT_SYMLINK"),
            AliasTopologyState::NotSymlink
        );
        assert_eq!(
            parse_alias_topology_state("WRONG_TARGET:/tmp/foo"),
            AliasTopologyState::WrongTarget("/tmp/foo".to_string())
        );
        log_test_pass("topology_bootstrap_parse_alias_states");
    }

    #[test]
    fn topology_bootstrap_failure_classification_covers_permission_filesystem_and_unknown() {
        log_test_start(
            "topology_bootstrap_failure_classification_covers_permission_filesystem_and_unknown",
        );
        assert_eq!(
            classify_topology_failure("Permission denied"),
            TopologyFailureKind::Permission
        );
        assert_eq!(
            classify_topology_failure("Read-only file system"),
            TopologyFailureKind::Filesystem
        );
        assert_eq!(
            classify_topology_failure("ln: failed to create symbolic link '/dp': File exists"),
            TopologyFailureKind::IntegrityMismatch
        );
        assert_eq!(
            classify_topology_failure("some unrelated stderr"),
            TopologyFailureKind::Unknown
        );
        log_test_pass(
            "topology_bootstrap_failure_classification_covers_permission_filesystem_and_unknown",
        );
    }

    #[test]
    fn topology_bootstrap_remediation_uses_configured_paths() {
        log_test_start("topology_bootstrap_remediation_uses_configured_paths");
        let canonical = Path::new("/custom/projects");
        let alias = Path::new("/custom/dp");

        let permission =
            remediation_for_failure_with_paths(TopologyFailureKind::Permission, canonical, alias);
        let integrity = remediation_for_failure_with_paths(
            TopologyFailureKind::IntegrityMismatch,
            canonical,
            alias,
        );

        assert!(permission.contains("/custom/projects"));
        assert!(permission.contains("/custom/dp"));
        assert!(integrity.contains("/custom/projects"));
        assert!(integrity.contains("/custom/dp"));
        assert!(
            !permission.contains(rch_common::DEFAULT_CANONICAL_PROJECT_ROOT),
            "custom remediation must not mention default canonical root: {permission}"
        );
        log_test_pass("topology_bootstrap_remediation_uses_configured_paths");
    }

    #[test]
    fn topology_bootstrap_alias_check_command_adds_one_trailing_slash_variant() {
        log_test_start("topology_bootstrap_alias_check_command_adds_one_trailing_slash_variant");

        let without_slash =
            alias_topology_check_cmd(Path::new("/custom/dp"), Path::new("/custom/projects"));
        let with_slash =
            alias_topology_check_cmd(Path::new("/custom/dp"), Path::new("/custom/projects/"));

        assert!(
            without_slash.contains("/custom/projects/"),
            "alias probe should accept readlink targets with one trailing slash: {without_slash}"
        );
        assert!(
            !without_slash.contains("/custom/projects//"),
            "alias probe should not generate double trailing slashes: {without_slash}"
        );
        assert!(
            !with_slash.contains("/custom/projects//"),
            "already-slashed canonical roots should stay single-slashed: {with_slash}"
        );
        log_test_pass("topology_bootstrap_alias_check_command_adds_one_trailing_slash_variant");
    }

    #[test]
    fn topology_bootstrap_alias_check_command_shell_escapes_configured_paths() {
        log_test_start("topology_bootstrap_alias_check_command_shell_escapes_configured_paths");
        let command = alias_topology_check_cmd(
            Path::new("/tmp/rch alias;bad"),
            Path::new("/tmp/rch weird'root"),
        );

        assert!(
            command.contains("'/tmp/rch alias;bad'"),
            "alias path must be shell escaped: {command}"
        );
        assert!(
            command.contains("'/tmp/rch weird'\\''root'"),
            "canonical path must escape single quotes: {command}"
        );
        log_test_pass("topology_bootstrap_alias_check_command_shell_escapes_configured_paths");
    }

    // Regression: a path starting with `-` (rare but possible in a
    // pathological path_topology config) is still shell-escaped even
    // though command builders also pass `--` before path operands.
    #[test]
    fn shell_escape_str_force_quotes_paths_starting_with_dash() {
        let escaped = shell_escape_str("-weird-name");
        assert!(
            escaped.starts_with('\'') && escaped.ends_with('\''),
            "leading-dash path must be quoted; got: {escaped}"
        );
        // Sanity: real absolute paths starting with `/` stay unquoted.
        let absolute = shell_escape_str("/data/projects");
        assert_eq!(
            absolute, "/data/projects",
            "absolute path with only safe chars must NOT be quoted"
        );
    }

    #[test]
    fn topology_bootstrap_mutation_commands_terminate_path_options() {
        let canonical = Path::new("-canonical-root");
        let alias = Path::new("-alias-root");

        let create_canonical = create_canonical_root_cmd(canonical);
        assert!(
            create_canonical.contains("mkdir -p -- '-canonical-root'"),
            "canonical create command must still terminate path options: {create_canonical}"
        );
        assert!(
            create_canonical.contains(
                "printf 'RCH_TOPOLOGY_ERR_CANONICAL_CREATE_FAILED:path=%s:%s\\n' '-canonical-root' \"$mkdir_stderr\""
            ),
            "canonical create failures must report the exact path: {create_canonical}"
        );
        assert_eq!(
            update_alias_symlink_cmd(alias, canonical),
            "ln -sfn -- '-canonical-root' '-alias-root'"
        );

        let create_alias = create_alias_symlink_cmd(alias, canonical);
        assert!(
            create_alias.contains("ln -s -- '-canonical-root' '-alias-root'"),
            "alias create must terminate path options before configured paths: {create_alias}"
        );
        assert_eq!(
            create_alias
                .matches("ln -s -- '-canonical-root' '-alias-root'")
                .count(),
            1,
            "alias create command should keep a single create operation: {create_alias}"
        );
        assert!(
            create_alias.contains("readlink -- '-alias-root'"),
            "alias create recovery must re-check symlink targets safely: {create_alias}"
        );
        assert!(
            create_alias.contains("RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK"),
            "regular-file alias conflicts must keep a structured reason: {create_alias}"
        );
        assert!(
            create_alias.contains("RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED"),
            "missing-alias create failures must keep a structured reason: {create_alias}"
        );
        assert!(
            create_alias.contains(
                "printf 'RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED:path=%s:target=%s:%s\\n' '-alias-root' '-canonical-root' \"$create_stderr\""
            ),
            "alias create failures must report the exact path and target: {create_alias}"
        );
        assert!(
            create_alias.contains(
                "printf 'RCH_TOPOLOGY_ERR_ALIAS_UPDATE_FAILED:path=%s:target=%s:%s\\n' '-alias-root' '-canonical-root' \"$update_stderr\""
            ),
            "alias update failures must report the exact path and target: {create_alias}"
        );

        let check_cmd = alias_topology_check_cmd(alias, canonical);
        assert!(
            check_cmd.contains("readlink -- '-alias-root'"),
            "alias probe must terminate readlink options before the path: {check_cmd}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn topology_bootstrap_diagnostics_do_not_reexpand_escaped_paths() {
        let canonical = Path::new("/tmp/rch canonical");
        let alias = Path::new("/tmp/rch alias/alias_$(touch /tmp/rch-owned)");

        let create_canonical = create_canonical_root_cmd(canonical);
        assert!(
            create_canonical
                .contains("printf 'RCH_TOPOLOGY_ERR_CANONICAL_CREATE_FAILED:path=%s:%s\\n'"),
            "canonical diagnostics must use a static printf format: {create_canonical}"
        );

        let create_alias = create_alias_symlink_cmd(alias, canonical);
        assert!(
            create_alias
                .contains("printf 'RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED:path=%s:target=%s:%s\\n'"),
            "alias create diagnostics must use a static printf format: {create_alias}"
        );
        assert!(
            create_alias
                .contains("printf 'RCH_TOPOLOGY_ERR_ALIAS_UPDATE_FAILED:path=%s:target=%s:%s\\n'"),
            "alias update diagnostics must use a static printf format: {create_alias}"
        );
        assert!(
            !create_alias.contains("echo \"RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED:path="),
            "diagnostics must not splice escaped paths into double-quoted shell text: {create_alias}"
        );
    }

    #[test]
    fn rust_toolchain_toml_parsing_handles_comments_and_rejects_controls() {
        let parsed = parse_rust_toolchain_toml_channel(
            "[toolchain]\nchannel = \"nightly-2026-04-22\" # pinned\n",
            Path::new("rust-toolchain.toml"),
        );

        assert!(
            matches!(&parsed, Ok(Some(channel)) if channel == "nightly-2026-04-22"),
            "TOML parser should extract channel with comments, got {parsed:?}"
        );

        let err = normalize_toolchain_channel("stable\nwhoops")
            .err()
            .map(|err| err.to_string());
        assert!(
            err.as_deref()
                .is_some_and(|message| message.contains("control characters")),
            "unexpected error for invalid toolchain channel: {err:?}"
        );
    }

    #[test]
    fn remote_toolchain_commands_escape_channel_values() {
        assert_eq!(
            check_toolchain_command("-nightly"),
            "rustup run -- '-nightly' rustc --version >/dev/null 2>&1 && echo FOUND || echo NOTFOUND"
        );
        assert_eq!(
            install_toolchain_command("-nightly"),
            "rustup install -- '-nightly' && rustup component add rust-src --toolchain='-nightly'"
        );

        let single_quote = install_toolchain_command("nightly'bad");
        assert!(
            single_quote.contains("'nightly'\\''bad'"),
            "single quotes in toolchain values must be shell escaped: {single_quote}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn topology_bootstrap_local_idempotent_repeated_runs() {
        log_test_start("topology_bootstrap_local_idempotent_repeated_runs");
        let tmp = TempDir::new().unwrap();
        let canonical = tmp.path().join("data/projects");
        let alias = tmp.path().join("dp");

        let first = enforce_local_topology_for_tests(&canonical, &alias, false);
        assert!(first.success);
        assert!(first.changed);
        assert!(canonical.is_dir());
        assert!(alias.symlink_metadata().unwrap().file_type().is_symlink());

        let second = enforce_local_topology_for_tests(&canonical, &alias, false);
        assert!(second.success);
        assert!(!second.changed);
        assert!(second.errors.is_empty());
        assert!(
            second
                .audit
                .iter()
                .all(|entry| entry.status == TopologyAuditStatus::AlreadyCompliant)
        );

        log_test_pass("topology_bootstrap_local_idempotent_repeated_runs");
    }

    #[cfg(unix)]
    #[test]
    fn topology_bootstrap_local_reports_integrity_mismatch_for_non_symlink_alias() {
        log_test_start("topology_bootstrap_local_reports_integrity_mismatch_for_non_symlink_alias");
        let tmp = TempDir::new().unwrap();
        let canonical = tmp.path().join("data/projects");
        let alias = tmp.path().join("dp");

        fs::create_dir_all(&canonical).unwrap();
        fs::create_dir_all(&alias).unwrap();

        let result = enforce_local_topology_for_tests(&canonical, &alias, false);
        assert!(!result.success);
        assert!(result.audit.iter().any(|entry| {
            entry.failure_kind == Some(TopologyFailureKind::IntegrityMismatch)
                && entry.status == TopologyAuditStatus::Failed
        }));
        log_test_pass("topology_bootstrap_local_reports_integrity_mismatch_for_non_symlink_alias");
    }

    #[cfg(unix)]
    #[test]
    fn topology_bootstrap_local_reports_integrity_mismatch_for_alias_symlink_loop() {
        log_test_start(
            "topology_bootstrap_local_reports_integrity_mismatch_for_alias_symlink_loop",
        );
        let tmp = TempDir::new().unwrap();
        let canonical = tmp.path().join("data/projects");
        let alias = tmp.path().join("dp");

        fs::create_dir_all(&canonical).unwrap();
        unix_fs::symlink("dp", &alias).unwrap();

        let result = enforce_local_topology_for_tests(&canonical, &alias, false);
        assert!(!result.success);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("alias path"))
        );
        assert!(result.audit.iter().any(|entry| {
            entry.step == "alias_symlink"
                && entry.failure_kind == Some(TopologyFailureKind::IntegrityMismatch)
                && entry.status == TopologyAuditStatus::Failed
        }));
        log_test_pass("topology_bootstrap_local_reports_integrity_mismatch_for_alias_symlink_loop");
    }

    #[cfg(unix)]
    #[test]
    fn topology_bootstrap_local_partial_failure_recovery_path() {
        log_test_start("topology_bootstrap_local_partial_failure_recovery_path");
        let tmp = TempDir::new().unwrap();
        let canonical = tmp.path().join("data/projects");
        let alias = tmp.path().join("dp");

        // Partial failure setup: canonical path exists as a file.
        fs::create_dir_all(canonical.parent().unwrap()).unwrap();
        fs::write(&canonical, "not a directory").unwrap();

        let first = enforce_local_topology_for_tests(&canonical, &alias, false);
        assert!(!first.success);
        assert!(first.audit.iter().any(|entry| {
            entry.failure_kind == Some(TopologyFailureKind::IntegrityMismatch)
                && entry.step == "canonical_root"
        }));

        // Manual remediation between runs.
        fs::remove_file(&canonical).unwrap();
        fs::create_dir_all(&canonical).unwrap();

        let second = enforce_local_topology_for_tests(&canonical, &alias, false);
        assert!(second.success);
        assert!(second.changed);
        assert!(alias.symlink_metadata().unwrap().file_type().is_symlink());

        let third = enforce_local_topology_for_tests(&canonical, &alias, false);
        assert!(third.success);
        assert!(!third.changed);
        log_test_pass("topology_bootstrap_local_partial_failure_recovery_path");
    }
}
