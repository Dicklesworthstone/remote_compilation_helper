//! PreToolUse hook implementation.
//!
//! Handles incoming hook requests from Claude Code, classifies commands,
//! and routes compilation commands to remote workers.

use crate::config::load_config;
use crate::error::{ArtifactRetrievalWarning, DaemonError, TransferError};
use crate::status_types::format_bytes;
use crate::toolchain::detect_toolchain;
use crate::transfer::{
    SyncResult, TransferPipeline, compute_project_hash_with_dependency_roots_and_policy,
    default_bun_artifact_patterns, default_c_cpp_artifact_patterns, default_rust_artifact_patterns,
    default_rust_test_artifact_patterns, project_id_from_path,
};
use crate::ui::console::RchConsole;
use rch_common::errors::catalog::ErrorCode;
use rch_common::repo_updater_contract::{
    REPO_UPDATER_ALLOW_OVERRIDE_ENV, REPO_UPDATER_ALLOWED_HOSTS_ENV, REPO_UPDATER_ALLOWLIST_ENV,
    REPO_UPDATER_AUTH_CREDENTIAL_ID_ENV, REPO_UPDATER_AUTH_EXPIRES_AT_MS_ENV,
    REPO_UPDATER_AUTH_ISSUED_AT_MS_ENV, REPO_UPDATER_AUTH_MODE_ENV, REPO_UPDATER_AUTH_REVOKED_ENV,
    REPO_UPDATER_AUTH_SCOPES_ENV, REPO_UPDATER_AUTH_SOURCE_ENV,
    REPO_UPDATER_AUTH_VERIFIED_HOSTS_ENV, REPO_UPDATER_OVERRIDE_APPROVED_AT_MS_ENV,
    REPO_UPDATER_OVERRIDE_AUDIT_EVENT_ID_ENV, REPO_UPDATER_OVERRIDE_JUSTIFICATION_ENV,
    REPO_UPDATER_OVERRIDE_OPERATOR_ID_ENV, REPO_UPDATER_OVERRIDE_TICKET_REF_ENV,
    REPO_UPDATER_REQUIRE_HOST_IDENTITY_ENV, REPO_UPDATER_REQUIRED_SCOPES_ENV,
    REPO_UPDATER_ROTATION_MAX_AGE_SECS_ENV, REPO_UPDATER_TRUSTED_HOST_IDENTITIES_ENV,
    RepoUpdaterAuthContext, RepoUpdaterAuthMode, RepoUpdaterCredentialSource,
    RepoUpdaterOperatorOverride, RepoUpdaterTrustedHostIdentity, RepoUpdaterVerifiedHostIdentity,
};
use rch_common::{
    BuildHeartbeatPhase, BuildHeartbeatRequest, ColorMode, CommandPriority, CommandTimingBreakdown,
    CompilationKind, DependencyClosurePlan, HookInput, HookOutput, OutputVisibility,
    REPO_UPDATER_CANONICAL_PROJECTS_ROOT, RepoUpdaterAdapterCommand, RepoUpdaterAdapterContract,
    RepoUpdaterAdapterRequest, RepoUpdaterOutputFormat, RequiredRuntime, SelectedWorker,
    SelectionReason, SelectionResponse, SelfHealingConfig, ToolchainInfo, TransferConfig,
    WorkerConfig, WorkerId, build_dependency_closure_plan_with_policy, build_invocation,
    classify_command, mock, normalize_project_path_with_policy,
    path_topology::PathTopologyPolicy,
    ui::{
        ArtifactSummary, CelebrationSummary, CompilationProgress, CompletionCelebration, Icons,
        OutputContext, RchTheme, TransferProgress,
    },
};
use rch_telemetry::protocol::{
    PIGGYBACK_MARKER, TelemetrySource, TestRunRecord, WorkerTelemetry,
    extract_piggybacked_telemetry,
};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};
use which::which;

#[cfg(all(feature = "rich-ui", unix))]
use rich_rust::renderables::Panel;

// ============================================================================
// Exit Code Constants
// ============================================================================
//
// Cargo test (and cargo build/check/clippy) use specific exit codes:
//
// - 0:   Success (all tests passed, or build succeeded)
// - 1:   Build/compilation error (couldn't compile tests or crate)
// - 101: Test failures (tests compiled and ran, but some failed)
// - 128+N: Process killed by signal N (e.g., 137 = SIGKILL, 143 = SIGTERM)
//
// For RCH, ALL non-zero exits should deny local re-execution because:
// 1. Exit 101: Tests failed remotely, re-running locally won't help
// 2. Exit 1: Build error would occur locally too
// 3. Exit 128+N: Likely resource exhaustion (OOM), local might also fail
//
// The only exception is toolchain failures (missing rust version), which
// should fall back to local in case the local machine has the toolchain.

/// Exit code for successful cargo command (tests passed, build succeeded).
#[allow(dead_code)]
const EXIT_SUCCESS: i32 = 0;

/// Exit code for build/compilation error.
const EXIT_BUILD_ERROR: i32 = 1;

/// Exit code for cargo test when tests ran but some failed.
#[allow(dead_code)] // Used in run_exec
const EXIT_TEST_FAILURES: i32 = 101;

/// Minimum exit code indicating the process was killed by a signal.
/// Exit code = 128 + signal number (e.g., 137 = 128 + 9 = SIGKILL).
#[allow(dead_code)] // Used in run_exec
const EXIT_SIGNAL_BASE: i32 = 128;

const RCH_CARGO_WRAPPER_BYPASS_ENV: &str = "RCH_CARGO_WRAPPER_BYPASS";
const RCH_REQUIRE_REMOTE_ENV: &str = "RCH_REQUIRE_REMOTE";
const RCH_WORKER_ENV: &str = "RCH_WORKER";
const RCH_WORKERS_ENV: &str = "RCH_WORKERS";

static HOOK_MODE_PANIC_FAIL_OPEN: AtomicBool = AtomicBool::new(false);
static AUTOSTART_LOCK_SEQUENCE: AtomicU64 = AtomicU64::new(0);

use rch_common::util::mask_sensitive_command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemotePipelineFailurePolicy {
    AllowLocalFallback,
    FailClosedNoLocalFallback,
}

fn classify_remote_pipeline_failure(error: &anyhow::Error) -> RemotePipelineFailurePolicy {
    if is_ssh_command_timeout_error(error) {
        RemotePipelineFailurePolicy::FailClosedNoLocalFallback
    } else {
        RemotePipelineFailurePolicy::AllowLocalFallback
    }
}

fn is_ssh_command_timeout_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("SSH command timed out after")
            || message.contains("Command timed out after")
    })
}

fn remote_pipeline_failure_summary(worker_id: &WorkerId) -> String {
    format!(
        "[RCH] remote {} failed [{}] SSH command timed out (no local fallback)",
        worker_id,
        ErrorCode::SshTimeout.code_string()
    )
}

#[derive(Debug, Deserialize)]
struct SelectionResponseWire {
    worker: Option<SelectedWorker>,
    reason: SelectionReasonWire,
    #[serde(default)]
    build_id: Option<u64>,
    #[serde(default)]
    diagnostics: Option<rch_common::SelectionDiagnostics>,
}

impl From<SelectionResponseWire> for SelectionResponse {
    fn from(value: SelectionResponseWire) -> Self {
        Self {
            worker: value.worker,
            reason: value.reason.into(),
            build_id: value.build_id,
            diagnostics: value.diagnostics,
        }
    }
}

#[derive(Debug)]
enum SelectionReasonWire {
    NoAdmissibleWorkers { no_admissible_workers: String },
    NoWorkersWithRuntime { no_workers_with_runtime: String },
    SelectionError { selection_error: String },
    Unit(UnitSelectionReasonWire),
    Unknown(serde_json::Value),
}

impl<'de> Deserialize<'de> for SelectionReasonWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        match &value {
            serde_json::Value::Object(object) if object.len() == 1 => {
                if let Some(reason) = object
                    .get("no_admissible_workers")
                    .and_then(serde_json::Value::as_str)
                {
                    return Ok(Self::NoAdmissibleWorkers {
                        no_admissible_workers: reason.to_string(),
                    });
                }
                if let Some(runtime) = object
                    .get("no_workers_with_runtime")
                    .and_then(serde_json::Value::as_str)
                {
                    return Ok(Self::NoWorkersWithRuntime {
                        no_workers_with_runtime: runtime.to_string(),
                    });
                }
                if let Some(error) = object
                    .get("selection_error")
                    .and_then(serde_json::Value::as_str)
                {
                    return Ok(Self::SelectionError {
                        selection_error: error.to_string(),
                    });
                }
            }
            serde_json::Value::String(_) => {
                let unit = serde_json::from_value::<UnitSelectionReasonWire>(value.clone())
                    .map_err(serde::de::Error::custom)?;
                return Ok(match unit {
                    UnitSelectionReasonWire::Unknown => Self::Unknown(value),
                    unit => Self::Unit(unit),
                });
            }
            _ => {}
        }

        Ok(Self::Unknown(value))
    }
}

impl From<SelectionReasonWire> for SelectionReason {
    fn from(value: SelectionReasonWire) -> Self {
        match value {
            SelectionReasonWire::NoAdmissibleWorkers {
                no_admissible_workers,
            } => Self::NoAdmissibleWorkers(no_admissible_workers),
            SelectionReasonWire::NoWorkersWithRuntime {
                no_workers_with_runtime,
            } => Self::NoWorkersWithRuntime(no_workers_with_runtime),
            SelectionReasonWire::SelectionError { selection_error } => {
                Self::SelectionError(selection_error)
            }
            SelectionReasonWire::Unit(unit) => unit.into(),
            SelectionReasonWire::Unknown(value) => Self::SelectionError(format!(
                "unknown daemon selection reason: {}",
                selection_reason_wire_detail(&value)
            )),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UnitSelectionReasonWire {
    Success,
    NoWorkersConfigured,
    AllWorkersUnreachable,
    AllCircuitsOpen,
    AllWorkersBusy,
    NoWorkersPassedHealth,
    AllWorkersFailedPreflight,
    AllWorkersFailedConvergence,
    NoMatchingWorkers,
    AffinityPinned,
    AffinityFallback,
    #[serde(other)]
    Unknown,
}

impl From<UnitSelectionReasonWire> for SelectionReason {
    fn from(value: UnitSelectionReasonWire) -> Self {
        match value {
            UnitSelectionReasonWire::Success => Self::Success,
            UnitSelectionReasonWire::NoWorkersConfigured => Self::NoWorkersConfigured,
            UnitSelectionReasonWire::AllWorkersUnreachable => Self::AllWorkersUnreachable,
            UnitSelectionReasonWire::AllCircuitsOpen => Self::AllCircuitsOpen,
            UnitSelectionReasonWire::AllWorkersBusy => Self::AllWorkersBusy,
            UnitSelectionReasonWire::NoWorkersPassedHealth => Self::NoWorkersPassedHealth,
            UnitSelectionReasonWire::AllWorkersFailedPreflight => Self::AllWorkersFailedPreflight,
            UnitSelectionReasonWire::AllWorkersFailedConvergence => {
                Self::AllWorkersFailedConvergence
            }
            UnitSelectionReasonWire::NoMatchingWorkers => Self::NoMatchingWorkers,
            UnitSelectionReasonWire::AffinityPinned => Self::AffinityPinned,
            UnitSelectionReasonWire::AffinityFallback => Self::AffinityFallback,
            UnitSelectionReasonWire::Unknown => {
                Self::SelectionError("unknown daemon selection reason".to_string())
            }
        }
    }
}

fn parse_selection_response(body: &str) -> anyhow::Result<SelectionResponse> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| anyhow::anyhow!("Failed to parse daemon response JSON: {}", e))?;
    validate_selection_response_protocol(&value)?;
    let wire: SelectionResponseWire = serde_json::from_value(value)
        .map_err(|e| anyhow::anyhow!("Failed to parse daemon selection response: {}", e))?;
    Ok(wire.into())
}

fn validate_selection_response_protocol(value: &serde_json::Value) -> anyhow::Result<()> {
    let Some(version_value) = value
        .get("selection_protocol_version")
        .or_else(|| value.get("protocol_version"))
    else {
        return Ok(());
    };

    let version = selection_protocol_version_value(version_value).ok_or_else(|| {
        anyhow::anyhow!(
            "Daemon selection protocol version must be an integer or integer string, got {}",
            version_value
        )
    })?;
    let supported = rch_common::SELECTION_RESPONSE_PROTOCOL_VERSION;
    if version > supported {
        return Err(anyhow::anyhow!(
            "Daemon selection protocol version {} exceeds client support {}; reinstall matching rch/rchd binaries",
            version,
            supported
        ));
    }

    Ok(())
}

fn selection_protocol_version_value(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

fn selection_reason_wire_detail(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(reason) => reason.clone(),
        serde_json::Value::Object(object) if object.len() == 1 => object
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| value.to_string()),
        _ => value.to_string(),
    }
}

/// Run the hook, reading from stdin and writing to stdout.
///
/// **Fail-open contract**: this function MUST return `Ok(())` for every
/// non-fatal failure mode. The hook runs synchronously in the agent's
/// Bash invocation path; any error we propagate becomes a non-zero exit
/// from `rch`, which Claude Code interprets as "hook said deny". We
/// would rather silently allow the command than block on stdin EOF, a
/// flushing hiccup, or a serialization edge case.
///
/// The single legitimate Err return is one we cannot fix locally
/// (e.g., `init_logging` error before this is called). All I/O within
/// run_hook is degraded to a silent allow.
pub async fn run_hook() -> anyhow::Result<()> {
    let mut stdout = io::stdout();

    // Read input from stdin with a 10MB limit to prevent OOM.
    // A truncated/closed pipe is treated as "no input" (fail-open).
    let mut input = String::new();
    {
        use tokio::io::{AsyncReadExt, stdin};
        if let Err(e) = stdin()
            .take(10 * 1024 * 1024)
            .read_to_string(&mut input)
            .await
        {
            warn!(target: "rch::hook", error = %e, "stdin read failed; allowing command (fail-open)");
            return Ok(());
        }
    }

    let input = input.trim();
    if input.is_empty() {
        // No input - just allow
        return Ok(());
    }

    // Parse the hook input
    let hook_input: HookInput = match serde_json::from_str(input) {
        Ok(hi) => hi,
        Err(e) => {
            warn!("Failed to parse hook input: {}", e);
            // On parse error, allow the command (fail-open)
            return Ok(());
        }
    };

    // Process the hook request
    let output = process_hook(hook_input).await;

    // Write output:
    //   - Deny: write JSON to block the command
    //   - AllowWithModifiedCommand: write JSON to replace the command (transparent interception)
    //   - Allow: output nothing (empty stdout = allow unchanged)
    //
    // serde / writeln errors here would be near-impossible (we just
    // built the value from typed Rust), but if they occur we log and
    // fall open rather than non-zero-exit and block the agent's Bash.
    match &output {
        HookOutput::Deny(_) | HookOutput::AllowWithModifiedCommand(_) => {
            match serde_json::to_string(&output) {
                Ok(json) => {
                    if let Err(e) = writeln!(stdout, "{}", json) {
                        warn!(target: "rch::hook", error = %e, "stdout write failed; falling open");
                        return Ok(());
                    }
                    if let Err(e) = stdout.flush() {
                        // Explicit flush: io::stdout() is fully buffered when
                        // attached to a pipe (Claude Code reads via pipe).
                        // Without this flush, abnormal exit could lose the JSON.
                        warn!(target: "rch::hook", error = %e, "stdout flush failed; falling open");
                        return Ok(());
                    }
                }
                Err(e) => {
                    warn!(target: "rch::hook", error = %e, "JSON serialization failed; falling open");
                    return Ok(());
                }
            }
        }
        HookOutput::Allow(_) => {
            // Empty stdout = allow command unchanged
        }
    }

    Ok(())
}

/// Install a panic hook that suppresses panic output and exits 0 when
/// the process is invoked as a Claude Code hook. Without this, any
/// panic in classify / serde / cache propagates as a non-zero exit,
/// which Claude Code interprets as "deny" and BLOCKS the agent's Bash.
///
/// The trade-off: a real bug in the hook becomes silent. That's the
/// correct call here — a hook that crashes silently and lets the
/// command run is strictly better for the agent than a hook that
/// blocks every Bash command on a regression. Real-world bug reports
/// surface via the daemon-side error logs, not the hook stderr.
///
/// Call this BEFORE any code that could panic.
pub fn install_hook_mode_panic_handler() {
    enable_hook_mode_panic_fail_open();

    // Idempotent guard: only install once.
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Capture the original hook so non-hook-mode invocations
        // (e.g. `rch exec`) keep their normal panic output.
        let original = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if hook_mode_panic_fail_open_enabled() {
                // Hook mode: log to stderr quietly, then exit 0 so the
                // agent's Bash command runs locally. Don't print the
                // backtrace to stderr (Claude Code may surface it).
                eprintln!("[rch] hook panicked; falling open. (set RUST_BACKTRACE=1 to see)");
                if std::env::var("RUST_BACKTRACE")
                    .ok()
                    .as_deref()
                    .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("full"))
                {
                    original(info);
                }
                std::process::exit(0);
            } else {
                // Non-hook invocation: original panic behavior.
                original(info);
            }
        }));
    });
}

fn enable_hook_mode_panic_fail_open() {
    HOOK_MODE_PANIC_FAIL_OPEN.store(true, Ordering::Release);
}

fn hook_mode_panic_fail_open_enabled() -> bool {
    HOOK_MODE_PANIC_FAIL_OPEN.load(Ordering::Acquire)
        || std::env::var("RCH_HOOK_MODE")
            .ok()
            .as_deref()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Execute a compilation command on a remote worker.
///
/// This is called by `rch exec -- <command>` which is invoked after the hook
/// rewrites the original compilation command. This separation allows the hook
/// to return immediately (<50ms) while the actual compilation runs as a
/// normal command invocation.
/// Re-assemble an argv vector into a shell command string that preserves
/// word boundaries under `sh -c` re-parsing.
///
/// Using a plain `parts.join(" ")` is wrong whenever an argv entry contains
/// shell-meaningful characters (spaces, quotes, `$`, etc.): the outer shell
/// that dispatched us already stripped the original quoting, leaving such
/// bytes as literal content in a single argv entry. `sh -c` would then
/// re-split on those literals and silently corrupt the command.
///
/// `shell_words::join` re-quotes each entry so round-tripping through
/// `sh -c` is a no-op. Some callers pass `rch exec -- "<whole shell command>"`
/// as a single argv entry; split that shell command once before re-quoting so
/// `sh -c` sees `env VAR=... cargo ...` instead of one quoted command name.
fn join_exec_command(command_parts: &[String]) -> String {
    let normalized_parts = normalize_exec_command_parts(command_parts);
    shell_words::join(normalized_parts)
}

fn normalize_exec_command_parts(command_parts: &[String]) -> Vec<String> {
    if command_parts.len() == 1 {
        match shell_words::split(&command_parts[0]) {
            Ok(parts) if parts.len() > 1 => return parts,
            _ => {}
        }
    }

    command_parts.to_vec()
}

fn env_flag_enabled(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn exec_requires_remote() -> bool {
    std::env::var(RCH_REQUIRE_REMOTE_ENV).is_ok_and(|value| env_flag_enabled(&value))
}

pub(crate) fn preferred_workers_from_env() -> Vec<WorkerId> {
    let mut preferred = Vec::new();
    if let Ok(value) = std::env::var(RCH_WORKER_ENV) {
        preferred.extend(parse_preferred_workers(&value));
    }
    if let Ok(value) = std::env::var(RCH_WORKERS_ENV) {
        preferred.extend(parse_preferred_workers(&value));
    }
    dedupe_worker_ids(preferred)
}

fn parse_preferred_workers(value: &str) -> Vec<WorkerId> {
    value
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(WorkerId::new)
        .collect()
}

fn dedupe_worker_ids(workers: Vec<WorkerId>) -> Vec<WorkerId> {
    let mut deduped = Vec::new();
    for worker in workers {
        if !deduped.contains(&worker) {
            deduped.push(worker);
        }
    }
    deduped
}

fn local_fallback_command(command: &str) -> std::process::Command {
    let mut child = std::process::Command::new("sh");
    child
        .env(RCH_CARGO_WRAPPER_BYPASS_ENV, "1")
        .arg("-c")
        .arg(command);
    child
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalFallbackRefusal {
    RemoteRequired,
}

fn local_fallback_command_for_policy(
    command: &str,
    require_remote: bool,
) -> Result<std::process::Command, LocalFallbackRefusal> {
    if require_remote {
        Err(LocalFallbackRefusal::RemoteRequired)
    } else {
        Ok(local_fallback_command(command))
    }
}

fn remote_required_refusal_summary(reason: &str) -> String {
    if reason == "non-compilation command" {
        format!(
            "[RCH] remote required; refusing local fallback [{}] ({reason})",
            ErrorCode::BuildUnknownCommand.code_string()
        )
    } else {
        format!("[RCH] remote required; refusing local fallback ({reason})")
    }
}

fn exit_with_local_fallback(command: &str, reporter: &HookReporter, reason: &str) -> ! {
    let mut child = match local_fallback_command_for_policy(command, exec_requires_remote()) {
        Ok(child) => child,
        Err(LocalFallbackRefusal::RemoteRequired) => {
            reporter.summary(&remote_required_refusal_summary(reason));
            std::process::exit(EXIT_BUILD_ERROR);
        }
    };

    match child.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(error) => {
            reporter.summary(&format!("[RCH] local fallback failed: {error}"));
            std::process::exit(EXIT_BUILD_ERROR);
        }
    }
}

pub async fn run_exec(command_parts: Vec<String>) -> anyhow::Result<()> {
    let command = join_exec_command(&command_parts);
    if command.is_empty() {
        anyhow::bail!("No command provided to exec");
    }

    // Classify the command
    let classification = classify_command(&command);
    if !classification.is_compilation {
        // This should not normally happen because the hook only rewrites
        // compilations. Preserve the ordinary local behavior, but honor
        // RCH_REQUIRE_REMOTE for explicit `rch exec` invocations.
        warn!("exec called with non-compilation command: {}", command);
        let reporter = HookReporter::new(OutputVisibility::Summary);
        exit_with_local_fallback(&command, &reporter, "non-compilation command");
    }

    let config = match load_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to load config: {}, running locally", e);
            let reporter = HookReporter::new(OutputVisibility::Summary);
            exit_with_local_fallback(&command, &reporter, "config unavailable");
        }
    };

    let reporter = HookReporter::new(config.output.visibility);

    // Build path topology policy from loaded config so that any normalization
    // warnings reference the configured roots rather than compiled-in defaults.
    let topology_policy = config.path_topology.to_policy();

    // Extract project name honoring configured path topology.
    let project = extract_project_name_with_policy(&topology_policy);

    // Estimate cores needed
    let estimated_cores =
        estimate_cores_for_command(classification.kind, &command, &config.compilation);

    // Detect toolchain
    let project_root = std::env::current_dir().ok();
    let toolchain = if let Some(root) = &project_root {
        detect_toolchain(root).ok()
    } else {
        None
    };
    let forwarded_cargo_target_dir = resolve_forwarded_cargo_target_dir(
        classification.kind,
        project_root.as_deref().unwrap_or_else(|| Path::new(".")),
        &reporter,
        Some(&command_parts),
    );
    let remote_command = rewrite_cargo_target_dir_command_for_remote(
        &command,
        Some(&command_parts),
        forwarded_cargo_target_dir.as_ref(),
        &reporter,
    );

    // Determine required runtime
    let required_runtime = required_runtime_for_kind(classification.kind);
    let command_priority = command_priority_from_env(&reporter);
    let wait_for_worker = queue_when_busy_enabled();
    let preferred_workers = preferred_workers_from_env();

    // Query daemon for worker selection
    let response = match query_daemon(
        &config.general.socket_path,
        &project,
        estimated_cores,
        &remote_command,
        toolchain.as_ref(),
        required_runtime,
        command_priority,
        0, // classification duration not relevant here
        Some(std::process::id()),
        wait_for_worker,
        &preferred_workers,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Failed to query daemon: {}, running locally", e);
            // Try auto-start daemon
            if let Ok(()) =
                try_auto_start_daemon(&config.self_healing, Path::new(&config.general.socket_path))
                    .await
            {
                // Retry query
                match query_daemon(
                    &config.general.socket_path,
                    &project,
                    estimated_cores,
                    &remote_command,
                    toolchain.as_ref(),
                    required_runtime,
                    command_priority,
                    0,
                    Some(std::process::id()),
                    wait_for_worker,
                    &preferred_workers,
                )
                .await
                {
                    Ok(resp) => resp,
                    Err(_) => {
                        reporter.summary("[RCH] local (daemon unavailable)");
                        exit_with_local_fallback(&command, &reporter, "daemon unavailable");
                    }
                }
            } else {
                reporter.summary("[RCH] local (daemon unavailable)");
                exit_with_local_fallback(&command, &reporter, "daemon unavailable");
            }
        }
    };

    // Check if a worker was assigned
    let Some(worker) = response.worker else {
        reporter.summary(&format!("[RCH] local ({})", response.reason));
        exit_with_local_fallback(&command, &reporter, "no worker assigned");
    };

    info!(
        "Selected worker: {} at {}@{} ({} slots remaining after reservation, speed {:.1})",
        worker.id, worker.user, worker.host, worker.slots_available, worker.speed_score
    );

    // Execute remote compilation pipeline (topology_policy was built earlier
    // from the loaded config so diagnostics reference configured roots).
    let remote_start = Instant::now();
    let result = execute_remote_compilation(
        &worker,
        &remote_command,
        config.transfer.clone(),
        config.environment.allowlist.clone(),
        forwarded_cargo_target_dir,
        &config.compilation,
        toolchain.as_ref(),
        classification.kind,
        &reporter,
        &config.general.socket_path,
        config.output.color_mode,
        response.build_id,
        &topology_policy,
    )
    .await;
    let remote_elapsed = remote_start.elapsed();

    // Release worker slots
    let release_exit_code = result
        .as_ref()
        .map(|ok| ok.exit_code)
        .unwrap_or(EXIT_BUILD_ERROR);
    let release_timing = result.as_ref().ok().map(|ok| {
        let mut timing = ok.timing.clone();
        timing.total = Some(remote_elapsed);
        timing
    });
    if let Err(e) = release_worker(
        &config.general.socket_path,
        &worker.id,
        estimated_cores,
        response.build_id,
        Some(release_exit_code),
        None,
        None,
        release_timing.as_ref(),
    )
    .await
    {
        warn!("Failed to release worker slots: {}", e);
    }

    // Handle result and exit with appropriate code
    match result {
        Ok(result) => {
            if result.exit_code == 0 {
                reporter.summary(&format!(
                    "[RCH] remote {} ({})",
                    worker.id,
                    format_duration_ms(remote_elapsed)
                ));
                // Record successful build
                let is_test = classification
                    .kind
                    .map(|kind| kind.is_test_command())
                    .unwrap_or(false);
                if let Err(e) =
                    record_build(&config.general.socket_path, &worker.id, &project, is_test).await
                {
                    warn!("Failed to record build: {}", e);
                }
                std::process::exit(0);
            } else if is_toolchain_failure(&result.stderr, result.exit_code) {
                // Toolchain failure - fall back to local
                warn!("Remote toolchain failure, falling back to local");
                reporter.summary(&format!("[RCH] local (toolchain missing on {})", worker.id));
                exit_with_local_fallback(&command, &reporter, "remote toolchain missing");
            } else if let Some(env_failure) =
                detect_worker_system_dependency_failure(&result.stderr, result.exit_code)
            {
                let error = ErrorCode::BuildEnvError;
                warn!(
                    "Remote worker build-environment failure on {} [{}]: {}",
                    worker.id,
                    error.code_string(),
                    env_failure.log_detail()
                );
                reporter.summary(&format!(
                    "[RCH] remote {} failed [{}] {}",
                    worker.id,
                    error.code_string(),
                    env_failure.summary()
                ));
                reporter.verbose(&format!(
                    "[RCH] remediation [{}]: {}",
                    error.code_string(),
                    env_failure.remediation()
                ));
                std::process::exit(result.exit_code);
            } else {
                // Command failed remotely - exit with the same code
                reporter.summary(&format!(
                    "[RCH] remote {} failed (exit {})",
                    worker.id, result.exit_code
                ));
                std::process::exit(result.exit_code);
            }
        }
        Err(e) => {
            if let Some(preflight_err) = e.downcast_ref::<DependencyPreflightFailure>() {
                warn!(
                    "Dependency preflight blocked remote execution [{}]: {}",
                    preflight_err.reason_code, preflight_err.remediation
                );
                reporter.summary(&format!(
                    "[RCH] local (dependency preflight {}: {})",
                    preflight_err.reason_code, preflight_err.remediation
                ));
                reporter.verbose(&format!(
                    "[RCH] dependency preflight report: {}",
                    preflight_err.report_json()
                ));
                exit_with_local_fallback(&command, &reporter, "dependency preflight failed");
            }

            // Check for transfer skip (not a failure)
            if let Some(skip_err) = e.downcast_ref::<TransferError>()
                && let TransferError::TransferSkipped { reason } = skip_err
            {
                reporter.summary(&format!("[RCH] local ({})", reason));
                exit_with_local_fallback(&command, &reporter, "transfer skipped");
            }

            if classify_remote_pipeline_failure(&e)
                == RemotePipelineFailurePolicy::FailClosedNoLocalFallback
            {
                warn!(
                    "Remote execution failed on {} with SSH timeout; refusing local fallback: {}",
                    worker.id, e
                );
                reporter.summary(&remote_pipeline_failure_summary(&worker.id));
                std::process::exit(EXIT_BUILD_ERROR);
            }

            // Other errors - run locally
            warn!("Remote execution failed: {}, running locally", e);
            reporter.summary("[RCH] local (remote execution failed)");
            exit_with_local_fallback(&command, &reporter, "remote execution failed");
        }
    }
}

#[derive(Clone, Copy)]
struct HookReporter {
    visibility: OutputVisibility,
}

impl HookReporter {
    fn new(visibility: OutputVisibility) -> Self {
        Self { visibility }
    }

    fn summary(&self, message: &str) {
        if self.visibility != OutputVisibility::None {
            eprintln!("{}", message);
        }
    }

    fn verbose(&self, message: &str) {
        if self.visibility == OutputVisibility::Verbose {
            eprintln!("{}", message);
        }
    }
}

fn format_duration_ms(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis >= 1000 {
        format!("{:.1}s", millis as f64 / 1000.0)
    } else {
        format!("{}ms", millis)
    }
}

fn format_speed(bytes: u64, duration_ms: u64) -> String {
    if duration_ms == 0 || bytes == 0 {
        return "--".to_string();
    }
    let secs = duration_ms as f64 / 1000.0;
    if secs <= 0.0 {
        return "--".to_string();
    }
    let per_sec = (bytes as f64 / secs).round() as u64;
    format!("{}/s", format_bytes(per_sec))
}

fn cache_hit(sync: &SyncResult) -> bool {
    sync.bytes_transferred == 0 && sync.files_transferred == 0
}

fn detect_target_label(command: &str, output: &str) -> Option<String> {
    if let Some(profile) = detect_profile_from_output(output) {
        return Some(profile);
    }
    if let Some(profile) = extract_profile_flag(command) {
        return Some(profile);
    }
    if command.contains("--release") {
        return Some("release".to_string());
    }
    None
}

fn detect_profile_from_output(output: &str) -> Option<String> {
    for line in output.lines() {
        if line.contains("Finished `release`") {
            return Some("release".to_string());
        }
        if line.contains("Finished `dev`") || line.contains("Finished `debug`") {
            return Some("debug".to_string());
        }
        if line.contains("Finished `bench`") {
            return Some("bench".to_string());
        }
    }
    None
}

fn extract_profile_flag(command: &str) -> Option<String> {
    for token in command.split_whitespace() {
        if let Some(profile) = token.strip_prefix("--profile=") {
            return Some(profile.to_string());
        }
    }

    let mut iter = command.split_whitespace();
    while let Some(token) = iter.next() {
        if token == "--profile"
            && let Some(value) = iter.next()
        {
            return Some(value.to_string());
        }
    }
    None
}

fn emit_job_banner(
    console: &RchConsole,
    ctx: OutputContext,
    worker: &SelectedWorker,
    build_id: Option<u64>,
) {
    if console.is_machine() {
        return;
    }

    let job = build_id
        .map(|id| format!("j-{}", id))
        .unwrap_or_else(|| "job".to_string());
    let message = format!(
        "{} Job {} submitted to {} ({} slots remaining, speed {:.1})",
        Icons::status_healthy(ctx),
        job,
        worker.id,
        worker.slots_available,
        worker.speed_score
    );

    #[cfg(all(feature = "rich-ui", unix))]
    if console.is_rich() {
        let rich = format!(
            "[bold {}]{}[/] Job {} submitted to {} ({} slots remaining, speed {:.1})",
            RchTheme::INFO,
            Icons::status_healthy(ctx),
            job,
            worker.id,
            worker.slots_available,
            worker.speed_score
        );
        console.print_rich(&rich);
        return;
    }

    console.print_plain(&message);
}

#[allow(clippy::too_many_arguments)] // Presentation helper; wiring is clearer with explicit params.
fn render_compile_summary(
    console: &RchConsole,
    ctx: OutputContext,
    worker: &SelectedWorker,
    build_id: Option<u64>,
    sync: &SyncResult,
    exec_ms: u64,
    artifacts: Option<&SyncResult>,
    artifacts_failed: bool,
    cache_hit: bool,
    success: bool,
) {
    if console.is_machine() {
        return;
    }

    let total_ms = sync.duration_ms + exec_ms + artifacts.map(|a| a.duration_ms).unwrap_or(0);
    let sync_duration = format_duration_ms(Duration::from_millis(sync.duration_ms));
    let exec_duration = format_duration_ms(Duration::from_millis(exec_ms));
    let total_duration = format_duration_ms(Duration::from_millis(total_ms));

    let sync_bytes = format_bytes(sync.bytes_transferred);
    let sync_speed = format_speed(sync.bytes_transferred, sync.duration_ms);

    let (artifact_line, artifact_duration) = if let Some(artifact) = artifacts {
        let bytes = format_bytes(artifact.bytes_transferred);
        let speed = format_speed(artifact.bytes_transferred, artifact.duration_ms);
        let duration = format_duration_ms(Duration::from_millis(artifact.duration_ms));
        (
            format!(
                "{} Artifacts: {} in {} ({})",
                Icons::arrow_down(ctx),
                bytes,
                duration,
                speed
            ),
            duration,
        )
    } else if artifacts_failed {
        ("Artifacts: failed".to_string(), "--".to_string())
    } else {
        ("Artifacts: skipped".to_string(), "--".to_string())
    };

    let job = build_id
        .map(|id| format!("j-{}", id))
        .unwrap_or_else(|| "job".to_string());

    let worker_line = format!(
        "{} Worker: {} | Job: {}",
        Icons::worker(ctx),
        worker.id,
        job
    );
    let timing_line = format!(
        "{} Total: {} (sync {}, build {}, artifacts {})",
        Icons::clock(ctx),
        total_duration,
        sync_duration,
        exec_duration,
        artifact_duration
    );
    let sync_line = format!(
        "{} Sync: {} in {} ({})",
        Icons::arrow_up(ctx),
        sync_bytes,
        sync_duration,
        sync_speed
    );
    let compile_line = format!("{} Compile: {}", Icons::compile(ctx), exec_duration);

    let cache_text = if cache_hit { "HIT" } else { "MISS" };
    let cache_line_plain = format!("{} Cache: {}", Icons::transfer(ctx), cache_text);

    let content_plain = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        worker_line, timing_line, sync_line, compile_line, artifact_line, cache_line_plain
    );

    #[cfg(all(feature = "rich-ui", unix))]
    if console.is_rich() {
        let cache_rich = if cache_hit {
            format!("[bold {}]HIT[/]", RchTheme::SUCCESS)
        } else {
            format!("[bold {}]MISS[/]", RchTheme::WARNING)
        };
        let cache_line = format!("{} Cache: {}", Icons::transfer(ctx), cache_rich);
        let content = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            worker_line, timing_line, sync_line, compile_line, artifact_line, cache_line
        );
        let title = if success {
            "Compilation Complete"
        } else {
            "Compilation Failed"
        };
        let border = if success {
            RchTheme::success()
        } else {
            RchTheme::error()
        };
        let panel = Panel::from_text(&content)
            .title(title)
            .border_style(border)
            .rounded();
        console.print_renderable(&panel);
        return;
    }

    console.print_plain(&content_plain);
}

#[allow(dead_code)] // May be used for timing estimates in run_exec
fn estimate_local_time_ms(remote_ms: u64, worker_speed_score: f64) -> Option<u64> {
    if remote_ms == 0 || worker_speed_score <= 0.0 {
        return None;
    }
    // Don't clamp upper bound - allow scores > 100 (faster than baseline)
    // Lower bound 1.0 prevents zero/negative logic issues
    let normalized = worker_speed_score.max(1.0);

    // Formula: LocalTime = RemoteTime * (WorkerScore / BaselineScore)
    // Example: Worker=200 (2x fast), Remote=5s. Local=5*(200/100)=10s.
    let estimate = (remote_ms as f64) * (normalized / 100.0);
    Some(estimate.round().max(1.0) as u64)
}

fn parse_u32(value: &str) -> Option<u32> {
    value
        .trim_matches('"')
        .parse::<u32>()
        .ok()
        .filter(|n| *n > 0)
}

fn parse_env_u32(command: &str, key: &str) -> Option<u32> {
    let needle = format!("{}=", key);
    command
        .split_whitespace()
        .find_map(|token| token.strip_prefix(&needle).and_then(parse_u32))
}

fn read_env_u32(key: &str) -> Option<u32> {
    if cfg!(test) {
        return None;
    }
    std::env::var(key).ok().and_then(|v| parse_u32(&v))
}

fn parse_jobs_flag(command: &str) -> Option<u32> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    for (idx, token) in tokens.iter().enumerate() {
        if (*token == "-j" || *token == "--jobs")
            && let Some(next) = tokens.get(idx + 1)
            && let Some(value) = parse_u32(next)
        {
            return Some(value);
        }
        if let Some(value) = token.strip_prefix("-j=").and_then(parse_u32) {
            return Some(value);
        }
        if let Some(value) = token.strip_prefix("-j").and_then(parse_u32) {
            return Some(value);
        }
        if let Some(value) = token.strip_prefix("--jobs=").and_then(parse_u32) {
            return Some(value);
        }
    }
    None
}

pub(crate) fn cargo_job_count_for_command(command: &str) -> Option<u32> {
    parse_jobs_flag(command)
        .or_else(|| parse_env_u32(command, "CARGO_BUILD_JOBS"))
        .or_else(|| read_env_u32("CARGO_BUILD_JOBS"))
}

fn parse_test_threads(command: &str) -> Option<u32> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    for (idx, token) in tokens.iter().enumerate() {
        if *token == "--test-threads"
            && let Some(next) = tokens.get(idx + 1)
            && let Some(value) = parse_u32(next)
        {
            return Some(value);
        }
        if let Some(value) = token.strip_prefix("--test-threads=").and_then(parse_u32) {
            return Some(value);
        }
    }
    None
}

// ============================================================================
// Daemon Auto-Start (Self-Healing)
// ============================================================================

#[derive(Debug, thiserror::Error)]
enum AutoStartError {
    #[error("Another process is starting the daemon (lock held)")]
    LockHeld,
    #[error("Auto-start on cooldown (last attempt {0}s ago, need {1}s)")]
    CooldownActive(u64, u64),
    #[error("Failed to spawn rchd: {0}")]
    SpawnFailed(#[source] std::io::Error),
    #[error("rchd launch wrapper exited unsuccessfully: {0}")]
    WrapperFailed(std::process::ExitStatus),
    #[error("Daemon started but socket not found after {0}s")]
    Timeout(u64),
    #[error("rchd binary not found in PATH")]
    BinaryNotFound,
    #[error("Socket exists but daemon not responding (stale socket)")]
    StaleSocket,
    #[error("Socket accepts connections but daemon health check failed")]
    UnhealthySocket,
    #[error("Configuration disabled auto-start")]
    Disabled,
    #[error("Auto-start I/O error: {0}")]
    Io(#[source] std::io::Error),
}

#[derive(Debug)]
struct AutoStartLock {
    path: PathBuf,
    body: String,
}

impl Drop for AutoStartLock {
    fn drop(&mut self) {
        let _ = remove_autostart_lock_if_unchanged(&self.path, &self.body);
    }
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
}

fn autostart_state_dir() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR")
        && !runtime_dir.trim().is_empty()
    {
        return PathBuf::from(runtime_dir).join("rch");
    }
    PathBuf::from("/tmp").join("rch")
}

fn autostart_lock_path() -> PathBuf {
    autostart_state_dir().join("hook_autostart.lock")
}

fn autostart_cooldown_path() -> PathBuf {
    autostart_state_dir().join("hook_autostart.cooldown")
}

fn read_cooldown_timestamp(path: &Path) -> Option<SystemTime> {
    let contents = std::fs::read_to_string(path).ok()?;
    let secs: u64 = contents.trim().parse().ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

fn write_cooldown_timestamp(path: &Path) -> Result<(), AutoStartError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(AutoStartError::Io)?;
    }
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    std::fs::write(path, format!("{now_secs}")).map_err(AutoStartError::Io)
}

/// Maximum age (in seconds) of a lockfile before it's eligible for
/// stale takeover regardless of the recorded PID. Belt-and-suspenders
/// against PID reuse: even if the recorded PID happens to be alive
/// (a different process that reused the ID after the original was
/// killed), a >60s-old lockfile is treated as stale.
const AUTOSTART_LOCK_STALE_TTL_SECS: u64 = 60;

/// Render the lockfile body. Format: newline-separated
/// `pid\nunix_secs\nhostname\nnonce\n`. Hand-rolled to avoid bringing in a
/// serializer for a small file the OS owns.
fn render_autostart_lock_body() -> String {
    let pid = std::process::id();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    let now_secs = now.as_secs();
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let sequence = AUTOSTART_LOCK_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nonce = now.as_nanos();
    format!("{pid}\n{now_secs}\n{hostname}\n{nonce:x}-{sequence:x}\n")
}

/// Parsed contents of an autostart lockfile.
#[derive(Debug)]
struct ParsedLock {
    pid: u32,
    created_at_secs: u64,
    hostname: String,
}

fn parse_autostart_lock_body(s: &str) -> Option<ParsedLock> {
    let mut lines = s.lines();
    let pid: u32 = lines.next()?.trim().parse().ok()?;
    let created_at_secs: u64 = lines.next()?.trim().parse().ok()?;
    let hostname = lines.next()?.trim().to_string();
    if hostname.is_empty() {
        return None;
    }
    Some(ParsedLock {
        pid,
        created_at_secs,
        hostname,
    })
}

fn remove_autostart_lock_if_unchanged(path: &Path, expected_body: &str) -> bool {
    match std::fs::read_to_string(path) {
        Ok(current_body) if current_body == expected_body => match std::fs::remove_file(path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        },
        _ => false,
    }
}

/// Check whether a PID is alive. On Unix: send signal 0 (no-op) — if
/// it succeeds the process exists; ESRCH means it's gone; EPERM also
/// means it's alive (we just can't signal it). On non-Unix platforms:
/// conservative `true` since we can't check cheaply — combined with
/// the TTL fallback, a wedged lockfile still recovers within 60s.
fn pid_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // /proc/<pid> probe — cheap and unambiguous on Linux. We do
        // NOT use kill(0) because rch is #![forbid(unsafe_code)] and
        // the kill(2) wrapper would require nix/libc raw syscalls.
        let proc_path = std::path::PathBuf::from(format!("/proc/{pid}"));
        if proc_path.exists() {
            return true;
        }
        // On non-Linux Unix (macOS, BSD), /proc may not exist. We can't
        // easily check liveness without unsafe; rely on TTL fallback.
        // To distinguish "no /proc" from "PID is dead" we check whether
        // /proc itself exists.
        if !std::path::Path::new("/proc").exists() {
            // No /proc on this platform — be conservative and assume alive.
            return true;
        }
        // /proc exists but /proc/<pid> doesn't — PID is definitively gone.
        false
    }
    #[cfg(not(unix))]
    {
        // Conservative on non-Unix; TTL handles the stale case.
        let _ = pid;
        true
    }
}

/// Decide whether an existing lockfile is stale and may be replaced.
/// A lockfile is stale when:
///   * its PID is not alive (process exited / SIGKILLed / power-cycled), OR
///   * its body is unparseable (corruption), OR
///   * its hostname matches this host AND it's older than the TTL (PID-reuse defense).
///
/// Lockfiles from a DIFFERENT host (NFS shared lock scenario) are NEVER
/// considered stale here — only the holder's own host can prove liveness.
fn autostart_lock_is_stale(parsed: &ParsedLock) -> bool {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    let age = now_secs.saturating_sub(parsed.created_at_secs);

    let our_hostname = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    if parsed.hostname != our_hostname {
        // Different host — don't touch the lock; trust the holder.
        // The cooldown mechanism upstream still prevents storm-spawning.
        return false;
    }

    if !pid_is_alive(parsed.pid) {
        return true;
    }

    // PID is alive, same host: TTL fallback for PID-reuse case.
    age > AUTOSTART_LOCK_STALE_TTL_SECS
}

fn acquire_autostart_lock(path: &Path) -> Result<AutoStartLock, AutoStartError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(AutoStartError::Io)?;
    }
    // Atomic create_new — winner of the race; loser falls into the
    // stale-detection branch below.
    let body = render_autostart_lock_body();
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut f) => {
            // Write the lockfile body so subsequent contenders can decide
            // whether to wait or take over. We deliberately don't fail the
            // acquire if the write itself fails — the lockfile-exists
            // mutual-exclusion is the load-bearing invariant; the body is
            // diagnostic + stale-detection metadata.
            let _ = std::io::Write::write_all(&mut f, body.as_bytes());
            let _ = f.sync_all();
            tracing::info!(
                target: "rch::hook::autostart_lock",
                path = %path.display(),
                pid = %std::process::id(),
                "doctor.autostart_lock.acquired",
            );
            Ok(AutoStartLock {
                path: path.to_path_buf(),
                body,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Stale-detection branch: read the existing body, decide
            // whether the holder is gone, and take over if so.
            match std::fs::read_to_string(path) {
                Ok(existing) => {
                    let parsed = parse_autostart_lock_body(&existing);
                    let stale = match &parsed {
                        Some(p) => autostart_lock_is_stale(p),
                        None => {
                            // Unparseable / corrupted body — treat as stale.
                            tracing::warn!(
                                target: "rch::hook::autostart_lock",
                                path = %path.display(),
                                bytes = existing.len(),
                                "doctor.autostart_lock.body_corrupt_treated_as_stale",
                            );
                            true
                        }
                    };
                    if stale {
                        if !remove_autostart_lock_if_unchanged(path, &existing) {
                            return Err(AutoStartError::LockHeld);
                        }
                        match OpenOptions::new().write(true).create_new(true).open(path) {
                            Ok(mut f) => {
                                let _ = std::io::Write::write_all(&mut f, body.as_bytes());
                                let _ = f.sync_all();
                                tracing::warn!(
                                    target: "rch::hook::autostart_lock",
                                    path = %path.display(),
                                    holder_pid = ?parsed.as_ref().map(|p| p.pid),
                                    holder_host = ?parsed.as_ref().map(|p| p.hostname.clone()),
                                    holder_age_secs = ?parsed.as_ref().map(|p| {
                                        SystemTime::now()
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or(Duration::from_secs(0))
                                            .as_secs()
                                            .saturating_sub(p.created_at_secs)
                                    }),
                                    "doctor.autostart_lock.stale_replaced",
                                );
                                Ok(AutoStartLock {
                                    path: path.to_path_buf(),
                                    body,
                                })
                            }
                            // Lost the race to recreate — another contender won.
                            Err(_) => Err(AutoStartError::LockHeld),
                        }
                    } else {
                        Err(AutoStartError::LockHeld)
                    }
                }
                // Couldn't even read the file — treat as held to be safe.
                Err(_) => Err(AutoStartError::LockHeld),
            }
        }
        Err(e) => Err(AutoStartError::Io(e)),
    }
}

fn which_rchd_path() -> Option<PathBuf> {
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(dir) = exe_path.parent()
    {
        let candidate = dir.join("rchd");
        if candidate.exists() {
            return Some(candidate);
        }
    }

    which("rchd").ok()
}

fn spawn_rchd(path: &Path) -> Result<(), AutoStartError> {
    let mut cmd = std::process::Command::new("nohup");
    cmd.arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    let mut child = cmd.spawn().map_err(AutoStartError::SpawnFailed)?;
    std::thread::sleep(std::time::Duration::from_millis(100));
    if let Some(status) = child.try_wait().map_err(AutoStartError::SpawnFailed)? {
        return if status.success() {
            Ok(())
        } else {
            Err(AutoStartError::WrapperFailed(status))
        };
    }

    // `nohup` does not daemonize by itself; it execs/wraps rchd as our
    // direct child. Keep a detached waiter while rch remains alive so a
    // later daemon exit is reaped instead of becoming a zombie.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

async fn probe_daemon_health(socket_path: &Path) -> bool {
    let connect = timeout(Duration::from_millis(300), UnixStream::connect(socket_path)).await;
    let stream = match connect {
        Ok(Ok(stream)) => stream,
        _ => return false,
    };

    let (reader, mut writer) = stream.into_split();
    if writer.write_all(b"GET /health\n").await.is_err() {
        return false;
    }
    let _ = writer.flush().await;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut body = String::new();
    let mut in_body = false;

    loop {
        line.clear();
        let read = match timeout(Duration::from_millis(300), reader.read_line(&mut line)).await {
            Ok(Ok(n)) => n,
            _ => return false,
        };
        if read == 0 {
            break;
        }
        if in_body {
            body.push_str(&line);
        } else if line.trim().is_empty() {
            in_body = true;
        }
    }

    let response: HealthResponse = match serde_json::from_str(body.trim()) {
        Ok(resp) => resp,
        Err(_) => return false,
    };

    response.status == "healthy"
}

async fn socket_is_confirmed_stale(socket_path: &Path) -> bool {
    match timeout(Duration::from_millis(300), UnixStream::connect(socket_path)).await {
        Ok(Ok(_stream)) => false,
        Ok(Err(error)) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
        ),
        Err(_) => false,
    }
}

async fn wait_for_socket(socket_path: &Path, timeout_secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if socket_path.exists() && probe_daemon_health(socket_path).await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn try_auto_start_daemon(
    config: &SelfHealingConfig,
    socket_path: &Path,
) -> Result<(), AutoStartError> {
    if !config.hook_starts_daemon {
        return Err(AutoStartError::Disabled);
    }

    info!(
        target: "rch::hook::autostart",
        "Daemon unavailable, attempting auto-start"
    );

    // Acquire the autostart lock BEFORE doing anything destructive
    // (stale-socket removal). Two concurrent hooks racing on the same
    // socket could otherwise both observe a transiently-unresponsive
    // daemon and the second hook deletes the socket the first hook
    // just verified — corrupting an in-flight connection.
    //
    // Order is now:
    //   1. Acquire autostart lock (only one hook auto-starts at a time).
    //   2. Re-probe socket: while waiting for the lock, the prior
    //      lock-holder may have already started the daemon.
    //   3. Only delete the socket if it's confirmed stale UNDER the lock.
    let _lock = acquire_autostart_lock(&autostart_lock_path())?;

    // Re-probe under the lock — another hook may have spawned rchd
    // while we were waiting.
    if socket_path.exists() && probe_daemon_health(socket_path).await {
        debug!(
            target: "rch::hook::autostart",
            "Socket became responsive while waiting for autostart lock"
        );
        return Ok(());
    }

    if socket_path.exists() {
        warn!(
            target: "rch::hook::autostart",
            "Socket exists but daemon not responding (after lock-protected re-probe)"
        );
        if !socket_is_confirmed_stale(socket_path).await {
            warn!(
                target: "rch::hook::autostart",
                "Socket still accepts connections or could not be proven stale; refusing to replace a possible live daemon"
            );
            return Err(AutoStartError::UnhealthySocket);
        }
        if let Err(err) = std::fs::remove_file(socket_path) {
            warn!(
                target: "rch::hook::autostart",
                "Failed to remove stale socket: {}",
                err
            );
            return Err(AutoStartError::StaleSocket);
        }
    }

    let cooldown_path = autostart_cooldown_path();
    if let Some(last_attempt) = read_cooldown_timestamp(&cooldown_path) {
        let elapsed = last_attempt
            .elapsed()
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        if elapsed < config.auto_start_cooldown_secs {
            return Err(AutoStartError::CooldownActive(
                elapsed,
                config.auto_start_cooldown_secs,
            ));
        }
    }

    // Note: the autostart lock acquired earlier is still held here.
    // It's released when this function returns (Drop).
    write_cooldown_timestamp(&cooldown_path)?;

    let rchd_path = which_rchd_path().ok_or(AutoStartError::BinaryNotFound)?;
    info!(
        target: "rch::hook::autostart",
        "Spawning rchd at {}",
        rchd_path.display()
    );
    spawn_rchd(&rchd_path)?;

    let timeout_secs = config.auto_start_timeout_secs;
    if !wait_for_socket(socket_path, timeout_secs).await {
        return Err(AutoStartError::Timeout(timeout_secs));
    }

    info!(
        target: "rch::hook::autostart",
        "Auto-start successful, socket is responsive"
    );
    Ok(())
}

fn tokenize_command(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for c in command.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if c == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if c.is_whitespace() && !in_single && !in_double {
            if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
            continue;
        }
        current.push(c);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Detect if a cargo test command has a test name filter.
///
/// Filtered tests (e.g., `cargo test my_test`) typically run fewer tests
/// and thus require fewer slots than a full test suite.
///
/// Returns true if the command appears to filter tests by name.
fn is_filtered_test_command(command: &str) -> bool {
    let tokens = tokenize_command(command);

    // Find the position of "test" or "run" (for nextest) in the command
    let test_pos = tokens
        .iter()
        .position(|t| t == "test" || t == "t" || t == "run");
    let Some(test_idx) = test_pos else {
        return false;
    };

    // Flags that take a separate argument (not using =)
    let flags_with_args = [
        "-p",
        "--package",
        "--bin",
        "--test",
        "--bench",
        "--example",
        "--features",
        "--target",
        "--target-dir",
        "-j",
        "--jobs",
        "--color",
        "--message-format",
        "--manifest-path",
        "--profile",
        "--config",
        "-Z",
    ];

    let mut i = test_idx + 1;
    while i < tokens.len() {
        let token = &tokens[i];

        // Stop at the separator
        if token == "--" {
            // Check if there is a positional argument after --
            if i + 1 < tokens.len() {
                let next = &tokens[i + 1];
                if !next.starts_with('-') {
                    return true;
                }
            }
            break;
        }

        // Check if this is a flag that takes an argument
        if flags_with_args.contains(&token.as_str()) {
            i += 2;
            continue;
        }

        // Check if this is a flag=value style
        if flags_with_args
            .iter()
            .any(|&f| token.starts_with(&format!("{}=", f)))
        {
            i += 1;
            continue;
        }

        // Skip any other flag-like tokens
        if token.starts_with('-') {
            i += 1;
            continue;
        }

        // Found a non-flag token - this is a test name filter
        return true;
    }

    false
}

/// Check if the command has the --ignored flag (for running only ignored tests).
///
/// Tests marked with `#[ignore]` are typically a small subset, so they need
/// fewer slots. However, --include-ignored runs all tests plus ignored ones.
fn has_ignored_only_flag(command: &str) -> bool {
    let tokens = tokenize_command(command);

    let has_ignored = tokens.iter().any(|t| t == "--ignored");
    let has_include_ignored = tokens.iter().any(|t| t == "--include-ignored");

    has_ignored && !has_include_ignored
}

/// Check if the command has the --exact flag for exact test name matching.
///
/// Exact matching typically results in running a single test.
fn has_exact_flag(command: &str) -> bool {
    tokenize_command(command).iter().any(|t| t == "--exact")
}

// ============================================================================
// Timing History (bd-2m7j Phase 2)
// ============================================================================

use std::collections::HashMap;

// Timing infrastructure: feeds the global `TIMING_CACHE` (live; populated
// by `record_build_timing` after every offloaded build). The estimator
// surface that consumes the cache (`estimate_timing_for_build`,
// `TimingEstimate`) is currently exercised only by unit tests — those
// items keep `#[allow(dead_code)]` until production callers materialize.
//
// `MAX_TIMING_SAMPLES` bounds the per-project sample list (used at line
// 1441). `MAX_TIMING_PROJECTS` bounds the project-keyed map for
// LRU-eviction (used at line 1618).
const MAX_TIMING_SAMPLES: usize = 20;

const MAX_TIMING_PROJECTS: usize = 500;

/// A single timing record for a completed build.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimingRecord {
    /// Timestamp when the build completed (Unix seconds).
    pub timestamp: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Whether this was a remote build (true) or local (false).
    pub remote: bool,
}

/// Timing data for a specific project+kind combination.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ProjectTimingData {
    /// Recent local build durations (ring buffer).
    pub local_samples: Vec<TimingRecord>,
    /// Recent remote build durations (ring buffer).
    pub remote_samples: Vec<TimingRecord>,
}

#[allow(dead_code)]
impl ProjectTimingData {
    /// Add a timing sample, maintaining ring buffer size.
    fn add_sample(&mut self, duration_ms: u64, remote: bool) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let record = TimingRecord {
            timestamp,
            duration_ms,
            remote,
        };

        let samples = if remote {
            &mut self.remote_samples
        } else {
            &mut self.local_samples
        };

        samples.push(record);
        if samples.len() > MAX_TIMING_SAMPLES {
            samples.remove(0);
        }
    }

    /// Calculate median duration from samples.
    fn median_duration(&self, remote: bool) -> Option<u64> {
        let samples = if remote {
            &self.remote_samples
        } else {
            &self.local_samples
        };

        if samples.is_empty() {
            return None;
        }

        let mut durations: Vec<u64> = samples.iter().map(|r| r.duration_ms).collect();
        durations.sort_unstable();
        let mid = durations.len() / 2;
        Some(if durations.len().is_multiple_of(2) {
            (durations[mid - 1] + durations[mid]) / 2
        } else {
            durations[mid]
        })
    }

    /// Calculate speedup ratio (local_time / remote_time).
    fn speedup_ratio(&self) -> Option<f64> {
        let local_median = self.median_duration(false)?;
        let remote_median = self.median_duration(true)?;
        if remote_median == 0 {
            return None;
        }
        Some(local_median as f64 / remote_median as f64)
    }

    /// Get the most recent timestamp from any sample (used for LRU eviction).
    fn most_recent_timestamp(&self) -> u64 {
        let local_max = self
            .local_samples
            .iter()
            .map(|r| r.timestamp)
            .max()
            .unwrap_or(0);
        let remote_max = self
            .remote_samples
            .iter()
            .map(|r| r.timestamp)
            .max()
            .unwrap_or(0);
        local_max.max(remote_max)
    }
}

/// Full timing history, keyed by project+kind.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TimingHistory {
    /// Map from "project_id:kind" to timing data.
    #[serde(default)]
    pub entries: HashMap<String, ProjectTimingData>,
}

/// Process-global in-memory cache for `TimingHistory`.
///
/// **Lifetime:** the hook is a fresh process per invocation, so the cache
/// is rebuilt at the start of every hook call. Within a single hook call
/// (or within `rchd` / a long-running `rch exec` session), `record_build_timing`
/// can fire multiple times across `tokio::task::spawn_blocking` blocks; the
/// `OnceLock` coalesces disk I/O for that batch — first call pays the
/// `load_from_disk` cost; subsequent calls in the same process operate on
/// the in-memory copy and write through to disk on update.
///
/// Consumers (live as of t19 close): two `record_build_timing` call sites
/// in `run_classification_remote_path`. The estimator surface
/// (`estimate_timing_for_build`, `TimingEstimate`) is currently exercised
/// only by unit tests; those keep their `#[allow(dead_code)]` annotation
/// until a production consumer wires them up.
static TIMING_CACHE: std::sync::OnceLock<std::sync::RwLock<TimingHistory>> =
    std::sync::OnceLock::new();

/// Get or initialize the global `TimingHistory` cache.
///
/// First call loads from disk (blocking); subsequent calls in the same
/// process return the cached copy.
fn timing_cache() -> &'static std::sync::RwLock<TimingHistory> {
    TIMING_CACHE.get_or_init(|| std::sync::RwLock::new(TimingHistory::load_from_disk()))
}

impl TimingHistory {
    /// Load timing history from disk. Returns empty history on error.
    fn load_from_disk() -> Self {
        let Some(path) = timing_history_path() else {
            return Self::default();
        };

        match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save timing history to disk. Logs warnings on error but does not propagate.
    fn save_to_disk(&self) {
        let Some(path) = timing_history_path() else {
            return;
        };

        // Ensure parent directory exists
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            warn!(
                "Failed to create timing history directory {}: {}",
                parent.display(),
                e
            );
            return;
        }

        // Write atomically using temp file
        let temp_path = path.with_extension("tmp");
        let content = match serde_json::to_string_pretty(self) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to serialize timing history: {}", e);
                return;
            }
        };
        if let Err(e) = std::fs::write(&temp_path, &content) {
            warn!(
                "Failed to write timing history to {}: {}",
                temp_path.display(),
                e
            );
            return;
        }
        if let Err(e) = std::fs::rename(&temp_path, &path) {
            warn!(
                "Failed to rename timing history {} -> {}: {}",
                temp_path.display(),
                path.display(),
                e
            );
        }
    }

    /// Get the key for a project+kind combination.
    fn key(project: &str, kind: Option<CompilationKind>) -> String {
        let kind_str = kind
            .map(|k| format!("{:?}", k))
            .unwrap_or_else(|| "Unknown".to_string());
        format!("{}:{}", project, kind_str)
    }

    /// Get timing data for a project+kind.
    fn get(&self, project: &str, kind: Option<CompilationKind>) -> Option<&ProjectTimingData> {
        self.entries.get(&Self::key(project, kind))
    }

    /// Record a timing sample.
    ///
    /// Implements LRU eviction to prevent unbounded memory growth:
    /// if entries exceed MAX_TIMING_PROJECTS, evicts the least recently used entry.
    fn record(
        &mut self,
        project: &str,
        kind: Option<CompilationKind>,
        duration_ms: u64,
        remote: bool,
    ) {
        let key = Self::key(project, kind);
        let data = self.entries.entry(key).or_default();
        data.add_sample(duration_ms, remote);

        // LRU eviction: if over limit, remove the entry with oldest timestamp
        if self.entries.len() > MAX_TIMING_PROJECTS {
            // Find the key with the oldest most_recent_timestamp
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, data)| data.most_recent_timestamp())
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }
    }
}

/// Get the path to the timing history file.
fn timing_history_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|dir| dir.join("rch").join("timing_history.json"))
}

/// Record a build timing to the history store.
///
/// Updates the in-memory cache immediately, then persists to disk.
/// Called after a build completes to update the timing history.
/// This is used by `estimate_timing_for_build` for future predictions.
///
/// **Lock-scope discipline (t18):** we acquire the write guard, mutate
/// the in-memory state, CLONE a snapshot, drop the guard, THEN write
/// to disk. The original implementation held the write guard across
/// `save_to_disk()` which serialized every other reader/writer on a
/// disk-I/O (~50ms on slow disks) — fine when nothing else needed the
/// cache, catastrophic under any concurrent access. The clone cost is
/// bounded by `MAX_TIMING_PROJECTS` (500) × `MAX_TIMING_SAMPLES` (20)
/// = at most ~10K small structs; ~µs vs the lock contention's ms.
pub fn record_build_timing(
    project: &str,
    kind: Option<CompilationKind>,
    duration_ms: u64,
    remote: bool,
) {
    let cache = timing_cache();
    // Step 1: mutate in-memory state under the write guard. Snapshot
    // for disk persistence. Then drop the guard before any I/O.
    let snapshot = {
        let mut history = match cache.write() {
            Ok(g) => g,
            Err(poison) => {
                // Poisoned RwLock — another caller panicked while
                // holding the write guard. Recover the value and
                // continue; failing here would deny the build a
                // timing record but isn't worth blocking the user.
                tracing::warn!(
                    target: "rch::hook::timing",
                    "timing cache RwLock poisoned; recovering"
                );
                poison.into_inner()
            }
        };
        history.record(project, kind, duration_ms, remote);
        history.clone()
        // guard dropped here
    };
    // Step 2: persist to disk WITHOUT holding the lock. Other readers
    // and writers can proceed in parallel with the fsync.
    snapshot.save_to_disk();
}

/// Timing estimate for offload gating decisions.
///
/// Used to determine whether a build is worth offloading based on
/// predicted local execution time and expected speedup.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct TimingEstimate {
    /// Predicted local build time in milliseconds.
    pub predicted_local_ms: u64,
    /// Predicted speedup ratio (local_time / remote_time), if available.
    /// None indicates insufficient data to estimate speedup.
    pub predicted_speedup: Option<f64>,
}

/// Estimate timing for a build to support offload gating.
///
/// This function attempts to estimate how long a build would take locally
/// and what speedup we might achieve by offloading. The estimation uses
/// this fallback order:
/// 1. Historical timing data for this project/kind
/// 2. Conservative defaults (allow offload)
///
/// When no historical data is available, returns None to trigger fail-open
/// behavior (allow offload attempt).
#[allow(dead_code)]
#[allow(unused_variables)] // config used for future speedscore integration
fn estimate_timing_for_build(
    project: &str,
    kind: Option<CompilationKind>,
    config: &rch_common::RchConfig,
) -> Option<TimingEstimate> {
    // Read from in-memory cache (zero disk I/O after first load)
    let cache = timing_cache();
    let history = cache.read().ok()?;

    // Look up timing data for this project+kind
    let data = history.get(project, kind)?;

    // Need at least local samples to estimate
    let local_median = data.median_duration(false)?;

    // Speedup is optional (requires both local and remote history)
    let speedup = data.speedup_ratio();

    Some(TimingEstimate {
        predicted_local_ms: local_median,
        predicted_speedup: speedup,
    })
}

pub(crate) fn estimate_cores_for_command(
    kind: Option<CompilationKind>,
    command: &str,
    config: &rch_common::CompilationConfig,
) -> u32 {
    let build_default = config.build_slots.max(1);
    let test_default = config.test_slots.max(1);
    let check_default = config.check_slots.max(1);

    // Slot reduction for filtered tests (fewer tests = fewer slots needed)
    let filtered_test_slots = (test_default / 2).max(2).min(test_default);

    match kind {
        Some(CompilationKind::CargoTest | CompilationKind::CargoNextest) => {
            // Priority order for test slot estimation:
            // 1. Explicit cargo -j/--jobs or CARGO_BUILD_JOBS
            // 2. Explicit --test-threads flag
            // 3. RUST_TEST_THREADS environment variable (inline or ambient)
            // 4. Inferred from test filtering (reduced slots)
            // 5. Default test_slots from config
            if let Some(jobs) = cargo_job_count_for_command(command) {
                return jobs.max(1);
            }
            if let Some(threads) = parse_test_threads(command) {
                return threads.max(1);
            }
            if let Some(threads) = parse_env_u32(command, "RUST_TEST_THREADS")
                .or_else(|| read_env_u32("RUST_TEST_THREADS"))
            {
                return threads.max(1);
            }

            // Reduce slots for filtered tests:
            // - Specific test name filter (cargo test my_test)
            // - --exact flag (single test match)
            // - --ignored only (typically few ignored tests)
            if is_filtered_test_command(command) || has_exact_flag(command) {
                return filtered_test_slots;
            }
            if has_ignored_only_flag(command) {
                return filtered_test_slots;
            }

            test_default.max(1)
        }
        Some(CompilationKind::BunTest) => {
            if let Some(threads) = parse_test_threads(command) {
                return threads.max(1);
            }
            if let Some(threads) = parse_env_u32(command, "RUST_TEST_THREADS")
                .or_else(|| read_env_u32("RUST_TEST_THREADS"))
            {
                return threads.max(1);
            }

            if is_filtered_test_command(command) || has_exact_flag(command) {
                return filtered_test_slots;
            }
            if has_ignored_only_flag(command) {
                return filtered_test_slots;
            }

            test_default.max(1)
        }
        Some(
            CompilationKind::CargoCheck
            | CompilationKind::CargoClippy
            | CompilationKind::BunTypecheck,
        ) => cargo_job_count_for_command(command)
            .unwrap_or(check_default)
            .max(1),
        Some(_) => cargo_job_count_for_command(command)
            .unwrap_or(build_default)
            .max(1),
        None => build_default,
    }
}

fn is_test_kind(kind: Option<CompilationKind>) -> bool {
    matches!(
        kind,
        Some(CompilationKind::CargoTest | CompilationKind::CargoNextest | CompilationKind::BunTest)
    )
}

#[allow(dead_code)]
fn emit_first_run_message(worker: &SelectedWorker, remote_ms: u64, local_ms: Option<u64>) {
    let divider = "----------------------------------------";
    let remote = format_duration_ms(Duration::from_millis(remote_ms));

    eprintln!();
    eprintln!("{}", divider);
    eprintln!("First remote build complete!");
    eprintln!();

    if let Some(local_ms) = local_ms {
        let local = format_duration_ms(Duration::from_millis(local_ms));
        eprintln!(
            "Your build ran on '{}' in {} (local estimate ~{}).",
            worker.id, remote, local
        );
    } else {
        eprintln!("Your build ran on '{}' in {}.", worker.id, remote);
    }

    eprintln!("RCH will run silently in the background from now on.");
    eprintln!();
    eprintln!("To see build activity: rch status --jobs");
    eprintln!("To disable this message: rch config set first_run_complete true");
    eprintln!("{}", divider);
    eprintln!();
}

/// Process a hook request and return the output.
async fn process_hook(input: HookInput) -> HookOutput {
    // Tier 0: Only process Bash tool
    if input.tool_name != "Bash" {
        debug!("Non-Bash tool: {}, allowing", input.tool_name);
        return HookOutput::allow();
    }

    let command = &input.tool_input.command;
    // Mask sensitive data in debug logs (API keys, tokens, passwords)
    debug!("Processing command: {}", mask_sensitive_command(command));

    // Classify the command using the 5-tier system.
    // Per AGENTS.md: non-compilation decisions must complete in <1ms, compilation in <5ms
    // The real hook path bypasses the classification cache because hook
    // invocations are one-shot even when RCH_HOOK_MODE is not set.
    let classify_start = Instant::now();
    let classification = crate::cache::classify_hook_command(command, classify_command);
    let classification_duration = classify_start.elapsed();
    let classification_duration_us = classification_duration.as_micros() as u64;

    if !classification.is_compilation {
        // Log non-compilation decision latency (budget: <1ms per AGENTS.md)
        let duration_ms = classification_duration_us as f64 / 1000.0;
        if duration_ms > 1.0 {
            warn!(
                "Non-compilation decision exceeded 1ms budget: {:.3}ms for '{}'",
                duration_ms, command
            );
        } else {
            debug!(
                "Non-compilation decision: {:.3}ms for '{}' ({})",
                duration_ms, command, classification.reason
            );
        }
        return HookOutput::allow();
    }

    let config = match load_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to load config: {}, allowing local execution", e);
            return HookOutput::allow();
        }
    };

    let reporter = HookReporter::new(config.output.visibility);

    if !config.general.enabled {
        debug!("RCH disabled via config, allowing local execution");
        return HookOutput::allow();
    }

    // Per-project overrides (bd-1vzb)
    //
    // - force_local: always allow local execution for compilation commands (skip daemon + transfer)
    // - force_remote: always attempt remote execution when safe (bypass confidence threshold)
    //
    // Conflicting flags should be caught by config validation, but handle defensively here.
    if config.general.force_local && config.general.force_remote {
        warn!(
            "Invalid config: both general.force_local and general.force_remote are set; allowing local execution"
        );
        reporter.summary("[RCH] local (invalid config: force_local+force_remote)");
        return HookOutput::allow();
    }
    if config.general.force_local {
        debug!("RCH force_local enabled, allowing local execution");
        reporter.summary("[RCH] local (force_local)");
        return HookOutput::allow();
    }

    // Log compilation decision latency (budget: <5ms per AGENTS.md)
    let duration_ms = classification_duration_us as f64 / 1000.0;
    if duration_ms > 5.0 {
        warn!(
            "Compilation decision exceeded 5ms budget: {:.3}ms",
            duration_ms
        );
    }

    info!(
        "Compilation detected: {:?} (confidence: {:.2}, classified in {:.3}ms)",
        classification.kind, classification.confidence, duration_ms
    );
    reporter.verbose(&format!(
        "[RCH] compile {:?} (confidence {:.2})",
        classification.kind, classification.confidence
    ));

    // Check confidence threshold
    let confidence_threshold = if config.general.force_remote {
        reporter.verbose("[RCH] force_remote enabled: bypassing confidence threshold");
        0.0
    } else {
        config.compilation.confidence_threshold
    };
    if classification.confidence < confidence_threshold {
        debug!(
            "Confidence {:.2} below threshold {:.2}, allowing local execution",
            classification.confidence, confidence_threshold
        );
        reporter.summary("[RCH] local (confidence below threshold)");
        return HookOutput::allow();
    }

    // Check execution allowlist (bd-785w)
    // Commands not in the allowlist fail-open to local execution
    if let Some(kind) = classification.kind {
        let command_base = kind.command_base();
        if !config.execution.is_allowed(command_base) {
            debug!(
                "Command base '{}' not in execution allowlist, allowing local execution",
                command_base
            );
            reporter.summary(&format!(
                "[RCH] local (command '{}' not in allowlist)",
                command_base
            ));
            return HookOutput::allow();
        }
    }

    // CRITICAL: Return immediately with delegated command to avoid hook timeout.
    //
    // Claude Code hooks have a tight timeout budget (~50-100ms). The full remote
    // compilation pipeline (daemon query + rsync + SSH + rsync back) takes 3+ seconds.
    // If we do that work here, the hook times out and Claude Code ignores our response.
    //
    // Solution: Return immediately with `rch exec -- <command>`. The hook completes
    // in <10ms, and the actual remote compilation happens when Claude Code executes
    // the modified command.
    //
    // For compound commands like "cd /path && cargo build", we preserve the prefix
    // and only wrap the compilation part: "cd /path && rch exec -- cargo build"
    info!(
        "Delegating compilation to rch exec (classification: {:?}, compound: {})",
        classification.kind,
        classification.command_prefix.is_some()
    );
    reporter.verbose("[RCH] delegating to rch exec...");

    let modified_command = if let (Some(prefix), Some(extracted)) = (
        &classification.command_prefix,
        &classification.extracted_command,
    ) {
        // Compound command: preserve prefix, wrap only the compilation part
        format!("{}rch exec -- {}", prefix, extracted)
    } else {
        // Simple command: wrap the entire command
        format!("rch exec -- {}", command)
    };

    HookOutput::allow_with_modified_command(modified_command)
}

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)] // Pipeline wiring favors explicit params.
async fn handle_selection_response(
    response: SelectionResponse,
    command: &str,
    config: &rch_common::RchConfig,
    reporter: &HookReporter,
    toolchain: Option<&ToolchainInfo>,
    classification_kind: Option<CompilationKind>,
    project: &str,
    estimated_cores: u32,
) -> HookOutput {
    // Check if a worker was assigned
    let Some(worker) = response.worker else {
        // No worker available - graceful fallback to local execution
        warn!(
            "⚠️ RCH: No remote workers available ({}), executing locally",
            response.reason
        );
        reporter.summary(&format!("[RCH] local ({})", response.reason));
        return HookOutput::allow();
    };

    info!(
        "Selected worker: {} at {}@{} ({} slots remaining after reservation, speed {:.1})",
        worker.id, worker.user, worker.host, worker.slots_available, worker.speed_score
    );
    reporter.verbose(&format!(
        "[RCH] selected {}@{} ({} slots remaining after reservation, speed {:.1})",
        worker.user, worker.host, worker.slots_available, worker.speed_score
    ));
    let invocation_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let command_tokens = parse_command_tokens(command, reporter);
    let forwarded_cargo_target_dir = resolve_forwarded_cargo_target_dir(
        classification_kind,
        &invocation_cwd,
        reporter,
        command_tokens.as_deref(),
    );
    let remote_command = rewrite_cargo_target_dir_command_for_remote(
        command,
        command_tokens.as_deref(),
        forwarded_cargo_target_dir.as_ref(),
        reporter,
    );

    // Execute remote compilation pipeline
    let topology_policy = config.path_topology.to_policy();
    let remote_start = Instant::now();
    let result = execute_remote_compilation(
        &worker,
        &remote_command,
        config.transfer.clone(),
        config.environment.allowlist.clone(),
        forwarded_cargo_target_dir,
        &config.compilation,
        toolchain,
        classification_kind,
        reporter,
        &config.general.socket_path,
        config.output.color_mode,
        response.build_id,
        &topology_policy,
    )
    .await;
    let remote_elapsed = remote_start.elapsed();

    // Always release slots after execution
    let release_exit_code = result
        .as_ref()
        .map(|ok| ok.exit_code)
        .unwrap_or(EXIT_BUILD_ERROR);
    // Add total elapsed time to the timing breakdown
    let release_timing = result.as_ref().ok().map(|ok| {
        let mut timing = ok.timing.clone();
        timing.total = Some(remote_elapsed);
        timing
    });
    if let Err(e) = release_worker(
        &config.general.socket_path,
        &worker.id,
        estimated_cores,
        response.build_id,
        Some(release_exit_code),
        None,
        None,
        release_timing.as_ref(),
    )
    .await
    {
        warn!("Failed to release worker slots: {}", e);
    }

    match result {
        Ok(result) => {
            if result.exit_code == 0 {
                // Command succeeded remotely - replace with no-op for transparency
                // The agent already saw output via stderr, artifacts are local
                // Using allow+modified_command makes this completely transparent to the agent
                info!("Remote compilation succeeded, replacing with no-op for transparency");
                reporter.summary(&format!(
                    "[RCH] remote {} ({})",
                    worker.id,
                    format_duration_ms(remote_elapsed)
                ));

                // Record successful build for cache affinity
                let is_test = classification_kind
                    .map(|kind| kind.is_test_command())
                    .unwrap_or(false);
                if let Err(e) =
                    record_build(&config.general.socket_path, &worker.id, project, is_test).await
                {
                    warn!("Failed to record build: {}", e);
                }

                // Record timing for future gating decisions (bd-mnhp: spawn_blocking for file I/O)
                let project_for_timing = project.to_string();
                let duration = result.duration_ms;
                tokio::task::spawn_blocking(move || {
                    record_build_timing(&project_for_timing, classification_kind, duration, true);
                });

                if !config.output.first_run_complete {
                    let local_estimate =
                        estimate_local_time_ms(result.duration_ms, worker.speed_score);
                    emit_first_run_message(&worker, result.duration_ms, local_estimate);
                    if let Err(e) = crate::config::set_first_run_complete(true) {
                        warn!("Failed to persist first_run_complete: {}", e);
                    }
                }

                // Replace original command with a no-op - agent thinks command ran locally
                HookOutput::allow_with_modified_command("true")
            } else if is_toolchain_failure(&result.stderr, result.exit_code) {
                // Toolchain failure - fall back to local execution
                warn!(
                    "Remote toolchain failure detected (exit {}), falling back to local",
                    result.exit_code
                );
                reporter.summary(&format!("[RCH] local (toolchain missing on {})", worker.id));
                HookOutput::allow()
            } else {
                // Command failed remotely - still deny to prevent re-execution
                // The agent saw the error output via stderr
                //
                // Exit code semantics:
                // - 101: Test failures (cargo test ran but tests failed)
                // - 1: Build/compilation error
                // - 128+N: Process killed by signal N
                let exit_code = result.exit_code;

                // Check for signal-killed processes (OOM, etc.)
                if let Some(signal) = is_signal_killed(exit_code) {
                    warn!(
                        "Remote command killed by signal {} ({}) on {}, replacing with exit code for transparency",
                        signal,
                        signal_name(signal),
                        worker.id
                    );
                    reporter.summary(&format!(
                        "[RCH] remote {} killed ({})",
                        worker.id,
                        signal_name(signal)
                    ));
                } else if exit_code == EXIT_TEST_FAILURES {
                    // Cargo test exit 101: tests ran but some failed
                    info!(
                        "Remote tests failed (exit 101) on {}, replacing with exit code for transparency",
                        worker.id
                    );
                    reporter.summary(&format!("[RCH] remote {} tests failed", worker.id));
                } else if exit_code == EXIT_BUILD_ERROR {
                    // Build/compilation error
                    info!(
                        "Remote build error (exit 1) on {}, replacing with exit code for transparency",
                        worker.id
                    );
                    reporter.summary(&format!("[RCH] remote {} build error", worker.id));
                } else {
                    // Other non-zero exit code
                    info!(
                        "Remote command failed (exit {}) on {}, replacing with exit code for transparency",
                        exit_code, worker.id
                    );
                    reporter.summary(&format!(
                        "[RCH] remote {} failed (exit {})",
                        worker.id, exit_code
                    ));
                }

                // Still record timing for failed builds (useful for predictions)
                // bd-mnhp: spawn_blocking for file I/O
                let project_for_timing = project.to_string();
                let duration = result.duration_ms;
                tokio::task::spawn_blocking(move || {
                    record_build_timing(&project_for_timing, classification_kind, duration, true);
                });

                // Replace with exit command to preserve the exit code transparently
                // Agent already saw the error output, now they see the correct exit code
                HookOutput::allow_with_modified_command(format!("exit {}", exit_code))
            }
        }
        Err(e) => {
            if let Some(preflight_err) = e.downcast_ref::<DependencyPreflightFailure>() {
                info!(
                    "Dependency preflight blocked remote execution [{}], falling back to local",
                    preflight_err.reason_code
                );
                reporter.summary(&format!(
                    "[RCH] local (dependency preflight {}: {})",
                    preflight_err.reason_code, preflight_err.remediation
                ));
                reporter.verbose(&format!(
                    "[RCH] dependency preflight report: {}",
                    preflight_err.report_json()
                ));
                return HookOutput::allow();
            }

            // Check if this is a transfer skip (not a failure, just too large/slow)
            if let Some(skip_err) = e.downcast_ref::<TransferError>()
                && let TransferError::TransferSkipped { reason } = skip_err
            {
                info!(
                    "Transfer skipped ({}), falling back to local execution",
                    reason
                );
                reporter.summary(&format!("[RCH] local ({})", reason));
                return HookOutput::allow();
            }

            if classify_remote_pipeline_failure(&e)
                == RemotePipelineFailurePolicy::FailClosedNoLocalFallback
            {
                warn!(
                    "Remote execution pipeline failed on {} with SSH timeout; refusing local fallback: {}",
                    worker.id, e
                );
                reporter.summary(&remote_pipeline_failure_summary(&worker.id));
                return HookOutput::allow_with_modified_command(format!(
                    "exit {}",
                    EXIT_BUILD_ERROR
                ));
            }

            // Pipeline failed - fall back to local execution
            warn!(
                "Remote execution pipeline failed: {}, falling back to local",
                e
            );
            reporter.summary("[RCH] local (remote pipeline failed)");
            HookOutput::allow()
        }
    }
}

/// Query the daemon for a worker.
#[allow(clippy::too_many_arguments)] // Command routing query wires many independent fields.
pub(crate) async fn query_daemon(
    socket_path: &str,
    project: &str,
    cores: u32,
    command: &str,
    toolchain: Option<&ToolchainInfo>,
    required_runtime: RequiredRuntime,
    command_priority: CommandPriority,
    classification_duration_us: u64,
    hook_pid: Option<u32>,
    wait_for_worker: bool,
    preferred_workers: &[WorkerId],
) -> anyhow::Result<SelectionResponse> {
    // Mock support: RCH_MOCK_CIRCUIT_OPEN simulates all circuits open
    // This needs to be checked in the hook since the daemon may be started
    // before this environment variable is set for the test scenario.
    if std::env::var("RCH_MOCK_CIRCUIT_OPEN").is_ok() {
        debug!("RCH_MOCK_CIRCUIT_OPEN set, returning AllCircuitsOpen");
        return Ok(SelectionResponse {
            worker: None,
            reason: SelectionReason::AllCircuitsOpen,
            build_id: None,
            diagnostics: None,
        });
    }

    // Check if socket exists
    if !Path::new(socket_path).exists() {
        return Err(DaemonError::SocketNotFound {
            socket_path: socket_path.to_string(),
        }
        .into());
    }

    // Connect to daemon (with timeout to avoid hanging if socket is stuck)
    let stream = timeout(Duration::from_secs(5), UnixStream::connect(socket_path))
        .await
        .map_err(|_| anyhow::anyhow!("Daemon connect timed out after 5s"))??;
    let (reader, mut writer) = stream.into_split();

    // Build query string
    let mut query = format!("project={}&cores={}", urlencoding_encode(project), cores);
    query.push_str(&format!("&command={}", urlencoding_encode(command)));

    if let Some(tc) = toolchain
        && let Ok(json) = serde_json::to_string(tc)
    {
        query.push_str(&format!("&toolchain={}", urlencoding_encode(&json)));
    }

    if required_runtime != RequiredRuntime::None {
        // Serialize to lowercase string (rust, bun, node)
        // Since it's an enum with lowercase serialization, serde_json::to_string gives "rust" (with quotes)
        // We want just the string.
        let json = serde_json::to_string(&required_runtime).unwrap_or_default();
        let raw = json.trim_matches('"');
        query.push_str(&format!("&runtime={}", urlencoding_encode(raw)));
    }

    query.push_str(&format!(
        "&priority={}",
        urlencoding_encode(&command_priority.to_string())
    ));

    // Add classification duration for AGENTS.md compliance tracking
    query.push_str(&format!(
        "&classification_us={}",
        classification_duration_us
    ));

    if let Some(pid) = hook_pid {
        query.push_str(&format!("&hook_pid={}", pid));
    }

    for worker in preferred_workers {
        query.push_str(&format!("&worker={}", urlencoding_encode(worker.as_str())));
    }
    if !preferred_workers.is_empty() {
        let legacy_preferred_workers = preferred_workers
            .iter()
            .map(|worker| worker.as_str())
            .collect::<Vec<_>>()
            .join(",");
        query.push_str(&format!(
            "&preferred_workers={}",
            urlencoding_encode(&legacy_preferred_workers)
        ));
    }

    // When all workers are at capacity, queue the build on the daemon instead of
    // falling back to a local compilation storm. Disable with RCH_QUEUE_WHEN_BUSY=0.
    if wait_for_worker {
        query.push_str("&wait=1");
        // Keep daemon queue timeout aligned with the client-side socket timeout
        // so queued requests return a structured SelectionReason instead of
        // triggering a client communication timeout.
        let wait_timeout_secs = daemon_response_timeout(wait_for_worker)
            .as_secs()
            .saturating_sub(1)
            .max(1);
        query.push_str(&format!("&wait_timeout_secs={}", wait_timeout_secs));
    }

    // Send request
    let request = format!("GET /select-worker?{}\n", query);
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read response (skip HTTP headers) with timeout and body size limit.
    // Body is capped at 64KB to prevent unbounded memory growth.
    const MAX_RESPONSE_BODY: usize = 64 * 1024;
    let response_timeout = daemon_response_timeout(wait_for_worker);

    let read_response = async {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let mut body = String::new();
        let mut in_body = false;

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break;
            }
            if in_body {
                if body.len() + line.len() > MAX_RESPONSE_BODY {
                    return Err(anyhow::anyhow!(
                        "Daemon response body exceeded {}KB limit",
                        MAX_RESPONSE_BODY / 1024
                    ));
                }
                body.push_str(&line);
            } else if line.trim().is_empty() {
                in_body = true;
            }
        }

        parse_selection_response(body.trim())
            .map_err(|e| anyhow::anyhow!("Failed to parse daemon response: {}", e))
    };

    let response = timeout(response_timeout, read_response)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Daemon response timed out after {}s",
                response_timeout.as_secs()
            )
        })??;

    Ok(response)
}

/// Release reserved slots on a worker.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn release_worker(
    socket_path: &str,
    worker_id: &WorkerId,
    slots: u32,
    build_id: Option<u64>,
    exit_code: Option<i32>,
    duration_ms: Option<u64>,
    bytes_transferred: Option<u64>,
    timing: Option<&CommandTimingBreakdown>,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(()); // Ignore if daemon gone
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — daemon likely busy, don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    // Send request
    let mut request = format!(
        "POST /release-worker?worker={}&slots={}",
        urlencoding_encode(worker_id.as_str()),
        slots
    );
    if let Some(build_id) = build_id {
        request.push_str(&format!("&build_id={}", build_id));
    }
    if let Some(exit_code) = exit_code {
        request.push_str(&format!("&exit_code={}", exit_code));
    }
    if let Some(duration_ms) = duration_ms {
        request.push_str(&format!("&duration_ms={}", duration_ms));
    }
    if let Some(bytes_transferred) = bytes_transferred {
        request.push_str(&format!("&bytes_transferred={}", bytes_transferred));
    }
    request.push('\n');

    // Add timing breakdown as JSON body if present
    if let Some(timing) = timing
        && let Ok(json) = serde_json::to_string(timing)
    {
        request.push_str(&json);
        request.push('\n');
    }

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read response line (to ensure daemon processed it) with timeout
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

/// Record a successful build on a worker (for cache affinity).
pub(crate) async fn record_build(
    socket_path: &str,
    worker_id: &WorkerId,
    project: &str,
    is_test: bool,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(()); // Ignore if daemon gone
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — daemon likely busy, don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    // Send request
    let mut request = format!(
        "POST /record-build?worker={}&project={}",
        urlencoding_encode(worker_id.as_str()),
        urlencoding_encode(project)
    );
    if is_test {
        request.push_str("&is_test=1");
    }
    request.push('\n');
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read response line with timeout
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

/// URL percent-encoding for query parameters.
///
/// Encodes characters that are not URL-safe (RFC 3986 unreserved characters).
/// Optimized to avoid allocations by using direct hex conversion.
fn urlencoding_encode(s: &str) -> String {
    // Hex digits lookup table for zero-allocation encoding
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

    let mut result = String::with_capacity(s.len() * 3); // Worst case: all encoded

    for byte in s.as_bytes() {
        match *byte {
            // Unreserved characters (RFC 3986) - don't encode
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*byte as char);
            }
            // Everything else needs encoding
            _ => {
                result.push('%');
                result.push(HEX_DIGITS[(byte >> 4) as usize] as char);
                result.push(HEX_DIGITS[(byte & 0x0F) as usize] as char);
            }
        }
    }

    result
}

const DEFAULT_DAEMON_RESPONSE_TIMEOUT_SECS: u64 = 30;
const DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS: u64 = 330;

fn queue_when_busy_enabled_from(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let value = value.trim().to_lowercase();
    !matches!(value.as_str(), "0" | "false" | "no" | "off")
}

fn queue_when_busy_enabled() -> bool {
    let value = std::env::var("RCH_QUEUE_WHEN_BUSY").ok();
    queue_when_busy_enabled_from(value.as_deref())
}

fn parse_timeout_secs(raw: &str) -> Option<u64> {
    raw.trim().parse::<u64>().ok().filter(|secs| *secs > 0)
}

fn daemon_response_timeout_for(
    wait_for_worker: bool,
    global_override: Option<&str>,
    wait_override: Option<&str>,
) -> Duration {
    if let Some(secs) = global_override.and_then(parse_timeout_secs) {
        return Duration::from_secs(secs);
    }

    if wait_for_worker {
        let secs = wait_override
            .and_then(parse_timeout_secs)
            .unwrap_or(DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS);
        return Duration::from_secs(secs);
    }

    Duration::from_secs(DEFAULT_DAEMON_RESPONSE_TIMEOUT_SECS)
}

fn daemon_response_timeout(wait_for_worker: bool) -> Duration {
    let global_override = std::env::var("RCH_DAEMON_RESPONSE_TIMEOUT_SECS").ok();
    let wait_override = std::env::var("RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS").ok();
    daemon_response_timeout_for(
        wait_for_worker,
        global_override.as_deref(),
        wait_override.as_deref(),
    )
}

/// Extract project name from current working directory using the default
/// path topology policy.
///
/// Prefer [`extract_project_name_with_policy`] when a configured
/// [`PathTopologyPolicy`] is available, so error messages reference the
/// configured roots rather than the compiled-in defaults. This shim is
/// retained for test coverage and for callers that provably operate under
/// the default topology.
#[allow(dead_code)]
pub(crate) fn extract_project_name() -> String {
    extract_project_name_with_policy(&PathTopologyPolicy::default())
}

/// Extract project name from current working directory, honoring the
/// supplied [`PathTopologyPolicy`].
pub(crate) fn extract_project_name_with_policy(policy: &PathTopologyPolicy) -> String {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("unknown"));
    let normalized_cwd = match normalize_project_path_with_policy(&cwd, policy) {
        Ok(normalized) => {
            for decision in normalized.decision_trace() {
                debug!("[RCH] project identity normalization: {}", decision);
            }
            normalized.canonical_path().to_path_buf()
        }
        Err(err) => {
            warn!(
                "Project path normalization failed for {}: {}",
                cwd.display(),
                err
            );
            for decision in err.decision_trace() {
                debug!(
                    "[RCH] project identity normalization failed at: {}",
                    decision
                );
            }
            cwd.clone()
        }
    };

    let name = normalized_cwd
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Compute short hash of the canonical project path to ensure stable identity
    // across equivalent aliases (for example /dp/repo and /data/projects/repo).
    // This prevents cache affinity collisions for projects with same dir name (e.g. "app")
    let hash = blake3::hash(normalized_cwd.to_string_lossy().as_bytes()).to_hex();
    let short_hash = &hash[..8];

    format!("{}-{}", name, short_hash)
}

fn command_priority_from_env(reporter: &HookReporter) -> CommandPriority {
    let Ok(raw) = std::env::var("RCH_PRIORITY") else {
        return CommandPriority::Normal;
    };

    match raw.parse::<CommandPriority>() {
        Ok(value) => value,
        Err(()) => {
            reporter.verbose(&format!(
                "[RCH] ignoring invalid RCH_PRIORITY={:?} (expected: low|normal|high)",
                raw
            ));
            CommandPriority::Normal
        }
    }
}

/// Convert a SelectedWorker to a WorkerConfig.
fn selected_worker_to_config(worker: &SelectedWorker) -> WorkerConfig {
    WorkerConfig {
        id: worker.id.clone(),
        host: worker.host.clone(),
        user: worker.user.clone(),
        identity_file: worker.identity_file.clone(),
        total_slots: worker.slots_available,
        priority: 100,
        tags: vec![],
    }
}

#[derive(Debug, Clone)]
struct DependencyRuntimePlan {
    sync_roots: Vec<PathBuf>,
    fail_open_decision: Option<DependencyRuntimeFailOpenDecision>,
}

#[derive(Debug, Clone)]
struct DependencyRuntimeFailOpenDecision {
    reason_code: &'static str,
    remediation: &'static str,
    detail: String,
}

fn text_indicates_timeout(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("timeout") || lower.contains("timed out")
}

fn classify_dependency_runtime_fail_open(
    plan: &DependencyClosurePlan,
) -> DependencyRuntimeFailOpenDecision {
    let has_policy_violation = plan
        .issues
        .iter()
        .any(|issue| issue.code == "path-policy-violation");
    let has_timeout = plan
        .fail_open_reason
        .as_deref()
        .is_some_and(text_indicates_timeout)
        || plan.issues.iter().any(|issue| {
            text_indicates_timeout(&issue.message)
                || issue
                    .diagnostics
                    .iter()
                    .any(|diag| text_indicates_timeout(diag))
        });

    let (reason_code, remediation) = if has_policy_violation {
        (
            DEPENDENCY_PREFLIGHT_CODE_POLICY,
            DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY,
        )
    } else if has_timeout {
        (
            DEPENDENCY_PREFLIGHT_CODE_TIMEOUT,
            DEPENDENCY_PREFLIGHT_REMEDIATION_TIMEOUT,
        )
    } else {
        (
            DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
            DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN,
        )
    };

    let issue_codes = if plan.issues.is_empty() {
        "none".to_string()
    } else {
        plan.issues
            .iter()
            .map(|issue| issue.code.clone())
            .collect::<Vec<_>>()
            .join(",")
    };
    let fail_open_reason = plan
        .fail_open_reason
        .as_deref()
        .unwrap_or("no planner fail-open reason supplied");
    let detail = format!("planner fail-open reason={fail_open_reason}; issue_codes={issue_codes}");

    DependencyRuntimeFailOpenDecision {
        reason_code,
        remediation,
        detail,
    }
}

fn build_dependency_runtime_fail_open_report(
    worker: &WorkerConfig,
    normalized_project_root: &Path,
    decision: &DependencyRuntimeFailOpenDecision,
) -> DependencyPreflightReport {
    let status = if decision.reason_code == DEPENDENCY_PREFLIGHT_CODE_POLICY {
        DependencyPreflightStatus::PolicyViolation
    } else if decision.reason_code == DEPENDENCY_PREFLIGHT_CODE_TIMEOUT {
        DependencyPreflightStatus::Timeout
    } else {
        DependencyPreflightStatus::Unknown
    };

    DependencyPreflightReport {
        schema_version: DEPENDENCY_PREFLIGHT_SCHEMA_VERSION,
        worker: worker.id.as_str().to_string(),
        verified: false,
        reason_code: Some(decision.reason_code),
        remediation: Some(decision.remediation),
        evidence: vec![DependencyPreflightEvidence {
            root: normalized_project_root.to_string_lossy().to_string(),
            manifest: normalized_project_root
                .join("Cargo.toml")
                .to_string_lossy()
                .to_string(),
            required_path: normalized_project_root
                .join("Cargo.toml")
                .to_string_lossy()
                .to_string(),
            required_kind: "manifest",
            status,
            reason_code: decision.reason_code,
            detail: decision.detail.clone(),
            is_primary: true,
        }],
    }
}

fn should_force_local_fallback_for_runtime_fail_open(reason_code: &str) -> bool {
    reason_code == DEPENDENCY_PREFLIGHT_CODE_POLICY
}

fn command_uses_cargo_dependency_graph(kind: Option<CompilationKind>) -> bool {
    matches!(
        kind,
        Some(
            CompilationKind::CargoBuild
                | CompilationKind::CargoCheck
                | CompilationKind::CargoClippy
                | CompilationKind::CargoDoc
                | CompilationKind::CargoTest
                | CompilationKind::CargoNextest
                | CompilationKind::CargoBench
        )
    )
}

fn normalize_dependency_root_for_runtime(
    root: &Path,
    policy: &PathTopologyPolicy,
) -> Option<PathBuf> {
    normalize_project_path_with_policy(root, policy)
        .ok()
        .map(|normalized| normalized.canonical_path().to_path_buf())
}

fn build_dependency_runtime_plan(
    normalized_project_root: &Path,
    kind: Option<CompilationKind>,
    reporter: &HookReporter,
    topology_policy: &PathTopologyPolicy,
) -> DependencyRuntimePlan {
    if !command_uses_cargo_dependency_graph(kind) {
        return DependencyRuntimePlan {
            sync_roots: vec![normalized_project_root.to_path_buf()],
            fail_open_decision: None,
        };
    }

    let plan = build_dependency_closure_plan_with_policy(normalized_project_root, topology_policy);
    if !plan.is_ready() {
        if let Some(reason) = &plan.fail_open_reason {
            reporter.verbose(&format!(
                "[RCH] dependency closure planner fail-open: {}",
                reason
            ));
        }
        for issue in &plan.issues {
            reporter.verbose(&format!(
                "[RCH] dependency closure issue {} ({:?}): {}",
                issue.code, issue.risk, issue.message
            ));
        }
        let decision = classify_dependency_runtime_fail_open(&plan);
        reporter.verbose(&format!(
            "[RCH] dependency planner fail-open decision [{}]: {}",
            decision.reason_code, decision.remediation
        ));
        return DependencyRuntimePlan {
            sync_roots: vec![normalized_project_root.to_path_buf()],
            fail_open_decision: Some(decision),
        };
    }

    let mut seen = std::collections::BTreeSet::<PathBuf>::new();
    let mut ordered = Vec::<PathBuf>::new();
    for action in &plan.sync_order {
        if let Some(root) =
            normalize_dependency_root_for_runtime(&action.package_root, topology_policy)
            && seen.insert(root.clone())
        {
            reporter.verbose(&format!(
                "[RCH] dependency root {} ({:?})",
                root.display(),
                action.metadata.reason
            ));
            ordered.push(root);
        }
    }

    if ordered.is_empty() {
        ordered.push(normalized_project_root.to_path_buf());
    }
    if !ordered.iter().any(|root| root == normalized_project_root) {
        ordered.push(normalized_project_root.to_path_buf());
    }

    DependencyRuntimePlan {
        sync_roots: ordered,
        fail_open_decision: None,
    }
}

fn env_allowlist_contains(env_allowlist: &[String], key: &str) -> bool {
    env_allowlist
        .iter()
        .map(|item| item.trim())
        .any(|item| item == key)
}

fn cargo_kind_uses_target_dir(kind: Option<CompilationKind>) -> bool {
    matches!(
        kind,
        Some(
            CompilationKind::CargoBuild
                | CompilationKind::CargoCheck
                | CompilationKind::CargoClippy
                | CompilationKind::CargoDoc
                | CompilationKind::CargoTest
                | CompilationKind::CargoNextest
                | CompilationKind::CargoBench,
        )
    )
}

fn resolve_forwarded_cargo_target_dir_with_lookup<F>(
    kind: Option<CompilationKind>,
    invocation_cwd: &Path,
    reporter: &HookReporter,
    mut lookup_env: F,
    command_tokens: Option<&[String]>,
) -> Option<PathBuf>
where
    F: FnMut(&str) -> Option<String>,
{
    if !cargo_kind_uses_target_dir(kind) {
        return None;
    }

    let raw = command_tokens
        .and_then(|tokens| {
            extract_cargo_target_dir_from_command_tokens(tokens).inspect(|_| {
                reporter.verbose(
                    "[RCH] CARGO_TARGET_DIR forwarding detected from delegated command tokens",
                );
            })
        })
        .or_else(|| {
            lookup_env("CARGO_TARGET_DIR").inspect(|_| {
                reporter.verbose("[RCH] CARGO_TARGET_DIR forwarding detected from environment");
            })
        });

    let resolved = raw.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            reporter.verbose("[RCH] CARGO_TARGET_DIR is empty; using default Cargo target dir");
            return None;
        }

        let requested = PathBuf::from(trimmed);
        Some(if requested.is_absolute() {
            requested
        } else {
            invocation_cwd.join(requested)
        })
    });

    let resolved = resolved.unwrap_or_else(|| invocation_cwd.join("target"));

    reporter.verbose(&format!(
        "[RCH] Cargo target sync active; forcing worker CARGO_TARGET_DIR to an isolated remote target and syncing back to {}",
        resolved.display()
    ));
    Some(resolved)
}

fn resolve_forwarded_cargo_target_dir(
    kind: Option<CompilationKind>,
    invocation_cwd: &Path,
    reporter: &HookReporter,
    command_tokens: Option<&[String]>,
) -> Option<PathBuf> {
    resolve_forwarded_cargo_target_dir_with_lookup(
        kind,
        invocation_cwd,
        reporter,
        |key| std::env::var(key).ok(),
        command_tokens,
    )
}

fn cargo_target_env_allowlist(env_allowlist: &[String], cargo_target_sync: bool) -> Vec<String> {
    let mut effective = env_allowlist.to_vec();
    if cargo_target_sync && !env_allowlist_contains(&effective, "CARGO_TARGET_DIR") {
        effective.push("CARGO_TARGET_DIR".to_string());
    }
    effective
}

fn cargo_target_env_overrides(local_target_dir: Option<&Path>) -> Option<HashMap<String, String>> {
    let local_target_dir = local_target_dir?;
    let mut overrides = HashMap::new();
    overrides.insert(
        "CARGO_TARGET_DIR".to_string(),
        local_target_dir.to_string_lossy().to_string(),
    );
    Some(overrides)
}

/// Reduce an arbitrary token to a path-safe basename component: ASCII
/// alphanumerics, `-` and `_` are kept; everything else collapses to `-`,
/// leading/trailing `-` are trimmed, and an empty result falls back to
/// `"worker"`. Shared by the per-job target dir and isolated CARGO_HOME naming.
fn sanitize_cargo_home_token(token: &str) -> String {
    let safe = token
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    let safe = safe.trim_matches('-');
    if safe.is_empty() {
        "worker".to_string()
    } else {
        safe.to_string()
    }
}

fn remote_cargo_target_dir_name(build_id: Option<u64>, worker_id: &WorkerId) -> String {
    static REMOTE_CARGO_TARGET_DIR_SEQUENCE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    let safe_worker_id = sanitize_cargo_home_token(worker_id.as_str());
    let job_id = build_id
        .map(|id| format!("job-{id}"))
        .unwrap_or_else(|| format!("pid-{}", std::process::id()));
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence =
        REMOTE_CARGO_TARGET_DIR_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    format!(".rch-target-{safe_worker_id}-{job_id}-{timestamp}-{sequence}")
}

/// Idle threshold (hours) after which an abandoned per-job remote target dir is
/// eligible for reaping. Defaults to 12h: empirically (ts2 disk-fill incident,
/// 2026-05) active per-job dirs are touched within ~2h while abandoned ones sit
/// idle 18h+, so 12h cleanly separates the two with margin. Overridable via
/// `RCH_STALE_TARGET_REAP_HOURS`; floored at 1h so a misconfiguration can never
/// reap a live incremental cache.
fn stale_target_reap_idle_hours() -> u32 {
    parse_stale_target_reap_idle_hours(std::env::var("RCH_STALE_TARGET_REAP_HOURS").ok())
}

fn parse_stale_target_reap_idle_hours(raw: Option<String>) -> u32 {
    const DEFAULT_IDLE_HOURS: u32 = 12;
    raw.and_then(|v| v.trim().parse::<u32>().ok())
        .map(|hours| hours.max(1))
        .unwrap_or(DEFAULT_IDLE_HOURS)
}

fn rewrite_cargo_target_dir_command_for_remote(
    command: &str,
    command_tokens: Option<&[String]>,
    forwarded_cargo_target_dir: Option<&PathBuf>,
    reporter: &HookReporter,
) -> String {
    if forwarded_cargo_target_dir.is_none() {
        return command.to_string();
    }

    let parsed_tokens;
    let tokens = if let Some(tokens) = command_tokens {
        tokens
    } else {
        parsed_tokens = parse_command_tokens(command, reporter);
        let Some(tokens) = parsed_tokens.as_deref() else {
            return command.to_string();
        };
        tokens
    };

    let mut stripped = tokens.to_vec();
    let mut removed_target_dir = false;
    if let Some(without_assignments) =
        strip_cargo_target_dir_assignments_from_command_tokens(&stripped)
    {
        stripped = without_assignments;
        removed_target_dir = true;
    }
    if let Some(without_flags) = strip_cargo_target_dir_flags_from_command_tokens(&stripped) {
        stripped = without_flags;
        removed_target_dir = true;
    }
    if removed_target_dir {
        reporter.verbose(
            "[RCH] removed local Cargo target-dir setting before remote execution; worker-scoped target dir will be injected",
        );
        return join_exec_command(&stripped);
    }

    command.to_string()
}

fn strip_cargo_target_dir_assignments_from_command_tokens(
    tokens: &[String],
) -> Option<Vec<String>> {
    fn strip_assignment_prefix(tokens: &mut Vec<String>, mut index: usize) -> bool {
        let mut changed = false;
        while let Some(token) = tokens.get(index) {
            let Some((key, _)) = token.split_once('=') else {
                break;
            };
            if key == "CARGO_TARGET_DIR" {
                tokens.remove(index);
                changed = true;
            } else {
                index += 1;
            }
        }
        changed
    }

    let mut stripped = tokens.to_vec();
    let mut index = 0usize;
    while let Some(token) = stripped.get(index) {
        match token.as_str() {
            "sudo" | "time" => {
                index += 1;
                while let Some(flag) = stripped.get(index) {
                    if flag.starts_with('-') {
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            "env" => {
                index = skip_env_option_prefix(&stripped, index + 1);
                return strip_assignment_prefix(&mut stripped, index).then_some(stripped);
            }
            _ => {
                return strip_assignment_prefix(&mut stripped, index).then_some(stripped);
            }
        }
    }

    None
}

fn skip_env_option_prefix(tokens: &[String], mut index: usize) -> usize {
    while let Some(flag) = tokens.get(index).map(String::as_str) {
        if flag == "--" {
            return index + 1;
        }

        match flag {
            "-u" | "--unset" => {
                index += 1;
                if tokens.get(index).is_some() {
                    index += 1;
                }
            }
            _ if flag.starts_with("--unset=") => {
                index += 1;
            }
            _ if flag.starts_with('-') && !flag.contains('=') => {
                index += 1;
            }
            _ => break,
        }
    }

    index
}

fn strip_cargo_target_dir_flags_from_command_tokens(tokens: &[String]) -> Option<Vec<String>> {
    let mut stripped = Vec::with_capacity(tokens.len());
    let mut changed = false;
    let mut index = 0usize;

    while let Some(token) = tokens.get(index) {
        if token == "--" {
            stripped.extend_from_slice(&tokens[index..]);
            break;
        }
        if token == "--target-dir" {
            changed = true;
            index += 1;
            if tokens.get(index).is_some() {
                index += 1;
            }
            continue;
        }

        if token
            .strip_prefix("--target-dir=")
            .is_some_and(|value| !value.is_empty())
        {
            changed = true;
            index += 1;
            continue;
        }

        stripped.push(token.clone());
        index += 1;
    }

    changed.then_some(stripped)
}

fn extract_cargo_target_dir_from_command_tokens(tokens: &[String]) -> Option<String> {
    fn scan_assignment_prefix(tokens: &[String], start: usize) -> Option<String> {
        let mut index = start;
        while let Some(token) = tokens.get(index) {
            if let Some((key, value)) = token.split_once('=') {
                if key == "CARGO_TARGET_DIR" {
                    return Some(value.to_string());
                }
                index += 1;
                continue;
            }
            break;
        }
        None
    }

    fn scan_target_dir_flag(tokens: &[String]) -> Option<String> {
        let mut index = 0usize;
        while let Some(token) = tokens.get(index) {
            if token == "--" {
                break;
            }
            if token == "--target-dir" {
                return tokens.get(index + 1).cloned();
            }
            if let Some(value) = token.strip_prefix("--target-dir=")
                && !value.is_empty()
            {
                return Some(value.to_string());
            }
            index += 1;
        }
        None
    }

    let mut index = 0usize;
    while let Some(token) = tokens.get(index) {
        match token.as_str() {
            "sudo" | "time" => {
                index += 1;
                while let Some(flag) = tokens.get(index) {
                    if flag.starts_with('-') {
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            "env" => {
                index = skip_env_option_prefix(tokens, index + 1);
                if let Some(value) = scan_assignment_prefix(tokens, index) {
                    return Some(value);
                }
                return scan_target_dir_flag(tokens);
            }
            _ => {
                if let Some(value) = scan_assignment_prefix(tokens, index) {
                    return Some(value);
                }
                return scan_target_dir_flag(tokens);
            }
        }
    }

    scan_target_dir_flag(tokens)
}

fn parse_command_tokens(command: &str, reporter: &HookReporter) -> Option<Vec<String>> {
    match shell_words::split(command) {
        Ok(tokens) => Some(tokens),
        Err(error) => {
            reporter.verbose(&format!(
                "[RCH] failed to parse delegated command for CARGO_TARGET_DIR forwarding: {}",
                error
            ));
            None
        }
    }
}

fn should_skip_remote_preflight(worker: &WorkerConfig) -> bool {
    mock::is_mock_enabled() || mock::is_mock_worker(worker)
}

async fn run_worker_ssh_command(
    worker: &WorkerConfig,
    remote_cmd: &str,
    timeout_duration: Duration,
) -> anyhow::Result<Output> {
    let identity_file = shellexpand::tilde(&worker.identity_file);
    let destination = format!("{}@{}", worker.user, worker.host);

    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-o").arg(format!(
        "ConnectTimeout={}",
        timeout_duration.as_secs().max(1)
    ));
    cmd.arg("-i").arg(identity_file.as_ref());
    cmd.arg(&destination);
    cmd.arg(build_remote_shell_command(remote_cmd));
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    // Spawn manually instead of `cmd.output()` so the local SSH process is
    // killed if our outer timeout fires. `tokio::time::timeout` only drops
    // the future; without `kill_on_drop`, the spawned ssh process keeps
    // running, holding the network socket open until SSH's own keepalive
    // gives up. For a busy hook this leaks fds and ssh processes — exactly
    // the kind of slow accumulation that turns into a daemon-restart bug
    // weeks later.
    cmd.kill_on_drop(true);

    use anyhow::Context as _;
    use tokio::io::AsyncReadExt as _;

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn ssh to {}", destination))?;

    // Drain stdout/stderr concurrently with the wait so that even verbose
    // remote output never deadlocks the child on a full pipe buffer.
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let collect = async {
        let stdout_fut = async {
            let mut buf = Vec::new();
            if let Some(p) = stdout_pipe.as_mut() {
                p.read_to_end(&mut buf).await?;
            }
            Ok::<_, std::io::Error>(buf)
        };
        let stderr_fut = async {
            let mut buf = Vec::new();
            if let Some(p) = stderr_pipe.as_mut() {
                p.read_to_end(&mut buf).await?;
            }
            Ok::<_, std::io::Error>(buf)
        };
        let (stdout_bytes, stderr_bytes) = tokio::try_join!(stdout_fut, stderr_fut)?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>(Output {
            status,
            stdout: stdout_bytes,
            stderr: stderr_bytes,
        })
    };

    match timeout(timeout_duration, collect).await {
        Ok(result) => result.context("Failed to collect ssh output"),
        Err(_) => {
            // collect future is dropped here; with kill_on_drop=true the
            // local ssh process is SIGKILLed when `child` (still owned by
            // the dropped future) is dropped.
            anyhow::bail!("SSH command timed out after {:?}", timeout_duration);
        }
    }
}

fn build_remote_shell_command(remote_cmd: &str) -> String {
    format!("sh -lc {}", shell_escape::escape(remote_cmd.into()))
}

fn build_worker_projects_topology_cmd(topology_policy: &PathTopologyPolicy) -> String {
    let canonical_display = topology_policy.canonical_root().display().to_string();
    let alias_display = topology_policy.alias_root().display().to_string();
    let canonical_slash_display = format!("{}/", canonical_display.trim_end_matches('/'));

    format!(
        "set -e; \
         if [ ! -e {canonical} ] && [ ! -L {canonical} ]; then mkdir_stderr=$(mkdir -p -- {canonical} 2>&1) || {{ printf 'RCH_TOPOLOGY_ERR_CANONICAL_CREATE_FAILED:path=%s:%s\\n' {canonical} \"$mkdir_stderr\" >&2; exit 45; }}; fi; \
         if [ -e {canonical} ] && [ ! -d {canonical} ]; then printf 'RCH_TOPOLOGY_ERR_CANONICAL_NOT_DIRECTORY:path=%s\\n' {canonical} >&2; exit 41; fi; \
         canonical_real=$(readlink -f -- {canonical} 2>/dev/null || printf '%s' {canonical}); \
         ensure_alias_symlink() {{ \
         if [ -L {alias} ]; then \
           target=$(readlink -- {alias} 2>/dev/null || true); \
           target_real=$(readlink -f -- {alias} 2>/dev/null || true); \
           if [ \"$target\" != {canonical} ] && [ \"$target\" != {canonical_slash} ] && [ \"$target_real\" != \"$canonical_real\" ]; then \
             update_stderr=$(ln -sfn -- {canonical} {alias} 2>&1) || {{ printf 'RCH_TOPOLOGY_ERR_ALIAS_UPDATE_FAILED:path=%s:target=%s:%s\\n' {alias} {canonical} \"$update_stderr\" >&2; return 43; }}; \
           fi; \
         elif [ -e {alias} ]; then \
           printf 'RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK:path=%s\\n' {alias} >&2; return 42; \
         else \
           create_stderr=$(ln -s -- {canonical} {alias} 2>&1) && return 0; \
           if [ -L {alias} ]; then ensure_alias_symlink; return $?; fi; \
           if [ -e {alias} ]; then printf 'RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK:path=%s\\n' {alias} >&2; return 42; fi; \
           printf 'RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED:path=%s:target=%s:%s\\n' {alias} {canonical} \"$create_stderr\" >&2; return 44; \
         fi; \
         }}; \
         ensure_alias_symlink; \
         echo RCH_TOPOLOGY_OK",
        canonical = shell_escape::escape(canonical_display.into()),
        canonical_slash = shell_escape::escape(canonical_slash_display.into()),
        alias = shell_escape::escape(alias_display.into())
    )
}

async fn ensure_worker_projects_topology(
    worker: &WorkerConfig,
    reporter: &HookReporter,
    topology_policy: &PathTopologyPolicy,
) -> anyhow::Result<()> {
    if should_skip_remote_preflight(worker) {
        reporter.verbose("[RCH] topology preflight skipped in mock mode");
        return Ok(());
    }

    let canonical_display = topology_policy.canonical_root().display().to_string();
    let alias_display = topology_policy.alias_root().display().to_string();
    let topology_cmd = build_worker_projects_topology_cmd(topology_policy);

    let output = run_worker_ssh_command(worker, &topology_cmd, Duration::from_secs(20)).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        anyhow::bail!(
            "remote topology preflight failed on {} (status {:?}): stdout='{}' stderr='{}'",
            worker.id,
            output.status.code(),
            stdout,
            stderr
        );
    }
    reporter.verbose(&format!(
        "[RCH] topology preflight ok on {} ({} -> {} enforced)",
        worker.id, alias_display, canonical_display
    ));
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RepoUpdaterSyncRoots {
    roots: Vec<PathBuf>,
    specs: Vec<String>,
}

async fn collect_repo_updater_roots_and_specs(sync_roots: &[PathBuf]) -> RepoUpdaterSyncRoots {
    let mut specs = std::collections::BTreeSet::new();
    let mut roots = Vec::new();

    for root in sync_roots {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .arg("remote")
            .arg("get-url")
            .arg("origin")
            .output()
            .await;

        let Ok(output) = output else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let remote = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !remote.is_empty() {
            roots.push(root.clone());
            specs.insert(remote);
        }
    }

    RepoUpdaterSyncRoots {
        roots,
        specs: specs.into_iter().collect(),
    }
}

async fn detect_dirty_sync_roots(sync_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirty = Vec::new();

    for root in sync_roots {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .arg("status")
            .arg("--porcelain")
            .output()
            .await;

        let Ok(output) = output else {
            continue;
        };
        if !output.status.success() {
            continue;
        }

        let status = String::from_utf8_lossy(&output.stdout);
        if !status.trim().is_empty() {
            dirty.push(root.clone());
        }
    }

    dirty
}

async fn detect_remote_unsuitable_sync_roots(
    worker: &WorkerConfig,
    sync_roots: &[PathBuf],
) -> Vec<(PathBuf, String)> {
    let mut unsuitable = Vec::new();

    for root in sync_roots {
        let escaped_root = shell_escape::escape(root.to_string_lossy()).to_string();
        let command = format!("git -C {escaped_root} status --porcelain");

        match run_worker_ssh_command(worker, &command, Duration::from_secs(10)).await {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    unsuitable.push((root.clone(), "dirty".to_string()));
                }
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let reason = if stderr.is_empty() {
                    format!("git status failed with exit {:?}", output.status.code())
                } else {
                    format!("git status failed: {stderr}")
                };
                unsuitable.push((root.clone(), reason));
            }
            Err(err) => unsuitable.push((root.clone(), format!("status probe error: {err}"))),
        }
    }

    unsuitable
}

fn repo_updater_timeout_for(
    contract: &RepoUpdaterAdapterContract,
    command: RepoUpdaterAdapterCommand,
) -> u64 {
    contract
        .command_budgets
        .iter()
        .find(|budget| budget.command == command)
        .map(|budget| budget.timeout_secs)
        .unwrap_or(contract.timeout_policy.sync_timeout_secs)
        .max(1)
}

fn build_repo_updater_remote_command(
    invocation: &rch_common::repo_updater_contract::RepoUpdaterInvocation,
) -> String {
    let env_prefix = invocation
        .env
        .iter()
        .map(|(k, v)| format!("{k}={}", shell_escape::escape(v.as_str().into())))
        .collect::<Vec<_>>()
        .join(" ");
    let escaped_binary = shell_escape::escape(invocation.binary.as_str().into()).to_string();
    let escaped_args = invocation
        .args
        .iter()
        .map(|arg| shell_escape::escape(arg.as_str().into()).to_string())
        .collect::<Vec<_>>()
        .join(" ");
    if env_prefix.is_empty() {
        format!("{escaped_binary} {escaped_args}")
    } else {
        format!("{env_prefix} {escaped_binary} {escaped_args}")
    }
}

fn build_repo_sync_idempotency_key(worker_id: &WorkerId, sync_roots: &[PathBuf]) -> String {
    build_repo_sync_idempotency_key_for_command(
        worker_id,
        sync_roots,
        RepoUpdaterAdapterCommand::SyncApply,
    )
}

fn repo_updater_command_name(command: RepoUpdaterAdapterCommand) -> &'static str {
    match command {
        RepoUpdaterAdapterCommand::ListPaths => "list-paths",
        RepoUpdaterAdapterCommand::StatusNoFetch => "status-no-fetch",
        RepoUpdaterAdapterCommand::SyncDryRun => "sync-dry-run",
        RepoUpdaterAdapterCommand::SyncApply => "sync-apply",
        RepoUpdaterAdapterCommand::RobotDocsSchemas => "robot-docs-schemas",
        RepoUpdaterAdapterCommand::Version => "version",
    }
}

fn build_repo_sync_idempotency_key_for_command(
    worker_id: &WorkerId,
    sync_roots: &[PathBuf],
    command: RepoUpdaterAdapterCommand,
) -> String {
    let mut material = worker_id.as_str().to_string();
    material.push('|');
    material.push_str(repo_updater_command_name(command));
    for root in sync_roots {
        material.push('|');
        material.push_str(&root.to_string_lossy());
    }
    let hash = blake3::hash(material.as_bytes()).to_hex();
    format!("rch-repo-sync-{}", &hash[..16])
}

async fn execute_repo_updater_command(
    worker: &WorkerConfig,
    contract: &RepoUpdaterAdapterContract,
    base_request: &RepoUpdaterAdapterRequest,
    sync_roots: &[PathBuf],
    command: RepoUpdaterAdapterCommand,
    reporter: &HookReporter,
) -> bool {
    let mut request = base_request.clone();
    let timeout_secs = repo_updater_timeout_for(contract, command);
    request.command = command;
    request.timeout_secs = timeout_secs;
    request.idempotency_key =
        build_repo_sync_idempotency_key_for_command(&worker.id, sync_roots, command);

    if let Err(err) = request.validate(contract) {
        let failure_kind = err.failure_kind();
        warn!(
            "repo_updater {} validation failed for {} [{} {:?}]: {}",
            repo_updater_command_name(command),
            worker.id,
            err.reason_code(),
            failure_kind,
            err
        );
        reporter.verbose(&format!(
            "[RCH] repo_updater {} skipped (validation failed [{} {:?}]): {} | remediation: {}",
            repo_updater_command_name(command),
            err.reason_code(),
            failure_kind,
            err,
            err.remediation()
        ));
        return false;
    }

    let invocation = build_invocation(&request, contract);
    let remote_cmd = build_repo_updater_remote_command(&invocation);
    let retry_policy = &contract.retry_policy;
    let max_attempts = retry_policy.max_attempts.max(1);
    let mut backoff_ms = retry_policy.initial_backoff_ms;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            reporter.verbose(&format!(
                "[RCH] repo_updater {} retry {}/{} on {} (backoff {}ms)",
                repo_updater_command_name(command),
                attempt + 1,
                max_attempts,
                worker.id,
                backoff_ms
            ));
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            backoff_ms = backoff_ms
                .saturating_mul(u64::from(retry_policy.backoff_multiplier_percent))
                .saturating_div(100)
                .min(retry_policy.max_backoff_ms);
        }

        match run_worker_ssh_command(worker, &remote_cmd, Duration::from_secs(timeout_secs)).await {
            Ok(output) if output.status.success() => {
                if attempt > 0 {
                    reporter.verbose(&format!(
                        "[RCH] repo_updater {} succeeded on attempt {}/{} for {} repositories on {}",
                        repo_updater_command_name(command),
                        attempt + 1,
                        max_attempts,
                        request.repo_specs.len(),
                        worker.id
                    ));
                } else {
                    reporter.verbose(&format!(
                        "[RCH] repo_updater {} succeeded for {} repositories on {}",
                        repo_updater_command_name(command),
                        request.repo_specs.len(),
                        worker.id
                    ));
                }
                return true;
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                warn!(
                    "repo_updater {} failed on {} attempt {}/{} (status {:?}): {}",
                    repo_updater_command_name(command),
                    worker.id,
                    attempt + 1,
                    max_attempts,
                    output.status.code(),
                    stderr
                );
                // Last attempt — give up
                if attempt + 1 >= max_attempts {
                    reporter.verbose(&format!(
                        "[RCH] repo_updater {} exhausted {} attempts on {} (continuing with direct sync)",
                        repo_updater_command_name(command),
                        max_attempts,
                        worker.id
                    ));
                    return false;
                }
            }
            Err(err) => {
                warn!(
                    "repo_updater {} transport failure on {} attempt {}/{}: {}",
                    repo_updater_command_name(command),
                    worker.id,
                    attempt + 1,
                    max_attempts,
                    err
                );
                // Last attempt — give up
                if attempt + 1 >= max_attempts {
                    reporter.verbose(&format!(
                        "[RCH] repo_updater {} unavailable on {} after {} attempts (continuing with direct sync)",
                        repo_updater_command_name(command),
                        max_attempts,
                        worker.id
                    ));
                    return false;
                }
            }
        }
    }

    false
}

fn parse_csv_env_var(var_name: &str) -> Option<Vec<String>> {
    let raw = std::env::var(var_name).ok()?;
    let entries = raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>();
    (!entries.is_empty()).then_some(entries)
}

fn parse_host_identity_pairs(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|entry| {
            let trimmed = entry.trim();
            let (host, fingerprint) = trimmed.split_once('=')?;
            let host = host.trim();
            let fingerprint = fingerprint.trim();
            if host.is_empty() || fingerprint.is_empty() {
                return None;
            }
            Some((host.to_string(), fingerprint.to_string()))
        })
        .collect()
}

fn parse_auth_source(raw: &str) -> Option<RepoUpdaterCredentialSource> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "gh_cli" | "gh" => Some(RepoUpdaterCredentialSource::GhCli),
        "token_env" | "token" => Some(RepoUpdaterCredentialSource::TokenEnv),
        "ssh_agent" | "ssh" => Some(RepoUpdaterCredentialSource::SshAgent),
        _ => None,
    }
}

fn parse_auth_mode(raw: &str) -> Option<RepoUpdaterAuthMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "inherit_environment" | "inherit" => Some(RepoUpdaterAuthMode::InheritEnvironment),
        "require_gh_auth" | "gh" | "gh_cli" => Some(RepoUpdaterAuthMode::RequireGhAuth),
        "require_token_env" | "token_env" | "token" => Some(RepoUpdaterAuthMode::RequireTokenEnv),
        _ => None,
    }
}

fn env_flag_is_truthy(var_name: &str) -> bool {
    std::env::var(var_name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn env_var_present(var_name: &str) -> bool {
    std::env::var(var_name)
        .ok()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn apply_repo_updater_contract_env_policy(contract: &mut RepoUpdaterAdapterContract) {
    if let Some(hosts) = parse_csv_env_var(REPO_UPDATER_ALLOWED_HOSTS_ENV) {
        contract.trust_policy.allowed_repo_hosts = hosts;
    }
    if let Some(spec_allowlist) = parse_csv_env_var(REPO_UPDATER_ALLOWLIST_ENV) {
        contract.trust_policy.allowlisted_repo_specs = spec_allowlist;
    }
    if let Ok(raw_mode) = std::env::var(REPO_UPDATER_AUTH_MODE_ENV)
        && let Some(mode) = parse_auth_mode(&raw_mode)
    {
        contract.auth_policy.mode = mode;
    }
    if env_flag_is_truthy(REPO_UPDATER_ALLOW_OVERRIDE_ENV) {
        contract.trust_policy.allow_operator_override = true;
    }
    if let Some(required_scopes) = parse_csv_env_var(REPO_UPDATER_REQUIRED_SCOPES_ENV) {
        contract.auth_policy.required_scopes = required_scopes;
    }
    if let Ok(rotation_max_age_secs) = std::env::var(REPO_UPDATER_ROTATION_MAX_AGE_SECS_ENV)
        && let Ok(parsed) = rotation_max_age_secs.trim().parse::<u64>()
    {
        contract.auth_policy.rotation_max_age_secs = parsed.max(1);
    }
    if env_flag_is_truthy(REPO_UPDATER_REQUIRE_HOST_IDENTITY_ENV) {
        contract.auth_policy.require_host_identity_verification = true;
    }
    if let Ok(raw_identities) = std::env::var(REPO_UPDATER_TRUSTED_HOST_IDENTITIES_ENV) {
        let trusted = parse_host_identity_pairs(&raw_identities)
            .into_iter()
            .map(|(host, key_fingerprint)| RepoUpdaterTrustedHostIdentity {
                host,
                key_fingerprint,
            })
            .collect::<Vec<_>>();
        if !trusted.is_empty() {
            contract.auth_policy.trusted_host_identities = trusted;
        }
    }
}

fn repo_updater_auth_context_env_supplied() -> bool {
    [
        REPO_UPDATER_AUTH_SOURCE_ENV,
        REPO_UPDATER_AUTH_CREDENTIAL_ID_ENV,
        REPO_UPDATER_AUTH_ISSUED_AT_MS_ENV,
        REPO_UPDATER_AUTH_EXPIRES_AT_MS_ENV,
        REPO_UPDATER_AUTH_SCOPES_ENV,
        REPO_UPDATER_AUTH_REVOKED_ENV,
        REPO_UPDATER_AUTH_VERIFIED_HOSTS_ENV,
    ]
    .iter()
    .any(|var_name| std::env::var(var_name).is_ok())
}

fn infer_repo_updater_auth_context_with_env_lookup<F>(
    requested_at_unix_ms: i64,
    env_present: F,
) -> Option<RepoUpdaterAuthContext>
where
    F: Fn(&str) -> bool,
{
    let (source, credential_id, granted_scopes) = if env_present("GH_TOKEN") {
        (
            RepoUpdaterCredentialSource::TokenEnv,
            "env:GH_TOKEN".to_string(),
            vec!["repo:read".to_string()],
        )
    } else if env_present("GITHUB_TOKEN") {
        (
            RepoUpdaterCredentialSource::TokenEnv,
            "env:GITHUB_TOKEN".to_string(),
            vec!["repo:read".to_string()],
        )
    } else if env_present("SSH_AUTH_SOCK") {
        (
            RepoUpdaterCredentialSource::SshAgent,
            "ssh-agent".to_string(),
            Vec::new(),
        )
    } else {
        return None;
    };

    let issued_at_unix_ms = if requested_at_unix_ms > 1_000 {
        requested_at_unix_ms - 1_000
    } else {
        1
    };
    let expires_at_unix_ms = requested_at_unix_ms.saturating_add(86_400_000);

    Some(RepoUpdaterAuthContext {
        source,
        credential_id,
        issued_at_unix_ms,
        expires_at_unix_ms,
        granted_scopes,
        revoked: false,
        verified_hosts: Vec::new(),
    })
}

fn infer_repo_updater_auth_context(requested_at_unix_ms: i64) -> Option<RepoUpdaterAuthContext> {
    infer_repo_updater_auth_context_with_env_lookup(requested_at_unix_ms, env_var_present)
}

fn auto_tune_repo_updater_contract(
    contract: &mut RepoUpdaterAdapterContract,
    repo_specs: &[String],
    auth_context: Option<&RepoUpdaterAuthContext>,
    has_explicit_allowlist: bool,
    has_explicit_auth_mode: bool,
    reporter: &HookReporter,
) {
    if !has_explicit_allowlist
        && contract.trust_policy.enforce_repo_spec_allowlist
        && contract.trust_policy.allowlisted_repo_specs.is_empty()
    {
        contract.trust_policy.allowlisted_repo_specs = repo_specs.to_vec();
        reporter.verbose(&format!(
            "[RCH] repo_updater allowlist auto-seeded from dependency closure ({} repos)",
            contract.trust_policy.allowlisted_repo_specs.len()
        ));
    }

    if !has_explicit_auth_mode {
        contract.auth_policy.mode = match auth_context.map(|ctx| ctx.source) {
            Some(RepoUpdaterCredentialSource::TokenEnv) => RepoUpdaterAuthMode::RequireTokenEnv,
            Some(RepoUpdaterCredentialSource::GhCli) => RepoUpdaterAuthMode::RequireGhAuth,
            Some(RepoUpdaterCredentialSource::SshAgent) | None => {
                RepoUpdaterAuthMode::InheritEnvironment
            }
        };
        reporter.verbose(&format!(
            "[RCH] repo_updater auth mode auto-selected: {:?}",
            contract.auth_policy.mode
        ));
    }
}

fn hydrate_repo_updater_auth_context_defaults(
    auth_context: &mut RepoUpdaterAuthContext,
    requested_at_unix_ms: i64,
    contract: &RepoUpdaterAdapterContract,
) {
    if auth_context.credential_id.trim().is_empty() {
        auth_context.credential_id = match auth_context.source {
            RepoUpdaterCredentialSource::GhCli => "gh-cli",
            RepoUpdaterCredentialSource::TokenEnv => "token-env",
            RepoUpdaterCredentialSource::SshAgent => "ssh-agent",
        }
        .to_string();
    }

    if auth_context.issued_at_unix_ms <= 0 || auth_context.issued_at_unix_ms > requested_at_unix_ms
    {
        auth_context.issued_at_unix_ms = if requested_at_unix_ms > 1_000 {
            requested_at_unix_ms - 1_000
        } else {
            1
        };
    }

    if auth_context.expires_at_unix_ms <= requested_at_unix_ms {
        let ttl_ms_u64 = contract
            .auth_policy
            .rotation_max_age_secs
            .saturating_mul(1_000)
            .max(60_000);
        let ttl_ms = i64::try_from(ttl_ms_u64).unwrap_or(i64::MAX / 2);
        auth_context.expires_at_unix_ms = requested_at_unix_ms.saturating_add(ttl_ms);
    }

    if auth_context.granted_scopes.is_empty() && !contract.auth_policy.required_scopes.is_empty() {
        auth_context.granted_scopes = contract.auth_policy.required_scopes.clone();
    }

    if auth_context.verified_hosts.is_empty()
        && contract.auth_policy.require_host_identity_verification
    {
        auth_context.verified_hosts = contract
            .auth_policy
            .trusted_host_identities
            .iter()
            .map(|identity| RepoUpdaterVerifiedHostIdentity {
                host: identity.host.clone(),
                key_fingerprint: identity.key_fingerprint.clone(),
                verified_at_unix_ms: requested_at_unix_ms,
            })
            .collect();
    }
}

fn repo_updater_operator_override_from_env() -> Option<RepoUpdaterOperatorOverride> {
    let operator_id = std::env::var(REPO_UPDATER_OVERRIDE_OPERATOR_ID_ENV).ok();
    let justification = std::env::var(REPO_UPDATER_OVERRIDE_JUSTIFICATION_ENV).ok();
    let ticket_ref = std::env::var(REPO_UPDATER_OVERRIDE_TICKET_REF_ENV).ok();
    let audit_event_id = std::env::var(REPO_UPDATER_OVERRIDE_AUDIT_EVENT_ID_ENV).ok();
    let approved_at_unix_ms = std::env::var(REPO_UPDATER_OVERRIDE_APPROVED_AT_MS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or_default();

    if operator_id.is_none()
        && justification.is_none()
        && ticket_ref.is_none()
        && audit_event_id.is_none()
        && approved_at_unix_ms == 0
    {
        return None;
    }

    Some(RepoUpdaterOperatorOverride {
        operator_id: operator_id.unwrap_or_default(),
        justification: justification.unwrap_or_default(),
        ticket_ref: ticket_ref.unwrap_or_default(),
        audit_event_id: audit_event_id.unwrap_or_default(),
        approved_at_unix_ms,
    })
}

fn repo_updater_auth_context_from_env(requested_at_unix_ms: i64) -> Option<RepoUpdaterAuthContext> {
    let source = std::env::var(REPO_UPDATER_AUTH_SOURCE_ENV)
        .ok()
        .and_then(|raw| parse_auth_source(&raw));
    let credential_id = std::env::var(REPO_UPDATER_AUTH_CREDENTIAL_ID_ENV).ok();
    let issued_at_unix_ms = std::env::var(REPO_UPDATER_AUTH_ISSUED_AT_MS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok());
    let expires_at_unix_ms = std::env::var(REPO_UPDATER_AUTH_EXPIRES_AT_MS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok());
    let scopes = parse_csv_env_var(REPO_UPDATER_AUTH_SCOPES_ENV).unwrap_or_default();
    let revoked = env_flag_is_truthy(REPO_UPDATER_AUTH_REVOKED_ENV);
    let verified_hosts = std::env::var(REPO_UPDATER_AUTH_VERIFIED_HOSTS_ENV)
        .ok()
        .map(|raw| {
            parse_host_identity_pairs(&raw)
                .into_iter()
                .map(|(host, key_fingerprint)| RepoUpdaterVerifiedHostIdentity {
                    host,
                    key_fingerprint,
                    verified_at_unix_ms: requested_at_unix_ms,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if source.is_none()
        && credential_id.is_none()
        && issued_at_unix_ms.is_none()
        && expires_at_unix_ms.is_none()
        && scopes.is_empty()
        && !revoked
        && verified_hosts.is_empty()
    {
        return None;
    }

    Some(RepoUpdaterAuthContext {
        source: source.unwrap_or(RepoUpdaterCredentialSource::TokenEnv),
        credential_id: credential_id.unwrap_or_default(),
        issued_at_unix_ms: issued_at_unix_ms.unwrap_or_default(),
        expires_at_unix_ms: expires_at_unix_ms.unwrap_or_default(),
        granted_scopes: scopes,
        revoked,
        verified_hosts,
    })
}

async fn maybe_sync_repo_set_with_repo_updater(
    worker: &WorkerConfig,
    sync_roots: &[PathBuf],
    reporter: &HookReporter,
) {
    if sync_roots.len() <= 1 {
        return;
    }
    if should_skip_remote_preflight(worker) {
        reporter.verbose("[RCH] repo_updater pre-sync skipped in mock mode");
        return;
    }

    let repo_updater_roots = collect_repo_updater_roots_and_specs(sync_roots).await;
    if repo_updater_roots.specs.is_empty() {
        reporter.verbose("[RCH] repo_updater pre-sync skipped (no git origin remotes found)");
        return;
    }

    let dirty_roots = detect_dirty_sync_roots(&repo_updater_roots.roots).await;
    if !dirty_roots.is_empty() {
        let joined = dirty_roots
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(", ");
        reporter.verbose(&format!(
            "[RCH] repo_updater pre-sync skipped (dirty local sync roots: {joined})"
        ));
        return;
    }

    let remote_unsuitable_roots =
        detect_remote_unsuitable_sync_roots(worker, &repo_updater_roots.roots).await;
    if !remote_unsuitable_roots.is_empty() {
        let joined = remote_unsuitable_roots
            .iter()
            .map(|(path, reason)| format!("{} ({reason})", path.display()))
            .collect::<Vec<_>>()
            .join(", ");
        reporter.verbose(&format!(
            "[RCH] repo_updater pre-sync skipped (dirty/broken remote sync roots on {}: {joined})",
            worker.id
        ));
        return;
    }

    let mut contract = RepoUpdaterAdapterContract::default();
    apply_repo_updater_contract_env_policy(&mut contract);
    let has_explicit_allowlist = env_var_present(REPO_UPDATER_ALLOWLIST_ENV);
    let has_explicit_auth_mode = env_var_present(REPO_UPDATER_AUTH_MODE_ENV);

    let command = RepoUpdaterAdapterCommand::SyncApply;
    let timeout_secs = repo_updater_timeout_for(&contract, command);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default();

    let mut auth_context = if repo_updater_auth_context_env_supplied() {
        repo_updater_auth_context_from_env(now_ms)
    } else {
        None
    };
    if auth_context.is_none() {
        auth_context = infer_repo_updater_auth_context(now_ms);
        if auth_context.is_some() {
            reporter.verbose("[RCH] repo_updater auth context inferred from runtime environment");
        } else {
            reporter.verbose(
                "[RCH] repo_updater auth context unavailable in local environment; sync-apply may be skipped",
            );
        }
    }

    auto_tune_repo_updater_contract(
        &mut contract,
        &repo_updater_roots.specs,
        auth_context.as_ref(),
        has_explicit_allowlist,
        has_explicit_auth_mode,
        reporter,
    );
    if let Some(context) = auth_context.as_mut() {
        hydrate_repo_updater_auth_context_defaults(context, now_ms, &contract);
    }

    let request = RepoUpdaterAdapterRequest {
        schema_version: rch_common::REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: format!("rch-{}-{}", worker.id, now_ms),
        worker_id: worker.id.to_string(),
        command,
        requested_at_unix_ms: now_ms,
        projects_root: PathBuf::from(REPO_UPDATER_CANONICAL_PROJECTS_ROOT),
        repo_specs: repo_updater_roots.specs.clone(),
        idempotency_key: build_repo_sync_idempotency_key(&worker.id, &repo_updater_roots.roots),
        retry_attempt: 0,
        timeout_secs,
        expected_output_format: RepoUpdaterOutputFormat::Json,
        auth_context,
        operator_override: repo_updater_operator_override_from_env(),
    };

    if let Err(err) = request.validate(&contract) {
        let failure_kind = err.failure_kind();
        warn!(
            "repo_updater request validation failed for {} [{} {:?}]: {}",
            worker.id,
            err.reason_code(),
            failure_kind,
            err
        );
        reporter.verbose(&format!(
            "[RCH] repo_updater pre-sync skipped (validation failed [{} {:?}]): {} | remediation: {}",
            err.reason_code(),
            failure_kind,
            err,
            err.remediation()
        ));
        return;
    }

    // Read-only convergence preflight to surface policy/auth/drift issues before mutation.
    let dry_run_ok = execute_repo_updater_command(
        worker,
        &contract,
        &request,
        &repo_updater_roots.roots,
        RepoUpdaterAdapterCommand::SyncDryRun,
        reporter,
    )
    .await;
    if !dry_run_ok {
        reporter.verbose(
            "[RCH] repo_updater dry-run did not complete cleanly; attempting sync apply anyway",
        );
    }

    let sync_apply_ok = execute_repo_updater_command(
        worker,
        &contract,
        &request,
        &repo_updater_roots.roots,
        RepoUpdaterAdapterCommand::SyncApply,
        reporter,
    )
    .await;
    if sync_apply_ok {
        // Post-apply non-mutating snapshot for diagnostics and observability.
        let _ = execute_repo_updater_command(
            worker,
            &contract,
            &request,
            &repo_updater_roots.roots,
            RepoUpdaterAdapterCommand::StatusNoFetch,
            reporter,
        )
        .await;
    }
}

fn merge_sync_result(base: &SyncResult, extra: &SyncResult) -> SyncResult {
    SyncResult {
        bytes_transferred: base
            .bytes_transferred
            .saturating_add(extra.bytes_transferred),
        files_transferred: base
            .files_transferred
            .saturating_add(extra.files_transferred),
        duration_ms: base.duration_ms.saturating_add(extra.duration_ms),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncClosurePlanEntry {
    local_root: PathBuf,
    remote_root: String,
    project_id: String,
    root_hash: String,
    is_primary: bool,
    mode: SyncClosureMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum SyncClosureMode {
    Full,
    WorkspaceMetadata,
}

/// Outcome of syncing a single closure root during multi-root transfer.
///
/// Used to collect per-root results and enable partial failure diagnostics
/// instead of aborting the entire sync on the first dependency root failure.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SyncRootOutcome {
    /// Root synced successfully.
    Synced,
    /// Dependency root sync was skipped (transfer estimation indicated skip).
    Skipped { reason: String },
    /// Dependency root sync failed (non-fatal for non-primary roots).
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SyncClosureManifest {
    schema_version: &'static str,
    generated_at_unix_ms: i64,
    project_root: String,
    entries: Vec<SyncClosureManifestEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SyncClosureManifestEntry {
    order: usize,
    local_root: String,
    remote_root: String,
    project_id: String,
    root_hash: String,
    is_primary: bool,
    mode: SyncClosureMode,
}

const DEPENDENCY_PREFLIGHT_SCHEMA_VERSION: &str = "rch.dependency_preflight.v1";
const DEPENDENCY_PREFLIGHT_CODE_PRESENT: &str = "RCH-I324";
const DEPENDENCY_PREFLIGHT_CODE_MISSING: &str = "RCH-E324";
const DEPENDENCY_PREFLIGHT_CODE_STALE: &str = "RCH-E325";
const DEPENDENCY_PREFLIGHT_CODE_UNKNOWN: &str = "RCH-E326";
const DEPENDENCY_PREFLIGHT_CODE_POLICY: &str = "RCH-E327";
const DEPENDENCY_PREFLIGHT_CODE_TIMEOUT: &str = "RCH-E328";
const DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING: &str = "Ensure every dependency root in the closure is synced and Cargo.toml plus required source entrypoints exist remotely.";
const DEPENDENCY_PREFLIGHT_REMEDIATION_STALE: &str = "One or more dependency roots were not refreshed; rerun after successful sync of skipped roots.";
const DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN: &str =
    "Dependency verification could not determine remote state; inspect sync/SSH logs and retry.";
const DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY: &str = "Path dependency topology policy failed; move dependencies under /data/projects (or /dp) and retry.";
const DEPENDENCY_PREFLIGHT_REMEDIATION_TIMEOUT: &str = "Dependency planner timed out; rerun after system load decreases or investigate cargo metadata latency.";
const DEPENDENCY_PREFLIGHT_PROBE_BATCH_SIZE: usize = 128;
const WORKSPACE_METADATA_SYNC_PATTERNS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain",
    "rust-toolchain.toml",
    ".cargo/",
    ".cargo/**",
];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DependencyPreflightStatus {
    Present,
    Missing,
    Stale,
    PolicyViolation,
    Timeout,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DependencyPreflightEvidence {
    root: String,
    manifest: String,
    required_path: String,
    required_kind: &'static str,
    status: DependencyPreflightStatus,
    reason_code: &'static str,
    detail: String,
    is_primary: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DependencyPreflightReport {
    schema_version: &'static str,
    worker: String,
    verified: bool,
    reason_code: Option<&'static str>,
    remediation: Option<&'static str>,
    evidence: Vec<DependencyPreflightEvidence>,
}

#[derive(Debug, thiserror::Error)]
#[error("dependency preflight verification failed [{reason_code}]")]
struct DependencyPreflightFailure {
    reason_code: &'static str,
    remediation: &'static str,
    report: DependencyPreflightReport,
}

impl DependencyPreflightFailure {
    fn from_report(report: DependencyPreflightReport) -> Self {
        let reason_code = report
            .reason_code
            .unwrap_or(DEPENDENCY_PREFLIGHT_CODE_UNKNOWN);
        let remediation = report
            .remediation
            .unwrap_or(DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN);
        Self {
            reason_code,
            remediation,
            report,
        }
    }

    fn report_json(&self) -> String {
        serde_json::to_string(&self.report).unwrap_or_else(|err| {
            format!(
                "{{\"schema_version\":\"{}\",\"verified\":false,\"reason_code\":\"{}\",\"serialization_error\":\"{}\"}}",
                DEPENDENCY_PREFLIGHT_SCHEMA_VERSION, self.reason_code, err
            )
        })
    }
}

fn parse_dependency_preflight_probe_output(
    stdout: &str,
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
) {
    let mut present = std::collections::BTreeSet::new();
    let mut missing = std::collections::BTreeSet::new();

    for line in stdout.lines() {
        if let Some(path) = line.strip_prefix("RCH_DEP_PRESENT:") {
            present.insert(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("RCH_DEP_MISSING:") {
            missing.insert(path.trim().to_string());
        }
    }

    (present, missing)
}

fn dependency_preflight_failure_reason(
    evidence: &[DependencyPreflightEvidence],
) -> Option<(&'static str, &'static str)> {
    // For Cargo dependency-closure builds, every synchronized root must reflect
    // the current local state. Proceeding when any non-primary dependency root
    // is stale or missing can silently compile against an older sibling checkout
    // on the worker, which is worse than falling back to a local build.
    if evidence
        .iter()
        .any(|item| item.status == DependencyPreflightStatus::Missing)
    {
        return Some((
            DEPENDENCY_PREFLIGHT_CODE_MISSING,
            DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING,
        ));
    }
    if evidence
        .iter()
        .any(|item| item.status == DependencyPreflightStatus::Stale)
    {
        return Some((
            DEPENDENCY_PREFLIGHT_CODE_STALE,
            DEPENDENCY_PREFLIGHT_REMEDIATION_STALE,
        ));
    }
    if evidence
        .iter()
        .any(|item| item.status == DependencyPreflightStatus::Unknown)
    {
        return Some((
            DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
            DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN,
        ));
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DependencyPreflightCheck {
    root: String,
    manifest: String,
    required_path: String,
    required_kind: &'static str,
    is_primary: bool,
}

fn clean_relative_cargo_path(raw: &str) -> Option<PathBuf> {
    let path = Path::new(raw);
    if path.is_absolute() {
        return None;
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return None;
    }
    Some(path.to_path_buf())
}

fn table_path_value(table: &toml::Table, key: &str) -> Option<PathBuf> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .and_then(clean_relative_cargo_path)
}

fn target_array_paths(table: &toml::Table, key: &str) -> Vec<PathBuf> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
        .filter_map(|target| table_path_value(target, "path"))
        .collect()
}

fn table_string_array(table: &toml::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(str::to_string)
        .collect()
}

fn package_auto_discovery_enabled(table: &toml::Table, key: &str) -> bool {
    table
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get(key))
        .and_then(toml::Value::as_bool)
        .unwrap_or(true)
}

fn insert_existing_relative_entrypoint(
    paths: &mut std::collections::BTreeSet<PathBuf>,
    package_root: &Path,
    relative_path: impl Into<PathBuf>,
) {
    let relative_path = relative_path.into();
    if package_root.join(&relative_path).is_file() {
        paths.insert(relative_path);
    }
}

fn insert_auto_discovered_target_entrypoints(
    paths: &mut std::collections::BTreeSet<PathBuf>,
    package_root: &Path,
    relative_dir: &str,
) {
    let Ok(entries) = std::fs::read_dir(package_root.join(relative_dir)) else {
        return;
    };

    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let file_name = entry.file_name();
        if file_type.is_file() {
            if entry.path().extension().is_some_and(|ext| ext == "rs") {
                paths.insert(PathBuf::from(relative_dir).join(file_name));
            }
        } else if file_type.is_dir() {
            insert_existing_relative_entrypoint(
                paths,
                package_root,
                PathBuf::from(relative_dir).join(file_name).join("main.rs"),
            );
        }
    }
}

fn cargo_package_source_entrypoints(package_root: &Path) -> Vec<PathBuf> {
    let manifest_path = package_root.join("Cargo.toml");
    let Ok(contents) = std::fs::read_to_string(&manifest_path) else {
        return Vec::new();
    };
    let Ok(table) = toml::from_str::<toml::Table>(&contents) else {
        return Vec::new();
    };
    if !table.contains_key("package") {
        return Vec::new();
    }

    let mut paths = std::collections::BTreeSet::<PathBuf>::new();

    if let Some(lib_path) = table
        .get("lib")
        .and_then(toml::Value::as_table)
        .and_then(|lib| table_path_value(lib, "path"))
    {
        paths.insert(lib_path);
    } else if package_auto_discovery_enabled(&table, "autolib") || table.contains_key("lib") {
        insert_existing_relative_entrypoint(&mut paths, package_root, "src/lib.rs");
    }

    if package_auto_discovery_enabled(&table, "autobins") {
        insert_existing_relative_entrypoint(&mut paths, package_root, "src/main.rs");
        insert_auto_discovered_target_entrypoints(&mut paths, package_root, "src/bin");
    }
    if package_auto_discovery_enabled(&table, "autoexamples") {
        insert_auto_discovered_target_entrypoints(&mut paths, package_root, "examples");
    }
    if package_auto_discovery_enabled(&table, "autotests") {
        insert_auto_discovered_target_entrypoints(&mut paths, package_root, "tests");
    }
    if package_auto_discovery_enabled(&table, "autobenches") {
        insert_auto_discovered_target_entrypoints(&mut paths, package_root, "benches");
    }

    for key in ["bin", "example", "test", "bench"] {
        paths.extend(target_array_paths(&table, key));
    }

    paths.into_iter().collect()
}

fn cargo_manifest_table(package_root: &Path) -> Option<toml::Table> {
    let manifest_path = package_root.join("Cargo.toml");
    let contents = std::fs::read_to_string(&manifest_path).ok()?;
    toml::from_str::<toml::Table>(&contents).ok()
}

fn has_glob_meta(pattern: &str) -> bool {
    pattern
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
}

fn path_slash_string(path: &Path) -> Option<String> {
    Some(
        path.to_str()?
            .trim_start_matches("./")
            .replace(std::path::MAIN_SEPARATOR, "/"),
    )
}

fn workspace_exclude_matches(relative_member: &Path, exclude_patterns: &[String]) -> bool {
    let Some(relative_member) = path_slash_string(relative_member) else {
        return false;
    };

    exclude_patterns.iter().any(|pattern| {
        let Some(pattern_path) = clean_relative_cargo_path(pattern) else {
            return false;
        };
        let Some(pattern_slash) = path_slash_string(&pattern_path) else {
            return false;
        };
        if has_glob_meta(&pattern_slash) {
            glob::Pattern::new(&pattern_slash)
                .map(|compiled| compiled.matches(&relative_member))
                .unwrap_or(false)
        } else {
            relative_member == pattern_slash
                || relative_member
                    .strip_prefix(&pattern_slash)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }
    })
}

fn workspace_member_manifest_paths(workspace_root: &Path) -> Vec<PathBuf> {
    let Some(table) = cargo_manifest_table(workspace_root) else {
        return Vec::new();
    };
    let Some(workspace) = table.get("workspace").and_then(toml::Value::as_table) else {
        return Vec::new();
    };

    let members = table_string_array(workspace, "members");
    let exclude_patterns = table_string_array(workspace, "exclude");
    let mut manifests = std::collections::BTreeSet::<PathBuf>::new();

    for member in members {
        let Some(member_path) = clean_relative_cargo_path(&member) else {
            continue;
        };
        if has_glob_meta(&member) {
            let glob_path = workspace_root.join(&member_path).join("Cargo.toml");
            let Some(glob_pattern) = glob_path.to_str() else {
                continue;
            };
            let Ok(entries) = glob::glob(glob_pattern) else {
                continue;
            };
            for entry in entries.flatten() {
                if !entry.is_file() {
                    continue;
                }
                let Ok(relative_manifest) = entry.strip_prefix(workspace_root) else {
                    continue;
                };
                let Some(relative_member) = relative_manifest.parent() else {
                    continue;
                };
                if !workspace_exclude_matches(relative_member, &exclude_patterns) {
                    manifests.insert(relative_manifest.to_path_buf());
                }
            }
        } else {
            let relative_manifest = member_path.join("Cargo.toml");
            if workspace_root.join(&relative_manifest).is_file()
                && !workspace_exclude_matches(&member_path, &exclude_patterns)
            {
                manifests.insert(relative_manifest);
            }
        }
    }

    manifests.into_iter().collect()
}

fn cargo_workspace_member_source_entrypoints(workspace_root: &Path) -> Vec<PathBuf> {
    let mut paths = std::collections::BTreeSet::<PathBuf>::new();
    for manifest_path in workspace_member_manifest_paths(workspace_root) {
        paths.insert(manifest_path.clone());
        if let Some(member_root) = manifest_path.parent() {
            paths.extend(
                cargo_package_source_entrypoints(&workspace_root.join(member_root))
                    .into_iter()
                    .map(|entrypoint| member_root.join(entrypoint)),
            );
        }
    }

    paths.into_iter().collect()
}

fn dependency_preflight_checks_for_entry(
    entry: &SyncClosurePlanEntry,
) -> Vec<DependencyPreflightCheck> {
    let remote_root = PathBuf::from(&entry.remote_root);
    let manifest = remote_root.join("Cargo.toml").to_string_lossy().to_string();
    let mut checks = Vec::new();
    checks.push(DependencyPreflightCheck {
        root: entry.remote_root.clone(),
        manifest: manifest.clone(),
        required_path: manifest.clone(),
        required_kind: "manifest",
        is_primary: entry.is_primary,
    });

    if entry.mode == SyncClosureMode::Full {
        checks.extend(
            cargo_package_source_entrypoints(&entry.local_root)
                .into_iter()
                .map(|relative_path| DependencyPreflightCheck {
                    root: entry.remote_root.clone(),
                    manifest: manifest.clone(),
                    required_path: remote_root
                        .join(relative_path)
                        .to_string_lossy()
                        .to_string(),
                    required_kind: "source_entrypoint",
                    is_primary: entry.is_primary,
                }),
        );
        checks.extend(
            cargo_workspace_member_source_entrypoints(&entry.local_root)
                .into_iter()
                .map(|relative_path| DependencyPreflightCheck {
                    root: entry.remote_root.clone(),
                    manifest: manifest.clone(),
                    required_path: remote_root
                        .join(relative_path)
                        .to_string_lossy()
                        .to_string(),
                    required_kind: "source_entrypoint",
                    is_primary: entry.is_primary,
                }),
        );
    }

    checks.sort_by(|left, right| {
        (&left.required_path, left.required_kind).cmp(&(&right.required_path, right.required_kind))
    });
    checks.dedup_by(|left, right| {
        left.required_path == right.required_path && left.required_kind == right.required_kind
    });
    checks
}

fn synced_dependency_preflight_checks(
    root_outcomes: &[(SyncClosurePlanEntry, SyncRootOutcome)],
) -> Vec<DependencyPreflightCheck> {
    root_outcomes
        .iter()
        .filter(|(_, outcome)| matches!(outcome, SyncRootOutcome::Synced))
        .flat_map(|(entry, _)| dependency_preflight_checks_for_entry(entry))
        .collect()
}

fn build_dependency_preflight_report(
    worker: &WorkerConfig,
    root_outcomes: &[(SyncClosurePlanEntry, SyncRootOutcome)],
    present_paths: &std::collections::BTreeSet<String>,
    missing_paths: &std::collections::BTreeSet<String>,
    probe_failure: Option<&str>,
) -> DependencyPreflightReport {
    let mut evidence = Vec::new();
    let mut unknown_probe_samples = std::collections::BTreeSet::<(String, &'static str)>::new();

    for (entry, outcome) in root_outcomes {
        for check in dependency_preflight_checks_for_entry(entry) {
            let (status, reason_code, detail) = match outcome {
                SyncRootOutcome::Synced => {
                    if missing_paths.contains(&check.required_path) {
                        let detail = match check.required_kind {
                            "manifest" => "required Cargo.toml is missing on remote worker",
                            "source_entrypoint" => {
                                "required package source entrypoint is missing on remote worker"
                            }
                            _ => "required dependency path is missing on remote worker",
                        };
                        (
                            DependencyPreflightStatus::Missing,
                            DEPENDENCY_PREFLIGHT_CODE_MISSING,
                            format!("{detail}: {}", check.required_path),
                        )
                    } else if present_paths.contains(&check.required_path) {
                        (
                            DependencyPreflightStatus::Present,
                            DEPENDENCY_PREFLIGHT_CODE_PRESENT,
                            format!(
                                "required {} present after current sync: {}",
                                check.required_kind, check.required_path
                            ),
                        )
                    } else {
                        let detail = probe_failure
                            .map(|failure| {
                                format!(
                                    "dependency probe unavailable for {} under {}; sample required_path={}; additional unreported paths for this root/kind share this failure; {}",
                                    check.required_kind,
                                    check.root,
                                    check.required_path,
                                    failure
                                )
                            })
                            .unwrap_or_else(|| {
                                format!(
                                    "probe output omitted status for synced required path: {}",
                                    check.required_path
                                )
                            });
                        (
                            DependencyPreflightStatus::Unknown,
                            DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
                            detail,
                        )
                    }
                }
                SyncRootOutcome::Skipped { reason } => (
                    DependencyPreflightStatus::Stale,
                    DEPENDENCY_PREFLIGHT_CODE_STALE,
                    format!(
                        "dependency root skipped before verification for {}: {}",
                        check.required_path, reason
                    ),
                ),
                SyncRootOutcome::Failed { error } => (
                    DependencyPreflightStatus::Unknown,
                    DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
                    format!(
                        "dependency root sync failed before verification for {}: {}",
                        check.required_path, error
                    ),
                ),
            };

            if probe_failure.is_some()
                && status == DependencyPreflightStatus::Unknown
                && matches!(outcome, SyncRootOutcome::Synced)
                && !unknown_probe_samples.insert((check.root.clone(), check.required_kind))
            {
                continue;
            }

            evidence.push(DependencyPreflightEvidence {
                root: check.root,
                manifest: check.manifest,
                required_path: check.required_path,
                required_kind: check.required_kind,
                status,
                reason_code,
                detail,
                is_primary: check.is_primary,
            });
        }
    }

    if evidence.is_empty() {
        for (entry, outcome) in root_outcomes {
            let manifest = PathBuf::from(&entry.remote_root)
                .join("Cargo.toml")
                .to_string_lossy()
                .to_string();
            let (status, reason_code, detail) = match outcome {
                SyncRootOutcome::Synced => (
                    DependencyPreflightStatus::Unknown,
                    DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
                    "dependency preflight had no required paths to verify".to_string(),
                ),
                SyncRootOutcome::Skipped { reason } => (
                    DependencyPreflightStatus::Stale,
                    DEPENDENCY_PREFLIGHT_CODE_STALE,
                    format!("dependency root skipped before verification: {}", reason),
                ),
                SyncRootOutcome::Failed { error } => (
                    DependencyPreflightStatus::Unknown,
                    DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
                    format!("dependency root sync failed before verification: {}", error),
                ),
            };
            evidence.push(DependencyPreflightEvidence {
                root: entry.remote_root.clone(),
                manifest: manifest.clone(),
                required_path: manifest,
                required_kind: "manifest",
                status,
                reason_code,
                detail,
                is_primary: entry.is_primary,
            });
        }
    }

    let (verified, reason_code, remediation) = match dependency_preflight_failure_reason(&evidence)
    {
        Some((reason_code, remediation)) => (false, Some(reason_code), Some(remediation)),
        None => (true, None, None),
    };

    DependencyPreflightReport {
        schema_version: DEPENDENCY_PREFLIGHT_SCHEMA_VERSION,
        worker: worker.id.as_str().to_string(),
        verified,
        reason_code,
        remediation,
        evidence,
    }
}

fn canonicalize_sync_root_for_plan(root: &Path, policy: &PathTopologyPolicy) -> PathBuf {
    normalize_dependency_root_for_runtime(root, policy)
        .or_else(|| std::fs::canonicalize(root).ok())
        .unwrap_or_else(|| root.to_path_buf())
}

fn manifest_declares_workspace(manifest_path: &Path) -> bool {
    let Ok(contents) = std::fs::read_to_string(manifest_path) else {
        return false;
    };
    let Ok(table) = toml::from_str::<toml::Table>(&contents) else {
        return false;
    };
    table.contains_key("workspace")
}

fn enclosing_workspace_root_for_sync_root(
    root: &Path,
    policy: &PathTopologyPolicy,
) -> Option<PathBuf> {
    for candidate in root.ancestors() {
        if !is_within_sync_topology(candidate, policy) {
            break;
        }
        let manifest_path = candidate.join("Cargo.toml");
        if manifest_path.is_file() && manifest_declares_workspace(&manifest_path) {
            return (candidate != root).then(|| candidate.to_path_buf());
        }
    }

    None
}

fn workspace_metadata_sync_patterns() -> Vec<String> {
    WORKSPACE_METADATA_SYNC_PATTERNS
        .iter()
        .map(|pattern| (*pattern).to_string())
        .collect()
}

fn effective_sync_topology_roots(policy: &PathTopologyPolicy) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    roots.push(policy.canonical_root().to_path_buf());
    roots.push(policy.alias_root().to_path_buf());

    if !policy.canonical_root().exists()
        && let Ok(alias_target) = std::fs::canonicalize(policy.alias_root())
    {
        roots.push(alias_target);
    }

    roots.sort();
    roots.dedup();
    roots
}

/// Returns `true` if `path` is within the allowed topology roots.
fn is_within_sync_topology(path: &Path, policy: &PathTopologyPolicy) -> bool {
    effective_sync_topology_roots(policy)
        .into_iter()
        .any(|root| path.starts_with(&root))
}

fn map_sync_root_to_remote_root(path: &Path, policy: &PathTopologyPolicy) -> String {
    // The remote canonical root comes from the same policy the rest of the
    // hook uses, never the compile-time `DEFAULT_CANONICAL_PROJECT_ROOT`,
    // because hosts that don't ship `/data/projects` (which is most of them)
    // configure their own canonical via `~/.config/rch/config.toml` and
    // would otherwise see their `[path_topology]` setting silently ignored
    // for the sync-target translation step. See rch#15.
    let remote_root = policy.canonical_root();

    for root in effective_sync_topology_roots(policy) {
        if let Ok(relative) = path.strip_prefix(&root) {
            return remote_root.join(relative).to_string_lossy().to_string();
        }
    }

    path.to_string_lossy().to_string()
}

fn build_sync_closure_plan(
    sync_roots: &[PathBuf],
    normalized_project_root: &Path,
    project_hash: &str,
    topology_policy: &PathTopologyPolicy,
) -> Vec<SyncClosurePlanEntry> {
    let mut ordered_entries = std::collections::BTreeSet::<(PathBuf, SyncClosureMode)>::new();
    for root in sync_roots {
        let canonicalized = canonicalize_sync_root_for_plan(root, topology_policy);
        if !is_within_sync_topology(&canonicalized, topology_policy) {
            warn!(
                "Dependency root {} (canonicalized: {}) is outside allowed topology ({} / {}); skipping from sync closure",
                root.display(),
                canonicalized.display(),
                topology_policy.canonical_root().display(),
                topology_policy.alias_root().display(),
            );
            continue;
        }
        ordered_entries.insert((canonicalized.clone(), SyncClosureMode::Full));
        if let Some(workspace_root) =
            enclosing_workspace_root_for_sync_root(&canonicalized, topology_policy)
        {
            ordered_entries.insert((workspace_root, SyncClosureMode::WorkspaceMetadata));
        }
    }

    let primary_root = canonicalize_sync_root_for_plan(normalized_project_root, topology_policy);
    ordered_entries.insert((primary_root.clone(), SyncClosureMode::Full));
    let full_roots: Vec<PathBuf> = ordered_entries
        .iter()
        .filter(|(_, mode)| *mode == SyncClosureMode::Full)
        .map(|(root, _)| root.clone())
        .collect();
    for root in full_roots {
        ordered_entries.remove(&(root, SyncClosureMode::WorkspaceMetadata));
    }

    ordered_entries
        .into_iter()
        .map(|(root, mode)| {
            let is_primary = root == primary_root && mode == SyncClosureMode::Full;
            let root_hash = if is_primary {
                project_hash.to_string()
            } else {
                compute_project_hash_with_dependency_roots_and_policy(&root, &[], topology_policy)
            };
            SyncClosurePlanEntry {
                remote_root: map_sync_root_to_remote_root(&root, topology_policy),
                project_id: project_id_from_path(&root),
                root_hash,
                is_primary,
                mode,
                local_root: root,
            }
        })
        .collect()
}

fn build_sync_closure_manifest(
    plan: &[SyncClosurePlanEntry],
    normalized_project_root: &Path,
) -> SyncClosureManifest {
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default();
    let entries = plan
        .iter()
        .enumerate()
        .map(|(idx, entry)| SyncClosureManifestEntry {
            order: idx + 1,
            local_root: entry.local_root.to_string_lossy().to_string(),
            remote_root: entry.remote_root.clone(),
            project_id: entry.project_id.clone(),
            root_hash: entry.root_hash.clone(),
            is_primary: entry.is_primary,
            mode: entry.mode,
        })
        .collect();
    SyncClosureManifest {
        schema_version: "rch.sync_closure_manifest.v2",
        generated_at_unix_ms,
        project_root: normalized_project_root.to_string_lossy().to_string(),
        entries,
    }
}

async fn verify_remote_dependency_manifests(
    worker: &WorkerConfig,
    root_outcomes: &[(SyncClosurePlanEntry, SyncRootOutcome)],
    reporter: &HookReporter,
) -> anyhow::Result<()> {
    if should_skip_remote_preflight(worker) {
        reporter.verbose("[RCH] remote dependency preflight skipped in mock mode");
        return Ok(());
    }
    if root_outcomes.is_empty() {
        return Ok(());
    }

    let synced_checks = synced_dependency_preflight_checks(root_outcomes);

    let mut present_paths = std::collections::BTreeSet::new();
    let mut missing_paths = std::collections::BTreeSet::new();
    let mut probe_failure: Option<String> = None;

    for verify_cmd in build_remote_dependency_preflight_commands(&synced_checks) {
        match run_worker_ssh_command(worker, &verify_cmd, Duration::from_secs(20)).await {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let (present, missing) = parse_dependency_preflight_probe_output(&stdout);
                let batch_had_missing = !missing.is_empty();
                present_paths.extend(present);
                missing_paths.extend(missing);
                if !output.status.success() && !batch_had_missing {
                    probe_failure = Some(format!(
                        "probe exited with status {:?}; stdout='{}'; stderr='{}'",
                        output.status.code(),
                        stdout,
                        stderr
                    ));
                }
            }
            Err(err) => {
                probe_failure = Some(err.to_string());
            }
        }
        if probe_failure.is_some() {
            break;
        }
    }

    let report = build_dependency_preflight_report(
        worker,
        root_outcomes,
        &present_paths,
        &missing_paths,
        probe_failure.as_deref(),
    );
    let report_json = serde_json::to_string(&report).unwrap_or_else(|err| {
        format!(
            "{{\"schema_version\":\"{}\",\"verified\":false,\"reason_code\":\"{}\",\"serialization_error\":\"{}\"}}",
            DEPENDENCY_PREFLIGHT_SCHEMA_VERSION, DEPENDENCY_PREFLIGHT_CODE_UNKNOWN, err
        )
    });
    reporter.verbose(&format!(
        "[RCH] dependency preflight report: {}",
        report_json
    ));
    if report.verified {
        reporter.verbose(&format!(
            "[RCH] remote dependency preflight verified {} roots on {}",
            report.evidence.len(),
            worker.id
        ));
        return Ok(());
    }

    let failure = DependencyPreflightFailure::from_report(report);
    warn!(
        "Remote dependency preflight blocked remote execution on {} [{}] remediation='{}'",
        worker.id, failure.reason_code, failure.remediation
    );
    reporter.verbose(&format!(
        "[RCH] dependency preflight remediation [{}]: {}",
        failure.reason_code, failure.remediation
    ));
    Err(failure.into())
}

fn build_remote_dependency_preflight_command(
    checks: &[DependencyPreflightCheck],
) -> Option<String> {
    if checks.is_empty() {
        return None;
    }

    let commands = checks
        .iter()
        .map(|check| {
            let escaped = shell_escape::escape(check.required_path.clone().into());
            escaped.to_string()
        })
        .collect::<Vec<_>>()
        .join(" ");

    Some(format!(
        "missing=0; for required in {commands}; do if [ -f \"$required\" ]; then printf 'RCH_DEP_PRESENT:%s\\n' \"$required\"; else printf 'RCH_DEP_MISSING:%s\\n' \"$required\"; missing=1; fi; done; if [ \"$missing\" -ne 0 ]; then exit 43; fi; echo RCH_REMOTE_DEPENDENCIES_OK"
    ))
}

fn build_remote_dependency_preflight_commands(checks: &[DependencyPreflightCheck]) -> Vec<String> {
    checks
        .chunks(DEPENDENCY_PREFLIGHT_PROBE_BATCH_SIZE)
        .filter_map(build_remote_dependency_preflight_command)
        .collect()
}

/// Result of remote compilation execution.
#[derive(Debug)]
struct RemoteExecutionResult {
    /// Exit code of the remote command.
    exit_code: i32,
    /// Standard error output (used for toolchain detection).
    stderr: String,
    /// Remote command duration in milliseconds.
    duration_ms: u64,
    /// Per-phase timing breakdown.
    timing: CommandTimingBreakdown,
}

/// Check if the failure is a toolchain-related infrastructure failure.
///
/// Returns true if the error indicates a toolchain issue that should
/// trigger a local fallback rather than denying execution.
fn is_toolchain_failure(stderr: &str, exit_code: i32) -> bool {
    if exit_code == 0 || exit_code == EXIT_TEST_FAILURES || is_signal_killed(exit_code).is_some() {
        return false;
    }

    stderr
        .lines()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .any(|line| {
            line.starts_with("rustup: command not found")
                || line.starts_with("rustup: not found")
                || line.contains("error: no default toolchain configured")
                || line.contains("error: no active toolchain")
                || (line.contains("error: toolchain ")
                    && (line.contains(" is not installed")
                        || line.contains(" is unavailable")
                        || line.contains(" does not have the binary ")))
                || (line.contains("error: override toolchain ")
                    && line.contains(" is not installed"))
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkerSystemDependencyFailure {
    system_library: Option<String>,
    crate_name: Option<String>,
    pkg_config_file: Option<String>,
}

impl WorkerSystemDependencyFailure {
    fn summary(&self) -> String {
        if let Some(pkg_config_file) = &self.pkg_config_file {
            return format!("missing worker system package {}", pkg_config_file);
        }
        if let Some(system_library) = &self.system_library {
            return format!("missing worker system library {}", system_library);
        }
        "worker build environment is missing a required system package".to_string()
    }

    fn remediation(&self) -> String {
        match (&self.pkg_config_file, &self.system_library) {
            (Some(pkg_config_file), Some(system_library)) => format!(
                "Install the worker-side development package that provides {} (system library {}) and ensure pkg-config can resolve it on the worker.",
                pkg_config_file, system_library
            ),
            (Some(pkg_config_file), None) => format!(
                "Install the worker-side development package that provides {} and ensure PKG_CONFIG_PATH includes its parent directory on the worker.",
                pkg_config_file
            ),
            (None, Some(system_library)) => format!(
                "Install the worker-side development package for system library {} and ensure pkg-config is configured on the worker.",
                system_library
            ),
            (None, None) => "Install the missing worker-side development package and ensure pkg-config can find it on the worker.".to_string(),
        }
    }

    fn log_detail(&self) -> String {
        let mut parts = Vec::new();
        if let Some(crate_name) = &self.crate_name {
            parts.push(format!("crate={}", crate_name));
        }
        if let Some(system_library) = &self.system_library {
            parts.push(format!("system_library={}", system_library));
        }
        if let Some(pkg_config_file) = &self.pkg_config_file {
            parts.push(format!("pkg_config_file={}", pkg_config_file));
        }
        if parts.is_empty() {
            "pkg-config/system dependency detection matched".to_string()
        } else {
            parts.join(" ")
        }
    }
}

fn detect_worker_system_dependency_failure(
    stderr: &str,
    exit_code: i32,
) -> Option<WorkerSystemDependencyFailure> {
    if exit_code == 0 {
        return None;
    }

    let mut system_library = None;
    let mut crate_name = None;
    let mut pkg_config_file = None;
    let mut pkg_config_signal = false;

    for raw_line in stderr.lines() {
        let line = raw_line.trim();
        let lower = line.to_ascii_lowercase();

        if lower.contains("pkg-config exited with status code")
            || lower.contains("pkg_config_path")
            || lower.contains("the system library `")
            || lower.contains(".pc` needs to be installed")
        {
            pkg_config_signal = true;
        }

        if let Some(value) = extract_tick_quoted_value(line, "The system library `") {
            system_library = Some(value);
        }
        if let Some(value) = extract_tick_quoted_value(line, "required by crate `") {
            crate_name = Some(value);
        }
        if let Some(value) = extract_tick_quoted_value(line, "The file `")
            && value.ends_with(".pc")
        {
            pkg_config_file = Some(value);
        }
    }

    if !pkg_config_signal || (system_library.is_none() && pkg_config_file.is_none()) {
        return None;
    }

    Some(WorkerSystemDependencyFailure {
        system_library,
        crate_name,
        pkg_config_file,
    })
}

fn extract_tick_quoted_value(line: &str, prefix: &str) -> Option<String> {
    let remainder = line.split_once(prefix)?.1;
    let value = remainder.split('`').next()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Check if the process was killed by a signal.
///
/// Exit codes > 128 indicate the process was terminated by a signal.
/// The signal number is exit_code - 128.
///
/// Common signals:
/// - 137 (SIGKILL = 9): Typically OOM killer
/// - 143 (SIGTERM = 15): Graceful termination request
/// - 139 (SIGSEGV = 11): Segmentation fault
#[allow(dead_code)]
fn is_signal_killed(exit_code: i32) -> Option<i32> {
    if exit_code > EXIT_SIGNAL_BASE {
        Some(exit_code - EXIT_SIGNAL_BASE)
    } else {
        None
    }
}

/// Format a signal number as a human-readable name.
#[allow(dead_code)]
fn signal_name(signal: i32) -> &'static str {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        6 => "SIGABRT",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        _ => "UNKNOWN",
    }
}

/// Map a classification kind to required runtime.
pub(crate) fn required_runtime_for_kind(kind: Option<CompilationKind>) -> RequiredRuntime {
    match kind {
        Some(k) => match k {
            CompilationKind::CargoBuild
            | CompilationKind::CargoTest
            | CompilationKind::CargoCheck
            | CompilationKind::CargoClippy
            | CompilationKind::CargoDoc
            | CompilationKind::CargoNextest
            | CompilationKind::CargoBench
            | CompilationKind::Rustc => RequiredRuntime::Rust,

            CompilationKind::BunTest | CompilationKind::BunTypecheck => RequiredRuntime::Bun,

            _ => RequiredRuntime::None,
        },
        None => RequiredRuntime::None,
    }
}

/// Get artifact patterns based on compilation kind.
///
/// Test and diagnostic commands use minimal patterns since their output is
/// streamed and the full target/ directory is not needed. This significantly
/// reduces artifact transfer time for commands that do not produce runnable
/// build artifacts.
fn get_artifact_patterns(kind: Option<CompilationKind>) -> Vec<String> {
    match kind {
        Some(CompilationKind::BunTest) | Some(CompilationKind::BunTypecheck) => {
            default_bun_artifact_patterns()
        }
        // Test, bench, and diagnostic commands do not need full target/.
        Some(CompilationKind::CargoTest)
        | Some(CompilationKind::CargoNextest)
        | Some(CompilationKind::CargoBench)
        | Some(CompilationKind::CargoCheck)
        | Some(CompilationKind::CargoClippy) => default_rust_test_artifact_patterns(),
        Some(CompilationKind::Rustc)
        | Some(CompilationKind::CargoBuild)
        | Some(CompilationKind::CargoDoc) => default_rust_artifact_patterns(),
        Some(CompilationKind::Gcc)
        | Some(CompilationKind::Gpp)
        | Some(CompilationKind::Clang)
        | Some(CompilationKind::Clangpp)
        | Some(CompilationKind::Make)
        | Some(CompilationKind::CmakeBuild)
        | Some(CompilationKind::Ninja)
        | Some(CompilationKind::Meson) => default_c_cpp_artifact_patterns(),
        _ => default_rust_artifact_patterns(),
    }
}

fn get_custom_target_artifact_patterns(kind: Option<CompilationKind>) -> Vec<String> {
    match kind {
        Some(CompilationKind::CargoTest)
        | Some(CompilationKind::CargoCheck)
        | Some(CompilationKind::CargoClippy) => Vec::new(),
        Some(CompilationKind::CargoNextest) | Some(CompilationKind::CargoBench) => {
            get_artifact_patterns(kind)
                .into_iter()
                .map(|pattern| {
                    pattern
                        .strip_prefix("target/")
                        .unwrap_or(pattern.as_str())
                        .to_string()
                })
                .collect()
        }
        _ => vec!["**".to_string()],
    }
}

const BUILD_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
struct BuildHeartbeatSnapshot {
    phase: BuildHeartbeatPhase,
    detail: Option<String>,
    progress_counter: u64,
    progress_percent: Option<f64>,
    remote_pgid_file: Option<String>,
}

impl BuildHeartbeatSnapshot {
    fn new() -> Self {
        Self {
            phase: BuildHeartbeatPhase::SyncUp,
            detail: Some("build_started".to_string()),
            progress_counter: 0,
            progress_percent: None,
            remote_pgid_file: None,
        }
    }

    fn update_phase(&mut self, phase: BuildHeartbeatPhase, detail: Option<String>) {
        self.phase = phase;
        self.detail = detail;
        self.progress_counter = self.progress_counter.saturating_add(1);
    }

    fn note_progress(&mut self) {
        self.progress_counter = self.progress_counter.saturating_add(1);
    }

    fn set_remote_pgid_file(&mut self, remote_pgid_file: Option<String>) {
        self.remote_pgid_file = remote_pgid_file;
    }
}

struct BuildHeartbeatLoop {
    socket_path: String,
    build_id: u64,
    worker_id: WorkerId,
    hook_pid: u32,
    state: Arc<Mutex<BuildHeartbeatSnapshot>>,
    stop_tx: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl BuildHeartbeatLoop {
    fn start(socket_path: &str, build_id: u64, worker_id: &WorkerId) -> Self {
        let state = Arc::new(Mutex::new(BuildHeartbeatSnapshot::new()));
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

        let socket_path_owned = socket_path.to_string();
        let worker_id_owned = worker_id.clone();
        let state_for_task = Arc::clone(&state);
        let hook_pid = std::process::id();

        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(BUILD_HEARTBEAT_INTERVAL);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let snapshot = {
                            state_for_task
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone()
                        };
                        let heartbeat = BuildHeartbeatRequest {
                            build_id,
                            worker_id: worker_id_owned.clone(),
                            hook_pid: Some(hook_pid),
                            remote_pgid_file: snapshot.remote_pgid_file.clone(),
                            phase: snapshot.phase,
                            detail: snapshot.detail,
                            progress_counter: Some(snapshot.progress_counter),
                            progress_percent: snapshot.progress_percent,
                        };
                        if let Err(e) = send_build_heartbeat(&socket_path_owned, &heartbeat).await {
                            debug!("build heartbeat send failed for build {}: {}", build_id, e);
                        }
                    }
                    _ = &mut stop_rx => break,
                }
            }
        });

        Self {
            socket_path: socket_path.to_string(),
            build_id,
            worker_id: worker_id.clone(),
            hook_pid,
            state,
            stop_tx: Some(stop_tx),
            task: Some(task),
        }
    }

    fn shared_state(&self) -> Arc<Mutex<BuildHeartbeatSnapshot>> {
        Arc::clone(&self.state)
    }

    fn update_phase(&self, phase: BuildHeartbeatPhase, detail: Option<String>) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .update_phase(phase, detail);
    }

    fn set_remote_pgid_file(&self, remote_pgid_file: Option<String>) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_remote_pgid_file(remote_pgid_file);
    }

    async fn flush(&self) {
        let snapshot = { self.state.lock().unwrap_or_else(|e| e.into_inner()).clone() };
        let heartbeat = BuildHeartbeatRequest {
            build_id: self.build_id,
            worker_id: self.worker_id.clone(),
            hook_pid: Some(self.hook_pid),
            remote_pgid_file: snapshot.remote_pgid_file.clone(),
            phase: snapshot.phase,
            detail: snapshot.detail,
            progress_counter: Some(snapshot.progress_counter),
            progress_percent: snapshot.progress_percent,
        };
        if let Err(e) = send_build_heartbeat(&self.socket_path, &heartbeat).await {
            debug!(
                "build heartbeat flush failed for build {}: {}",
                self.build_id, e
            );
        }
    }

    async fn finish(mut self, phase: BuildHeartbeatPhase, detail: Option<String>) {
        self.update_phase(phase, detail);
        self.flush().await;
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for BuildHeartbeatLoop {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn mark_heartbeat_progress(state: &Arc<Mutex<BuildHeartbeatSnapshot>>) {
    state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .note_progress();
}

/// Execute a compilation command on a remote worker.
///
/// This function:
/// 1. Syncs the project to the remote worker
/// 2. Executes the command remotely with streaming output
/// 3. Retrieves build artifacts back to local
///
/// Returns the execution result including exit code and stderr.
#[allow(clippy::too_many_arguments)] // Pipeline wiring favors explicit params
async fn execute_remote_compilation(
    worker: &SelectedWorker,
    command: &str,
    transfer_config: TransferConfig,
    env_allowlist: Vec<String>,
    forwarded_cargo_target_dir: Option<PathBuf>,
    compilation_config: &rch_common::CompilationConfig,
    toolchain: Option<&ToolchainInfo>,
    kind: Option<CompilationKind>,
    reporter: &HookReporter,
    socket_path: &str,
    color_mode: ColorMode,
    build_id: Option<u64>,
    topology_policy: &PathTopologyPolicy,
) -> anyhow::Result<RemoteExecutionResult> {
    let worker_config = selected_worker_to_config(worker);

    // Get current working directory and normalize it to the canonical project root.
    let project_root =
        std::env::current_dir().map_err(|e| TransferError::NoProjectRoot { source: e })?;
    let normalized_project = normalize_project_path_with_policy(&project_root, topology_policy)
        .map_err(|e| {
            anyhow::anyhow!(
                "Project path normalization failed for {}: {}",
                project_root.display(),
                e
            )
        })?;
    for decision in normalized_project.decision_trace() {
        reporter.verbose(&format!("[RCH] project path normalized: {}", decision));
    }
    let normalized_project_root = normalized_project.canonical_path().to_path_buf();

    let dependency_plan =
        build_dependency_runtime_plan(&normalized_project_root, kind, reporter, topology_policy);
    let exact_dependency_closure_sync = command_uses_cargo_dependency_graph(kind);
    if let Some(decision) = dependency_plan.fail_open_decision.as_ref() {
        let report = build_dependency_runtime_fail_open_report(
            &worker_config,
            &normalized_project_root,
            decision,
        );
        if let Ok(report_json) = serde_json::to_string(&report) {
            reporter.verbose(&format!(
                "[RCH] dependency planner fail-open report: {}",
                report_json
            ));
        }
        if exact_dependency_closure_sync
            && should_force_local_fallback_for_runtime_fail_open(decision.reason_code)
        {
            warn!(
                "Dependency planner fail-open on {} [{}]: refusing remote Cargo execution and falling back local ({})",
                worker_config.id, decision.reason_code, decision.remediation
            );
            reporter.verbose(&format!(
                "[RCH] dependency planner fail-open [{}]: exact dependency closure required, forcing local fallback — {}",
                decision.reason_code, decision.remediation
            ));
            return Err(DependencyPreflightFailure::from_report(report).into());
        }
        warn!(
            "Dependency planner fail-open on {} [{}]: proceeding with primary-root-only sync ({})",
            worker_config.id, decision.reason_code, decision.remediation
        );
        reporter.verbose(&format!(
            "[RCH] dependency planner fail-open [{}]: proceeding with primary root only — {}",
            decision.reason_code, decision.remediation
        ));
    }
    let raw_sync_roots = dependency_plan.sync_roots;
    let project_id = project_id_from_path(&normalized_project_root);
    let project_hash = compute_project_hash_with_dependency_roots_and_policy(
        &normalized_project_root,
        &raw_sync_roots,
        topology_policy,
    );
    let sync_plan = build_sync_closure_plan(
        &raw_sync_roots,
        &normalized_project_root,
        &project_hash,
        topology_policy,
    );
    let sync_roots = sync_plan
        .iter()
        .map(|entry| entry.local_root.clone())
        .collect::<Vec<_>>();
    let sync_manifest = build_sync_closure_manifest(&sync_plan, &normalized_project_root);

    let output_ctx = OutputContext::detect();
    let console = RchConsole::with_context(output_ctx);
    let feedback_visible = reporter.visibility != OutputVisibility::None && !console.is_machine();
    let progress_enabled =
        output_ctx.supports_rich() && reporter.visibility != OutputVisibility::None;
    let remote_pgid_file = build_id.and_then(|id| {
        sync_plan
            .iter()
            .find(|entry| entry.is_primary)
            .map(|entry| TransferPipeline::remote_pgid_file_path_for_root(&entry.remote_root, id))
    });
    let mut heartbeat_loop =
        build_id.map(|id| BuildHeartbeatLoop::start(socket_path, id, &worker_config.id));
    if let Some(loop_ref) = heartbeat_loop.as_ref() {
        loop_ref.set_remote_pgid_file(remote_pgid_file);
        loop_ref.update_phase(BuildHeartbeatPhase::SyncUp, Some("sync_start".to_string()));
        loop_ref.flush().await;
    }

    if feedback_visible {
        emit_job_banner(&console, output_ctx, worker, build_id);
    }

    info!(
        "Starting remote compilation pipeline for {} (hash: {})",
        project_id, project_hash
    );
    reporter.verbose(&format!(
        "[RCH] dependency sync roots planned: {}",
        sync_plan.len()
    ));
    for (idx, entry) in sync_plan.iter().enumerate() {
        reporter.verbose(&format!(
            "[RCH] dependency sync root {}/{}: {}",
            idx + 1,
            sync_plan.len(),
            entry.local_root.display()
        ));
    }
    match serde_json::to_string(&sync_manifest) {
        Ok(manifest_json) => {
            reporter.verbose(&format!(
                "[RCH] dependency sync manifest: {}",
                manifest_json
            ));
            info!(
                "Prepared dependency sync manifest for {} roots",
                sync_manifest.entries.len()
            );
        }
        Err(err) => warn!("Failed to serialize dependency sync manifest: {}", err),
    }
    reporter.verbose(&format!(
        "[RCH] sync start (project {} on {})",
        project_id, worker_config.id
    ));

    // Ensure deterministic remote topology before any repo synchronization.
    ensure_worker_projects_topology(&worker_config, reporter, topology_policy).await?;

    // Best-effort repo convergence for multi-repo dependency graphs.
    maybe_sync_repo_set_with_repo_updater(&worker_config, &sync_roots, reporter).await;

    // Build transfer pipelines with color mode, command timeout, and compilation kind.
    let command_timeout = compilation_config.timeout_for_kind(kind);
    let effective_env_allowlist =
        cargo_target_env_allowlist(&env_allowlist, forwarded_cargo_target_dir.is_some());
    let cargo_env_overrides = cargo_target_env_overrides(forwarded_cargo_target_dir.as_deref());
    let remote_cargo_target_dir_name_override = forwarded_cargo_target_dir
        .as_ref()
        .map(|_| remote_cargo_target_dir_name(build_id, &worker_config.id));
    let mut primary_pipeline: Option<TransferPipeline> = None;
    let mut aggregate_sync_result: Option<SyncResult> = None;

    // Step 1: Sync project to remote
    info!("Syncing project to worker {}...", worker_config.id);
    let mut upload_progress = if progress_enabled {
        Some(TransferProgress::upload(
            output_ctx,
            "Syncing workspace closure",
            reporter.visibility == OutputVisibility::None,
        ))
    } else {
        None
    };
    let mut root_outcomes: Vec<(SyncClosurePlanEntry, SyncRootOutcome)> = Vec::new();
    for entry in &sync_plan {
        let mut root_pipeline = TransferPipeline::new(
            entry.local_root.clone(),
            entry.project_id.clone(),
            entry.root_hash.clone(),
            transfer_config.clone(),
        )
        .with_color_mode(color_mode)
        .with_command_timeout(command_timeout)
        .with_compilation_config(compilation_config.clone())
        .with_compilation_kind(kind)
        .with_remote_path_override(entry.remote_root.clone())
        .with_build_id(build_id);
        if entry.mode == SyncClosureMode::WorkspaceMetadata {
            root_pipeline = root_pipeline
                .with_sync_include_patterns(workspace_metadata_sync_patterns())
                .with_sync_delete(false);
        }
        if entry.is_primary {
            root_pipeline = root_pipeline.with_env_allowlist(effective_env_allowlist.clone());
            if let Some(overrides) = cargo_env_overrides.as_ref() {
                root_pipeline = root_pipeline.with_env_overrides(overrides.clone());
            }
            if let Some(name) = remote_cargo_target_dir_name_override.as_ref() {
                root_pipeline = root_pipeline.with_remote_cargo_target_dir_name(name.clone());
            }
        }

        if exact_dependency_closure_sync {
            reporter.verbose(&format!(
                "[RCH] exact dependency closure sync required; bypassing transfer estimator for {}",
                entry.local_root.display()
            ));
        } else if let Some(skip_reason) = root_pipeline.should_skip_transfer(&worker_config).await {
            info!(
                "Transfer estimation indicates skip for {}: {} (worker {})",
                entry.local_root.display(),
                skip_reason,
                worker_config.id
            );
            reporter.verbose(&format!(
                "[RCH] skip transfer for {}: {}",
                entry.local_root.display(),
                skip_reason
            ));
            if entry.is_primary {
                // Primary root skip is fatal — cannot build without the main project.
                return Err(TransferError::TransferSkipped {
                    reason: skip_reason,
                }
                .into());
            }
            root_outcomes.push((
                entry.clone(),
                SyncRootOutcome::Skipped {
                    reason: skip_reason,
                },
            ));
            continue;
        }

        reporter.verbose(&format!(
            "[RCH] syncing dependency root {} to remote {}",
            entry.local_root.display(),
            entry.remote_root.as_str()
        ));
        let sync_attempt = if let Some(progress) = &mut upload_progress {
            root_pipeline
                .sync_to_remote_streaming(&worker_config, |line| {
                    progress.update_from_line(line);
                })
                .await
        } else {
            root_pipeline.sync_to_remote(&worker_config).await
        };
        match sync_attempt {
            Ok(root_sync_result) => {
                aggregate_sync_result = Some(match &aggregate_sync_result {
                    Some(existing) => merge_sync_result(existing, &root_sync_result),
                    None => root_sync_result,
                });
                if entry.is_primary {
                    primary_pipeline = Some(root_pipeline);
                }
                root_outcomes.push((entry.clone(), SyncRootOutcome::Synced));
            }
            Err(e) => {
                if entry.is_primary || exact_dependency_closure_sync {
                    // Cargo dependency-closure builds must not continue against
                    // stale sibling repositories on the worker.
                    return Err(e);
                }
                // Dependency root failure is non-fatal (fail-open for deps).
                warn!(
                    "Dependency root sync failed for {} (non-fatal): {}",
                    entry.local_root.display(),
                    e
                );
                reporter.verbose(&format!(
                    "[RCH] dependency root sync failed (fail-open): {} — {}",
                    entry.local_root.display(),
                    e
                ));
                root_outcomes.push((
                    entry.clone(),
                    SyncRootOutcome::Failed {
                        error: e.to_string(),
                    },
                ));
            }
        }
    }

    // Emit structured partial-sync diagnostics when any dependency roots had issues.
    let failed_count = root_outcomes
        .iter()
        .filter(|(_, o)| !matches!(o, SyncRootOutcome::Synced))
        .count();
    if failed_count > 0 {
        warn!(
            "Partial sync: {}/{} closure roots had issues (build continues with available roots)",
            failed_count,
            sync_plan.len()
        );
        for (entry, outcome) in &root_outcomes {
            match outcome {
                SyncRootOutcome::Synced => {}
                SyncRootOutcome::Skipped { reason } => {
                    info!(
                        "  dependency root skipped: {} — {}",
                        entry.local_root.display(),
                        reason
                    );
                }
                SyncRootOutcome::Failed { error } => {
                    info!(
                        "  dependency root failed: {} — {}",
                        entry.local_root.display(),
                        error
                    );
                }
            }
        }
    }
    let sync_result = aggregate_sync_result
        .ok_or_else(|| anyhow::anyhow!("dependency sync produced no transfer result"))?;
    let pipeline = primary_pipeline.ok_or_else(|| {
        anyhow::anyhow!(
            "dependency sync did not include primary project root {}",
            normalized_project_root.display()
        )
    })?;
    info!(
        "Sync complete: {} files, {} bytes in {}ms",
        sync_result.files_transferred, sync_result.bytes_transferred, sync_result.duration_ms
    );
    // Opportunistically reclaim *abandoned* per-job target dirs for this project
    // on the chosen worker. Only siblings with no file activity past the threshold
    // are removed, so any dir still in active use is preserved and this never races
    // a concurrent build on the same project. The heavy removal is detached on the
    // worker (a backgrounded rm); only a quick SSH dispatch is awaited here.
    // Best-effort; gated to the forwarded-CARGO_TARGET_DIR mode that makes per-job dirs.
    if forwarded_cargo_target_dir.is_some() {
        // Cheap, current-project-only reap: only this build's own repo dir is
        // swept for abandoned sibling per-job dirs. The durable cross-project
        // GC (every repo under the worker's sync-root) now runs OFF this
        // per-dispatch path in the background daemon sweep
        // (`rchd::stale_target_reap`), so this stays a single `cd` + glob loop.
        pipeline
            .reap_stale_sibling_per_job_target_dirs(&worker_config, stale_target_reap_idle_hours())
            .await;
    }
    reporter.verbose(&format!(
        "[RCH] sync done: {} files, {} bytes in {}ms",
        sync_result.files_transferred, sync_result.bytes_transferred, sync_result.duration_ms
    ));
    if let Some(progress) = &mut upload_progress {
        progress.apply_summary(sync_result.bytes_transferred, sync_result.files_transferred);
        progress.finish();
    }
    if let Some(loop_ref) = heartbeat_loop.as_ref() {
        loop_ref.update_phase(
            BuildHeartbeatPhase::Execute,
            Some("remote_exec_start".to_string()),
        );
        loop_ref.flush().await;
    }

    if command_uses_cargo_dependency_graph(kind) {
        verify_remote_dependency_manifests(&worker_config, &root_outcomes, reporter).await?;
    }

    // Step 2: Execute command remotely with streaming output
    // Mask sensitive data (API keys, tokens, passwords) before logging
    let masked_command = mask_sensitive_command(command);
    info!("Executing command remotely: {}", masked_command);
    reporter.verbose(&format!("[RCH] exec start: {}", masked_command));

    // Capture stderr for toolchain failure detection
    //
    // `std::env::set_var` is unsafe in Rust 2024, but reading env is fine. For streaming,
    // we need shared mutable state across stdout/stderr callbacks; use `Rc<RefCell<_>>`
    // to avoid borrow-checker conflicts between the two closures.
    use std::cell::RefCell;
    use std::rc::Rc;

    let stderr_capture_cell = Rc::new(RefCell::new(String::new()));

    struct CompileUiState {
        progress: Option<CompilationProgress>,
        output: String,
        output_truncated: bool,
        crates_compiled: Option<u32>,
        warnings: Option<u32>,
    }
    let use_compile_progress = progress_enabled
        && matches!(
            kind,
            Some(
                CompilationKind::CargoBuild
                    | CompilationKind::CargoCheck
                    | CompilationKind::CargoClippy
                    | CompilationKind::CargoDoc
                    | CompilationKind::CargoBench
            )
        );
    let ui_state = Rc::new(RefCell::new(CompileUiState {
        progress: if use_compile_progress {
            Some(CompilationProgress::new(
                output_ctx,
                worker_config.id.as_str().to_string(),
                reporter.visibility == OutputVisibility::None,
            ))
        } else {
            None
        },
        output: String::new(),
        output_truncated: false,
        crates_compiled: None,
        warnings: None,
    }));

    // Add per-worker CARGO_HOME isolation to prevent cache lock contention
    let isolated_command = add_cargo_isolation(command, &worker_config.id);

    // Stream stdout/stderr to our stderr so the agent sees the output
    let command_with_telemetry = wrap_command_with_telemetry(&isolated_command, &worker_config.id);
    let ui_state_stdout = Rc::clone(&ui_state);
    let ui_state_stderr = Rc::clone(&ui_state);
    let stderr_capture_stderr = Rc::clone(&stderr_capture_cell);
    let heartbeat_state_stdout = heartbeat_loop
        .as_ref()
        .map(BuildHeartbeatLoop::shared_state);
    let heartbeat_state_stderr = heartbeat_loop
        .as_ref()
        .map(BuildHeartbeatLoop::shared_state);
    let mut suppress_telemetry = false;

    let result = pipeline
        .execute_remote_streaming(
            &worker_config,
            &command_with_telemetry,
            toolchain,
            move |line| {
                if suppress_telemetry {
                    return;
                }
                if line.trim() == PIGGYBACK_MARKER {
                    suppress_telemetry = true;
                    return;
                }
                if let Some(state) = heartbeat_state_stdout.as_ref() {
                    mark_heartbeat_progress(state);
                }

                let mut state = ui_state_stdout.borrow_mut();
                if let Some(progress) = state.progress.as_mut() {
                    progress.update_from_line(line);
                    if !state.output_truncated {
                        const MAX_OUTPUT_BYTES: usize = 256 * 1024;
                        if state.output.len() + line.len() <= MAX_OUTPUT_BYTES {
                            state.output.push_str(line);
                        } else {
                            state.output_truncated = true;
                        }
                    }
                } else {
                    // Write stdout lines to stderr (hook stdout is for protocol)
                    eprint!("{}", line);
                }
            },
            move |line| {
                if let Some(state) = heartbeat_state_stderr.as_ref() {
                    mark_heartbeat_progress(state);
                }
                // Write stderr lines to stderr and capture for analysis
                let mut state = ui_state_stderr.borrow_mut();
                if let Some(progress) = state.progress.as_mut() {
                    progress.update_from_line(line);
                    if !state.output_truncated {
                        const MAX_OUTPUT_BYTES: usize = 256 * 1024;
                        if state.output.len() + line.len() <= MAX_OUTPUT_BYTES {
                            state.output.push_str(line);
                        } else {
                            state.output_truncated = true;
                        }
                    }
                } else {
                    eprint!("{}", line);
                }
                drop(state);

                stderr_capture_stderr.borrow_mut().push_str(line);
            },
        )
        .await?;

    let stderr_capture = std::mem::take(&mut *stderr_capture_cell.borrow_mut());

    info!(
        "Remote command finished: exit={} in {}ms",
        result.exit_code, result.duration_ms
    );
    reporter.verbose(&format!(
        "[RCH] exec done: exit={} in {}ms",
        result.exit_code, result.duration_ms
    ));

    {
        let mut state = ui_state.borrow_mut();

        let mut progress_stats = None;
        if let Some(progress) = state.progress.as_mut() {
            progress_stats = Some((progress.crates_compiled(), progress.warnings()));
            if result.success() {
                progress.finish();
            } else {
                let message = stderr_capture
                    .lines()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("remote compilation failed");
                progress.finish_error(message);
            }
        }
        if let Some((crates_compiled, warnings)) = progress_stats {
            state.crates_compiled = Some(crates_compiled);
            state.warnings = Some(warnings);
        }

        if use_compile_progress && !result.success() && !state.output.is_empty() {
            eprintln!("{}", state.output);
            if state.output_truncated {
                eprintln!("[RCH] output truncated (increase buffer if needed)");
            }
        }
    }

    let mut artifacts_result: Option<SyncResult> = None;
    let mut artifacts_failed = false;
    // Step 3: Retrieve artifacts
    if result.success() {
        if let Some(loop_ref) = heartbeat_loop.as_ref() {
            loop_ref.update_phase(
                BuildHeartbeatPhase::SyncDown,
                Some("artifact_sync_start".to_string()),
            );
            loop_ref.flush().await;
        }
        info!("Retrieving build artifacts...");
        reporter.verbose("[RCH] artifacts: retrieving...");
        let artifact_patterns = get_artifact_patterns(kind);
        let heartbeat_state_download = heartbeat_loop
            .as_ref()
            .map(BuildHeartbeatLoop::shared_state);
        let mut download_progress = if progress_enabled {
            Some(TransferProgress::download(
                output_ctx,
                "Retrieving artifacts",
                reporter.visibility == OutputVisibility::None,
            ))
        } else {
            None
        };

        let retrieval = if let Some(progress) = &mut download_progress {
            pipeline
                .retrieve_artifacts_streaming(&worker_config, &artifact_patterns, |line| {
                    progress.update_from_line(line);
                    if let Some(state) = heartbeat_state_download.as_ref() {
                        mark_heartbeat_progress(state);
                    }
                })
                .await
        } else {
            pipeline
                .retrieve_artifacts(&worker_config, &artifact_patterns)
                .await
        };

        match retrieval {
            Ok(artifact_result) => {
                info!(
                    "Artifacts retrieved: {} files, {} bytes in {}ms",
                    artifact_result.files_transferred,
                    artifact_result.bytes_transferred,
                    artifact_result.duration_ms
                );
                reporter.verbose(&format!(
                    "[RCH] artifacts done: {} files, {} bytes in {}ms",
                    artifact_result.files_transferred,
                    artifact_result.bytes_transferred,
                    artifact_result.duration_ms
                ));
                if let Some(progress) = &mut download_progress {
                    progress.apply_summary(
                        artifact_result.bytes_transferred,
                        artifact_result.files_transferred,
                    );
                    progress.finish();
                }
                artifacts_result = Some(match artifacts_result.take() {
                    Some(existing) => merge_sync_result(&existing, &artifact_result),
                    None => artifact_result,
                });
            }
            Err(e) => {
                artifacts_failed = true;

                // Extract rsync exit code from error message if present
                let error_str = e.to_string();
                let rsync_exit_code = error_str.find("exit code").and_then(|_| {
                    error_str
                        .split("exit code")
                        .nth(1)
                        .and_then(|s| s.split(':').next())
                        .and_then(|s| {
                            s.trim()
                                .trim_start_matches("Some(")
                                .trim_end_matches(')')
                                .parse()
                                .ok()
                        })
                });

                // Create structured warning (bd-1q3p)
                let warning = ArtifactRetrievalWarning::new(
                    worker_config.id.as_str(),
                    artifact_patterns.clone(),
                    &error_str,
                    rsync_exit_code,
                );

                warn!("Failed to retrieve artifacts: {}", e);

                // Show detailed warning in verbose mode or when not in machine mode
                if !console.is_machine() {
                    reporter.verbose(&warning.format_warning());
                } else {
                    // For machine mode, output JSON warning
                    debug!("Artifact retrieval warning (JSON): {}", warning.to_json());
                    reporter.verbose("[RCH] artifacts failed (continuing)");
                }

                if let Some(progress) = &mut download_progress {
                    progress.finish_error(&e.to_string());
                }
                // Continue anyway - compilation succeeded
            }
        }

        if let Some(local_target_dir) = forwarded_cargo_target_dir.as_ref() {
            let remote_target_path = pipeline.remote_cargo_target_dir();
            let custom_patterns = get_custom_target_artifact_patterns(kind);
            if custom_patterns.is_empty() {
                reporter.verbose(&format!(
                    "[RCH] custom target dir sync skipped for {} after command with no target artifacts",
                    local_target_dir.display()
                ));
            } else {
                let target_pipeline = TransferPipeline::new(
                    local_target_dir.clone(),
                    project_id_from_path(local_target_dir),
                    compute_project_hash_with_dependency_roots_and_policy(
                        local_target_dir,
                        &[],
                        topology_policy,
                    ),
                    transfer_config.clone(),
                )
                .with_color_mode(color_mode)
                .with_command_timeout(command_timeout)
                .with_compilation_config(compilation_config.clone())
                .with_compilation_kind(kind)
                .with_remote_path_override(remote_target_path.clone());

                let mut target_progress = if progress_enabled {
                    Some(TransferProgress::download(
                        output_ctx,
                        "Syncing custom CARGO_TARGET_DIR artifacts",
                        reporter.visibility == OutputVisibility::None,
                    ))
                } else {
                    None
                };

                let target_retrieval = if let Some(progress) = &mut target_progress {
                    let heartbeat_state_target = heartbeat_loop
                        .as_ref()
                        .map(BuildHeartbeatLoop::shared_state);
                    target_pipeline
                        .retrieve_artifacts_streaming(&worker_config, &custom_patterns, |line| {
                            progress.update_from_line(line);
                            if let Some(state) = heartbeat_state_target.as_ref() {
                                mark_heartbeat_progress(state);
                            }
                        })
                        .await
                } else {
                    target_pipeline
                        .retrieve_artifacts(&worker_config, &custom_patterns)
                        .await
                };

                match target_retrieval {
                    Ok(target_result) => {
                        info!(
                            "Custom CARGO_TARGET_DIR artifacts retrieved: {} files, {} bytes in {}ms",
                            target_result.files_transferred,
                            target_result.bytes_transferred,
                            target_result.duration_ms
                        );
                        reporter.verbose(&format!(
                            "[RCH] custom target dir sync done: {} -> {} ({} files, {} bytes in {}ms)",
                            remote_target_path,
                            local_target_dir.display(),
                            target_result.files_transferred,
                            target_result.bytes_transferred,
                            target_result.duration_ms
                        ));
                        if let Some(progress) = &mut target_progress {
                            progress.apply_summary(
                                target_result.bytes_transferred,
                                target_result.files_transferred,
                            );
                            progress.finish();
                        }
                        artifacts_result = Some(match artifacts_result.take() {
                            Some(existing) => merge_sync_result(&existing, &target_result),
                            None => target_result,
                        });
                    }
                    Err(e) => {
                        artifacts_failed = true;
                        warn!("Failed to sync custom CARGO_TARGET_DIR artifacts: {}", e);
                        reporter.verbose(&format!(
                            "[RCH] custom target dir sync failed for {}: {}",
                            local_target_dir.display(),
                            e
                        ));
                        if let Some(progress) = &mut target_progress {
                            progress.finish_error(&e.to_string());
                        }
                    }
                }
            }
        }
    }

    // Step 4: Extract and forward telemetry (piggybacked in stdout)
    let extraction = extract_piggybacked_telemetry(&result.stdout);
    if let Some(error) = extraction.extraction_error {
        warn!("Telemetry extraction failed: {}", error);
    }
    if let Some(telemetry) = extraction.telemetry
        && let Err(e) = send_telemetry(socket_path, TelemetrySource::Piggyback, &telemetry).await
    {
        warn!("Failed to forward telemetry to daemon: {}", e);
    }

    if is_test_kind(kind)
        && let Some(kind) = kind
    {
        let record = TestRunRecord::new(
            project_id.clone(),
            worker_config.id.as_str().to_string(),
            command.to_string(),
            kind,
            result.exit_code,
            result.duration_ms,
        );
        if let Err(e) = send_test_run(socket_path, &record).await {
            warn!("Failed to forward test run telemetry: {}", e);
        }
    }

    let (crates_compiled, output_snapshot) = {
        let state = ui_state.borrow();
        (state.crates_compiled, state.output.clone())
    };

    if feedback_visible {
        render_compile_summary(
            &console,
            output_ctx,
            worker,
            build_id,
            &sync_result,
            result.duration_ms,
            artifacts_result.as_ref(),
            artifacts_failed,
            cache_hit(&sync_result),
            result.success(),
        );
    }

    if result.success() {
        let artifacts_summary = artifacts_result.as_ref().map(|artifact| ArtifactSummary {
            files: u64::from(artifact.files_transferred),
            bytes: artifact.bytes_transferred,
        });
        let target_label = detect_target_label(command, &output_snapshot);

        let summary = CelebrationSummary::new(project_id.clone(), result.duration_ms)
            .worker(worker_config.id.as_str())
            .crates_compiled(crates_compiled)
            .artifacts(artifacts_summary)
            .cache_hit(Some(cache_hit(&sync_result)))
            .target(target_label)
            .quiet(reporter.visibility == OutputVisibility::None);

        CompletionCelebration::new(summary).record_and_render(output_ctx);
    }

    // Construct per-phase timing breakdown
    let timing = CommandTimingBreakdown {
        sync_up: Some(Duration::from_millis(sync_result.duration_ms)),
        exec: Some(Duration::from_millis(result.duration_ms)),
        sync_down: artifacts_result
            .as_ref()
            .map(|ar| Duration::from_millis(ar.duration_ms)),
        ..Default::default()
    };

    if let Some(loop_ref) = heartbeat_loop.take() {
        let detail = if result.success() {
            Some("build_complete".to_string())
        } else {
            Some(format!("build_exit_{}", result.exit_code))
        };
        loop_ref.finish(BuildHeartbeatPhase::Finalize, detail).await;
    }

    Ok(RemoteExecutionResult {
        exit_code: result.exit_code,
        stderr: stderr_capture,
        duration_ms: result.duration_ms,
        timing,
    })
}

/// Add per-worker CARGO_HOME isolation to prevent cache lock contention.
fn add_cargo_isolation(command: &str, worker_id: &WorkerId) -> String {
    // Check if this is a cargo command that could benefit from isolation
    if !command.contains("cargo") {
        return command.to_string();
    }

    // Generate unique cargo home per worker session to prevent cache lock contention
    let session_id = std::process::id();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    // The staging base is resolved on the worker at execution time (honoring
    // $TMPDIR / /data/tmp / /tmp) rather than hardcoding /tmp, so these caches
    // don't eat RAM on tmpfs-/tmp hosts. `cargo_home` is therefore a shell
    // expression (`${RCH_CH_BASE}/rch-cargo-home-…`) and must be double-quoted,
    // not shell-escaped, so `$RCH_CH_BASE` expands; the worker_id is sanitized
    // and the rest is numeric, so the basename needs no further escaping.
    let safe_worker_id = sanitize_cargo_home_token(worker_id.as_str());
    let cargo_home =
        rch_common::remote_cargo_home_expr(&format!("{safe_worker_id}-{session_id}-{timestamp}"));
    let quoted_cargo_home = format!("\"{cargo_home}\"");
    let base_prelude = rch_common::remote_cargo_home_base_prelude();

    let escaped_command = shell_escape::escape(command.into());
    let script = format!(
        "{base_prelude}; mkdir -p {cargo_home} || exit $?; export CARGO_HOME={cargo_home}; sh -c {command}; status=$?; rm -rf {cargo_home}; exit $status",
        base_prelude = base_prelude,
        cargo_home = quoted_cargo_home,
        command = escaped_command
    );

    // The transfer layer may prepend `timeout ...` directly before this string.
    // Running the env assignment inside an explicit shell prevents `timeout`
    // from trying to exec `CARGO_HOME=...` as argv[0], while preserving the
    // original cargo exit status after cleanup.
    format!("sh -c {}", shell_escape::escape(script.into()))
}

fn wrap_command_with_telemetry(command: &str, worker_id: &WorkerId) -> String {
    let escaped_worker = shell_escape::escape(worker_id.as_str().into());
    // Use newline instead of semicolon to ensure trailing comments in command
    // don't comment out the status capture logic.
    format!(
        "{cmd}\nstatus=$?; if command -v rch-telemetry >/dev/null 2>&1; then \
         telemetry=$(rch-telemetry collect --format json --worker-id {worker} 2>/dev/null || true); \
         if [ -n \"$telemetry\" ]; then echo '{marker}'; echo \"$telemetry\"; fi; \
         fi; exit $status",
        cmd = command,
        worker = escaped_worker,
        marker = PIGGYBACK_MARKER
    )
}

async fn send_telemetry(
    socket_path: &str,
    source: TelemetrySource,
    telemetry: &WorkerTelemetry,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(());
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    let body = telemetry.to_json()?;
    let request = format!(
        "POST /telemetry/ingest?source={}\n{}\n",
        urlencoding_encode(&source.to_string()),
        body
    );

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;
    writer.shutdown().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

async fn send_test_run(socket_path: &str, record: &TestRunRecord) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(());
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    let body = record.to_json()?;
    let request = format!("POST /test-run\n{}\n", body);

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;
    writer.shutdown().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

async fn send_build_heartbeat(
    socket_path: &str,
    heartbeat: &BuildHeartbeatRequest,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(());
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    let body = serde_json::to_string(heartbeat)?;
    let request = format!("POST /build-heartbeat\n{}\n", body);
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;
    writer.shutdown().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rch_common::mock::{
        self, MockConfig, MockRsyncConfig, clear_mock_overrides, set_mock_enabled_override,
        set_mock_rsync_config_override, set_mock_ssh_config_override,
    };
    use rch_common::test_guard;
    use rch_common::{SelectionReason, TierDecision, ToolInput, classify_command_detailed};
    use serial_test::serial;
    use std::sync::OnceLock;
    use tokio::io::BufReader as TokioBufReader;
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    fn delegated_command(output: &HookOutput) -> &str {
        if let HookOutput::AllowWithModifiedCommand(modified) = output {
            &modified.hook_specific_output.updated_input.command
        } else {
            assert!(
                matches!(output, HookOutput::AllowWithModifiedCommand(_)),
                "expected AllowWithModifiedCommand"
            );
            ""
        }
    }

    // ------------------------------------------------------------------
    // join_exec_command tests — guard against the `.join(" ")` round-trip
    // corruption that was present when `rch exec --` rebuilt a command
    // string for `sh -c` (bug audit 2026-04-23).
    // ------------------------------------------------------------------

    #[test]
    fn join_exec_command_plain_args_unchanged() {
        let _guard = test_guard!();
        let parts = vec![
            "cargo".to_string(),
            "build".to_string(),
            "--release".to_string(),
        ];
        let joined = join_exec_command(&parts);
        // shell_words::split of the result should reproduce the original argv.
        let round_trip = shell_words::split(&joined).expect("valid shell words");
        assert_eq!(round_trip, parts);
    }

    #[test]
    fn join_exec_command_preserves_space_bearing_arg() {
        let _guard = test_guard!();
        // The outer shell merges `--features='foo bar'` into one argv
        // entry with a literal space. We must re-quote so `sh -c` does
        // not re-split it into two tokens.
        let parts = vec![
            "cargo".to_string(),
            "build".to_string(),
            "--features=foo bar".to_string(),
        ];
        let joined = join_exec_command(&parts);
        let round_trip = shell_words::split(&joined).expect("valid shell words");
        assert_eq!(
            round_trip, parts,
            "space must survive round-trip through sh"
        );
    }

    #[test]
    fn join_exec_command_preserves_quote_metachars() {
        let _guard = test_guard!();
        let parts = vec![
            "cargo".to_string(),
            "run".to_string(),
            "--".to_string(),
            "he said \"hi\"".to_string(),
            "$PATH".to_string(),
            "a;b".to_string(),
        ];
        let joined = join_exec_command(&parts);
        let round_trip = shell_words::split(&joined).expect("valid shell words");
        assert_eq!(round_trip, parts);
    }

    #[test]
    fn join_exec_command_splits_single_shell_command_arg() {
        let _guard = test_guard!();
        let parts = vec![
            "env RUSTFLAGS=\"-C linker=cc\" cargo build --bin generate_react_goldens".to_string(),
        ];
        let joined = join_exec_command(&parts);
        let round_trip = shell_words::split(&joined).expect("valid shell words");
        assert_eq!(
            round_trip,
            vec![
                "env".to_string(),
                "RUSTFLAGS=-C linker=cc".to_string(),
                "cargo".to_string(),
                "build".to_string(),
                "--bin".to_string(),
                "generate_react_goldens".to_string(),
            ]
        );
        assert!(
            !joined.starts_with("'env "),
            "env wrapper must remain the executable, not part of one quoted command: {joined}"
        );
    }

    #[test]
    fn join_exec_command_preserves_already_split_env_prefix() {
        let _guard = test_guard!();
        let parts = vec![
            "env".to_string(),
            "RUSTFLAGS=-C linker=cc".to_string(),
            "cargo".to_string(),
            "build".to_string(),
        ];
        let joined = join_exec_command(&parts);
        let round_trip = shell_words::split(&joined).expect("valid shell words");
        assert_eq!(round_trip, parts);
    }

    #[test]
    fn join_exec_command_empty_input() {
        let _guard = test_guard!();
        let parts: Vec<String> = Vec::new();
        assert_eq!(join_exec_command(&parts), "");
    }

    #[test]
    fn local_fallback_command_bypasses_cargo_wrapper() {
        let _guard = test_guard!();
        let command = local_fallback_command("cargo test -p rch");

        let has_bypass = command.get_envs().any(|(key, value)| {
            key == std::ffi::OsStr::new(RCH_CARGO_WRAPPER_BYPASS_ENV)
                && value == Some(std::ffi::OsStr::new("1"))
        });
        assert!(
            has_bypass,
            "local fallback must bypass the PATH cargo wrapper to avoid recursive rch exec"
        );

        let args = command.get_args().collect::<Vec<_>>();
        assert_eq!(
            args,
            vec![
                std::ffi::OsStr::new("-c"),
                std::ffi::OsStr::new("cargo test -p rch")
            ]
        );
    }

    #[test]
    fn remote_required_fallback_refuses_before_building_local_shell_command() {
        let _guard = test_guard!();
        let command = "bash -lc 'cargo test --lib focused_case -- --nocapture'";

        assert!(
            matches!(
                local_fallback_command_for_policy(command, true),
                Err(LocalFallbackRefusal::RemoteRequired)
            ),
            "remote-required policy must refuse before constructing a local shell fallback"
        );
        assert!(
            local_fallback_command_for_policy(command, false).is_ok(),
            "ordinary local fallback behavior remains available when remote is not required"
        );
    }

    #[test]
    fn remote_required_non_compilation_shell_wrapped_cargo_has_stable_refusal_code() {
        let _guard = test_guard!();
        let parts = vec![
            "bash".to_string(),
            "-lc".to_string(),
            "cargo test --lib focused_case -- --nocapture".to_string(),
        ];
        let command = join_exec_command(&parts);
        let classification = classify_command(&command);

        assert!(
            !classification.is_compilation,
            "global classification should keep arbitrary shell wrappers out of hook-mode offload"
        );
        assert!(
            matches!(
                local_fallback_command_for_policy(&command, true),
                Err(LocalFallbackRefusal::RemoteRequired)
            ),
            "RCH_REQUIRE_REMOTE must prevent the shell from running locally even when classification rejects it"
        );
        assert!(remote_required_refusal_summary("non-compilation command").contains("RCH-E301"));
        assert!(
            !remote_required_refusal_summary("dependency preflight failed").contains("RCH-E301"),
            "dependency-topology refusals should remain distinguishable from command-classification refusals"
        );
    }

    #[test]
    fn env_flag_enabled_accepts_common_truthy_values() {
        let _guard = test_guard!();

        for value in ["1", "true", "TRUE", "yes", "on"] {
            assert!(env_flag_enabled(value), "{value} should be truthy");
        }

        for value in ["", "0", "false", "no", "off", "remote"] {
            assert!(!env_flag_enabled(value), "{value} should not be truthy");
        }
    }

    #[test]
    fn hook_panic_fail_open_can_be_enabled_without_env_var() {
        let _guard = test_guard!();

        let previous = HOOK_MODE_PANIC_FAIL_OPEN.swap(false, Ordering::AcqRel);
        enable_hook_mode_panic_fail_open();
        assert!(
            hook_mode_panic_fail_open_enabled(),
            "installing the hook panic handler must mark no-subcommand hook mode as fail-open even when RCH_HOOK_MODE is unset"
        );
        HOOK_MODE_PANIC_FAIL_OPEN.store(previous, Ordering::Release);
    }

    fn test_lock() -> &'static Mutex<()> {
        static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_MUTEX.get_or_init(|| Mutex::new(()))
    }

    struct TestOverridesGuard;

    impl TestOverridesGuard {
        fn set(socket_path: &str, ssh_config: MockConfig, rsync_config: MockRsyncConfig) -> Self {
            let mut config = rch_common::RchConfig::default();
            config.general.socket_path = socket_path.to_string();
            crate::config::set_test_config_override(Some(config));

            set_mock_enabled_override(Some(true));
            set_mock_ssh_config_override(Some(ssh_config));
            set_mock_rsync_config_override(Some(rsync_config));

            Self
        }
    }

    impl Drop for TestOverridesGuard {
        fn drop(&mut self) {
            crate::config::set_test_config_override(None);
            clear_mock_overrides();
        }
    }

    struct ConfigOverrideGuard;

    impl ConfigOverrideGuard {
        fn set(config: rch_common::RchConfig) -> Self {
            crate::config::set_test_config_override(Some(config));
            Self
        }
    }

    impl Drop for ConfigOverrideGuard {
        fn drop(&mut self) {
            crate::config::set_test_config_override(None);
        }
    }

    /// RAII wrapper around `tempfile::TempDir` that always reports the
    /// canonical form of the scratch path via `.path()`, so subdirectories
    /// derived from it pass `starts_with` against a canonicalized
    /// topology root even when the OS routes `/tmp` through a symlink
    /// (macOS resolves `/tmp` to `/private/tmp`).
    ///
    /// Deliberately mimics the `tempfile::TempDir` shape (`.path()` only)
    /// so call sites can continue to write
    /// `temp_dir.path().join("subdir")` without change.
    struct CanonicalTempDir {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl CanonicalTempDir {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    /// Create a platform-portable tempdir and a matching `PathTopologyPolicy`
    /// whose canonical root points at the tempdir's canonical path.
    ///
    /// Tests previously used `tempfile::tempdir_in("/data/projects")` +
    /// `PathTopologyPolicy::default()` so the default `/data/projects`
    /// topology would accept the tempdir paths. That pins tests to the
    /// maintainer's dev machine and fails on every CI runner that doesn't
    /// have `/data/projects`. This helper keeps the intent (tempdir paths
    /// are "within topology") without the path pin — we simply build a
    /// policy that recognises the tempdir itself as the topology root.
    ///
    /// The tempdir path is canonicalized so macOS `/tmp -> /private/tmp`
    /// and similar symlinks don't cause `starts_with` mismatches when
    /// paths are compared against the policy.
    ///
    /// The `alias_root` is set to a sibling path that is deliberately *not*
    /// a prefix of the tempdir. This keeps
    /// `normalize_project_path_with_policy` from trying to verify the alias
    /// as a symlink (which fails when the alias is a plain directory or
    /// missing) while still giving `is_within_sync_topology` a well-formed
    /// second entry.
    fn topology_tempdir() -> (CanonicalTempDir, PathTopologyPolicy) {
        let raw = tempfile::tempdir().expect("create tempdir");
        let canonical = std::fs::canonicalize(raw.path()).expect("canonicalize tempdir");
        let alias_root = canonical
            .parent()
            .map(|parent| {
                let leaf = canonical
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("tmp");
                parent.join(format!("{leaf}__rch_alias_sentinel"))
            })
            .unwrap_or_else(|| canonical.clone());
        let policy = PathTopologyPolicy::new(canonical.clone(), alias_root);
        (
            CanonicalTempDir {
                _dir: raw,
                path: canonical,
            },
            policy,
        )
    }

    async fn spawn_mock_daemon(socket_path: &str, response: SelectionResponse) {
        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path).expect("Failed to bind mock socket");

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("Accept failed");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            let mut request_line = String::new();
            buf_reader
                .read_line(&mut request_line)
                .await
                .expect("Failed to read request");

            let body = serde_json::to_string(&response).expect("Serialize response");
            let http = format!("HTTP/1.1 200 OK\r\n\r\n{}", body);
            writer
                .write_all(http.as_bytes())
                .await
                .expect("Failed to write response");
            writer.flush().await.expect("Failed to flush response");
        });
    }

    #[tokio::test]
    async fn test_non_bash_allowed() {
        let input = HookInput {
            tool_name: "Read".to_string(),
            tool_input: ToolInput {
                command: "anything".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_non_compilation_allowed() {
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "ls -la".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_process_hook_allows_beads_comment_with_embedded_build_text() {
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command:
                    r#"br comments add ft-4tp7g.1 "remote proof blocked: cargo test -p rchd --lib""#
                        .to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        assert!(
            matches!(output, HookOutput::Allow(_)),
            "embedded build text in a Beads comment must not delegate to rch exec: {output:?}"
        );
    }

    #[tokio::test]
    async fn test_process_hook_allows_env_prefixed_beads_comment_with_embedded_build_text() {
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: r#"AGENT_NAME=Codex br comments add ft-4tp7g.4 "proof lane: cargo clippy --workspace""#
                    .to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        assert!(
            matches!(output, HookOutput::Allow(_)),
            "env-prefixed Beads comments with build text must not delegate to rch exec: {output:?}"
        );
    }

    #[tokio::test]
    async fn test_process_hook_bypasses_classification_cache_without_env_flag() {
        let unique_cmd = "echo rch-hook-cache-bypass-without-env-marker";
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: unique_cmd.to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        assert!(output.is_allow());

        assert!(
            crate::cache::global_cache().get(unique_cmd).is_none(),
            "process_hook must bypass the cache even when RCH_HOOK_MODE is unset"
        );
    }

    #[tokio::test]
    async fn test_compilation_detected() {
        let _lock = test_lock().lock().await;
        // Disable mock mode to test real fail-open behavior (no daemon = allow)
        mock::set_mock_enabled_override(Some(false));

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build --release".to_string(),
                description: None,
            },
            session_id: None,
        };

        // Without daemon, should fail-open and allow local execution
        // This tests that classification works and fail-open behavior is preserved
        let output = process_hook(input).await;
        assert!(
            output.is_allow(),
            "Expected allow when daemon unavailable (fail-open)"
        );

        // Reset mock override
        mock::set_mock_enabled_override(None);
    }

    // ========================================================================
    // TimingEstimate and Timing Gating Tests
    // ========================================================================

    #[test]
    fn test_timing_estimate_struct() {
        let _guard = test_guard!();
        let estimate = TimingEstimate {
            predicted_local_ms: 5000,
            predicted_speedup: Some(2.5),
        };
        assert_eq!(estimate.predicted_local_ms, 5000);
        assert_eq!(estimate.predicted_speedup, Some(2.5));
    }

    #[test]
    fn test_timing_estimate_no_speedup() {
        let _guard = test_guard!();
        let estimate = TimingEstimate {
            predicted_local_ms: 3000,
            predicted_speedup: None,
        };
        assert_eq!(estimate.predicted_local_ms, 3000);
        assert!(estimate.predicted_speedup.is_none());
    }

    #[test]
    fn test_estimate_timing_returns_none_without_history() {
        let _guard = test_guard!();
        // Currently returns None (fail-open) since no timing history exists
        let config = rch_common::RchConfig::default();
        let estimate =
            estimate_timing_for_build("test-project", Some(CompilationKind::CargoBuild), &config);
        assert!(estimate.is_none());
    }

    #[test]
    fn test_timing_gating_thresholds_default() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig::default();
        // Default min_local_time_ms: 2000ms
        assert_eq!(config.min_local_time_ms, 2000);
        // Default speedup threshold: 1.2x
        assert!((config.remote_speedup_threshold - 1.2).abs() < 0.001);
    }

    #[test]
    fn test_urlencoding_encode_basic() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("hello world"), "hello%20world");
        assert_eq!(urlencoding_encode("path/to/file"), "path%2Fto%2Ffile");
        assert_eq!(urlencoding_encode("foo:bar"), "foo%3Abar");
    }

    #[test]
    fn test_urlencoding_encode_special_chars() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencoding_encode("100%"), "100%25");
        assert_eq!(urlencoding_encode("hello+world"), "hello%2Bworld");
    }

    #[test]
    fn test_urlencoding_encode_no_encoding_needed() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("simple"), "simple");
        assert_eq!(
            urlencoding_encode("with-dash_underscore.dot~tilde"),
            "with-dash_underscore.dot~tilde"
        );
        assert_eq!(urlencoding_encode("ABC123"), "ABC123");
    }

    #[test]
    fn test_urlencoding_encode_unicode() {
        let _guard = test_guard!();
        // Unicode characters should be encoded as UTF-8 bytes
        let encoded = urlencoding_encode("café");
        assert!(encoded.contains("%")); // 'é' should be encoded
        assert!(encoded.starts_with("caf")); // ASCII part preserved
    }

    #[test]
    fn test_parse_jobs_flag_variants() {
        let _guard = test_guard!();
        assert_eq!(parse_jobs_flag("cargo build -j 8"), Some(8));
        assert_eq!(parse_jobs_flag("cargo build -j8"), Some(8));
        assert_eq!(parse_jobs_flag("cargo build --jobs 4"), Some(4));
        assert_eq!(parse_jobs_flag("cargo build --jobs=12"), Some(12));
        assert_eq!(parse_jobs_flag("cargo build -j=16"), Some(16));
        assert_eq!(parse_jobs_flag("cargo build --jobs=12"), Some(12));
        assert_eq!(parse_jobs_flag("cargo build -j"), None);
        assert_eq!(parse_jobs_flag("cargo build --jobs"), None);
    }

    #[test]
    fn test_parse_test_threads_variants() {
        let _guard = test_guard!();
        assert_eq!(
            parse_test_threads("cargo test -- --test-threads=4"),
            Some(4)
        );
        assert_eq!(
            parse_test_threads("cargo test -- --test-threads 2"),
            Some(2)
        );
        assert_eq!(parse_test_threads("cargo test"), None);
    }

    #[test]
    fn test_estimate_cores_for_command() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 10,
            check_slots: 3,
            ..Default::default()
        };

        let build =
            estimate_cores_for_command(Some(CompilationKind::CargoBuild), "cargo build", &config);
        assert_eq!(build, 6);

        let build_jobs = estimate_cores_for_command(
            Some(CompilationKind::CargoBuild),
            "cargo build -j 12",
            &config,
        );
        assert_eq!(build_jobs, 12);

        let test_default =
            estimate_cores_for_command(Some(CompilationKind::CargoTest), "cargo test", &config);
        assert_eq!(test_default, 10);

        let test_threads = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -- --test-threads=4",
            &config,
        );
        assert_eq!(test_threads, 4);

        let test_jobs = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -j 1 -p rchd --lib",
            &config,
        );
        assert_eq!(test_jobs, 1);

        let test_long_jobs = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test --jobs=3 -p rchd --lib",
            &config,
        );
        assert_eq!(test_long_jobs, 3);

        let test_jobs_override_threads = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -j 1 -- --test-threads=8",
            &config,
        );
        assert_eq!(test_jobs_override_threads, 1);

        let test_build_jobs_env = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "CARGO_BUILD_JOBS=2 cargo test -p rchd --lib",
            &config,
        );
        assert_eq!(test_build_jobs_env, 2);

        let test_env = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "RUST_TEST_THREADS=3 cargo test",
            &config,
        );
        assert_eq!(test_env, 3);

        let check_default =
            estimate_cores_for_command(Some(CompilationKind::CargoCheck), "cargo check", &config);
        assert_eq!(check_default, 3);
    }

    // =========================================================================
    // Classification + threshold interaction tests
    // =========================================================================

    #[test]
    fn test_classification_confidence_levels() {
        let _guard = test_guard!();
        // High confidence: explicit cargo build
        let result = classify_command("cargo build");
        assert!(result.is_compilation);
        assert!(result.confidence >= 0.90);

        // Still compilation but different command
        let result = classify_command("cargo test --release");
        assert!(result.is_compilation);
        assert!(result.confidence >= 0.85);

        // Non-compilation cargo commands should not trigger
        let result = classify_command("cargo fmt");
        assert!(!result.is_compilation);
    }

    #[test]
    fn test_classification_bun_commands() {
        let _guard = test_guard!();
        // Bun compilation commands should be intercepted
        let result = classify_command("bun test");
        assert!(result.is_compilation);

        let result = classify_command("bun typecheck");
        assert!(result.is_compilation);

        // Bun watch modes should NOT be intercepted
        let result = classify_command("bun test --watch");
        assert!(!result.is_compilation);

        let result = classify_command("bun typecheck --watch");
        assert!(!result.is_compilation);

        // Bun package management should NOT be intercepted
        let result = classify_command("bun install");
        assert!(!result.is_compilation);

        let result = classify_command("bun add react");
        assert!(!result.is_compilation);

        let result = classify_command("bun remove react");
        assert!(!result.is_compilation);

        let result = classify_command("bun link");
        assert!(!result.is_compilation);

        // Bun execution helpers should NOT be intercepted
        let result = classify_command("bun run build");
        assert!(!result.is_compilation);

        let result = classify_command("bun build");
        assert!(!result.is_compilation);

        let result = classify_command("bun dev");
        assert!(!result.is_compilation);

        let result = classify_command("bun repl");
        assert!(!result.is_compilation);

        let result = classify_command("bun x vite build");
        assert!(!result.is_compilation);

        let result = classify_command("bunx vite build");
        assert!(!result.is_compilation);
    }

    #[test]
    fn test_classification_c_compilers_and_build_systems() {
        let _guard = test_guard!();
        let result = classify_command("gcc -O2 -o hello hello.c");
        assert!(result.is_compilation);

        let result = classify_command("g++ -std=c++20 -o hello hello.cpp");
        assert!(result.is_compilation);

        let result = classify_command("clang -o hello hello.c");
        assert!(result.is_compilation);

        let result = classify_command("clang++ -o hello hello.cpp");
        assert!(result.is_compilation);

        let result = classify_command("make");
        assert!(result.is_compilation);

        let result = classify_command("ninja -C build");
        assert!(result.is_compilation);

        let result = classify_command("cmake --build build");
        assert!(result.is_compilation);
    }

    #[test]
    fn test_classification_env_wrapped_commands() {
        let _guard = test_guard!();
        let result = classify_command("RUST_BACKTRACE=1 cargo test");
        assert!(result.is_compilation);

        let result = classify_command("RUST_TEST_THREADS=4 cargo test");
        assert!(result.is_compilation);
    }

    #[test]
    fn test_classification_rejects_shell_metachars() {
        let _guard = test_guard!();
        // Piped commands should not be intercepted
        let result = classify_command("cargo build | tee log.txt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("pipe"));

        // Backgrounded commands should not be intercepted
        let result = classify_command("cargo build &");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("background"));

        // Redirected commands should not be intercepted
        let result = classify_command("cargo build > output.log");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("redirect"));

        // Subshell capture should not be intercepted
        let result = classify_command("result=$(cargo build)");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("subshell"));
    }

    #[test]
    fn test_extract_project_name() {
        let _guard = test_guard!();
        // The function uses current directory, but we can test it runs
        let project = extract_project_name();
        // Should return something (either actual dir name or "unknown")
        assert!(!project.is_empty());
    }

    /// Regression test for GitHub #9: when a custom [`PathTopologyPolicy`]
    /// is supplied and the cwd lives under the configured canonical root,
    /// normalization must succeed and must not fall back to the
    /// default `/data/projects` root.
    #[test]
    fn test_extract_project_name_honors_custom_policy() {
        let _guard = test_guard!();
        use std::fs;

        // Create an isolated canonical root inside the OS temp dir.
        let tmp = std::env::temp_dir().join(format!(
            "rch_extract_custom_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&tmp).expect("create canonical root");
        let project_dir = tmp.join("sample_project");
        fs::create_dir_all(&project_dir).expect("create project dir");

        // Resolve to the real path so symlinked temp dirs (e.g. /tmp -> /private/tmp
        // on macOS) don't trip the `OutsideCanonicalRoot` check.
        let canonical_tmp = fs::canonicalize(&tmp).expect("canonicalize tmp");
        let canonical_project = fs::canonicalize(&project_dir).expect("canonicalize project");

        let policy = PathTopologyPolicy::new(canonical_tmp.clone(), canonical_tmp.clone());

        let prev_cwd = std::env::current_dir().ok();
        std::env::set_current_dir(&canonical_project).expect("cd into project dir");

        let project = extract_project_name_with_policy(&policy);

        // Restore cwd before any assertion so failure doesn't poison other tests.
        if let Some(prev) = prev_cwd {
            let _ = std::env::set_current_dir(prev);
        }
        let _ = fs::remove_dir_all(&tmp);

        // The project name must be based on the configured root's subdir,
        // and crucially must not equal "unknown" (the fallback when
        // normalization against the default `/data/projects` policy fails).
        assert!(
            project.starts_with("sample_project-"),
            "expected project name to start with sample_project-, got {:?} \
             (cwd was {:?})",
            project,
            canonical_project
        );
    }

    // =========================================================================
    // Hook output protocol tests
    // =========================================================================

    #[test]
    fn test_hook_output_allow_is_empty() {
        let _guard = test_guard!();
        // Allow output should serialize to nothing (empty stdout = allow)
        let output = HookOutput::allow();
        assert!(output.is_allow());
    }

    #[test]
    fn test_hook_output_deny_serializes() {
        let _guard = test_guard!();
        let output = HookOutput::deny("Test denial reason".to_string());
        let json = serde_json::to_string(&output).expect("Should serialize");
        assert!(json.contains("deny"));
        assert!(json.contains("Test denial reason"));
    }

    #[test]
    fn test_selected_worker_to_config() {
        let _guard = test_guard!();
        let worker = SelectedWorker {
            id: rch_common::WorkerId::new("test-worker"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            slots_available: 8,
            speed_score: 75.5,
        };

        let config = selected_worker_to_config(&worker);
        assert_eq!(config.id.as_str(), "test-worker");
        assert_eq!(config.host, "192.168.1.100");
        assert_eq!(config.user, "ubuntu");
        assert_eq!(config.total_slots, 8);
    }

    #[test]
    fn test_parse_preferred_workers_dedupes_ordered_values() {
        let _guard = test_guard!();
        let workers = dedupe_worker_ids(parse_preferred_workers(" ts2, vmi1,,ts2 , vmi2 "));
        let ids: Vec<&str> = workers.iter().map(|worker| worker.as_str()).collect();
        assert_eq!(ids, vec!["ts2", "vmi1", "vmi2"]);
    }

    // =========================================================================
    // Mock daemon socket tests
    // =========================================================================

    #[tokio::test]
    async fn test_daemon_query_missing_socket() {
        // Query a non-existent socket should fail gracefully
        let result = query_daemon(
            "/tmp/nonexistent_rch_test.sock",
            "testproj",
            4,
            "cargo build",
            None,
            RequiredRuntime::None,
            CommandPriority::Normal,
            100, // 100µs classification time
            None,
            false,
            &[],
        )
        .await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not found") || err_msg.contains("No such file"));
    }

    #[tokio::test]
    async fn test_daemon_query_protocol() {
        // Create a mock daemon socket
        let socket_path = format!("/tmp/rch_test_daemon_{}.sock", std::process::id());

        // Clean up any existing socket
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");

        // Spawn mock daemon handler
        let socket_path_clone = socket_path.clone();
        let daemon_handle = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("Failed to accept connection");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            // Read the request line
            let mut request_line = String::new();
            buf_reader
                .read_line(&mut request_line)
                .await
                .expect("Failed to read request");

            // Verify request format
            assert!(request_line.starts_with("GET /select-worker"));
            assert!(request_line.contains("project="));
            assert!(request_line.contains("cores="));
            assert!(request_line.contains("command=cargo%20build"));
            assert!(request_line.contains("priority=normal"));

            // Send mock response
            let response = SelectionResponse {
                worker: Some(SelectedWorker {
                    id: rch_common::WorkerId::new("mock-worker"),
                    host: "mock.host.local".to_string(),
                    user: "mockuser".to_string(),
                    identity_file: "~/.ssh/mock_key".to_string(),
                    slots_available: 16,
                    speed_score: 95.0,
                }),
                reason: SelectionReason::Success,
                build_id: None,
                diagnostics: None,
            };
            let body = serde_json::to_string(&response).unwrap();
            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            writer
                .write_all(http_response.as_bytes())
                .await
                .expect("Failed to write response");
            writer.flush().await.expect("Failed to flush response");
        });

        // Give daemon time to start listening
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Query the mock daemon
        let result = query_daemon(
            &socket_path,
            "test-project",
            4,
            "cargo build",
            None,
            RequiredRuntime::None,
            CommandPriority::Normal,
            100,
            None,
            false,
            &[],
        )
        .await;

        // Clean up
        daemon_handle.await.expect("Daemon task panicked");
        let _ = std::fs::remove_file(&socket_path_clone);

        // Verify result
        let response = result.expect("Query should succeed");
        let worker = response.worker.expect("Should have worker");
        assert_eq!(worker.id.as_str(), "mock-worker");
        assert_eq!(worker.host, "mock.host.local");
        assert_eq!(worker.slots_available, 16);
    }

    #[tokio::test]
    async fn test_daemon_query_sends_preferred_workers() {
        let socket_path = format!("/tmp/rch_test_daemon_preferred_{}.sock", std::process::id());
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");

        let socket_path_clone = socket_path.clone();
        let daemon_handle = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("Failed to accept connection");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            let mut request_line = String::new();
            buf_reader
                .read_line(&mut request_line)
                .await
                .expect("Failed to read request");

            assert!(request_line.contains("worker=ts2"));
            assert!(request_line.contains("worker=vmi1264463"));
            assert!(request_line.contains("preferred_workers=ts2%2Cvmi1264463"));

            let response = SelectionResponse {
                worker: Some(SelectedWorker {
                    id: rch_common::WorkerId::new("ts2"),
                    host: "mock.host.local".to_string(),
                    user: "mockuser".to_string(),
                    identity_file: "~/.ssh/mock_key".to_string(),
                    slots_available: 16,
                    speed_score: 95.0,
                }),
                reason: SelectionReason::Success,
                build_id: None,
                diagnostics: None,
            };
            let body = serde_json::to_string(&response).unwrap();
            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            writer
                .write_all(http_response.as_bytes())
                .await
                .expect("Failed to write response");
            writer.flush().await.expect("Failed to flush response");
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let preferred = vec![
            rch_common::WorkerId::new("ts2"),
            rch_common::WorkerId::new("vmi1264463"),
        ];
        let result = query_daemon(
            &socket_path,
            "test-project",
            4,
            "cargo build",
            None,
            RequiredRuntime::None,
            CommandPriority::Normal,
            100,
            None,
            false,
            &preferred,
        )
        .await;

        daemon_handle.await.expect("Daemon task panicked");
        let _ = std::fs::remove_file(&socket_path_clone);

        let response = result.expect("Query should succeed");
        let worker = response.worker.expect("Should have worker");
        assert_eq!(worker.id.as_str(), "ts2");
    }

    #[tokio::test]
    async fn test_daemon_query_wait_parameters() {
        let socket_path = format!("/tmp/rch_test_wait_{}.sock", std::process::id());
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");
        let expected_wait_timeout_secs = daemon_response_timeout_for(true, None, None)
            .as_secs()
            .saturating_sub(1)
            .max(1);

        let socket_path_clone = socket_path.clone();
        let daemon_handle = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("Failed to accept connection");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            let mut request_line = String::new();
            buf_reader
                .read_line(&mut request_line)
                .await
                .expect("Failed to read request");

            assert!(request_line.starts_with("GET /select-worker"));
            assert!(request_line.contains("wait=1"));
            assert!(
                request_line.contains(&format!("wait_timeout_secs={expected_wait_timeout_secs}"))
            );

            let response = SelectionResponse {
                worker: Some(SelectedWorker {
                    id: rch_common::WorkerId::new("mock-worker"),
                    host: "mock.host.local".to_string(),
                    user: "mockuser".to_string(),
                    identity_file: "~/.ssh/mock_key".to_string(),
                    slots_available: 16,
                    speed_score: 95.0,
                }),
                reason: SelectionReason::Success,
                build_id: None,
                diagnostics: None,
            };
            let body = serde_json::to_string(&response).unwrap();
            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            writer
                .write_all(http_response.as_bytes())
                .await
                .expect("Failed to write response");
            writer.flush().await.expect("Failed to flush response");
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let result = query_daemon(
            &socket_path,
            "test-project",
            4,
            "cargo build",
            None,
            RequiredRuntime::None,
            CommandPriority::Normal,
            100,
            None,
            true,
            &[],
        )
        .await;

        daemon_handle.await.expect("Daemon task panicked");
        let _ = std::fs::remove_file(&socket_path_clone);

        let response = result.expect("Query should succeed");
        let worker = response.worker.expect("Should have worker");
        assert_eq!(worker.id.as_str(), "mock-worker");
    }

    #[tokio::test]
    async fn test_daemon_query_url_encoding() {
        // Verify special characters in project name are encoded
        let socket_path = format!("/tmp/rch_test_url_{}.sock", std::process::id());
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");

        let socket_path_clone = socket_path.clone();
        let daemon_handle = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("Failed to accept connection");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            // Read the request line
            let mut request_line = String::new();
            buf_reader.read_line(&mut request_line).await.expect("Read");

            // The project name "my project/test" should be URL encoded
            assert!(request_line.contains("my%20project%2Ftest"));

            // Send minimal response
            let response = SelectionResponse {
                worker: Some(SelectedWorker {
                    id: rch_common::WorkerId::new("w1"),
                    host: "h".to_string(),
                    user: "u".to_string(),
                    identity_file: "i".to_string(),
                    slots_available: 1,
                    speed_score: 1.0,
                }),
                reason: SelectionReason::Success,
                build_id: None,
                diagnostics: None,
            };
            let body = serde_json::to_string(&response).unwrap();
            let http = format!("HTTP/1.1 200 OK\r\n\r\n{}", body);
            writer.write_all(http.as_bytes()).await.expect("Write");
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let result = query_daemon(
            &socket_path,
            "my project/test",
            2,
            "cargo build --release",
            None,
            RequiredRuntime::None,
            CommandPriority::Normal,
            150, // 150µs classification time
            None,
            false,
            &[],
        )
        .await;
        daemon_handle.await.expect("Daemon task");
        let _ = std::fs::remove_file(&socket_path_clone);

        assert!(result.is_ok());
    }

    // =========================================================================
    // Fail-open behavior tests
    // =========================================================================

    #[tokio::test]
    async fn test_fail_open_on_invalid_json() {
        let _lock = test_lock().lock().await;
        // Disable mock mode to test real fail-open behavior
        mock::set_mock_enabled_override(Some(false));

        let mut config = rch_common::RchConfig::default();
        config.general.socket_path = "/tmp/rch-test-no-daemon.sock".to_string();
        let _ = std::fs::remove_file(&config.general.socket_path);
        let _config_guard = ConfigOverrideGuard::set(config);

        // If hook input is invalid JSON, should allow (fail-open)
        // This tests the run_hook behavior implicitly through process_hook
        // We can't easily test run_hook directly as it reads stdin

        // But we can verify that process_hook with valid input returns Allow
        // when no daemon is available (which is the fail-open case)
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        // With no daemon running, should fail-open to allow
        let output = process_hook(input).await;
        mock::clear_mock_overrides();
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fail_open_on_config_error() {
        let _lock = test_lock().lock().await;
        // Disable mock mode to test real fail-open behavior
        mock::set_mock_enabled_override(Some(false));

        // If config is missing or invalid, should allow
        // This is tested implicitly by process_hook when config can't load
        // The current implementation falls back to allow
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build --release".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        mock::clear_mock_overrides();
        // Should allow because daemon isn't running (fail-open)
        assert!(output.is_allow());
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_process_hook_remote_success_mocked() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_hook_success_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("mock-worker"),
                host: "mock.host.local".to_string(),
                user: "mockuser".to_string(),
                identity_file: "~/.ssh/mock_key".to_string(),
                slots_available: 8,
                speed_score: 90.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output: HookOutput = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Hook should return AllowWithModifiedCommand delegating to `rch exec`
        // The actual remote compilation happens when `rch exec` runs, not in the hook
        assert!(output.is_allow());
        let cmd = delegated_command(&output);
        assert!(
            cmd.starts_with("rch exec -- "),
            "Modified command should delegate to rch exec: {}",
            cmd
        );
        assert!(
            cmd.contains("cargo build"),
            "Modified command should contain original command: {}",
            cmd
        );

        // No rsync/SSH should be invoked during the hook - that happens in run_exec
        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(
            rsync_logs.is_empty(),
            "Hook should not invoke rsync directly"
        );
        assert!(ssh_logs.is_empty(), "Hook should not invoke SSH directly");
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_force_local_allows_even_when_remote_available() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_hook_force_local_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let mut config = rch_common::RchConfig::default();
        config.general.socket_path = socket_path.to_string();
        config.general.force_local = true;
        crate::config::set_test_config_override(Some(config));

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("mock-worker"),
                host: "mock.host.local".to_string(),
                user: "mockuser".to_string(),
                identity_file: "~/.ssh/mock_key".to_string(),
                slots_available: 8,
                speed_score: 90.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        assert!(output.is_allow());

        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(rsync_logs.is_empty());
        assert!(ssh_logs.is_empty());
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_force_remote_bypasses_confidence_threshold() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_hook_force_remote_threshold_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let classification = classify_command("cargo build");
        assert!(classification.is_compilation);
        let high_threshold = (classification.confidence + 0.01).min(1.0);

        let mut config = rch_common::RchConfig::default();
        config.general.socket_path = socket_path.to_string();
        config.general.force_remote = true;
        config.compilation.confidence_threshold = high_threshold;
        crate::config::set_test_config_override(Some(config));

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("mock-worker"),
                host: "mock.host.local".to_string(),
                user: "mockuser".to_string(),
                identity_file: "~/.ssh/mock_key".to_string(),
                slots_available: 8,
                speed_score: 90.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // force_remote should result in transparent interception (AllowWithModifiedCommand)
        // with delegation to `rch exec`
        assert!(output.is_allow());
        let cmd = delegated_command(&output);
        assert!(
            cmd.starts_with("rch exec -- "),
            "Should delegate to rch exec: {}",
            cmd
        );

        // No rsync/SSH should be invoked during the hook - that happens in run_exec
        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(
            rsync_logs.is_empty(),
            "Hook should not invoke rsync directly"
        );
        assert!(ssh_logs.is_empty(), "Hook should not invoke SSH directly");
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_process_hook_delegates_to_rch_exec() {
        // Test that process_hook always delegates to `rch exec` without doing
        // any remote operations itself. Sync failures (if any) would happen
        // in run_exec, not in process_hook.
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_hook_delegate_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Even with sync_failure mock config, the hook should succeed
        // because it doesn't do sync - it just delegates to rch exec
        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::sync_failure(),
        );
        mock::clear_global_invocations();

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Hook should return AllowWithModifiedCommand delegating to rch exec
        assert!(output.is_allow());
        let cmd = delegated_command(&output);
        assert!(
            cmd.starts_with("rch exec -- "),
            "Should delegate to rch exec: {}",
            cmd
        );

        // No rsync/SSH should be invoked during the hook
        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(
            rsync_logs.is_empty(),
            "Hook should not invoke rsync directly"
        );
        assert!(ssh_logs.is_empty(), "Hook should not invoke SSH directly");
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_process_hook_delegates_env_prefixed_cargo_command() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_hook_delegate_env_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::sync_failure(),
        );
        mock::clear_global_invocations();

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "env RUSTFLAGS=\"-C linker=cc\" cargo build --bin frankenctl".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        let cmd = delegated_command(&output);
        assert!(
            cmd.starts_with("rch exec -- env "),
            "env wrapper must remain an argv prefix in delegated command: {cmd}"
        );
        let tokens = shell_words::split(
            cmd.strip_prefix("rch exec -- ")
                .expect("delegated command prefix"),
        )
        .expect("delegated command should parse as shell words");
        assert_eq!(
            tokens,
            vec![
                "env".to_string(),
                "RUSTFLAGS=-C linker=cc".to_string(),
                "cargo".to_string(),
                "build".to_string(),
                "--bin".to_string(),
                "frankenctl".to_string(),
            ]
        );

        assert!(mock::global_rsync_invocations_snapshot().is_empty());
        assert!(mock::global_ssh_invocations_snapshot().is_empty());
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_process_hook_remote_nonzero_exit_uses_transparent_interception() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_hook_exit_nonzero_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig {
                default_exit_code: 2,
                ..MockConfig::default()
            },
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("mock-worker"),
                host: "mock.host.local".to_string(),
                user: "mockuser".to_string(),
                identity_file: "~/.ssh/mock_key".to_string(),
                slots_available: 8,
                speed_score: 90.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Remote failure should still use transparent interception (AllowWithModifiedCommand)
        // with "exit <code>" to preserve the exit code for the agent
        assert!(output.is_allow());
        assert!(
            matches!(output, HookOutput::AllowWithModifiedCommand(_)),
            "Expected AllowWithModifiedCommand for remote execution with non-zero exit"
        );
    }

    #[test]
    fn test_transfer_config_defaults() {
        let _guard = test_guard!();
        // Verify TransferConfig has sensible defaults
        let config = TransferConfig::default();
        assert!(!config.exclude_patterns.is_empty());
        assert!(config.exclude_patterns.iter().any(|p| p.contains("target")));
    }

    #[test]
    fn test_worker_config_from_selected_worker() {
        let _guard = test_guard!();
        // Test the conversion preserves all fields correctly
        let worker = SelectedWorker {
            id: rch_common::WorkerId::new("worker-alpha"),
            host: "alpha.example.com".to_string(),
            user: "deploy".to_string(),
            identity_file: "/keys/deploy.pem".to_string(),
            slots_available: 32,
            speed_score: 88.8,
        };

        let config = selected_worker_to_config(&worker);

        assert_eq!(config.id.as_str(), "worker-alpha");
        assert_eq!(config.host, "alpha.example.com");
        assert_eq!(config.user, "deploy");
        assert_eq!(config.identity_file, "/keys/deploy.pem");
        assert_eq!(config.total_slots, 32);
        assert_eq!(config.priority, 100); // Default priority
        assert!(config.tags.is_empty()); // Default empty tags
    }

    // =========================================================================
    // Local fallback scenario tests (remote_compilation_helper-od4)
    // =========================================================================

    #[tokio::test]
    async fn test_fallback_no_workers_configured() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_no_workers_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Daemon returns no workers configured
        let response = SelectionResponse {
            worker: None,
            reason: SelectionReason::NoWorkersConfigured,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_all_workers_unreachable() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_unreachable_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Daemon returns all workers unreachable
        let response = SelectionResponse {
            worker: None,
            reason: SelectionReason::AllWorkersUnreachable,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build --release".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_all_workers_busy() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_busy_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Daemon returns all workers busy
        let response = SelectionResponse {
            worker: None,
            reason: SelectionReason::AllWorkersBusy,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_all_circuits_open() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_circuits_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Daemon returns all circuits open (circuit breaker tripped)
        let response = SelectionResponse {
            worker: None,
            reason: SelectionReason::AllCircuitsOpen,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo check".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_selection_error() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_sel_err_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Daemon returns a selection error
        let response = SelectionResponse {
            worker: None,
            reason: SelectionReason::SelectionError("Internal error".to_string()),
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_daemon_error_response() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_daemon_err_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Spawn a daemon that returns HTTP 500 error
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            let mut request_line = String::new();
            buf_reader.read_line(&mut request_line).await.expect("read");

            // Return HTTP 500 error
            let http = "HTTP/1.1 500 Internal Server Error\r\n\r\n Расположение: {\"error\": \"internal\"}";
            writer.write_all(http.as_bytes()).await.expect("write");
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution (fail-open)
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_daemon_malformed_json() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_malformed_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Spawn a daemon that returns malformed JSON
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            let mut request_line = String::new();
            buf_reader.read_line(&mut request_line).await.expect("read");

            // Return malformed JSON
            let http = "HTTP/1.1 200 OK\r\n\r\n{invalid json}";
            writer.write_all(http.as_bytes()).await.expect("write");
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution (fail-open on parse error)
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_daemon_connection_reset() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_reset_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Spawn a daemon that immediately closes connection
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            // Immediately drop the stream to simulate connection reset
            drop(stream);
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution (fail-open on connection error)
        assert!(output.is_allow());
    }

    // =========================================================================
    // Exit code handling tests (bead remote_compilation_helper-zerp)
    // =========================================================================

    #[test]
    fn test_is_signal_killed() {
        let _guard = test_guard!();
        // Normal exit codes should not be signal-killed
        assert!(is_signal_killed(0).is_none());
        assert!(is_signal_killed(1).is_none());
        assert!(is_signal_killed(101).is_none());
        assert!(is_signal_killed(128).is_none()); // 128 is exactly at boundary

        // Signal kills (128 + signal)
        assert_eq!(is_signal_killed(129), Some(1)); // SIGHUP
        assert_eq!(is_signal_killed(130), Some(2)); // SIGINT
        assert_eq!(is_signal_killed(137), Some(9)); // SIGKILL
        assert_eq!(is_signal_killed(139), Some(11)); // SIGSEGV
        assert_eq!(is_signal_killed(143), Some(15)); // SIGTERM
    }

    #[test]
    fn test_signal_name() {
        let _guard = test_guard!();
        assert_eq!(signal_name(1), "SIGHUP");
        assert_eq!(signal_name(2), "SIGINT");
        assert_eq!(signal_name(9), "SIGKILL");
        assert_eq!(signal_name(11), "SIGSEGV");
        assert_eq!(signal_name(15), "SIGTERM");
        assert_eq!(signal_name(99), "UNKNOWN");
    }

    #[test]
    fn test_exit_code_constants() {
        let _guard = test_guard!();
        // Verify exit code constants match cargo's documented behavior
        assert_eq!(EXIT_SUCCESS, 0);
        assert_eq!(EXIT_BUILD_ERROR, 1);
        assert_eq!(EXIT_TEST_FAILURES, 101);
        assert_eq!(EXIT_SIGNAL_BASE, 128);
    }

    #[test]
    fn test_remote_pipeline_failure_policy_ssh_timeout_fails_closed() {
        let _guard = test_guard!();
        let error = anyhow::anyhow!("SSH command timed out after 1800s");

        assert_eq!(
            classify_remote_pipeline_failure(&error),
            RemotePipelineFailurePolicy::FailClosedNoLocalFallback
        );
    }

    #[test]
    fn test_remote_pipeline_failure_policy_wrapped_ssh_timeout_fails_closed() {
        let _guard = test_guard!();
        let error =
            anyhow::anyhow!("SSH command timed out after 1800s").context("remote execution failed");

        assert_eq!(
            classify_remote_pipeline_failure(&error),
            RemotePipelineFailurePolicy::FailClosedNoLocalFallback
        );
    }

    #[test]
    fn test_remote_pipeline_failure_policy_non_timeout_allows_existing_fallback() {
        let _guard = test_guard!();
        let error = anyhow::anyhow!("rsync failed before remote execution");

        assert_eq!(
            classify_remote_pipeline_failure(&error),
            RemotePipelineFailurePolicy::AllowLocalFallback
        );
    }

    #[test]
    fn test_is_toolchain_failure_basic() {
        let _guard = test_guard!();
        // Should detect toolchain issues
        assert!(is_toolchain_failure(
            "error: toolchain 'nightly-2025-01-01' is not installed",
            1
        ));
        assert!(is_toolchain_failure("rustup: command not found", 127));
        assert!(is_toolchain_failure(
            "error: no default toolchain configured",
            1
        ));
        assert!(is_toolchain_failure(
            "error: toolchain 'nightly-2025-01-01' does not have the binary `cargo`",
            1
        ));

        // Should not flag normal failures
        assert!(!is_toolchain_failure(
            "error[E0425]: cannot find value `x`",
            1
        ));
        assert!(!is_toolchain_failure(
            "test result: FAILED. 1 passed; 2 failed",
            101
        ));

        // Success should never be a toolchain failure
        assert!(!is_toolchain_failure("anything", 0));
    }

    #[test]
    fn test_is_toolchain_failure_ignores_rustup_toolchain_paths_in_normal_failures() {
        let _guard = test_guard!();
        let stderr = r#"error: could not compile `serde` (lib)
Caused by:
  process didn't exit successfully: `/home/ubuntu/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rustc --crate-name serde ...` (signal: 9, SIGKILL: kill)
"#;

        assert!(
            !is_toolchain_failure(stderr, 137),
            "SIGKILL/OOM stderr mentioning .rustup/toolchains paths must not trigger local fallback"
        );

        let compile_error = r#"error[E0425]: cannot find value `x` in this scope
note: the compiler executable is /home/ubuntu/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rustc
"#;

        assert!(
            !is_toolchain_failure(compile_error, EXIT_BUILD_ERROR),
            "ordinary compile errors mentioning the rustc toolchain path must not trigger local fallback"
        );
    }

    #[test]
    fn test_detect_worker_system_dependency_failure_from_pkg_config_output() {
        let _guard = test_guard!();
        let stderr = r#"thread 'main' panicked at build.rs:42:14:
called `Result::unwrap()` on an `Err` value:
pkg-config exited with status code 1
> PKG_CONFIG_ALLOW_SYSTEM_LIBS=1 pkg-config --libs --cflags x11 'x11 >= 1.4.99.1'

The system library `x11` required by crate `x11` was not found.
The file `x11.pc` needs to be installed and the PKG_CONFIG_PATH environment variable must contain its parent directory.
"#;

        let failure = detect_worker_system_dependency_failure(stderr, EXIT_BUILD_ERROR)
            .expect("pkg-config/system dependency failure should be detected");

        assert_eq!(failure.system_library.as_deref(), Some("x11"));
        assert_eq!(failure.crate_name.as_deref(), Some("x11"));
        assert_eq!(failure.pkg_config_file.as_deref(), Some("x11.pc"));
        assert_eq!(failure.summary(), "missing worker system package x11.pc");
        assert!(failure.remediation().contains("x11.pc"));
    }

    #[test]
    fn test_detect_worker_system_dependency_failure_ignores_normal_compile_errors() {
        let _guard = test_guard!();
        let stderr = r#"error[E0425]: cannot find value `oops` in this scope
 --> src/main.rs:4:5
  |
4 |     oops();
  |     ^^^^ not found in this scope
"#;

        assert!(
            detect_worker_system_dependency_failure(stderr, EXIT_BUILD_ERROR).is_none(),
            "ordinary compile errors must not be misclassified as worker env failures"
        );
    }

    #[test]
    fn test_exit_code_semantics_documented() {
        let _guard = test_guard!();
        // This test documents the expected behavior for different exit codes
        // Exit 0: Success - should deny local (verified in other tests)
        // Exit 101: Test failures - should deny local (re-running won't help)
        // Exit 1: Build error - should deny local (same error locally)
        // Exit 137: SIGKILL - should deny local (likely OOM)

        // Verify constants are what we expect
        assert_eq!(EXIT_SUCCESS, 0, "Success exit code should be 0");
        assert_eq!(EXIT_BUILD_ERROR, 1, "Build error exit code should be 1");
        assert_eq!(
            EXIT_TEST_FAILURES, 101,
            "Test failures exit code should be 101"
        );

        // Verify signal detection
        let sigkill = 128 + 9;
        assert_eq!(is_signal_killed(sigkill), Some(9), "Should detect SIGKILL");
        assert_eq!(signal_name(9), "SIGKILL", "Should name SIGKILL correctly");
    }

    // =========================================================================
    // Cargo test integration tests (bead remote_compilation_helper-iyv1)
    // =========================================================================

    #[test]
    fn test_wrap_command_with_telemetry_handles_comments() {
        let _guard = test_guard!();
        let worker_id = rch_common::WorkerId::new("worker1");
        let command = "echo hello # my comment";
        let wrapped = wrap_command_with_telemetry(command, &worker_id);

        // Ensure newline separation exists
        assert!(wrapped.contains(&format!("{}\nstatus=$?", command)));

        // Ensure status capture isn't commented out (it should be on a new line)
        let lines: Vec<&str> = wrapped.lines().collect();
        assert!(lines.iter().any(|l| l.starts_with("status=$?")));

        // Basic sanity check on structure
        assert!(wrapped.contains("rch-telemetry collect"));
        assert!(wrapped.contains("exit $status"));
    }

    #[test]
    fn test_add_cargo_isolation_adds_unique_cargo_home() {
        let _guard = test_guard!();
        let worker_id = rch_common::WorkerId::new("test-worker");

        // Test cargo build command gets isolation
        let cargo_command = "cargo build --release";
        let isolated = add_cargo_isolation(cargo_command, &worker_id);

        assert!(isolated.starts_with("sh -c "));
        assert!(!isolated.starts_with("CARGO_HOME="));
        // The staging base is resolved on the worker (no hardcoded /tmp) and the
        // basename keeps the rch-cargo-home- prefix that cleanup matches.
        assert!(
            !isolated.contains("/tmp/rch-cargo-home-"),
            "must not hardcode /tmp: {isolated}"
        );
        assert!(isolated.contains("RCH_CH_BASE="));
        assert!(isolated.contains("/data/tmp"));
        assert!(isolated.contains("mkdir -p \"${RCH_CH_BASE}/rch-cargo-home-test-worker-"));
        assert!(isolated.contains("CARGO_HOME=\"${RCH_CH_BASE}/rch-cargo-home-test-worker-"));
        assert!(isolated.contains("cargo build --release"));
        assert!(isolated.contains("status=$?"));
        assert!(isolated.contains("exit $status"));
        assert!(isolated.contains("rm -rf \"${RCH_CH_BASE}/rch-cargo-home-test-worker-"));
    }

    #[test]
    fn test_sanitize_cargo_home_token_collapses_unsafe_chars() {
        // Path-safe tokens pass through unchanged.
        assert_eq!(sanitize_cargo_home_token("worker-1_2"), "worker-1_2");
        // Spaces, slashes and other shell-meaningful chars collapse to '-'.
        assert_eq!(sanitize_cargo_home_token("a b/c"), "a-b-c");
        // Leading/trailing unsafe chars are trimmed, not left as dangling '-'.
        assert_eq!(sanitize_cargo_home_token("  weird!! "), "weird");
        // An entirely-unsafe (or empty) token falls back to a stable default.
        assert_eq!(sanitize_cargo_home_token("***"), "worker");
        assert_eq!(sanitize_cargo_home_token(""), "worker");
    }

    #[test]
    fn test_add_cargo_isolation_skips_non_cargo_commands() {
        let _guard = test_guard!();
        let worker_id = rch_common::WorkerId::new("test-worker");

        // Test non-cargo command is unchanged
        let non_cargo_command = "echo hello world";
        let isolated = add_cargo_isolation(non_cargo_command, &worker_id);

        assert_eq!(isolated, non_cargo_command);
        assert!(!isolated.contains("CARGO_HOME"));
    }

    #[test]
    fn test_add_cargo_isolation_handles_complex_cargo_commands() {
        let _guard = test_guard!();
        let worker_id = rch_common::WorkerId::new("worker-123");

        // Test complex cargo command with environment variables and arguments
        let complex_command = "cd /some/path && RUSTFLAGS=\"-C target-cpu=native\" cargo test --release --features=foo";
        let isolated = add_cargo_isolation(complex_command, &worker_id);

        assert!(isolated.starts_with("sh -c "));
        assert!(
            !isolated.contains("/tmp/rch-cargo-home-"),
            "must not hardcode /tmp: {isolated}"
        );
        assert!(isolated.contains("mkdir -p \"${RCH_CH_BASE}/rch-cargo-home-worker-123-"));
        assert!(isolated.contains("CARGO_HOME=\"${RCH_CH_BASE}/rch-cargo-home-worker-123-"));
        assert!(isolated.contains("cd /some/path && RUSTFLAGS=\"-C target-cpu=native\" cargo test --release --features=foo"));
        assert!(isolated.contains("status=$?"));
        assert!(isolated.contains("exit $status"));
        assert!(isolated.contains("rm -rf \"${RCH_CH_BASE}/rch-cargo-home-worker-123-"));
    }

    #[test]
    fn test_add_cargo_isolation_survives_timeout_prefix_and_preserves_status() {
        let _guard = test_guard!();
        let worker_id = rch_common::WorkerId::new("timeout-worker");
        let isolated = add_cargo_isolation("printf cargo >/dev/null; exit 42", &worker_id);
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "timeout --foreground --preserve-status 5 {}",
                isolated
            ))
            .status()
            .expect("timeout-wrapped isolated command should execute");

        assert_eq!(
            status.code(),
            Some(42),
            "timeout must execute the shell wrapper and preserve the command status"
        );
    }

    #[test]
    fn test_remote_cargo_target_dir_name_is_unique_and_path_safe() {
        let _guard = test_guard!();
        let worker_id = rch_common::WorkerId::new("worker/with spaces");
        let first = remote_cargo_target_dir_name(Some(42), &worker_id);
        let second = remote_cargo_target_dir_name(Some(42), &worker_id);

        assert!(first.starts_with(".rch-target-worker-with-spaces-job-42-"));
        assert!(!first.contains('/'));
        assert!(!first.contains(' '));
        assert_ne!(first, second);
    }

    #[test]
    fn test_parse_stale_target_reap_idle_hours() {
        // Default when unset or unparseable.
        assert_eq!(parse_stale_target_reap_idle_hours(None), 12);
        assert_eq!(
            parse_stale_target_reap_idle_hours(Some("not-a-number".into())),
            12
        );
        assert_eq!(parse_stale_target_reap_idle_hours(Some(String::new())), 12);
        // Honors a valid override (with surrounding whitespace).
        assert_eq!(parse_stale_target_reap_idle_hours(Some("24".into())), 24);
        assert_eq!(parse_stale_target_reap_idle_hours(Some("  6 ".into())), 6);
        // Floors at 1h so a misconfiguration can never reap a live cache.
        assert_eq!(parse_stale_target_reap_idle_hours(Some("0".into())), 1);
    }

    #[test]
    fn test_resolve_forwarded_cargo_target_dir_reads_env_without_allowlist() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
            Some(CompilationKind::CargoBuild),
            Path::new("/tmp/rch"),
            &reporter,
            |_| Some("/tmp/rch-target-no-allowlist".to_string()),
            None,
        );

        assert_eq!(
            resolved,
            Some(PathBuf::from("/tmp/rch-target-no-allowlist"))
        );
    }

    #[test]
    fn test_resolve_forwarded_cargo_target_dir_defaults_for_cargo() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
            Some(CompilationKind::CargoBuild),
            Path::new("/data/projects/remote_compilation_helper"),
            &reporter,
            |_| None,
            None,
        );

        assert_eq!(
            resolved,
            Some(PathBuf::from(
                "/data/projects/remote_compilation_helper/target"
            ))
        );
    }

    #[test]
    fn test_resolve_forwarded_cargo_target_dir_ignores_non_cargo() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
            Some(CompilationKind::BunTest),
            Path::new("/data/projects/remote_compilation_helper"),
            &reporter,
            |_| Some("/tmp/should-not-forward".to_string()),
            None,
        );

        assert!(resolved.is_none());
    }

    #[test]
    fn test_resolve_forwarded_cargo_target_dir_resolves_relative_path() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
            Some(CompilationKind::CargoBuild),
            Path::new("/data/projects/remote_compilation_helper"),
            &reporter,
            |_| Some("tmp/custom-target".to_string()),
            None,
        );

        assert_eq!(
            resolved,
            Some(PathBuf::from(
                "/data/projects/remote_compilation_helper/tmp/custom-target"
            ))
        );
    }

    #[test]
    fn test_resolve_forwarded_cargo_target_dir_extracts_env_wrapper_assignment() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let command_tokens = vec![
            "env".to_string(),
            "-u".to_string(),
            "RUST_LOG".to_string(),
            "RUST_BACKTRACE=1".to_string(),
            "CARGO_TARGET_DIR=/data/projects/custom-target".to_string(),
            "cargo".to_string(),
            "check".to_string(),
        ];
        let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
            Some(CompilationKind::CargoBuild),
            Path::new("/data/projects/remote_compilation_helper"),
            &reporter,
            |_| Some("/tmp/env-should-lose-to-command".to_string()),
            Some(&command_tokens),
        );

        assert_eq!(
            resolved,
            Some(PathBuf::from("/data/projects/custom-target"))
        );
    }

    #[test]
    fn test_resolve_forwarded_cargo_target_dir_extracts_inline_assignment() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let command_tokens = vec![
            "CARGO_TARGET_DIR=.rch-target-inline".to_string(),
            "cargo".to_string(),
            "build".to_string(),
        ];
        let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
            Some(CompilationKind::CargoBuild),
            Path::new("/data/projects/remote_compilation_helper"),
            &reporter,
            |_| None,
            Some(&command_tokens),
        );

        assert_eq!(
            resolved,
            Some(PathBuf::from(
                "/data/projects/remote_compilation_helper/.rch-target-inline"
            ))
        );
    }

    #[test]
    fn test_resolve_forwarded_cargo_target_dir_extracts_target_dir_flag() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let command_tokens = vec![
            "cargo".to_string(),
            "build".to_string(),
            "--target-dir".to_string(),
            "/data/tmp/rch-target-flag".to_string(),
            "--release".to_string(),
        ];
        let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
            Some(CompilationKind::CargoBuild),
            Path::new("/data/projects/remote_compilation_helper"),
            &reporter,
            |_| None,
            Some(&command_tokens),
        );

        assert_eq!(resolved, Some(PathBuf::from("/data/tmp/rch-target-flag")));
    }

    #[test]
    fn test_resolve_forwarded_cargo_target_dir_extracts_target_dir_equals_flag() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let command_tokens = vec![
            "cargo".to_string(),
            "check".to_string(),
            "--target-dir=/data/tmp/rch-target-equals".to_string(),
        ];
        let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
            Some(CompilationKind::CargoCheck),
            Path::new("/data/projects/remote_compilation_helper"),
            &reporter,
            |_| None,
            Some(&command_tokens),
        );

        assert_eq!(resolved, Some(PathBuf::from("/data/tmp/rch-target-equals")));
    }

    #[test]
    fn test_rewrite_cargo_target_dir_command_for_remote_strips_inline_assignment() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let command_tokens = vec![
            "env".to_string(),
            "-u".to_string(),
            "RUST_LOG".to_string(),
            "RUST_BACKTRACE=1".to_string(),
            "CARGO_TARGET_DIR=/data/projects/custom-target".to_string(),
            "cargo".to_string(),
            "build".to_string(),
            "--release".to_string(),
        ];

        let rewritten = rewrite_cargo_target_dir_command_for_remote(
            "env -u RUST_LOG RUST_BACKTRACE=1 CARGO_TARGET_DIR=/data/projects/custom-target cargo build --release",
            Some(&command_tokens),
            Some(&PathBuf::from("/data/projects/custom-target")),
            &reporter,
        );

        assert_eq!(
            rewritten,
            "env -u RUST_LOG 'RUST_BACKTRACE=1' cargo build --release"
        );
        assert!(!rewritten.contains("CARGO_TARGET_DIR=/data/projects/custom-target"));
    }

    #[test]
    fn test_rewrite_cargo_target_dir_command_for_remote_strips_target_dir_flag() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let command_tokens = vec![
            "cargo".to_string(),
            "build".to_string(),
            "--target-dir".to_string(),
            "/data/tmp/rch-target-flag".to_string(),
            "--release".to_string(),
        ];

        let rewritten = rewrite_cargo_target_dir_command_for_remote(
            "cargo build --target-dir /data/tmp/rch-target-flag --release",
            Some(&command_tokens),
            Some(&PathBuf::from("/data/tmp/rch-target-flag")),
            &reporter,
        );

        assert_eq!(rewritten, "cargo build --release");
        assert!(!rewritten.contains("--target-dir"));
        assert!(!rewritten.contains("/data/tmp/rch-target-flag"));
    }

    #[test]
    fn test_rewrite_cargo_target_dir_command_for_remote_strips_target_dir_equals_flag() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let command_tokens = vec![
            "cargo".to_string(),
            "check".to_string(),
            "--target-dir=/data/tmp/rch-target-equals".to_string(),
            "--workspace".to_string(),
        ];

        let rewritten = rewrite_cargo_target_dir_command_for_remote(
            "cargo check --target-dir=/data/tmp/rch-target-equals --workspace",
            Some(&command_tokens),
            Some(&PathBuf::from("/data/tmp/rch-target-equals")),
            &reporter,
        );

        assert_eq!(rewritten, "cargo check --workspace");
        assert!(!rewritten.contains("--target-dir"));
        assert!(!rewritten.contains("/data/tmp/rch-target-equals"));
    }

    #[test]
    fn test_cargo_target_dir_scanner_ignores_args_after_delimiter() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let command_tokens = vec![
            "cargo".to_string(),
            "test".to_string(),
            "--".to_string(),
            "--target-dir".to_string(),
            "test-filter".to_string(),
        ];
        let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
            Some(CompilationKind::CargoTest),
            Path::new("/data/projects/remote_compilation_helper"),
            &reporter,
            |_| None,
            Some(&command_tokens),
        );
        let rewritten = rewrite_cargo_target_dir_command_for_remote(
            "cargo test -- --target-dir test-filter",
            Some(&command_tokens),
            Some(&PathBuf::from(
                "/data/projects/remote_compilation_helper/target",
            )),
            &reporter,
        );

        assert_eq!(
            resolved,
            Some(PathBuf::from(
                "/data/projects/remote_compilation_helper/target"
            ))
        );
        assert_eq!(rewritten, "cargo test -- --target-dir test-filter");
    }

    #[test]
    fn test_rewrite_cargo_target_dir_command_preserves_args_after_delimiter() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let command_tokens = vec![
            "cargo".to_string(),
            "test".to_string(),
            "--target-dir".to_string(),
            "/data/tmp/rch-target-flag".to_string(),
            "--".to_string(),
            "--nocapture".to_string(),
        ];

        let rewritten = rewrite_cargo_target_dir_command_for_remote(
            "cargo test --target-dir /data/tmp/rch-target-flag -- --nocapture",
            Some(&command_tokens),
            Some(&PathBuf::from("/data/tmp/rch-target-flag")),
            &reporter,
        );

        assert_eq!(rewritten, "cargo test -- --nocapture");
    }

    fn env_key_strategy() -> impl Strategy<Value = String> {
        prop::string::string_regex("[A-Z_][A-Z0-9_]{0,16}")
            .expect("valid env key regex")
            .prop_filter("not the target dir key under test", |key| {
                key != "CARGO_TARGET_DIR"
            })
    }

    fn shell_safe_value_strategy() -> impl Strategy<Value = String> {
        prop::string::string_regex("[A-Za-z0-9_./:+-]{0,40}").expect("valid env value regex")
    }

    fn relative_target_dir_strategy() -> impl Strategy<Value = String> {
        prop::string::string_regex("[A-Za-z0-9_.-]{1,16}(/[A-Za-z0-9_.-]{1,16}){0,2}")
            .expect("valid relative path regex")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn env_prefix_target_dir_parser_round_trips_and_rewrites(
            target_dir in relative_target_dir_strategy(),
            extra_envs in prop::collection::vec((env_key_strategy(), shell_safe_value_strategy()), 0..4),
            cargo_subcommand in prop_oneof![
                Just("build".to_string()),
                Just("check".to_string()),
                Just("test".to_string()),
                Just("clippy".to_string()),
            ],
        ) {
            let _guard = test_guard!();
            let reporter = HookReporter::new(OutputVisibility::Verbose);
            let mut tokens = vec!["env".to_string()];
            for (key, value) in &extra_envs {
                tokens.push(format!("{key}={value}"));
            }
            tokens.push(format!("CARGO_TARGET_DIR={target_dir}"));
            tokens.push("cargo".to_string());
            tokens.push(cargo_subcommand);
            tokens.push("--release".to_string());

            let command = join_exec_command(&tokens);
            let parsed = parse_command_tokens(&command, &reporter).expect("joined command should parse");
            prop_assert_eq!(&parsed, &tokens);
            prop_assert_eq!(
                extract_cargo_target_dir_from_command_tokens(&parsed),
                Some(target_dir.clone())
            );

            let invocation_cwd = Path::new("/tmp/rch-proptest-project");
            let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
                Some(CompilationKind::CargoBuild),
                invocation_cwd,
                &reporter,
                |_| Some("/tmp/ambient-target".to_string()),
                Some(&parsed),
            );
            let expected_resolved = Some(invocation_cwd.join(&target_dir));
            prop_assert_eq!(resolved.as_ref(), expected_resolved.as_ref());

            let rewritten = rewrite_cargo_target_dir_command_for_remote(
                &command,
                Some(&parsed),
                resolved.as_ref(),
                &reporter,
            );
            prop_assert!(!rewritten.contains("CARGO_TARGET_DIR="));
            let rewritten_tokens = parse_command_tokens(&rewritten, &reporter)
                .expect("rewritten command should remain parseable");
            prop_assert_eq!(rewritten_tokens.first().map(String::as_str), Some("env"));
            for (key, value) in &extra_envs {
                let expected_assignment = format!("{key}={value}");
                prop_assert!(
                    rewritten_tokens.contains(&expected_assignment),
                    "rewritten command dropped env assignment {expected_assignment:?}"
                );
            }
            prop_assert!(rewritten_tokens.iter().any(|token| token == "cargo"));
        }

        #[test]
        fn env_prefix_helpers_do_not_panic_on_arbitrary_command_bytes(
            bytes in prop::collection::vec(any::<u8>(), 0..192),
        ) {
            let _guard = test_guard!();
            let reporter = HookReporter::new(OutputVisibility::Verbose);
            let command = String::from_utf8_lossy(&bytes).into_owned();

            if let Some(tokens) = parse_command_tokens(&command, &reporter) {
                let _ = extract_cargo_target_dir_from_command_tokens(&tokens);
                let _ = strip_cargo_target_dir_assignments_from_command_tokens(&tokens);
                let _ = strip_cargo_target_dir_flags_from_command_tokens(&tokens);

                let rewritten = rewrite_cargo_target_dir_command_for_remote(
                    &command,
                    Some(&tokens),
                    Some(&PathBuf::from("/tmp/rch-proptest-target")),
                    &reporter,
                );
                prop_assert!(
                    parse_command_tokens(&rewritten, &reporter).is_some(),
                    "parsed command rewrote to an unparsable command: {rewritten:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_collect_repo_updater_roots_and_specs_filters_to_git_roots_with_origin() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let with_origin = temp_dir.path().join("with_origin");
        let duplicate_origin = temp_dir.path().join("duplicate_origin");
        let without_origin = temp_dir.path().join("without_origin");
        let not_git = temp_dir.path().join("not_git");

        std::fs::create_dir_all(&with_origin).expect("create with_origin");
        std::fs::create_dir_all(&duplicate_origin).expect("create duplicate_origin");
        std::fs::create_dir_all(&without_origin).expect("create without_origin");
        std::fs::create_dir_all(&not_git).expect("create not_git");

        for repo in [&with_origin, &duplicate_origin, &without_origin] {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .arg("init")
                .arg("-q")
                .status()
                .expect("git init should run");
            assert!(
                status.success(),
                "git init should succeed for {}",
                repo.display()
            );
        }

        let origin_url = "git@github.com:example/repo-with-origin.git";
        for repo in [&with_origin, &duplicate_origin] {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .arg("remote")
                .arg("add")
                .arg("origin")
                .arg(origin_url)
                .status()
                .expect("git remote add should run");
            assert!(
                status.success(),
                "git remote add should succeed for {}",
                repo.display()
            );
        }

        let collected = collect_repo_updater_roots_and_specs(&[
            with_origin.clone(),
            without_origin.clone(),
            not_git.clone(),
            duplicate_origin.clone(),
        ])
        .await;

        assert_eq!(
            collected.roots,
            vec![with_origin.clone(), duplicate_origin.clone()]
        );
        assert_eq!(collected.specs, vec![origin_url.to_string()]);
    }

    #[test]
    fn test_auto_tune_repo_updater_contract_autoseeds_allowlist_and_mode() {
        let _guard = test_guard!();
        let mut contract = RepoUpdaterAdapterContract::default();
        let repo_specs = vec!["github.com/example/repo".to_string()];
        let auth_context = RepoUpdaterAuthContext {
            source: RepoUpdaterCredentialSource::SshAgent,
            credential_id: "ssh-agent".to_string(),
            issued_at_unix_ms: 1_700_000_000_000,
            expires_at_unix_ms: 1_700_000_060_000,
            granted_scopes: vec![],
            revoked: false,
            verified_hosts: vec![],
        };
        let reporter = HookReporter::new(OutputVisibility::None);

        auto_tune_repo_updater_contract(
            &mut contract,
            &repo_specs,
            Some(&auth_context),
            false,
            false,
            &reporter,
        );

        assert_eq!(contract.trust_policy.allowlisted_repo_specs, repo_specs);
        assert_eq!(
            contract.auth_policy.mode,
            RepoUpdaterAuthMode::InheritEnvironment
        );
    }

    #[test]
    fn test_hydrate_repo_updater_auth_context_defaults_populates_required_fields() {
        let _guard = test_guard!();
        let contract = RepoUpdaterAdapterContract::default();
        let now_ms = 1_700_000_000_000_i64;
        let mut auth_context = RepoUpdaterAuthContext {
            source: RepoUpdaterCredentialSource::TokenEnv,
            credential_id: String::new(),
            issued_at_unix_ms: 0,
            expires_at_unix_ms: 0,
            granted_scopes: vec![],
            revoked: false,
            verified_hosts: vec![],
        };

        hydrate_repo_updater_auth_context_defaults(&mut auth_context, now_ms, &contract);

        assert_eq!(auth_context.credential_id, "token-env");
        assert!(auth_context.issued_at_unix_ms > 0);
        assert!(auth_context.issued_at_unix_ms <= now_ms);
        assert!(auth_context.expires_at_unix_ms > now_ms);
        assert_eq!(
            auth_context.granted_scopes,
            contract.auth_policy.required_scopes
        );
        assert_eq!(
            auth_context.verified_hosts.len(),
            contract.auth_policy.trusted_host_identities.len()
        );
    }

    #[test]
    fn test_infer_repo_updater_auth_context_returns_none_without_local_auth() {
        let _guard = test_guard!();
        assert!(
            infer_repo_updater_auth_context_with_env_lookup(1_700_000_000_000, |_| false).is_none()
        );
    }

    #[test]
    fn test_infer_repo_updater_auth_context_uses_token_env_when_present() {
        let _guard = test_guard!();
        let auth_context =
            infer_repo_updater_auth_context_with_env_lookup(1_700_000_000_000, |key| {
                key == "GH_TOKEN"
            })
            .expect("token env should infer auth context");
        assert_eq!(auth_context.source, RepoUpdaterCredentialSource::TokenEnv);
        assert_eq!(auth_context.credential_id, "env:GH_TOKEN");
        assert_eq!(auth_context.granted_scopes, vec!["repo:read".to_string()]);
    }

    #[test]
    fn test_repo_updater_command_name_is_stable() {
        let _guard = test_guard!();
        assert_eq!(
            repo_updater_command_name(RepoUpdaterAdapterCommand::SyncApply),
            "sync-apply"
        );
        assert_eq!(
            repo_updater_command_name(RepoUpdaterAdapterCommand::SyncDryRun),
            "sync-dry-run"
        );
        assert_eq!(
            repo_updater_command_name(RepoUpdaterAdapterCommand::StatusNoFetch),
            "status-no-fetch"
        );
    }

    #[test]
    fn test_build_repo_sync_idempotency_key_for_command_distinguishes_commands() {
        let _guard = test_guard!();
        let worker_id = WorkerId::new("worker-a");
        let sync_roots = vec![
            PathBuf::from("/data/projects/repo-a"),
            PathBuf::from("/data/projects/repo-b"),
        ];

        let apply_key = build_repo_sync_idempotency_key_for_command(
            &worker_id,
            &sync_roots,
            RepoUpdaterAdapterCommand::SyncApply,
        );
        let dry_run_key = build_repo_sync_idempotency_key_for_command(
            &worker_id,
            &sync_roots,
            RepoUpdaterAdapterCommand::SyncDryRun,
        );
        let status_key = build_repo_sync_idempotency_key_for_command(
            &worker_id,
            &sync_roots,
            RepoUpdaterAdapterCommand::StatusNoFetch,
        );

        assert_ne!(apply_key, dry_run_key);
        assert_ne!(dry_run_key, status_key);
        assert_ne!(apply_key, status_key);
        assert!(apply_key.starts_with("rch-repo-sync-"));
    }

    #[test]
    fn test_build_remote_dependency_preflight_command_empty_roots() {
        let _guard = test_guard!();
        assert!(build_remote_dependency_preflight_command(&[]).is_none());
    }

    #[test]
    fn test_build_remote_dependency_preflight_command_separates_checks() {
        let _guard = test_guard!();
        let checks = vec![
            DependencyPreflightCheck {
                root: "/data/projects/repo-a".to_string(),
                manifest: "/data/projects/repo-a/Cargo.toml".to_string(),
                required_path: "/data/projects/repo-a/Cargo.toml".to_string(),
                required_kind: "manifest",
                is_primary: true,
            },
            DependencyPreflightCheck {
                root: "/data/projects/repo-b".to_string(),
                manifest: "/data/projects/repo-b/Cargo.toml".to_string(),
                required_path: "/data/projects/repo-b/src/lib.rs".to_string(),
                required_kind: "source_entrypoint",
                is_primary: false,
            },
        ];

        let command = build_remote_dependency_preflight_command(&checks)
            .expect("command should be constructed");

        assert!(
            command.contains("for required in "),
            "generated command must batch paths through one bounded shell loop"
        );
        assert!(
            !command.contains("fi if ["),
            "generated command must not concatenate checks without separator"
        );
        assert!(
            command.contains("RCH_DEP_PRESENT:"),
            "generated command must emit structured present marker"
        );
        assert!(
            command.contains("RCH_DEP_MISSING:"),
            "generated command must emit structured missing marker"
        );
    }

    #[test]
    fn test_build_remote_dependency_preflight_commands_batches_large_workspaces() {
        let _guard = test_guard!();
        let checks = (0..=DEPENDENCY_PREFLIGHT_PROBE_BATCH_SIZE)
            .map(|idx| DependencyPreflightCheck {
                root: "/data/projects/big".to_string(),
                manifest: "/data/projects/big/Cargo.toml".to_string(),
                required_path: format!("/data/projects/big/tests/case_{idx}.rs"),
                required_kind: "source_entrypoint",
                is_primary: true,
            })
            .collect::<Vec<_>>();

        let commands = build_remote_dependency_preflight_commands(&checks);

        assert_eq!(
            commands.len(),
            2,
            "one more than the batch size must be split into two SSH commands"
        );
        assert!(commands[0].contains("/data/projects/big/tests/case_127.rs"));
        assert!(!commands[0].contains("/data/projects/big/tests/case_128.rs"));
        assert!(commands[1].contains("/data/projects/big/tests/case_128.rs"));
    }

    #[test]
    fn test_synced_dependency_preflight_checks_use_remote_paths() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let package_root = temp_dir.path().join("package");
        std::fs::create_dir_all(package_root.join("src")).expect("create package src");
        std::fs::write(
            package_root.join("Cargo.toml"),
            r#"[package]
name = "package"
version = "0.1.0"
edition = "2024"
"#,
        )
        .expect("write manifest");
        std::fs::write(package_root.join("src/lib.rs"), "pub fn package() {}\n")
            .expect("write lib");

        let root_outcomes = vec![
            (
                SyncClosurePlanEntry {
                    local_root: package_root,
                    remote_root: "/data/projects/frankenterm".to_string(),
                    project_id: "frankenterm".to_string(),
                    root_hash: "hash-primary".to_string(),
                    is_primary: true,
                    mode: SyncClosureMode::Full,
                },
                SyncRootOutcome::Synced,
            ),
            (
                SyncClosurePlanEntry {
                    local_root: PathBuf::from("/Users/jemanuel/projects/frankentui"),
                    remote_root: "/data/projects/frankentui".to_string(),
                    project_id: "frankentui".to_string(),
                    root_hash: "hash-dep".to_string(),
                    is_primary: false,
                    mode: SyncClosureMode::Full,
                },
                SyncRootOutcome::Failed {
                    error: "no sync".to_string(),
                },
            ),
        ];

        let synced = synced_dependency_preflight_checks(&root_outcomes);
        let required_paths = synced
            .iter()
            .map(|check| check.required_path.as_str())
            .collect::<Vec<_>>();
        assert!(required_paths.contains(&"/data/projects/frankenterm/Cargo.toml"));
        assert!(required_paths.contains(&"/data/projects/frankenterm/src/lib.rs"));
        assert!(
            !required_paths
                .iter()
                .any(|path| path.starts_with("/data/projects/frankentui")),
            "failed roots must not be probed as freshly synced"
        );
    }

    #[test]
    fn test_parse_dependency_preflight_probe_output_extracts_markers() {
        let _guard = test_guard!();
        let stdout = "\
RCH_DEP_PRESENT:/data/projects/a/Cargo.toml
noise
RCH_DEP_MISSING:/data/projects/b/Cargo.toml
RCH_DEP_PRESENT:/data/projects/c/Cargo.toml
";

        let (present, missing) = parse_dependency_preflight_probe_output(stdout);

        assert_eq!(present.len(), 2);
        assert_eq!(missing.len(), 1);
        assert!(present.contains("/data/projects/a/Cargo.toml"));
        assert!(present.contains("/data/projects/c/Cargo.toml"));
        assert!(missing.contains("/data/projects/b/Cargo.toml"));
    }

    fn make_sync_entry(root: &str, is_primary: bool) -> SyncClosurePlanEntry {
        SyncClosurePlanEntry {
            local_root: PathBuf::from(root),
            remote_root: root.to_string(),
            project_id: format!("id-{}", root.replace('/', "_")),
            root_hash: format!("hash-{}", root.replace('/', "_")),
            is_primary,
            mode: SyncClosureMode::Full,
        }
    }

    fn make_test_worker_config(id: &str) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: "worker.host".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_ed25519".to_string(),
            total_slots: 8,
            priority: 100,
            tags: Vec::new(),
        }
    }

    fn make_fail_open_plan(
        fail_open_reason: Option<&str>,
        issues: Vec<rch_common::DependencyPlanIssue>,
    ) -> DependencyClosurePlan {
        DependencyClosurePlan {
            state: rch_common::DependencyClosurePlanState::FailOpen,
            entry_manifest_path: PathBuf::from("/data/projects/example/Cargo.toml"),
            workspace_root: Some(PathBuf::from("/data/projects/example")),
            canonical_roots: Vec::new(),
            sync_order: Vec::new(),
            fail_open: true,
            fail_open_reason: fail_open_reason.map(ToString::to_string),
            issues,
        }
    }

    #[test]
    fn test_classify_dependency_runtime_fail_open_policy_violation() {
        let _guard = test_guard!();
        let plan = make_fail_open_plan(
            Some("resolver produced path policy violation"),
            vec![rch_common::DependencyPlanIssue {
                code: "path-policy-violation".to_string(),
                message: "dependency path escapes canonical root".to_string(),
                risk: rch_common::DependencyRiskClass::High,
                diagnostics: vec!["dependency_path=/tmp/off-policy".to_string()],
            }],
        );

        let decision = classify_dependency_runtime_fail_open(&plan);
        assert_eq!(decision.reason_code, DEPENDENCY_PREFLIGHT_CODE_POLICY);
        assert_eq!(
            decision.remediation,
            DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY
        );
    }

    #[test]
    fn test_classify_dependency_runtime_fail_open_timeout_signal() {
        let _guard = test_guard!();
        let plan = make_fail_open_plan(
            Some("cargo metadata timed out after 10s"),
            vec![rch_common::DependencyPlanIssue {
                code: "metadata-invocation-failure".to_string(),
                message: "metadata invocation timed out".to_string(),
                risk: rch_common::DependencyRiskClass::Critical,
                diagnostics: vec!["timeout=10s".to_string()],
            }],
        );

        let decision = classify_dependency_runtime_fail_open(&plan);
        assert_eq!(decision.reason_code, DEPENDENCY_PREFLIGHT_CODE_TIMEOUT);
        assert_eq!(
            decision.remediation,
            DEPENDENCY_PREFLIGHT_REMEDIATION_TIMEOUT
        );
    }

    #[test]
    fn test_classify_dependency_runtime_fail_open_defaults_unknown() {
        let _guard = test_guard!();
        let plan = make_fail_open_plan(
            Some("resolver returned unverifiable graph ordering"),
            vec![rch_common::DependencyPlanIssue {
                code: "non-deterministic-order".to_string(),
                message: "graph order could not be proven".to_string(),
                risk: rch_common::DependencyRiskClass::Critical,
                diagnostics: vec!["planner_state=fail_open".to_string()],
            }],
        );

        let decision = classify_dependency_runtime_fail_open(&plan);
        assert_eq!(decision.reason_code, DEPENDENCY_PREFLIGHT_CODE_UNKNOWN);
        assert_eq!(
            decision.remediation,
            DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN
        );
    }

    #[test]
    fn test_build_dependency_runtime_fail_open_report_uses_status_mapping() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-runtime-report");
        let project_root = PathBuf::from("/data/projects/runtime-policy");
        let decision = DependencyRuntimeFailOpenDecision {
            reason_code: DEPENDENCY_PREFLIGHT_CODE_POLICY,
            remediation: DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY,
            detail: "policy violation detail".to_string(),
        };

        let report = build_dependency_runtime_fail_open_report(&worker, &project_root, &decision);
        assert!(!report.verified);
        assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_POLICY));
        assert_eq!(
            report.remediation,
            Some(DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY)
        );
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(
            report.evidence[0].status,
            DependencyPreflightStatus::PolicyViolation
        );
    }

    #[test]
    fn test_should_force_local_fallback_for_runtime_fail_open_policy_only() {
        let _guard = test_guard!();
        assert!(should_force_local_fallback_for_runtime_fail_open(
            DEPENDENCY_PREFLIGHT_CODE_POLICY
        ));
        assert!(!should_force_local_fallback_for_runtime_fail_open(
            DEPENDENCY_PREFLIGHT_CODE_UNKNOWN
        ));
        assert!(!should_force_local_fallback_for_runtime_fail_open(
            DEPENDENCY_PREFLIGHT_CODE_TIMEOUT
        ));
    }

    #[test]
    fn test_e2e_dependency_preflight_verified_success_path() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-success");
        let entry = make_sync_entry("/data/projects/repo-success", true);
        let manifest = entry
            .local_root
            .join("Cargo.toml")
            .to_string_lossy()
            .to_string();
        let outcomes = vec![(entry, SyncRootOutcome::Synced)];
        let present = std::collections::BTreeSet::from([manifest]);
        let missing = std::collections::BTreeSet::new();

        let report =
            build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

        assert!(report.verified, "all-present manifests should verify");
        assert!(report.reason_code.is_none());
        assert!(report.remediation.is_none());
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(
            report.evidence[0].status,
            DependencyPreflightStatus::Present,
            "evidence must mark synced+present roots as present"
        );
    }

    #[test]
    fn test_build_dependency_preflight_report_uses_remote_manifest_paths() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-remote-paths");
        let entry = SyncClosurePlanEntry {
            local_root: PathBuf::from("/Users/jemanuel/projects/repo-success"),
            remote_root: "/data/projects/repo-success".to_string(),
            project_id: "id-remote-paths".to_string(),
            root_hash: "hash-remote-paths".to_string(),
            is_primary: true,
            mode: SyncClosureMode::Full,
        };
        let outcomes = vec![(entry, SyncRootOutcome::Synced)];
        let present = std::collections::BTreeSet::from([String::from(
            "/data/projects/repo-success/Cargo.toml",
        )]);
        let missing = std::collections::BTreeSet::new();

        let report =
            build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

        assert!(report.verified, "remote manifest markers should verify");
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(
            report.evidence[0].root, "/data/projects/repo-success",
            "evidence should report the remote synced root"
        );
        assert_eq!(
            report.evidence[0].manifest, "/data/projects/repo-success/Cargo.toml",
            "manifest matching must use remote paths from the probe"
        );
        assert_eq!(
            report.evidence[0].status,
            DependencyPreflightStatus::Present
        );
    }

    #[test]
    fn test_build_dependency_preflight_report_missing_stale_and_unknown_paths() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-mixed");
        // Use is_primary: true so the missing status triggers blocking.
        let synced_missing = make_sync_entry("/data/projects/repo-missing", true);
        let skipped_stale = make_sync_entry("/data/projects/repo-stale", false);
        let failed_unknown = make_sync_entry("/data/projects/repo-unknown", false);
        let missing_manifest = synced_missing
            .local_root
            .join("Cargo.toml")
            .to_string_lossy()
            .to_string();
        let outcomes = vec![
            (synced_missing, SyncRootOutcome::Synced),
            (
                skipped_stale,
                SyncRootOutcome::Skipped {
                    reason: "transfer skipped by estimator".to_string(),
                },
            ),
            (
                failed_unknown,
                SyncRootOutcome::Failed {
                    error: "rsync timeout".to_string(),
                },
            ),
        ];
        let present = std::collections::BTreeSet::new();
        let missing = std::collections::BTreeSet::from([missing_manifest]);

        let report = build_dependency_preflight_report(
            &worker,
            &outcomes,
            &present,
            &missing,
            Some("probe returned missing markers"),
        );

        assert!(
            !report.verified,
            "missing primary root evidence must block remote execution"
        );
        assert_eq!(
            report.reason_code,
            Some(DEPENDENCY_PREFLIGHT_CODE_MISSING),
            "missing primary should dominate failure reason"
        );
        assert_eq!(
            report.remediation,
            Some(DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING)
        );
        assert!(
            report
                .evidence
                .iter()
                .any(|item| item.status == DependencyPreflightStatus::Missing)
        );
        assert!(
            report
                .evidence
                .iter()
                .any(|item| item.status == DependencyPreflightStatus::Stale)
        );
        assert!(
            report
                .evidence
                .iter()
                .any(|item| item.status == DependencyPreflightStatus::Unknown)
        );
    }

    #[test]
    fn test_e2e_dependency_preflight_stale_fallback_path_maps_reason_code() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-stale");
        // Use is_primary: true so stale status triggers blocking.
        let stale_entry = make_sync_entry("/data/projects/repo-stale-only", true);
        let outcomes = vec![(
            stale_entry,
            SyncRootOutcome::Skipped {
                reason: "bandwidth guard skip".to_string(),
            },
        )];
        let present = std::collections::BTreeSet::new();
        let missing = std::collections::BTreeSet::new();

        let report =
            build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

        assert!(!report.verified);
        assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_STALE));
        assert_eq!(
            report.remediation,
            Some(DEPENDENCY_PREFLIGHT_REMEDIATION_STALE)
        );
    }

    #[test]
    fn test_e2e_dependency_preflight_missing_fallback_path_maps_reason_code() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-missing");
        // Use is_primary: true so missing status triggers blocking.
        let entry = make_sync_entry("/data/projects/repo-missing-only", true);
        let manifest = entry
            .local_root
            .join("Cargo.toml")
            .to_string_lossy()
            .to_string();
        let outcomes = vec![(entry, SyncRootOutcome::Synced)];
        let present = std::collections::BTreeSet::new();
        let missing = std::collections::BTreeSet::from([manifest]);

        let report =
            build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

        assert!(!report.verified);
        assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_MISSING));
        assert_eq!(
            report.remediation,
            Some(DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING)
        );
    }

    #[test]
    fn test_cargo_package_source_entrypoints_include_auto_discovered_targets() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let package_root = temp_dir.path().join("auto-targets");
        for dir in [
            "src",
            "src/bin/nested",
            "examples/demo",
            "tests/integration",
            "benches/speed",
        ] {
            std::fs::create_dir_all(package_root.join(dir)).expect("create target dir");
        }
        std::fs::write(
            package_root.join("Cargo.toml"),
            r#"[package]
name = "auto-targets"
version = "0.1.0"
edition = "2024"
"#,
        )
        .expect("write manifest");
        for path in [
            "src/lib.rs",
            "src/main.rs",
            "src/bin/tool.rs",
            "src/bin/nested/main.rs",
            "examples/example.rs",
            "examples/demo/main.rs",
            "tests/integration.rs",
            "tests/integration/main.rs",
            "benches/speed.rs",
            "benches/speed/main.rs",
        ] {
            std::fs::write(package_root.join(path), "fn main() {}\n").expect("write entrypoint");
        }

        let entrypoints = cargo_package_source_entrypoints(&package_root);

        for path in [
            "src/lib.rs",
            "src/main.rs",
            "src/bin/tool.rs",
            "src/bin/nested/main.rs",
            "examples/example.rs",
            "examples/demo/main.rs",
            "tests/integration.rs",
            "tests/integration/main.rs",
            "benches/speed.rs",
            "benches/speed/main.rs",
        ] {
            assert!(
                entrypoints.contains(&PathBuf::from(path)),
                "missing auto-discovered entrypoint {path}"
            );
        }
    }

    #[test]
    fn test_cargo_package_source_entrypoints_respect_auto_discovery_flags() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let package_root = temp_dir.path().join("manual-targets");
        for dir in ["src/bin", "examples", "tests", "benches", "custom"] {
            std::fs::create_dir_all(package_root.join(dir)).expect("create target dir");
        }
        std::fs::write(
            package_root.join("Cargo.toml"),
            r#"[package]
name = "manual-targets"
version = "0.1.0"
edition = "2024"
autolib = false
autobins = false
autoexamples = false
autotests = false
autobenches = false

[lib]
path = "custom/lib.rs"

[[bin]]
path = "custom/bin.rs"
"#,
        )
        .expect("write manifest");
        for path in [
            "src/lib.rs",
            "src/main.rs",
            "src/bin/tool.rs",
            "examples/example.rs",
            "tests/integration.rs",
            "benches/speed.rs",
            "custom/lib.rs",
            "custom/bin.rs",
        ] {
            std::fs::write(package_root.join(path), "fn main() {}\n").expect("write entrypoint");
        }

        let entrypoints = cargo_package_source_entrypoints(&package_root);

        assert_eq!(
            entrypoints,
            vec![
                PathBuf::from("custom/bin.rs"),
                PathBuf::from("custom/lib.rs")
            ]
        );
    }

    #[test]
    fn test_workspace_member_source_entrypoints_include_all_targets_and_exclusions() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let workspace_root = temp_dir.path().join("workspace");

        for dir in [
            "crates/core/src",
            "crates/core/benches",
            "crates/core/examples",
            "crates/atlas-types/src",
            "crates/skipped/src",
            "tools/cli/src",
        ] {
            std::fs::create_dir_all(workspace_root.join(dir)).expect("create workspace dir");
        }
        std::fs::write(
            workspace_root.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/*", "tools/cli"]
exclude = ["crates/skipped"]
"#,
        )
        .expect("write workspace manifest");
        for (manifest, name) in [
            ("crates/core/Cargo.toml", "core"),
            ("crates/atlas-types/Cargo.toml", "atlas-types"),
            ("crates/skipped/Cargo.toml", "skipped"),
            ("tools/cli/Cargo.toml", "cli"),
        ] {
            std::fs::write(
                workspace_root.join(manifest),
                format!(
                    r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2024"
"#
                ),
            )
            .expect("write member manifest");
        }
        for path in [
            "crates/core/src/lib.rs",
            "crates/core/benches/interval_tree_bench.rs",
            "crates/core/examples/atlas_packing_attestation.rs",
            "crates/atlas-types/src/lib.rs",
            "crates/skipped/src/lib.rs",
            "tools/cli/src/lib.rs",
        ] {
            std::fs::write(workspace_root.join(path), "pub fn marker() {}\n")
                .expect("write member entrypoint");
        }

        let entrypoints = cargo_workspace_member_source_entrypoints(&workspace_root);

        for path in [
            "crates/core/Cargo.toml",
            "crates/core/src/lib.rs",
            "crates/core/benches/interval_tree_bench.rs",
            "crates/core/examples/atlas_packing_attestation.rs",
            "crates/atlas-types/Cargo.toml",
            "crates/atlas-types/src/lib.rs",
            "tools/cli/Cargo.toml",
            "tools/cli/src/lib.rs",
        ] {
            assert!(
                entrypoints.contains(&PathBuf::from(path)),
                "missing workspace member entrypoint {path}"
            );
        }
        assert!(
            !entrypoints
                .iter()
                .any(|path| path.starts_with("crates/skipped")),
            "workspace exclude entries must not be preflighted"
        );
    }

    #[test]
    fn test_dependency_preflight_checks_expand_virtual_workspace_all_targets() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let workspace_root = temp_dir.path().join("frankenterm");

        for dir in [
            "crates/frankenterm-core/src",
            "crates/frankenterm-core/benches",
            "crates/frankenterm-core/examples",
            "crates/frankenterm-core-atlas-pack-types/src",
            "crates/frankenterm-core-connectors/src",
            "crates/skipped/src",
        ] {
            std::fs::create_dir_all(workspace_root.join(dir)).expect("create workspace dir");
        }
        std::fs::write(
            workspace_root.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/frankenterm-core", "crates/frankenterm-core-*", "crates/skipped"]
exclude = ["crates/skipped"]
"#,
        )
        .expect("write workspace manifest");
        for (manifest, name) in [
            ("crates/frankenterm-core/Cargo.toml", "frankenterm-core"),
            (
                "crates/frankenterm-core-atlas-pack-types/Cargo.toml",
                "frankenterm-core-atlas-pack-types",
            ),
            (
                "crates/frankenterm-core-connectors/Cargo.toml",
                "frankenterm-core-connectors",
            ),
            ("crates/skipped/Cargo.toml", "skipped"),
        ] {
            std::fs::write(
                workspace_root.join(manifest),
                format!(
                    r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2024"
"#
                ),
            )
            .expect("write member manifest");
        }
        for path in [
            "crates/frankenterm-core/src/lib.rs",
            "crates/frankenterm-core/benches/interval_tree_bench.rs",
            "crates/frankenterm-core/examples/atlas_packing_attestation.rs",
            "crates/frankenterm-core-atlas-pack-types/src/lib.rs",
            "crates/frankenterm-core-connectors/src/lib.rs",
            "crates/skipped/src/lib.rs",
        ] {
            std::fs::write(workspace_root.join(path), "pub fn marker() {}\n")
                .expect("write member entrypoint");
        }
        let entry = SyncClosurePlanEntry {
            local_root: workspace_root,
            remote_root: "/data/projects/frankenterm".to_string(),
            project_id: "frankenterm".to_string(),
            root_hash: "frankenterm-hash".to_string(),
            is_primary: true,
            mode: SyncClosureMode::Full,
        };

        let checks = dependency_preflight_checks_for_entry(&entry);
        let required_paths = checks
            .iter()
            .map(|check| check.required_path.as_str())
            .collect::<std::collections::BTreeSet<_>>();

        for path in [
            "/data/projects/frankenterm/Cargo.toml",
            "/data/projects/frankenterm/crates/frankenterm-core/Cargo.toml",
            "/data/projects/frankenterm/crates/frankenterm-core/src/lib.rs",
            "/data/projects/frankenterm/crates/frankenterm-core/benches/interval_tree_bench.rs",
            "/data/projects/frankenterm/crates/frankenterm-core/examples/atlas_packing_attestation.rs",
            "/data/projects/frankenterm/crates/frankenterm-core-atlas-pack-types/src/lib.rs",
            "/data/projects/frankenterm/crates/frankenterm-core-connectors/src/lib.rs",
        ] {
            assert!(
                required_paths.contains(path),
                "missing dependency preflight check for {path}"
            );
        }
        assert!(
            !required_paths
                .iter()
                .any(|path| path.contains("/crates/skipped/")),
            "workspace excluded members must not be preflighted"
        );
    }

    #[test]
    fn test_dependency_preflight_blocks_missing_source_entrypoint() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-missing-source");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let package_root = temp_dir.path().join("member");
        std::fs::create_dir_all(package_root.join("src")).expect("create src");
        std::fs::write(
            package_root.join("Cargo.toml"),
            r#"[package]
name = "member"
version = "0.1.0"
edition = "2024"
"#,
        )
        .expect("write manifest");
        std::fs::write(package_root.join("src/lib.rs"), "pub fn member() {}\n").expect("write lib");
        let entry = SyncClosurePlanEntry {
            local_root: package_root,
            remote_root: "/data/projects/app/crates/member".to_string(),
            project_id: "member".to_string(),
            root_hash: "member-hash".to_string(),
            is_primary: false,
            mode: SyncClosureMode::Full,
        };
        let outcomes = vec![(entry, SyncRootOutcome::Synced)];
        let present = std::collections::BTreeSet::from([String::from(
            "/data/projects/app/crates/member/Cargo.toml",
        )]);
        let missing = std::collections::BTreeSet::from([String::from(
            "/data/projects/app/crates/member/src/lib.rs",
        )]);

        let report =
            build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

        assert!(
            !report.verified,
            "a synced root with a missing package source entrypoint must not reach Cargo"
        );
        assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_MISSING));
        assert!(report.evidence.iter().any(|item| {
            item.required_kind == "source_entrypoint"
                && item.required_path == "/data/projects/app/crates/member/src/lib.rs"
                && item.status == DependencyPreflightStatus::Missing
        }));
    }

    #[test]
    fn test_dependency_preflight_probe_failure_compacts_unknown_source_entrypoints() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-probe-reset");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let package_root = temp_dir.path().join("large-member");
        std::fs::create_dir_all(package_root.join("src")).expect("create src");
        std::fs::create_dir_all(package_root.join("tests")).expect("create tests");
        std::fs::write(
            package_root.join("Cargo.toml"),
            r#"[package]
name = "large-member"
version = "0.1.0"
edition = "2024"
"#,
        )
        .expect("write manifest");
        std::fs::write(package_root.join("src/lib.rs"), "pub fn member() {}\n").expect("write lib");
        for idx in 0..150 {
            std::fs::write(
                package_root.join("tests").join(format!("case_{idx}.rs")),
                "#[test]\nfn case() {}\n",
            )
            .expect("write test entrypoint");
        }
        let entry = SyncClosurePlanEntry {
            local_root: package_root,
            remote_root: "/data/projects/app/crates/large-member".to_string(),
            project_id: "large-member".to_string(),
            root_hash: "large-member-hash".to_string(),
            is_primary: false,
            mode: SyncClosureMode::Full,
        };
        let outcomes = vec![(entry, SyncRootOutcome::Synced)];
        let present = std::collections::BTreeSet::new();
        let missing = std::collections::BTreeSet::new();

        let report = build_dependency_preflight_report(
            &worker,
            &outcomes,
            &present,
            &missing,
            Some("probe exited with status Some(255); connection reset"),
        );

        assert!(!report.verified);
        assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_UNKNOWN));
        let unknown_source_entrypoints = report
            .evidence
            .iter()
            .filter(|item| {
                item.status == DependencyPreflightStatus::Unknown
                    && item.required_kind == "source_entrypoint"
            })
            .collect::<Vec<_>>();
        assert_eq!(
            unknown_source_entrypoints.len(),
            1,
            "transport failures should keep one sample per root/kind instead of duplicating every source entrypoint"
        );
        assert!(
            unknown_source_entrypoints[0]
                .detail
                .contains("additional unreported paths"),
            "unknown sample should explain why the report is compacted"
        );
        assert!(
            report.evidence.len() < 10,
            "large all-unknown reports should be compact, got {} evidence rows",
            report.evidence.len()
        );
    }

    #[tokio::test]
    async fn test_verify_remote_dependency_manifests_blocks_stale_outcomes_deterministically() {
        let _guard = test_guard!();
        // Disable mock mode so verify_remote_dependency_manifests reaches
        // the preflight report logic instead of short-circuiting.
        mock::set_thread_mock_override(Some(false));
        let worker = make_test_worker_config("worker-stale-verify");
        // Use is_primary: true so stale status triggers blocking.
        let outcomes = vec![(
            make_sync_entry("/data/projects/repo-stale-verify", true),
            SyncRootOutcome::Skipped {
                reason: "transfer budget skip".to_string(),
            },
        )];
        let reporter = HookReporter::new(OutputVisibility::Verbose);

        let err = verify_remote_dependency_manifests(&worker, &outcomes, &reporter)
            .await
            .expect_err("stale dependency evidence should block remote execution");
        let preflight = err
            .downcast_ref::<DependencyPreflightFailure>()
            .expect("error should preserve DependencyPreflightFailure type");
        assert_eq!(preflight.reason_code, DEPENDENCY_PREFLIGHT_CODE_STALE);
        assert_eq!(
            preflight.remediation,
            DEPENDENCY_PREFLIGHT_REMEDIATION_STALE
        );
        mock::set_thread_mock_override(None);
    }

    #[test]
    fn test_non_primary_missing_deps_block_preflight() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-non-primary");
        let primary = make_sync_entry("/data/projects/main-project", true);
        let dep = make_sync_entry("/data/projects/sibling-dep", false);
        let primary_manifest = primary
            .local_root
            .join("Cargo.toml")
            .to_string_lossy()
            .to_string();
        let dep_manifest = dep
            .local_root
            .join("Cargo.toml")
            .to_string_lossy()
            .to_string();

        let outcomes = vec![
            (primary, SyncRootOutcome::Synced),
            (dep, SyncRootOutcome::Synced),
        ];
        let present = std::collections::BTreeSet::from([primary_manifest]);
        let missing = std::collections::BTreeSet::from([dep_manifest]);

        let report =
            build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

        assert!(
            !report.verified,
            "non-primary missing dep must block preflight to avoid stale sibling builds"
        );
        assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_MISSING));
    }

    #[test]
    fn test_non_primary_stale_deps_block_preflight() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-non-primary-stale");
        let primary = make_sync_entry("/data/projects/main-project", true);
        let dep = make_sync_entry("/data/projects/sibling-dep-stale", false);
        let primary_manifest = primary
            .local_root
            .join("Cargo.toml")
            .to_string_lossy()
            .to_string();

        let outcomes = vec![
            (primary, SyncRootOutcome::Synced),
            (
                dep,
                SyncRootOutcome::Skipped {
                    reason: "estimator skip".to_string(),
                },
            ),
        ];
        let present = std::collections::BTreeSet::from([primary_manifest]);
        let missing = std::collections::BTreeSet::new();

        let report =
            build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

        assert!(
            !report.verified,
            "non-primary stale dep must block preflight to avoid stale sibling builds"
        );
        assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_STALE));
    }

    #[test]
    fn test_build_remote_shell_command_wraps_and_escapes_script() {
        let _guard = test_guard!();
        let command = "missing=0; if [ \"$missing\" -ne 0 ]; then echo 'bad'; fi";

        let wrapped = build_remote_shell_command(command);

        assert!(wrapped.starts_with("sh -lc "));
        assert!(
            wrapped.starts_with("sh -lc '"),
            "shell wrapper must quote the script as a single argument"
        );
        assert!(
            !wrapped.starts_with("sh -lc missing=0"),
            "script must not be passed unquoted"
        );
        assert!(
            wrapped.contains("if ["),
            "wrapped command should preserve the full script"
        );
    }

    #[test]
    fn test_build_worker_projects_topology_cmd_uses_supplied_policy() {
        let _guard = test_guard!();
        let policy = PathTopologyPolicy::new(
            PathBuf::from("/custom/projects"),
            PathBuf::from("/custom/dp"),
        );

        let command = build_worker_projects_topology_cmd(&policy);

        assert!(
            command.contains("/custom/projects"),
            "preflight command must use the supplied canonical root: {command}"
        );
        assert!(
            command.contains("/custom/dp"),
            "preflight command must use the supplied alias root: {command}"
        );
        assert!(
            !command.contains("/data/projects"),
            "preflight command must not silently fall back to default canonical root: {command}"
        );
    }

    #[test]
    fn test_build_worker_projects_topology_cmd_shell_escapes_policy_paths() {
        let _guard = test_guard!();
        let policy = PathTopologyPolicy::new(
            PathBuf::from("/tmp/rch weird'root"),
            PathBuf::from("/tmp/rch alias;bad"),
        );

        let command = build_worker_projects_topology_cmd(&policy);

        assert!(
            command.contains("'/tmp/rch weird'\\''root'"),
            "single quotes in canonical root must be shell escaped: {command}"
        );
        assert!(
            command.contains("'/tmp/rch alias;bad'"),
            "shell metacharacters in alias root must be quoted: {command}"
        );
    }

    #[test]
    fn test_build_worker_projects_topology_cmd_terminates_path_options() {
        let _guard = test_guard!();
        let policy = PathTopologyPolicy::new(
            PathBuf::from("-custom/projects"),
            PathBuf::from("-custom/dp"),
        );
        let canonical =
            shell_escape::escape(std::borrow::Cow::from("-custom/projects")).to_string();
        let alias = shell_escape::escape(std::borrow::Cow::from("-custom/dp")).to_string();

        let command = build_worker_projects_topology_cmd(&policy);

        assert!(
            command.contains(&format!("mkdir -p -- {canonical}")),
            "mkdir must terminate options before configured paths: {command}"
        );
        assert!(
            command.contains(&format!("readlink -- {alias}")),
            "readlink must terminate options before configured paths: {command}"
        );
        assert!(
            command.contains(&format!("ln -sfn -- {canonical} {alias}")),
            "ln update must terminate options before configured paths: {command}"
        );
        assert!(
            command.contains(&format!("ln -s -- {canonical} {alias}")),
            "ln create must terminate options before configured paths: {command}"
        );
    }

    #[test]
    fn test_build_worker_projects_topology_cmd_rechecks_alias_after_create_race() {
        let _guard = test_guard!();
        let policy = PathTopologyPolicy::new(
            PathBuf::from("/custom/projects"),
            PathBuf::from("/custom/dp"),
        );
        let canonical =
            shell_escape::escape(std::borrow::Cow::from("/custom/projects")).to_string();
        let alias = shell_escape::escape(std::borrow::Cow::from("/custom/dp")).to_string();

        let command = build_worker_projects_topology_cmd(&policy);

        assert!(
            command.contains(&format!(
                "create_stderr=$(ln -s -- {canonical} {alias} 2>&1) && return 0"
            )),
            "create path must handle normal symlink creation inside the alias helper: {command}"
        );
        assert!(
            command.contains(&format!(
                "if [ -L {alias} ]; then ensure_alias_symlink; return $?; fi"
            )),
            "failed create must re-check alias state so a concurrent correct symlink is harmless: {command}"
        );
        assert!(
            command.contains("RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK"),
            "regular-file alias conflicts must still fail with a structured reason: {command}"
        );
        assert!(
            command.contains("RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED"),
            "missing-alias create failures must report a structured reason: {command}"
        );
        assert!(
            command.contains(&format!(
                "printf 'RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED:path=%s:target=%s:%s\\n' {alias} {canonical} \"$create_stderr\""
            )),
            "missing-alias create failures must report the exact alias and canonical paths: {command}"
        );
        assert!(
            command.contains(&format!(
                "printf 'RCH_TOPOLOGY_ERR_ALIAS_UPDATE_FAILED:path=%s:target=%s:%s\\n' {alias} {canonical} \"$update_stderr\""
            )),
            "alias update failures must report the exact alias and canonical paths: {command}"
        );
        assert!(
            command.contains(&format!(
                "printf 'RCH_TOPOLOGY_ERR_CANONICAL_CREATE_FAILED:path=%s:%s\\n' {canonical} \"$mkdir_stderr\""
            )),
            "canonical mkdir failures must report the exact canonical path: {command}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_build_worker_projects_topology_cmd_treats_file_exists_race_as_success() {
        let _guard = test_guard!();
        use std::os::unix::fs::PermissionsExt;

        let (temp_dir, policy) = topology_tempdir();
        let fake_bin = temp_dir.path().join("fake-bin");
        std::fs::create_dir_all(&fake_bin).expect("create fake bin dir");
        let fake_ln = fake_bin.join("ln");
        std::fs::write(
            &fake_ln,
            "#!/bin/sh\n\
if [ \"$1\" = \"-s\" ] && [ \"$2\" = \"--\" ]; then\n\
  /bin/ln -s \"$3\" \"$4\" 2>/dev/null || true\n\
  echo \"ln: failed to create symbolic link '$4': File exists\" >&2\n\
  exit 1\n\
fi\n\
exec /bin/ln \"$@\"\n",
        )
        .expect("write fake ln");
        let mut perms = std::fs::metadata(&fake_ln)
            .expect("fake ln metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_ln, perms).expect("chmod fake ln");

        let command = build_worker_projects_topology_cmd(&policy);
        let path = format!(
            "{}:{}",
            fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("PATH", path)
            .output()
            .expect("run topology command");

        assert!(
            output.status.success(),
            "file-exists create race should be harmless; status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("RCH_TOPOLOGY_OK"),
            "successful preflight should emit OK"
        );
        assert_eq!(
            std::fs::read_link(policy.alias_root()).expect("alias symlink target"),
            policy.canonical_root().to_path_buf()
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_build_worker_projects_topology_cmd_reports_alias_create_collision_path() {
        let _guard = test_guard!();
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let sentinel = temp_dir.path().join("diagnostic-substitution-ran");
        let policy = PathTopologyPolicy::new(
            temp_dir.path().join("projects"),
            temp_dir
                .path()
                .join(format!("dp_$(touch {})", sentinel.display())),
        );
        let fake_bin = temp_dir.path().join("fake-bin");
        std::fs::create_dir_all(&fake_bin).expect("create fake bin dir");
        let fake_ln = fake_bin.join("ln");
        std::fs::write(
            &fake_ln,
            "#!/bin/sh\n\
if [ \"$1\" = \"-s\" ] && [ \"$2\" = \"--\" ]; then\n\
  echo \"ln: Already exists\" >&2\n\
  exit 1\n\
fi\n\
exec /bin/ln \"$@\"\n",
        )
        .expect("write fake ln");
        let mut perms = std::fs::metadata(&fake_ln)
            .expect("fake ln metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_ln, perms).expect("chmod fake ln");

        let command = build_worker_projects_topology_cmd(&policy);
        let path = format!(
            "{}:{}",
            fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("PATH", path)
            .output()
            .expect("run topology command");
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !output.status.success(),
            "unresolved alias create collision should fail"
        );
        assert!(
            stderr.contains("RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED"),
            "stderr should keep a structured failure code: {stderr}"
        );
        assert!(
            stderr.contains(&format!("path={}", policy.alias_root().display())),
            "stderr should include the exact colliding alias path: {stderr}"
        );
        assert!(
            stderr.contains("$(touch "),
            "stderr should include the literal configured path: {stderr}"
        );
        assert!(
            stderr.contains(&format!("target={}", policy.canonical_root().display())),
            "stderr should include the intended canonical target: {stderr}"
        );
        assert!(
            stderr.contains("ln: Already exists"),
            "stderr should preserve the underlying ln diagnostic: {stderr}"
        );
        assert!(
            !sentinel.exists(),
            "diagnostic formatting must not re-expand command substitutions from configured paths"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_build_worker_projects_topology_cmd_accepts_resolved_alias_target() {
        let _guard = test_guard!();
        use std::os::unix::fs::symlink;

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let real_root = temp_dir.path().join("data/projects");
        let configured_root = temp_dir.path().join("Users/jemanuel/projects");
        let alias_root = temp_dir.path().join("dp");
        std::fs::create_dir_all(&real_root).expect("create real root");
        std::fs::create_dir_all(configured_root.parent().expect("configured parent"))
            .expect("create configured parent");
        symlink(&real_root, &configured_root).expect("create configured canonical symlink");
        symlink(&real_root, &alias_root).expect("create alias symlink");

        let policy = PathTopologyPolicy::new(configured_root.clone(), alias_root.clone());
        let output = std::process::Command::new("sh")
            .arg("-lc")
            .arg(build_worker_projects_topology_cmd(&policy))
            .output()
            .expect("run topology command");

        assert!(
            output.status.success(),
            "resolved alias target should be accepted; status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("RCH_TOPOLOGY_OK"),
            "successful preflight should emit OK"
        );
        assert_eq!(
            std::fs::read_link(&alias_root).expect("alias symlink target"),
            real_root,
            "alias should not be rewritten when it resolves to the configured canonical root"
        );
    }

    #[test]
    fn test_build_sync_closure_plan_deterministic_under_permutation() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("project");
        let dep_a = temp_dir.path().join("dep_a");
        let dep_b = temp_dir.path().join("dep_b");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep_a).expect("create dep_a");
        std::fs::create_dir_all(&dep_b).expect("create dep_b");

        let project_hash = "1234abcd";
        let plan_a = build_sync_closure_plan(
            &[dep_b.clone(), project_root.clone(), dep_a.clone()],
            &project_root,
            project_hash,
            &policy,
        );
        let plan_b = build_sync_closure_plan(
            &[dep_a.clone(), dep_b.clone(), project_root.clone()],
            &project_root,
            project_hash,
            &policy,
        );

        assert_eq!(plan_a, plan_b, "sync closure plan should be deterministic");
        assert!(
            plan_a
                .iter()
                .any(|entry| entry.is_primary && entry.root_hash == project_hash),
            "primary root must retain the closure hash"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_build_sync_closure_plan_dedupes_alias_entries() {
        let _guard = test_guard!();
        use std::os::unix::fs::symlink;

        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("project");
        let dep = temp_dir.path().join("dep");
        let dep_alias = temp_dir.path().join("dep_alias");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep).expect("create dep root");
        symlink(&dep, &dep_alias).expect("create dep alias symlink");

        let dep_canonical = std::fs::canonicalize(&dep).expect("canonicalize dep");
        let plan = build_sync_closure_plan(
            &[dep_alias.clone(), dep.clone(), project_root.clone()],
            &project_root,
            "beefcafe",
            &policy,
        );

        let dep_entries = plan
            .iter()
            .filter(|entry| {
                std::fs::canonicalize(&entry.local_root)
                    .map(|canonical| canonical == dep_canonical)
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(dep_entries, 1, "alias/canonical roots should deduplicate");
    }

    #[test]
    fn test_build_sync_closure_plan_adds_workspace_metadata_for_member_roots() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("project");
        let dep_workspace_root = temp_dir.path().join("dep_workspace");
        let dep_member_root = dep_workspace_root.join("crates/member");

        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep_member_root).expect("create member root");
        std::fs::write(
            dep_workspace_root.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/member"]
"#,
        )
        .expect("write workspace manifest");
        std::fs::write(
            dep_member_root.join("Cargo.toml"),
            r#"[package]
name = "member"
version = "0.1.0"
edition = "2024"
"#,
        )
        .expect("write member manifest");

        let plan = build_sync_closure_plan(
            &[dep_member_root.clone(), project_root.clone()],
            &project_root,
            "workspace_hash",
            &policy,
        );

        assert!(
            plan.iter().any(|entry| entry.local_root == dep_member_root
                && entry.mode == SyncClosureMode::Full
                && !entry.is_primary),
            "workspace member root should remain a full sync root"
        );
        assert!(
            plan.iter()
                .any(|entry| entry.local_root == dep_workspace_root
                    && entry.mode == SyncClosureMode::WorkspaceMetadata
                    && !entry.is_primary),
            "workspace member roots should add a thin workspace metadata sync"
        );
        assert!(
            !plan
                .iter()
                .any(|entry| entry.local_root == dep_workspace_root
                    && entry.mode == SyncClosureMode::Full),
            "workspace root should not become a full sync root unless it was explicitly requested"
        );
    }

    #[test]
    fn test_build_dependency_runtime_plan_keeps_workspace_member_roots() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("project");
        let dep_workspace_root = temp_dir.path().join("dep_workspace");
        let dep_member_root = dep_workspace_root.join("crates/member");

        std::fs::create_dir_all(project_root.join("src")).expect("create project src");
        std::fs::create_dir_all(dep_member_root.join("src")).expect("create member src");
        std::fs::write(
            project_root.join("Cargo.toml"),
            r#"[package]
name = "project"
version = "0.1.0"
edition = "2024"

[dependencies]
member = { path = "../dep_workspace/crates/member" }
"#,
        )
        .expect("write project manifest");
        std::fs::write(project_root.join("src/lib.rs"), "pub fn project() {}\n")
            .expect("write project lib");
        std::fs::write(
            dep_workspace_root.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/member"]
"#,
        )
        .expect("write workspace manifest");
        std::fs::write(
            dep_member_root.join("Cargo.toml"),
            r#"[package]
name = "member"
version = "0.1.0"
edition = "2024"
"#,
        )
        .expect("write member manifest");
        std::fs::write(dep_member_root.join("src/lib.rs"), "pub fn member() {}\n")
            .expect("write member lib");

        let project_root = std::fs::canonicalize(&project_root).expect("canonicalize project");
        let dep_workspace_root =
            std::fs::canonicalize(&dep_workspace_root).expect("canonicalize workspace");
        let dep_member_root = std::fs::canonicalize(&dep_member_root).expect("canonicalize member");
        let reporter = HookReporter::new(OutputVisibility::None);

        let plan = build_dependency_runtime_plan(
            &project_root,
            Some(CompilationKind::CargoCheck),
            &reporter,
            &policy,
        );

        assert!(
            plan.fail_open_decision.is_none(),
            "dependency runtime planning should stay on the ready path"
        );
        assert!(
            plan.sync_roots.contains(&dep_member_root),
            "workspace member root must stay in the runtime sync roots"
        );
        assert!(
            !plan.sync_roots.contains(&dep_workspace_root),
            "workspace root should be added later as metadata-only sync, not full runtime root"
        );
        assert!(
            plan.sync_roots.contains(&project_root),
            "primary project root must remain in the sync roots"
        );
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_execute_remote_compilation_syncs_custom_cargo_target_dir_artifacts() {
        let _lock = test_lock().lock().await;
        let _guard = test_guard!();

        let socket_path = format!(
            "/tmp/rch_test_custom_target_artifacts_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        // `execute_remote_compilation` reads the current project root from
        // `std::env::current_dir()` and normalizes it through the supplied
        // topology policy. Pin the cwd to a tempdir and build a policy that
        // recognises it so the test runs anywhere (including CI runners with
        // no `/data/projects`).
        let (temp_dir, policy) = topology_tempdir();
        let project_dir = temp_dir.path().join("remote_compilation_helper");
        std::fs::create_dir_all(&project_dir).expect("create project dir");
        let custom_target_dir_path = project_dir.join(".rch-test-target-cache");
        let custom_target_dir = custom_target_dir_path.to_string_lossy().to_string();

        let prev_cwd = std::env::current_dir().ok();
        std::env::set_current_dir(&project_dir).expect("cd into project dir");

        let worker = SelectedWorker {
            id: rch_common::WorkerId::new("mock-worker"),
            host: "mock.host.local".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock_key".to_string(),
            slots_available: 8,
            speed_score: 90.0,
        };

        let reporter = HookReporter::new(OutputVisibility::None);
        let result = execute_remote_compilation(
            &worker,
            "cargo build",
            TransferConfig::default(),
            Vec::new(),
            Some(PathBuf::from(&custom_target_dir)),
            &rch_common::CompilationConfig::default(),
            None,
            Some(CompilationKind::CargoBuild),
            &reporter,
            &socket_path,
            ColorMode::Auto,
            None,
            &policy,
        )
        .await;

        // Restore cwd before any assertion so a failure doesn't poison other tests.
        if let Some(prev) = prev_cwd {
            let _ = std::env::set_current_dir(prev);
        }

        let execution = result.expect("remote execution should succeed in mock mode");
        assert_eq!(execution.exit_code, 0);

        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let custom_target_artifact_sync = rsync_logs
            .iter()
            .find(|entry| {
                entry.phase == mock::Phase::Artifacts
                    && entry.destination == custom_target_dir
                    && entry.source.contains(".rch-target")
            })
            .expect(
            "expected artifact retrieval into custom CARGO_TARGET_DIR from worker .rch-target path"
        );
        assert!(
            custom_target_artifact_sync
                .source
                .contains(".rch-target-mock-worker-"),
            "expected per-job remote target dir, got {}",
            custom_target_artifact_sync.source
        );
        assert!(
            !custom_target_artifact_sync.source.contains("/.rch-target/"),
            "custom target sync must not use the shared .rch-target dir: {}",
            custom_target_artifact_sync.source
        );

        let ssh_logs = mock::global_ssh_invocations_snapshot();
        let execute_command = ssh_logs
            .iter()
            .find(|entry| entry.phase == mock::Phase::Execute)
            .and_then(|entry| entry.command.as_deref())
            .expect("execute command should be recorded");
        assert!(
            execute_command.contains("CARGO_TARGET_DIR=")
                && execute_command.contains(".rch-target-mock-worker-"),
            "expected remote Cargo execution to force per-job worker CARGO_TARGET_DIR, got {execute_command}"
        );
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_cargo_test_delegates_to_rch_exec() {
        // Test that cargo test commands are delegated to rch exec
        let _lock = test_lock().lock().await;
        let _guard = test_guard!();
        mock::clear_global_invocations();
        crate::config::set_test_config_override(Some(rch_common::RchConfig::default()));

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        crate::config::set_test_config_override(None);

        // Hook should delegate to rch exec
        assert!(
            output.is_allow(),
            "cargo test should be allowed via delegation"
        );
        let cmd = delegated_command(&output);
        assert_eq!(cmd, "rch exec -- cargo test");

        // No rsync/SSH during hook - that happens in run_exec
        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(rsync_logs.is_empty(), "Hook should not invoke rsync");
        assert!(ssh_logs.is_empty(), "Hook should not invoke SSH");
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_cargo_test_with_args_delegates_correctly() {
        // Test that cargo test with arguments is delegated correctly
        let _lock = test_lock().lock().await;
        let _guard = test_guard!();
        mock::clear_global_invocations();
        crate::config::set_test_config_override(Some(rch_common::RchConfig::default()));

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test --release -- --nocapture".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        crate::config::set_test_config_override(None);

        // Hook should delegate with all arguments preserved
        assert!(output.is_allow());
        let cmd = delegated_command(&output);
        assert_eq!(cmd, "rch exec -- cargo test --release -- --nocapture");

        // No rsync/SSH during hook
        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(rsync_logs.is_empty(), "Hook should not invoke rsync");
        assert!(ssh_logs.is_empty(), "Hook should not invoke SSH");
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_cargo_test_remote_build_failure() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_build_fail_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Configure mock for build failure (exit 1)
        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig {
                default_exit_code: 1,
                default_stderr: "error[E0425]: cannot find value `undefined_var` in this scope\n  --> src/lib.rs:10:5\n".to_string(),
                ..MockConfig::default()
            },
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Build failure (exit 1) should use transparent interception with exit code
        // Agent sees the error output and gets correct exit code
        assert!(
            output.is_allow(),
            "cargo test build failure should use transparent interception"
        );
        assert!(
            matches!(output, HookOutput::AllowWithModifiedCommand(_)),
            "cargo test build failure should return AllowWithModifiedCommand"
        );
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_cargo_test_with_filter() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_filter_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        // Test with filter pattern
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test specific_test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Filtered test command should use transparent interception
        assert!(
            output.is_allow(),
            "Filtered cargo test should use transparent interception"
        );
        assert!(
            matches!(output, HookOutput::AllowWithModifiedCommand(_)),
            "Filtered cargo test should return AllowWithModifiedCommand"
        );
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_cargo_test_with_test_threads() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_threads_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        // Test with --test-threads flag (should parse correctly for slot estimation)
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test -- --test-threads=4".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should use transparent interception regardless of thread count
        assert!(
            output.is_allow(),
            "cargo test with --test-threads should use transparent interception"
        );
        assert!(
            matches!(output, HookOutput::AllowWithModifiedCommand(_)),
            "cargo test with --test-threads should return AllowWithModifiedCommand"
        );
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_cargo_test_signal_killed() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_signal_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Configure mock for OOM kill (exit 137 = 128 + 9 = SIGKILL)
        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig {
                default_exit_code: 137,
                default_stderr: "Killed\n".to_string(),
                ..MockConfig::default()
            },
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Signal killed (likely OOM) should use transparent interception with exit code
        assert!(
            output.is_allow(),
            "Signal-killed cargo test should use transparent interception"
        );
        assert!(
            matches!(output, HookOutput::AllowWithModifiedCommand(_)),
            "Signal-killed cargo test should return AllowWithModifiedCommand"
        );
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_cargo_test_signal_killed_with_toolchain_path_does_not_fallback_local() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_signal_toolchain_path_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let stderr = "error: could not compile `serde` (lib)\nCaused by:\n  process didn't exit successfully: `/home/ubuntu/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rustc --crate-name serde ...` (signal: 9, SIGKILL: kill)\n";

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig {
                default_exit_code: 137,
                default_stderr: stderr.to_string(),
                ..MockConfig::default()
            },
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        assert!(
            matches!(output, HookOutput::AllowWithModifiedCommand(_)),
            "signal-killed remote failures that mention .rustup/toolchains must preserve the remote exit code instead of falling back local"
        );
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_cargo_test_toolchain_fallback() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_toolchain_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Configure mock for toolchain failure - should allow local fallback
        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig {
                default_exit_code: 1,
                default_stderr: "error: toolchain 'nightly-2025-01-15' is not installed\n"
                    .to_string(),
                ..MockConfig::default()
            },
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Toolchain failure should allow local fallback
        // Local machine might have the toolchain
        assert!(
            output.is_allow(),
            "Toolchain failure should allow local fallback"
        );
    }

    #[test]
    fn test_cargo_test_classification() {
        let _guard = test_guard!();
        // Verify cargo test commands are classified correctly
        let result = classify_command("cargo test");
        assert!(result.is_compilation, "cargo test should be compilation");
        assert_eq!(
            result.kind,
            Some(CompilationKind::CargoTest),
            "Should be CargoTest kind"
        );

        let result = classify_command("cargo test specific_test");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));

        let result = classify_command("cargo test -- --test-threads=4");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));

        let result = classify_command("cargo test --release");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));

        let result = classify_command("cargo test -p mypackage");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_nextest_classification() {
        let _guard = test_guard!();
        // Verify cargo nextest commands are classified correctly
        let result = classify_command("cargo nextest run");
        assert!(result.is_compilation, "cargo nextest should be compilation");
        assert_eq!(
            result.kind,
            Some(CompilationKind::CargoNextest),
            "Should be CargoNextest kind"
        );

        let result = classify_command("cargo nextest run --no-fail-fast");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));
    }

    #[test]
    fn test_artifact_patterns_for_test_commands() {
        let _guard = test_guard!();
        // Verify test commands use minimal artifact patterns
        let test_patterns = get_artifact_patterns(Some(CompilationKind::CargoTest));
        let check_patterns = get_artifact_patterns(Some(CompilationKind::CargoCheck));
        let clippy_patterns = get_artifact_patterns(Some(CompilationKind::CargoClippy));
        let build_patterns = get_artifact_patterns(Some(CompilationKind::CargoBuild));

        // Test patterns should be smaller (more targeted)
        // They should include coverage/results but not full target/
        assert!(
            !test_patterns.iter().any(|p| p == "target/"),
            "Test artifacts should not include full target/"
        );

        // Build patterns should include full build outputs
        assert!(
            build_patterns.iter().any(|p| p == "target/debug/**"),
            "Build artifacts should include target/debug/**"
        );
        assert!(
            build_patterns.iter().any(|p| p == "target/release/**"),
            "Build artifacts should include target/release/**"
        );
        assert!(
            !test_patterns.iter().any(|p| p == "target/debug/**"),
            "Test artifacts should not include target/debug/**"
        );
        assert!(
            !test_patterns.iter().any(|p| p == "target/release/**"),
            "Test artifacts should not include target/release/**"
        );
        assert!(
            !check_patterns.iter().any(|p| p == "target/debug/**"),
            "Cargo check artifacts should not include target/debug/**"
        );
        assert!(
            !clippy_patterns.iter().any(|p| p == "target/debug/**"),
            "Cargo clippy artifacts should not include target/debug/**"
        );
    }

    #[test]
    fn test_custom_target_artifact_patterns_for_cargo_test_are_skipped() {
        let _guard = test_guard!();
        let patterns = get_custom_target_artifact_patterns(Some(CompilationKind::CargoTest));

        assert!(
            patterns.is_empty(),
            "cargo test output is streamed; do not sync a custom target dir after tests"
        );
    }

    #[test]
    fn test_custom_target_artifact_patterns_for_diagnostic_commands_are_skipped() {
        let _guard = test_guard!();

        assert!(
            get_custom_target_artifact_patterns(Some(CompilationKind::CargoCheck)).is_empty(),
            "cargo check output is streamed; do not sync a custom target dir"
        );
        assert!(
            get_custom_target_artifact_patterns(Some(CompilationKind::CargoClippy)).is_empty(),
            "cargo clippy output is streamed; do not sync a custom target dir"
        );
    }

    #[test]
    fn test_custom_target_artifact_patterns_for_nextest_are_target_relative() {
        let _guard = test_guard!();
        let patterns = get_custom_target_artifact_patterns(Some(CompilationKind::CargoNextest));

        assert!(
            !patterns.iter().any(|p| p == "**"),
            "nextest custom target retrieval must not sync the full target dir"
        );
        assert!(
            !patterns.iter().any(|p| p.starts_with("target/")),
            "custom target retrieval is already rooted at the target dir"
        );
        assert!(
            patterns.iter().any(|p| p == "nextest/**"),
            "nextest custom target retrieval should keep targeted test artifacts"
        );
    }

    #[test]
    fn test_custom_target_artifact_patterns_for_build_commands_keep_full_target() {
        let _guard = test_guard!();
        let patterns = get_custom_target_artifact_patterns(Some(CompilationKind::CargoBuild));

        assert_eq!(patterns, vec!["**".to_string()]);
    }

    // =========================================================================
    // Test filtering and special flags tests (bead remote_compilation_helper-ya16)
    // =========================================================================

    #[test]
    fn test_is_filtered_test_command_basic() {
        let _guard = test_guard!();
        // Basic test name filter
        assert!(
            is_filtered_test_command("cargo test my_test"),
            "Should detect test name filter"
        );
        assert!(
            is_filtered_test_command("cargo test test_foo"),
            "Should detect test name filter"
        );
        assert!(
            is_filtered_test_command("cargo test some::module::test"),
            "Should detect module path filter"
        );

        // Full test suite (no filter)
        assert!(
            !is_filtered_test_command("cargo test"),
            "No filter in basic cargo test"
        );
        assert!(
            !is_filtered_test_command("cargo test --release"),
            "Flags are not filters"
        );
    }

    #[test]
    fn test_is_filtered_test_command_with_flags() {
        let _guard = test_guard!();
        // Filter with flags
        assert!(
            is_filtered_test_command("cargo test --release my_test"),
            "Should detect filter after flags"
        );
        assert!(
            is_filtered_test_command("cargo test -p mypackage my_test"),
            "Should detect filter after package flag"
        );

        // Only package flag (not a name filter)
        assert!(
            !is_filtered_test_command("cargo test -p mypackage"),
            "Package is not a test name filter"
        );
        assert!(
            !is_filtered_test_command("cargo test --lib"),
            "--lib is not a test name filter"
        );
    }

    #[test]
    fn test_is_filtered_test_command_with_separator() {
        let _guard = test_guard!();
        // Filter before --
        assert!(
            is_filtered_test_command("cargo test my_test -- --nocapture"),
            "Should detect filter before separator"
        );

        // No filter, args after --
        assert!(
            !is_filtered_test_command("cargo test -- --nocapture"),
            "Args after -- are not test name filters"
        );
        assert!(
            !is_filtered_test_command("cargo test -- --test-threads=4"),
            "Args after -- are not test name filters"
        );
    }

    #[test]
    fn test_has_ignored_only_flag() {
        let _guard = test_guard!();
        // Only --ignored
        assert!(
            has_ignored_only_flag("cargo test -- --ignored"),
            "Should detect --ignored"
        );

        // --include-ignored (runs all tests)
        assert!(
            !has_ignored_only_flag("cargo test -- --include-ignored"),
            "--include-ignored runs all tests"
        );

        // Both flags (--include-ignored takes precedence)
        assert!(
            !has_ignored_only_flag("cargo test -- --ignored --include-ignored"),
            "--include-ignored takes precedence"
        );

        // No flags
        assert!(!has_ignored_only_flag("cargo test"), "No flags");
    }

    #[test]
    fn test_has_exact_flag() {
        let _guard = test_guard!();
        assert!(
            has_exact_flag("cargo test my_test -- --exact"),
            "--exact detected"
        );
        assert!(!has_exact_flag("cargo test my_test"), "No --exact");
        assert!(!has_exact_flag("cargo test -- --nocapture"), "No --exact");
    }

    #[test]
    fn test_estimate_cores_filtered_tests() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 10,
            check_slots: 3,
            ..Default::default()
        };

        // Full test suite gets default slots
        let full =
            estimate_cores_for_command(Some(CompilationKind::CargoTest), "cargo test", &config);
        assert_eq!(full, 10, "Full test suite uses default test_slots");

        // Filtered test gets reduced slots (test_slots / 2, min 2)
        let filtered = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test my_test",
            &config,
        );
        assert_eq!(filtered, 5, "Filtered test uses reduced slots");

        // --exact flag gets reduced slots
        let exact = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test my_test -- --exact",
            &config,
        );
        assert_eq!(exact, 5, "--exact uses reduced slots");

        // --ignored only gets reduced slots
        let ignored = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -- --ignored",
            &config,
        );
        assert_eq!(ignored, 5, "--ignored uses reduced slots");

        // --include-ignored gets full slots (runs all tests plus ignored)
        let include_ignored = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -- --include-ignored",
            &config,
        );
        assert_eq!(include_ignored, 10, "--include-ignored uses full slots");
    }

    #[test]
    fn test_estimate_cores_explicit_threads_overrides_filter() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 10,
            check_slots: 3,
            ..Default::default()
        };

        // Explicit --test-threads should override filtering heuristics
        let explicit = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test my_test -- --test-threads=8",
            &config,
        );
        assert_eq!(explicit, 8, "Explicit --test-threads overrides filtering");

        // RUST_TEST_THREADS also overrides
        let env = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "RUST_TEST_THREADS=6 cargo test my_test",
            &config,
        );
        assert_eq!(env, 6, "RUST_TEST_THREADS overrides filtering");
    }

    #[test]
    fn test_estimate_cores_filtered_minimum() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 2, // Very low test_slots
            check_slots: 3,
            ..Default::default()
        };

        // With test_slots=2, filtered should be max(2/2, 2) = max(1, 2) = 2
        let filtered = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test my_test",
            &config,
        );
        assert!(filtered >= 2, "Filtered slots should be at least 2");
    }

    #[test]
    fn test_estimate_cores_filtered_never_exceeds_default() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 1, // Single-slot environment
            check_slots: 3,
            ..Default::default()
        };

        let filtered = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test my_test",
            &config,
        );
        assert_eq!(
            filtered, 1,
            "Filtered tests should not request more slots than test_slots"
        );
    }

    #[test]
    fn test_nocapture_does_not_affect_slots() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 10,
            check_slots: 3,
            ..Default::default()
        };

        // --nocapture doesn't affect slot estimation
        let with_nocapture = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -- --nocapture",
            &config,
        );
        let without =
            estimate_cores_for_command(Some(CompilationKind::CargoTest), "cargo test", &config);
        assert_eq!(with_nocapture, without, "--nocapture doesn't affect slots");

        // --show-output also doesn't affect slots
        let with_show = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -- --show-output",
            &config,
        );
        assert_eq!(with_show, without, "--show-output doesn't affect slots");
    }

    #[test]
    fn test_skip_pattern_uses_full_slots() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 10,
            check_slots: 3,
            ..Default::default()
        };

        // --skip doesn't reduce the test suite significantly
        // (still runs most tests, just skipping some)
        let with_skip = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -- --skip slow_test",
            &config,
        );
        assert_eq!(with_skip, 10, "--skip uses full slots");
    }

    #[test]
    fn test_parse_selection_response_accepts_known_newer_health_reason() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "selection_protocol_version": rch_common::SELECTION_RESPONSE_PROTOCOL_VERSION,
            "worker": null,
            "reason": "no_workers_passed_health",
            "build_id": null,
            "diagnostics": null
        })
        .to_string();

        let response = parse_selection_response(&json).expect("selection response parses");

        assert_eq!(response.reason, SelectionReason::NoWorkersPassedHealth);
        assert!(response.worker.is_none());
    }

    #[test]
    fn test_parse_selection_response_tolerates_unknown_unit_reason() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "selection_protocol_version": rch_common::SELECTION_RESPONSE_PROTOCOL_VERSION,
            "worker": null,
            "reason": "future_selector_gate",
            "build_id": null,
            "diagnostics": null
        })
        .to_string();

        let response = parse_selection_response(&json).expect("unknown reason should not fail");

        assert!(response.worker.is_none());
        assert!(matches!(
            response.reason,
            SelectionReason::SelectionError(_)
        ));
        assert!(
            response
                .reason
                .to_string()
                .contains("unknown daemon selection reason")
        );
        assert!(
            response.reason.to_string().contains("future_selector_gate"),
            "unknown unit reason should preserve daemon detail: {}",
            response.reason
        );
    }

    #[test]
    fn test_parse_selection_response_rejects_unsupported_protocol_version() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "selection_protocol_version": rch_common::SELECTION_RESPONSE_PROTOCOL_VERSION + 1,
            "worker": null,
            "reason": "all_workers_busy",
            "build_id": null,
            "diagnostics": null
        })
        .to_string();

        let error = parse_selection_response(&json).expect_err("future protocol should fail");

        assert!(
            error.to_string().contains("exceeds client support"),
            "unexpected error: {error}"
        );
    }

    // =========================================================================
    // Timeout handling tests (bead bd-1aim.2)
    // =========================================================================

    #[tokio::test]
    async fn test_daemon_query_connect_timeout_fail_open() {
        // When the daemon socket exists but doesn't accept connections quickly,
        // the hook should timeout and fail-open to allow local execution.
        //
        // We simulate this by creating a socket that accepts but never responds.
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_connect_timeout_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Clean up any existing socket
        let _ = std::fs::remove_file(&socket_path);

        // Create a socket that accepts connections but never responds
        let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");

        let socket_path_clone = socket_path.clone();
        tokio::spawn(async move {
            // Accept the connection but do nothing with it
            let _ = listener.accept().await;
            // Hold connection open for longer than the timeout
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        });

        // Give listener time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        // Query should timeout since daemon never responds
        let result: anyhow::Result<SelectionResponse> = query_daemon(
            &socket_path,
            "test-project",
            4,
            "cargo build",
            None,
            RequiredRuntime::None,
            CommandPriority::Normal,
            100,
            None,
            false,
            &[],
        )
        .await;

        let _ = std::fs::remove_file(&socket_path_clone);

        // Should fail due to read timeout (empty response)
        assert!(
            result.is_err(),
            "Query should fail when daemon doesn't respond"
        );
    }

    #[tokio::test]
    async fn test_process_hook_timeout_fail_open() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_process_timeout_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Create test config with our socket
        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Clean up any existing socket
        let _ = std::fs::remove_file(&socket_path);

        // Create a slow daemon that doesn't respond in time
        let listener = UnixListener::bind(&socket_path).expect("bind");

        tokio::spawn(async move {
            // Accept and hold connection but don't respond
            let (stream, _) = listener.accept().await.expect("accept");
            // Hold the stream open
            let (_reader, _writer) = stream.into_split();
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fail-open when daemon times out
        assert!(
            output.is_allow(),
            "Hook should fail-open when daemon query times out"
        );
    }

    #[tokio::test]
    async fn test_daemon_query_partial_response_timeout() {
        // Test behavior when daemon sends partial response and then hangs
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_partial_timeout_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        let socket_path_clone = socket_path.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            // Read request
            let mut request_line = String::new();
            let _ = buf_reader.read_line(&mut request_line).await;

            // Write partial HTTP response (no body)
            writer
                .write_all(b"HTTP/1.1 200 OK\r\n")
                .await
                .expect("write");
            // Hang without completing the response
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let result = query_daemon(
            &socket_path,
            "test-project",
            4,
            "cargo build",
            None,
            RequiredRuntime::None,
            CommandPriority::Normal,
            100,
            None,
            false,
            &[],
        )
        .await;

        let _ = std::fs::remove_file(&socket_path_clone);

        // Partial response should result in error (no body to parse)
        assert!(result.is_err(), "Partial response should result in error");
    }

    #[test]
    fn test_queue_when_busy_enabled_parser() {
        let _guard = test_guard!();
        assert!(queue_when_busy_enabled_from(None));
        assert!(queue_when_busy_enabled_from(Some("1")));
        assert!(queue_when_busy_enabled_from(Some("true")));
        assert!(queue_when_busy_enabled_from(Some("yes")));
        assert!(!queue_when_busy_enabled_from(Some("0")));
        assert!(!queue_when_busy_enabled_from(Some("false")));
        assert!(!queue_when_busy_enabled_from(Some("off")));
    }

    #[test]
    fn test_daemon_response_timeout_defaults_and_overrides() {
        let _guard = test_guard!();
        assert_eq!(
            daemon_response_timeout_for(false, None, None),
            Duration::from_secs(DEFAULT_DAEMON_RESPONSE_TIMEOUT_SECS)
        );
        assert_eq!(
            daemon_response_timeout_for(true, None, None),
            Duration::from_secs(DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS)
        );
        assert_eq!(
            daemon_response_timeout_for(true, None, Some("900")),
            Duration::from_secs(900)
        );
        assert_eq!(
            daemon_response_timeout_for(true, Some("45"), Some("900")),
            Duration::from_secs(45)
        );
        assert_eq!(
            daemon_response_timeout_for(true, Some("invalid"), Some("invalid")),
            Duration::from_secs(DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS)
        );
    }

    // ============================================================================
    // Auto-start (Self-Healing) Tests
    // ============================================================================

    /// Test helper to create a unique temp directory for auto-start tests
    fn create_test_state_dir() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("Failed to create temp dir")
    }

    #[test]
    fn test_read_cooldown_timestamp_valid() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("cooldown");

        // Write a known timestamp (100 seconds ago)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::write(&cooldown_path, format!("{}", now - 100)).unwrap();

        let timestamp = super::read_cooldown_timestamp(&cooldown_path);
        assert!(timestamp.is_some(), "Should read valid timestamp");

        let elapsed = timestamp.unwrap().elapsed().unwrap().as_secs();
        assert!(
            (99..=102).contains(&elapsed),
            "Elapsed time should be ~100s, got {}",
            elapsed
        );
    }

    #[test]
    fn test_read_cooldown_timestamp_missing() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("nonexistent");

        let timestamp = super::read_cooldown_timestamp(&cooldown_path);
        assert!(timestamp.is_none(), "Missing file should return None");
    }

    #[test]
    fn test_read_cooldown_timestamp_invalid_content() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("cooldown");

        std::fs::write(&cooldown_path, "not a number").unwrap();

        let timestamp = super::read_cooldown_timestamp(&cooldown_path);
        assert!(timestamp.is_none(), "Invalid content should return None");
    }

    #[test]
    fn test_write_cooldown_timestamp_creates_file() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("subdir/cooldown");

        let result = super::write_cooldown_timestamp(&cooldown_path);
        assert!(result.is_ok(), "Should create file and parent directories");
        assert!(cooldown_path.exists(), "Cooldown file should exist");

        let contents = std::fs::read_to_string(&cooldown_path).unwrap();
        let secs: u64 = contents.trim().parse().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(secs <= now && secs >= now - 2, "Timestamp should be recent");
    }

    #[test]
    fn test_acquire_autostart_lock_success() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(lock.is_ok(), "Should acquire lock on first attempt");
        assert!(lock_path.exists(), "Lock file should exist");
    }

    #[test]
    fn test_acquire_autostart_lock_contention() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        // First acquisition should succeed
        let lock1 = super::acquire_autostart_lock(&lock_path);
        assert!(lock1.is_ok(), "First lock should succeed");

        // Second acquisition should fail with LockHeld
        let lock2 = super::acquire_autostart_lock(&lock_path);
        assert!(lock2.is_err(), "Second lock should fail");
        assert!(
            matches!(lock2.unwrap_err(), super::AutoStartError::LockHeld),
            "Error should be LockHeld"
        );
    }

    #[test]
    fn test_autostart_lock_released_on_drop() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        // Acquire and drop the lock
        {
            let lock = super::acquire_autostart_lock(&lock_path);
            assert!(lock.is_ok(), "First lock should succeed");
            assert!(lock_path.exists(), "Lock file should exist while held");
            // lock is dropped here
        }

        // Lock file should be removed
        assert!(
            !lock_path.exists(),
            "Lock file should be removed after drop"
        );

        // Should be able to acquire lock again
        let lock2 = super::acquire_autostart_lock(&lock_path);
        assert!(lock2.is_ok(), "Should be able to reacquire lock after drop");
    }

    #[test]
    fn test_autostart_lock_drop_preserves_replaced_lock_body() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        let lock = super::acquire_autostart_lock(&lock_path).expect("fresh acquire");
        let replacement_body = format!(
            "{}\n{}\n{}-replacement\n",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            our_hostname()
        );
        std::fs::write(&lock_path, &replacement_body).expect("replace lock body");

        drop(lock);

        let body = std::fs::read_to_string(&lock_path).expect("replacement should remain");
        assert_eq!(body, replacement_body);
    }

    // ========================================================================
    // t17 — stale-PID detection on autostart lockfile
    // ========================================================================

    fn write_lockfile(path: &std::path::Path, pid: u32, age_secs: u64, hostname: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let created_at = now.saturating_sub(age_secs);
        std::fs::write(path, format!("{pid}\n{created_at}\n{hostname}\n")).unwrap();
    }

    fn our_hostname() -> String {
        std::env::var("HOSTNAME")
            .ok()
            .or_else(|| {
                std::fs::read_to_string("/etc/hostname")
                    .ok()
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|| "unknown".to_string())
    }

    #[test]
    fn test_acquire_autostart_lock_writes_body() {
        // Fresh acquire writes pid/timestamp/hostname so subsequent
        // contenders can decide whether to wait or take over.
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        let _lock = super::acquire_autostart_lock(&lock_path).expect("fresh acquire");
        let body = std::fs::read_to_string(&lock_path).expect("read body");
        let parsed = super::parse_autostart_lock_body(&body).expect("body parses");
        assert_eq!(parsed.pid, std::process::id());
        assert!(!parsed.hostname.is_empty());
    }

    #[test]
    fn test_render_autostart_lock_body_is_unique_owner_token() {
        let _guard = test_guard!();

        let body1 = super::render_autostart_lock_body();
        let body2 = super::render_autostart_lock_body();

        assert_ne!(
            body1, body2,
            "lock cleanup token must be acquisition-unique"
        );
        assert!(super::parse_autostart_lock_body(&body1).is_some());
        assert!(super::parse_autostart_lock_body(&body2).is_some());
    }

    #[test]
    fn test_autostart_lock_detects_dead_pid() {
        // PID 99999 is virtually guaranteed not to exist (kernel PID
        // max is typically 4194304, but the actual running set is sparse;
        // we pick a value high enough to almost never collide).
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        write_lockfile(&lock_path, 99999, 5, &our_hostname());
        // Acquire — should detect stale and take over.
        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(
            lock.is_ok(),
            "Stale PID should be detected and replaced; got {:?}",
            lock.err()
        );
        // The new body should record our own PID.
        let body = std::fs::read_to_string(&lock_path).expect("read body");
        let parsed = super::parse_autostart_lock_body(&body).expect("body parses");
        assert_eq!(parsed.pid, std::process::id());
    }

    #[test]
    fn test_autostart_lock_respects_live_pid_recent() {
        // Our own PID, age 5s, same host: definitely alive AND fresh.
        // Must return LockHeld.
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        write_lockfile(&lock_path, std::process::id(), 5, &our_hostname());
        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(lock.is_err(), "Live recent holder must hold the lock");
        assert!(matches!(lock.unwrap_err(), super::AutoStartError::LockHeld));
    }

    #[test]
    fn test_autostart_lock_corrupt_body_treated_as_stale() {
        // Garbage body (couldn't parse) → take over.
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        std::fs::write(
            &lock_path,
            "this is not\nthe expected\nlock format with extra junk",
        )
        .unwrap();
        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(
            lock.is_ok(),
            "Corrupted lockfile should be treated as stale; got {:?}",
            lock.err()
        );
    }

    #[test]
    fn test_autostart_lock_empty_body_treated_as_stale() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        std::fs::write(&lock_path, "").unwrap();
        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(
            lock.is_ok(),
            "Empty lockfile body should be treated as stale; got {:?}",
            lock.err()
        );
    }

    #[test]
    fn test_autostart_lock_different_hostname_blocks() {
        // NFS-shared scenario: a different host holds the lock. Even if
        // the PID isn't alive on our host, we can't tell — so we trust
        // the holder and return LockHeld.
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        // Use a PID that's almost certainly NOT alive on our host AND
        // a hostname that's almost certainly not ours.
        write_lockfile(&lock_path, 99999, 5, "definitely-not-our-host-xyz");
        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(
            lock.is_err(),
            "Lock from a different host must not be taken over"
        );
    }

    #[test]
    fn test_autostart_lock_ttl_fallback_for_same_host() {
        // PID-reuse defense: our own PID, but the lockfile is very old.
        // Should be treated as stale (TTL exceeded) and replaced.
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        // Age > TTL (60s) with our own PID + hostname.
        write_lockfile(&lock_path, std::process::id(), 120, &our_hostname());
        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(
            lock.is_ok(),
            "Old lockfile (TTL exceeded) should be stale-replaced even when PID is alive; got {:?}",
            lock.err()
        );
    }

    #[test]
    fn test_autostart_stale_sweep_preserves_changed_lock_body() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        write_lockfile(&lock_path, std::process::id(), 120, &our_hostname());
        let observed_stale_body = std::fs::read_to_string(&lock_path).expect("read stale body");
        let replacement_body = super::render_autostart_lock_body();
        std::fs::write(&lock_path, &replacement_body).expect("replace lock body");

        assert!(
            !super::remove_autostart_lock_if_unchanged(&lock_path, &observed_stale_body),
            "changed lock body must not be removed"
        );
        let body = std::fs::read_to_string(&lock_path).expect("replacement should remain");
        assert_eq!(body, replacement_body);
    }

    #[test]
    fn test_parse_autostart_lock_body_valid() {
        let body = "12345\n1778000000\nmybox\n";
        let p = super::parse_autostart_lock_body(body).expect("valid body parses");
        assert_eq!(p.pid, 12345);
        assert_eq!(p.created_at_secs, 1_778_000_000);
        assert_eq!(p.hostname, "mybox");
    }

    #[test]
    fn test_parse_autostart_lock_body_invalid() {
        // Various invalid shapes.
        assert!(super::parse_autostart_lock_body("").is_none());
        assert!(super::parse_autostart_lock_body("abc\n123\nhost\n").is_none());
        assert!(super::parse_autostart_lock_body("123\nabc\nhost\n").is_none());
        assert!(super::parse_autostart_lock_body("123\n456\n").is_none());
        assert!(super::parse_autostart_lock_body("123\n456\n\n").is_none()); // empty hostname
    }

    #[test]
    fn test_acquire_autostart_lock_creates_parent_dirs() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("deep/nested/dir/autostart.lock");

        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(lock.is_ok(), "Should create parent directories");
        assert!(lock_path.exists(), "Lock file should exist");
    }

    // ========================================================================
    // t13 follow-up — rchd launch should return quickly for a live daemon,
    // but immediate launch failures should still surface.
    // ========================================================================

    #[cfg(unix)]
    #[test]
    fn test_spawn_rchd_returns_quickly_for_live_child() {
        let _guard = test_guard!();
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = create_test_state_dir();
        let fake_rchd = temp_dir.path().join("rchd");
        std::fs::write(&fake_rchd, "#!/usr/bin/env sh\nsleep 0.3\n").expect("write fake rchd");
        let mut perms = std::fs::metadata(&fake_rchd)
            .expect("fake rchd metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_rchd, perms).expect("chmod fake rchd");

        let started = std::time::Instant::now();
        super::spawn_rchd(&fake_rchd).expect("spawn fake rchd");
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(250),
            "spawn_rchd should not wait for the daemon body to finish; elapsed={elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_spawn_rchd_reports_immediate_child_failure() {
        let _guard = test_guard!();
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = create_test_state_dir();
        let fake_rchd = temp_dir.path().join("rchd");
        std::fs::write(&fake_rchd, "#!/usr/bin/env sh\nexit 42\n").expect("write fake rchd");
        let mut perms = std::fs::metadata(&fake_rchd)
            .expect("fake rchd metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_rchd, perms).expect("chmod fake rchd");

        let err = super::spawn_rchd(&fake_rchd).expect_err("child failure should surface");
        assert!(
            matches!(err, super::AutoStartError::WrapperFailed(status) if status.code() == Some(42)),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_auto_start_config_disabled() {
        let temp_dir = create_test_state_dir();
        let socket_path = temp_dir.path().join("test.sock");

        let config = rch_common::SelfHealingConfig {
            hook_starts_daemon: false,
            ..Default::default()
        };

        let result = super::try_auto_start_daemon(&config, &socket_path).await;

        assert!(result.is_err(), "Should return error when disabled");
        assert!(
            matches!(result.unwrap_err(), super::AutoStartError::Disabled),
            "Error should be Disabled"
        );
    }

    #[tokio::test]
    async fn test_socket_is_confirmed_stale_false_for_live_listener() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let socket_path = temp_dir.path().join("test.sock");
        let _listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        assert!(
            !super::socket_is_confirmed_stale(&socket_path).await,
            "live listener must not be treated as stale"
        );
    }

    #[tokio::test]
    async fn test_socket_is_confirmed_stale_true_for_dropped_listener() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let socket_path = temp_dir.path().join("test.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        drop(listener);

        for _ in 0..20 {
            if super::socket_is_confirmed_stale(&socket_path).await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(
            super::socket_is_confirmed_stale(&socket_path).await,
            "dropped listener should leave a stale socket path"
        );
    }

    // Note: Tests that require env var manipulation are marked with #[ignore] for safety.
    // Env var manipulation in tests can cause data races and is unsafe in Rust 2024 edition.
    // The core functionality is tested via the helper functions that don't depend on env vars.

    #[test]
    fn test_autostart_state_dir_returns_path() {
        let _guard = test_guard!();
        // Basic test that autostart_state_dir returns a valid path
        // (without manipulating env vars which is unsafe)
        let dir = super::autostart_state_dir();
        assert!(!dir.as_os_str().is_empty(), "Path should not be empty");
        assert!(
            dir.to_string_lossy().contains("rch"),
            "Path should contain 'rch'"
        );
    }

    #[test]
    fn test_autostart_lock_path_ends_with_expected_name() {
        let _guard = test_guard!();
        let path = super::autostart_lock_path();
        assert!(
            path.file_name()
                .map(|n| n == "hook_autostart.lock")
                .unwrap_or(false),
            "Lock path should end with hook_autostart.lock"
        );
    }

    #[test]
    fn test_autostart_cooldown_path_ends_with_expected_name() {
        let _guard = test_guard!();
        let path = super::autostart_cooldown_path();
        assert!(
            path.file_name()
                .map(|n| n == "hook_autostart.cooldown")
                .unwrap_or(false),
            "Cooldown path should end with hook_autostart.cooldown"
        );
    }

    // =========================================================================
    // Cooldown Integration Tests (bd-59kg)
    // =========================================================================
    //
    // Note: Full integration tests for cooldown behavior in try_auto_start_daemon
    // would require manipulating the state directory via env vars, which is unsafe
    // in Rust 2024 (data races in parallel tests). The cooldown logic is tested via:
    //
    // 1. test_read_cooldown_timestamp_valid - validates reading timestamps works
    // 2. test_read_cooldown_timestamp_missing - validates missing file returns None
    // 3. test_write_cooldown_timestamp_creates_file - validates writing timestamps
    // 4. test_auto_start_config_disabled - validates early exit when disabled
    //
    // The integration flow in try_auto_start_daemon is:
    //   cooldown_path = autostart_cooldown_path()
    //   if read_cooldown_timestamp(path).elapsed() < config.cooldown_secs:
    //       return Err(CooldownActive)
    //   ... proceed with daemon start ...
    //   write_cooldown_timestamp(path)

    #[test]
    fn test_autostart_error_cooldown_active_variant() {
        let _guard = test_guard!();
        // TEST START: AutoStartError::CooldownActive has expected structure
        let error = super::AutoStartError::CooldownActive(15, 30);

        // Verify debug formatting includes timing info
        let debug = format!("{:?}", error);
        assert!(
            debug.contains("CooldownActive"),
            "Debug should contain variant name"
        );
        assert!(debug.contains("15"), "Debug should contain elapsed seconds");
        assert!(
            debug.contains("30"),
            "Debug should contain cooldown threshold"
        );

        // Verify it's a distinct error variant
        assert!(
            !matches!(error, super::AutoStartError::Disabled),
            "Should not be Disabled"
        );
        assert!(
            !matches!(error, super::AutoStartError::LockHeld),
            "Should not be LockHeld"
        );
        // TEST PASS: CooldownActive error variant
    }

    #[test]
    fn test_cooldown_logic_simulation() {
        let _guard = test_guard!();
        // TEST START: Simulate cooldown logic without touching real state files
        // This mirrors the logic in try_auto_start_daemon lines 628-640

        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("cooldown");
        let cooldown_secs: u64 = 30;

        // Case 1: No cooldown file -> should proceed
        let last_attempt = super::read_cooldown_timestamp(&cooldown_path);
        assert!(
            last_attempt.is_none(),
            "No file means no cooldown active - should proceed"
        );

        // Case 2: Recent cooldown file -> should block
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Write timestamp from 10 seconds ago (within 30s cooldown)
        std::fs::write(&cooldown_path, format!("{}", now - 10)).unwrap();

        let last_attempt = super::read_cooldown_timestamp(&cooldown_path).unwrap();
        let elapsed = last_attempt
            .elapsed()
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        assert!(
            elapsed < cooldown_secs,
            "Elapsed {} should be < cooldown {} - should block",
            elapsed,
            cooldown_secs
        );

        // Case 3: Old cooldown file -> should proceed
        // Write timestamp from 60 seconds ago (outside 30s cooldown)
        std::fs::write(&cooldown_path, format!("{}", now - 60)).unwrap();

        let last_attempt = super::read_cooldown_timestamp(&cooldown_path).unwrap();
        let elapsed = last_attempt
            .elapsed()
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        assert!(
            elapsed >= cooldown_secs,
            "Elapsed {} should be >= cooldown {} - should proceed",
            elapsed,
            cooldown_secs
        );
        // TEST PASS: Cooldown logic simulation
    }

    #[test]
    fn test_cooldown_file_update_after_attempt() {
        let _guard = test_guard!();
        // TEST START: Verify cooldown timestamp is updated after write
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("subdir/cooldown");

        // Write initial cooldown
        let result = super::write_cooldown_timestamp(&cooldown_path);
        assert!(result.is_ok(), "First write should succeed");

        let timestamp1 = std::fs::read_to_string(&cooldown_path).unwrap();
        let ts1: u64 = timestamp1
            .trim()
            .parse()
            .expect("cooldown timestamp must be a unix seconds integer");

        // Sleep briefly and write again
        let result = super::write_cooldown_timestamp(&cooldown_path);
        assert!(result.is_ok(), "Second write should succeed");

        let timestamp2 = std::fs::read_to_string(&cooldown_path).unwrap();
        let ts2: u64 = timestamp2
            .trim()
            .parse()
            .expect("cooldown timestamp must be a unix seconds integer");

        assert!(
            ts2 >= ts1,
            "Second write should be >= first write (ts2={ts2} >= ts1={ts1})"
        );
        // TEST PASS: Cooldown file update
    }

    // =========================================================================
    // Timing History Tests
    // =========================================================================

    #[test]
    fn test_timing_record_creation() {
        let _guard = test_guard!();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let record = super::TimingRecord {
            timestamp: now_secs,
            duration_ms: 5000,
            remote: true,
        };

        assert_eq!(record.duration_ms, 5000);
        assert!(record.remote);
        assert!(record.timestamp >= now_secs - 1 && record.timestamp <= now_secs + 1);
    }

    #[test]
    fn test_project_timing_data_add_sample() {
        let _guard = test_guard!();
        let mut data = super::ProjectTimingData::default();

        // Add local sample
        data.add_sample(1000, false);
        assert_eq!(data.local_samples.len(), 1);
        assert_eq!(data.remote_samples.len(), 0);
        assert_eq!(data.local_samples[0].duration_ms, 1000);

        // Add remote sample
        data.add_sample(500, true);
        assert_eq!(data.local_samples.len(), 1);
        assert_eq!(data.remote_samples.len(), 1);
        assert_eq!(data.remote_samples[0].duration_ms, 500);
    }

    #[test]
    fn test_project_timing_data_median_odd_count() {
        let _guard = test_guard!();
        let mut data = super::ProjectTimingData::default();
        data.add_sample(100, false);
        data.add_sample(300, false);
        data.add_sample(200, false);

        // Median of [100, 200, 300] = 200
        assert_eq!(data.median_duration(false), Some(200));
    }

    #[test]
    fn test_project_timing_data_median_even_count() {
        let _guard = test_guard!();
        let mut data = super::ProjectTimingData::default();
        data.add_sample(100, true);
        data.add_sample(300, true);
        data.add_sample(200, true);
        data.add_sample(400, true);

        // Median of [100, 200, 300, 400] = (200 + 300) / 2 = 250
        assert_eq!(data.median_duration(true), Some(250));
    }

    #[test]
    fn test_project_timing_data_median_empty() {
        let _guard = test_guard!();
        let data = super::ProjectTimingData::default();
        assert_eq!(data.median_duration(false), None);
        assert_eq!(data.median_duration(true), None);
    }

    #[test]
    fn test_project_timing_data_speedup_ratio() {
        let _guard = test_guard!();
        let mut data = super::ProjectTimingData::default();
        // Local takes 1000ms
        data.add_sample(1000, false);
        // Remote takes 500ms
        data.add_sample(500, true);

        // Speedup = local / remote = 1000 / 500 = 2.0
        assert_eq!(data.speedup_ratio(), Some(2.0));
    }

    #[test]
    fn test_project_timing_data_speedup_no_data() {
        let _guard = test_guard!();
        let mut data = super::ProjectTimingData::default();
        data.add_sample(1000, false);

        // No remote data, can't compute speedup
        assert_eq!(data.speedup_ratio(), None);
    }

    #[test]
    fn test_project_timing_data_sample_truncation() {
        let _guard = test_guard!();
        let mut data = super::ProjectTimingData::default();

        // Add more than MAX_TIMING_SAMPLES
        for i in 0..25 {
            data.add_sample(i * 100, false);
        }

        // Should be capped at MAX_TIMING_SAMPLES (20)
        assert_eq!(data.local_samples.len(), super::MAX_TIMING_SAMPLES);
        // First sample should be removed (FIFO)
        assert_eq!(data.local_samples[0].duration_ms, 500); // Started at 0, removed 0-4
    }

    #[test]
    fn test_timing_history_key() {
        let _guard = test_guard!();
        let key = super::TimingHistory::key("my_project", Some(CompilationKind::CargoTest));
        assert!(key.contains("my_project"));
        assert!(key.contains("CargoTest"));

        let key_unknown = super::TimingHistory::key("project2", None);
        assert!(key_unknown.contains("project2"));
        assert!(key_unknown.contains("Unknown"));
    }

    #[test]
    fn test_timing_history_record_and_get() {
        let _guard = test_guard!();
        let mut history = super::TimingHistory::default();

        history.record("proj1", Some(CompilationKind::CargoBuild), 1000, true);
        history.record("proj1", Some(CompilationKind::CargoBuild), 800, true);

        let data = history.get("proj1", Some(CompilationKind::CargoBuild));
        assert!(data.is_some());
        let data = data.unwrap();
        assert_eq!(data.remote_samples.len(), 2);
        assert_eq!(data.median_duration(true), Some(900)); // (800 + 1000) / 2

        // Different kind should be separate
        let data2 = history.get("proj1", Some(CompilationKind::CargoTest));
        assert!(data2.is_none());
    }

    #[test]
    fn test_timing_history_serialization() {
        let _guard = test_guard!();
        let mut history = super::TimingHistory::default();
        history.record("proj", Some(CompilationKind::CargoCheck), 500, false);
        history.record("proj", Some(CompilationKind::CargoCheck), 250, true);

        let json = serde_json::to_string(&history).unwrap();
        let loaded: super::TimingHistory = serde_json::from_str(&json).unwrap();

        let data = loaded
            .get("proj", Some(CompilationKind::CargoCheck))
            .unwrap();
        assert_eq!(data.local_samples.len(), 1);
        assert_eq!(data.remote_samples.len(), 1);
    }

    // ========================================================================
    // t18 — record_build_timing lock-scope discipline. Verify the write
    // guard is dropped BEFORE save_to_disk, so other readers/writers
    // aren't blocked on disk I/O.
    // ========================================================================

    #[test]
    fn test_record_build_timing_releases_guard_before_disk_io() {
        // Verify: between cache.write()-release and cache.read()-acquire
        // there is no overlap — i.e., another thread can acquire a
        // read lock while save_to_disk is in flight.
        //
        // Property tested indirectly: spawn many threads each calling
        // record_build_timing concurrently. With the OLD code (save
        // inside the write guard), high contention would serialize all
        // calls behind a 5-10ms disk write per thread. With the NEW
        // code, only the in-memory mutation serializes; disk writes
        // parallelize. A wallclock cap detects the regression.
        //
        // Per-thread project keys are uniquely prefixed so the test
        // doesn't depend on cache-clearing (which would race with other
        // tests sharing the global cache).
        let _guard = test_guard!();
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;
        use std::time::{Duration, Instant};

        let unique = format!(
            "t18-conc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );

        let n_threads = 8;
        let calls_per_thread = 5;
        let started = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        let t0 = Instant::now();
        for t in 0..n_threads {
            let started = Arc::clone(&started);
            let unique = unique.clone();
            handles.push(thread::spawn(move || {
                for i in 0..calls_per_thread {
                    started.fetch_add(1, Ordering::Relaxed);
                    let project = format!("{unique}-{t}-{i}");
                    super::record_build_timing(
                        &project,
                        Some(CompilationKind::CargoBuild),
                        100 + (i as u64),
                        true,
                    );
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }
        let elapsed = t0.elapsed();
        let total_calls = n_threads * calls_per_thread;
        assert_eq!(
            started.load(Ordering::Relaxed),
            total_calls,
            "all threads should have started"
        );
        // Wallclock cap: 8 threads × 5 calls × 50ms (slow disk fsync)
        // = 2000ms WORST case if serial. Allow 4s for very slow CI.
        // A regression to "save inside the write guard" would dominate
        // the wallclock at scale; this cap catches the worst regressions.
        assert!(
            elapsed < Duration::from_millis(4000),
            "{total_calls} concurrent record_build_timing calls took {elapsed:?} (expected <4s)"
        );
    }

    #[test]
    fn test_record_build_timing_in_memory_state_survives_disk_failure() {
        // Even if save_to_disk fails (e.g., disk full, permission denied),
        // the in-memory cache MUST contain the recorded sample. The lock
        // is dropped before the I/O, so I/O failure can't corrupt the
        // cache state.
        //
        // Uses a unique key (PID + nanosecond timestamp) so the assertion
        // doesn't depend on cache-clearing — which would race with other
        // tests sharing the global cache.
        let _guard = test_guard!();

        let unique = format!(
            "t18-disk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );

        super::record_build_timing(&unique, Some(CompilationKind::CargoBuild), 1234, true);

        let history = super::timing_cache().read().expect("read");
        let entry = history.get(&unique, Some(CompilationKind::CargoBuild));
        assert!(
            entry.is_some(),
            "in-memory entry for key {unique:?} must be present even if disk write failed"
        );
        let data = entry.unwrap();
        assert!(
            !data.remote_samples.is_empty(),
            "at least one remote sample recorded"
        );
        // We're the only writer for this unique key, so the last sample
        // must be the one we recorded.
        assert_eq!(
            data.remote_samples.last().unwrap().duration_ms,
            1234,
            "recorded duration matches the call"
        );
    }

    // ========================================================================
    // WS1.4: Tests for spawn_blocking wrappers (bd-3s1j)
    // ========================================================================

    #[tokio::test]
    async fn test_spawn_blocking_load_with_valid_file() {
        let _guard = test_guard!();
        // Create a temp directory with a timing history file
        let temp_dir = tempfile::tempdir().unwrap();
        let history_path = temp_dir.path().join("timing_history.json");

        // Create valid timing data
        let mut history = super::TimingHistory::default();
        history.record(
            "test-project",
            Some(CompilationKind::CargoBuild),
            1000,
            false,
        );
        let json = serde_json::to_string_pretty(&history).unwrap();
        std::fs::write(&history_path, json).unwrap();

        // Load via spawn_blocking (simulating what we do in production)
        let path = history_path.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            // In production we use timing_history_path(), here we test the pattern
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|content| serde_json::from_str::<super::TimingHistory>(&content).ok())
                .unwrap_or_default()
        })
        .await
        .unwrap();

        // Verify data loaded correctly
        let data = loaded.get("test-project", Some(CompilationKind::CargoBuild));
        assert!(data.is_some());
        assert_eq!(data.unwrap().local_samples.len(), 1);
    }

    #[tokio::test]
    async fn test_spawn_blocking_load_missing_file() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let missing_path = temp_dir.path().join("nonexistent.json");

        let loaded = tokio::task::spawn_blocking(move || {
            std::fs::read_to_string(&missing_path)
                .ok()
                .and_then(|content| serde_json::from_str::<super::TimingHistory>(&content).ok())
                .unwrap_or_default()
        })
        .await
        .unwrap();

        // Should return default (empty history)
        assert!(loaded.entries.is_empty());
    }

    #[tokio::test]
    async fn test_spawn_blocking_load_corrupt_json() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let corrupt_path = temp_dir.path().join("corrupt.json");
        std::fs::write(&corrupt_path, "not valid json {{{").unwrap();

        let loaded = tokio::task::spawn_blocking(move || {
            std::fs::read_to_string(&corrupt_path)
                .ok()
                .and_then(|content| serde_json::from_str::<super::TimingHistory>(&content).ok())
                .unwrap_or_default()
        })
        .await
        .unwrap();

        // Should return default on corrupt data (graceful degradation)
        assert!(loaded.entries.is_empty());
    }

    #[tokio::test]
    async fn test_spawn_blocking_save_creates_file() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let save_path = temp_dir.path().join("saved_history.json");

        let mut history = super::TimingHistory::default();
        history.record(
            "saved-project",
            Some(CompilationKind::CargoTest),
            2000,
            true,
        );

        let path = save_path.clone();
        tokio::task::spawn_blocking(move || {
            let content = serde_json::to_string_pretty(&history).unwrap();
            std::fs::write(&path, content).unwrap();
        })
        .await
        .unwrap();

        // Verify file was created and has correct content
        assert!(save_path.exists());
        let content = std::fs::read_to_string(&save_path).unwrap();
        let loaded: super::TimingHistory = serde_json::from_str(&content).unwrap();
        let data = loaded.get("saved-project", Some(CompilationKind::CargoTest));
        assert!(data.is_some());
        assert_eq!(data.unwrap().remote_samples.len(), 1);
    }

    #[tokio::test]
    async fn test_spawn_blocking_timeout_protection() {
        let _guard = test_guard!();
        // Verify spawn_blocking completes within reasonable time (not deadlocked)
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::task::spawn_blocking(|| {
                let history = super::TimingHistory::default();
                // Simulate some work
                std::thread::sleep(std::time::Duration::from_millis(10));
                history
            }),
        )
        .await;

        assert!(
            result.is_ok(),
            "spawn_blocking should complete within 5s timeout"
        );
    }

    #[tokio::test]
    async fn test_spawn_blocking_concurrent_loads() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let history_path = temp_dir.path().join("concurrent.json");

        // Create test file
        let mut history = super::TimingHistory::default();
        history.record("concurrent", Some(CompilationKind::CargoBuild), 500, false);
        std::fs::write(&history_path, serde_json::to_string(&history).unwrap()).unwrap();

        // Spawn 5 concurrent loads
        let mut handles = Vec::new();
        for _ in 0..5 {
            let path = history_path.clone();
            handles.push(tokio::task::spawn_blocking(move || {
                std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|c| serde_json::from_str::<super::TimingHistory>(&c).ok())
                    .unwrap_or_default()
            }));
        }

        // All should complete without deadlock
        for handle in handles {
            let loaded = handle.await.unwrap();
            assert!(
                loaded
                    .get("concurrent", Some(CompilationKind::CargoBuild))
                    .is_some()
            );
        }
    }

    #[tokio::test]
    async fn test_spawn_blocking_concurrent_saves() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();

        // Spawn 5 concurrent saves to different files
        let mut handles = Vec::new();
        for i in 0..5 {
            let path = temp_dir.path().join(format!("save_{}.json", i));
            let mut history = super::TimingHistory::default();
            history.record(
                &format!("project-{}", i),
                Some(CompilationKind::CargoBuild),
                100 * i as u64,
                false,
            );

            handles.push(tokio::task::spawn_blocking(move || {
                let content = serde_json::to_string(&history).unwrap();
                std::fs::write(&path, content).unwrap();
                path
            }));
        }

        // All should complete and files should exist
        for handle in handles {
            let path = handle.await.unwrap();
            assert!(path.exists(), "File should be created: {:?}", path);
        }
    }

    #[tokio::test]
    async fn test_spawn_blocking_performance_budget() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let history_path = temp_dir.path().join("perf_test.json");

        // Create a reasonably sized history file
        let mut history = super::TimingHistory::default();
        for i in 0..10 {
            history.record(
                &format!("project-{}", i),
                Some(CompilationKind::CargoBuild),
                1000 + i * 100,
                false,
            );
            history.record(
                &format!("project-{}", i),
                Some(CompilationKind::CargoBuild),
                800 + i * 50,
                true,
            );
        }
        std::fs::write(
            &history_path,
            serde_json::to_string_pretty(&history).unwrap(),
        )
        .unwrap();

        // Measure load time
        let load_path = history_path.clone();
        let start = std::time::Instant::now();
        let _loaded = tokio::task::spawn_blocking(move || {
            std::fs::read_to_string(&load_path)
                .ok()
                .and_then(|c| serde_json::from_str::<super::TimingHistory>(&c).ok())
                .unwrap_or_default()
        })
        .await
        .unwrap();
        let load_duration = start.elapsed();

        // Measure save time
        let save_path = temp_dir.path().join("perf_save.json");
        let start = std::time::Instant::now();
        tokio::task::spawn_blocking(move || {
            let content = serde_json::to_string_pretty(&history).unwrap();
            std::fs::write(&save_path, content).unwrap();
        })
        .await
        .unwrap();
        let save_duration = start.elapsed();

        let total = load_duration + save_duration;

        // Log timings for diagnostics (visible with --nocapture)
        eprintln!("Performance test results:");
        eprintln!("  Load: {:?}", load_duration);
        eprintln!("  Save: {:?}", save_duration);
        eprintln!("  Total: {:?}", total);

        // Total should be well under 2ms budget (leaving room for the rest of the 5ms)
        // On fast SSDs this is typically <1ms, but we allow up to 50ms for slow CI
        assert!(
            total < std::time::Duration::from_millis(50),
            "Load+save took {:?}, should be <50ms for CI compatibility",
            total
        );
    }

    // ── Multi-root sync manifest & partial failure tests (bd-vvmd.2.3 AC5) ──

    #[test]
    fn test_build_sync_closure_manifest_deterministic_entries() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("project");
        let dep_a = temp_dir.path().join("dep_a");
        let dep_b = temp_dir.path().join("dep_b");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep_a).expect("create dep_a");
        std::fs::create_dir_all(&dep_b).expect("create dep_b");

        let plan = build_sync_closure_plan(
            &[dep_b.clone(), dep_a.clone(), project_root.clone()],
            &project_root,
            "abc123",
            &policy,
        );
        let manifest_a = build_sync_closure_manifest(&plan, &project_root);
        let manifest_b = build_sync_closure_manifest(&plan, &project_root);

        // Entries must be identical (order, roots, hashes, primary flag).
        assert_eq!(
            manifest_a.entries, manifest_b.entries,
            "manifest entries should be deterministic for the same plan"
        );
        assert_eq!(
            manifest_a.schema_version, manifest_b.schema_version,
            "schema version must be stable"
        );
        assert_eq!(
            manifest_a.project_root, manifest_b.project_root,
            "project root must be stable"
        );
    }

    #[test]
    fn test_build_sync_closure_manifest_schema_version_stable() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("project");
        std::fs::create_dir_all(&project_root).expect("create project root");

        let plan = build_sync_closure_plan(
            std::slice::from_ref(&project_root),
            &project_root,
            "deadbeef",
            &policy,
        );
        let manifest = build_sync_closure_manifest(&plan, &project_root);

        assert_eq!(
            manifest.schema_version, "rch.sync_closure_manifest.v2",
            "schema version must match the documented v2 contract"
        );
    }

    #[test]
    fn test_build_sync_closure_manifest_entries_faithfully_represent_plan() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("project");
        let dep = temp_dir.path().join("dep");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep).expect("create dep");

        let plan = build_sync_closure_plan(
            &[dep.clone(), project_root.clone()],
            &project_root,
            "cafe0001",
            &policy,
        );
        let manifest = build_sync_closure_manifest(&plan, &project_root);

        assert_eq!(
            manifest.entries.len(),
            plan.len(),
            "manifest must have one entry per plan entry"
        );
        for (idx, (plan_entry, manifest_entry)) in
            plan.iter().zip(manifest.entries.iter()).enumerate()
        {
            assert_eq!(manifest_entry.order, idx + 1, "order must be 1-indexed");
            assert_eq!(
                manifest_entry.local_root,
                plan_entry.local_root.to_string_lossy().to_string()
            );
            assert_eq!(manifest_entry.remote_root, plan_entry.remote_root);
            assert_eq!(manifest_entry.project_id, plan_entry.project_id);
            assert_eq!(manifest_entry.root_hash, plan_entry.root_hash);
            assert_eq!(manifest_entry.is_primary, plan_entry.is_primary);
        }
    }

    #[test]
    fn test_build_sync_closure_manifest_primary_root_present() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("project");
        let dep = temp_dir.path().join("dep");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep).expect("create dep");

        let plan = build_sync_closure_plan(
            &[dep.clone(), project_root.clone()],
            &project_root,
            "primary_hash",
            &policy,
        );
        let manifest = build_sync_closure_manifest(&plan, &project_root);

        let primary_entries: Vec<_> = manifest.entries.iter().filter(|e| e.is_primary).collect();
        assert_eq!(
            primary_entries.len(),
            1,
            "exactly one manifest entry should be the primary root"
        );
        assert_eq!(
            primary_entries[0].root_hash, "primary_hash",
            "primary entry must carry the project-level hash"
        );
    }

    #[test]
    fn test_build_sync_closure_plan_adds_primary_even_when_absent_from_roots() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("project");
        let dep = temp_dir.path().join("dep");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep).expect("create dep");

        // Deliberately omit project_root from sync_roots list.
        let plan = build_sync_closure_plan(
            std::slice::from_ref(&dep),
            &project_root,
            "hash_auto_add",
            &policy,
        );
        let has_primary = plan.iter().any(|e| e.is_primary);
        assert!(
            has_primary,
            "primary root must be auto-added to plan even when not in sync_roots"
        );
        let primary = plan.iter().find(|e| e.is_primary).unwrap();
        assert_eq!(primary.root_hash, "hash_auto_add");
    }

    #[test]
    fn test_sync_root_outcome_diagnostic_counting() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("project");
        let dep_a = temp_dir.path().join("dep_a");
        let dep_b = temp_dir.path().join("dep_b");
        let dep_c = temp_dir.path().join("dep_c");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep_a).expect("create dep_a");
        std::fs::create_dir_all(&dep_b).expect("create dep_b");
        std::fs::create_dir_all(&dep_c).expect("create dep_c");

        let plan = build_sync_closure_plan(
            &[
                dep_a.clone(),
                dep_b.clone(),
                dep_c.clone(),
                project_root.clone(),
            ],
            &project_root,
            "diag_hash",
            &policy,
        );

        // Simulate outcomes: primary synced, one dep synced, one skipped, one failed.
        let outcomes: Vec<(&SyncClosurePlanEntry, SyncRootOutcome)> = plan
            .iter()
            .map(|entry| {
                let outcome = if entry.is_primary || entry.local_root.ends_with("dep_a") {
                    SyncRootOutcome::Synced
                } else if entry.local_root.ends_with("dep_b") {
                    SyncRootOutcome::Skipped {
                        reason: "size too small".to_string(),
                    }
                } else {
                    SyncRootOutcome::Failed {
                        error: "rsync timeout".to_string(),
                    }
                };
                (entry, outcome)
            })
            .collect();

        let failed_count = outcomes
            .iter()
            .filter(|(_, o)| !matches!(o, SyncRootOutcome::Synced))
            .count();
        assert_eq!(
            failed_count, 2,
            "skipped + failed should count as non-synced"
        );

        let synced_count = outcomes
            .iter()
            .filter(|(_, o)| matches!(o, SyncRootOutcome::Synced))
            .count();
        assert_eq!(synced_count, 2, "primary + dep_a should be synced");
    }

    #[test]
    fn test_build_sync_closure_manifest_serializes_to_json() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("project");
        let dep = temp_dir.path().join("dep");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep).expect("create dep");

        let plan = build_sync_closure_plan(
            &[dep.clone(), project_root.clone()],
            &project_root,
            "serial_hash",
            &policy,
        );
        let manifest = build_sync_closure_manifest(&plan, &project_root);

        let json =
            serde_json::to_string_pretty(&manifest).expect("manifest should serialize to JSON");
        assert!(
            json.contains("rch.sync_closure_manifest.v2"),
            "JSON must contain schema_version"
        );
        assert!(
            json.contains("serial_hash"),
            "JSON must contain the primary root hash"
        );
        assert!(
            json.contains("\"is_primary\": true"),
            "JSON must contain primary flag"
        );

        // Roundtrip: deserialize should also work for consumers.
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("manifest JSON should be valid");
        let entries = parsed["entries"]
            .as_array()
            .expect("entries should be an array");
        assert_eq!(entries.len(), plan.len());
    }

    // ── Closure topology validation tests (bd-vvmd.2.3 AC3) ──

    #[test]
    fn test_is_within_sync_topology_accepts_canonical_root() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        let path = PathBuf::from("/data/projects/my_project");
        assert!(
            is_within_sync_topology(&path, &policy),
            "paths under /data/projects should be accepted"
        );
    }

    #[test]
    fn test_is_within_sync_topology_accepts_alias_root() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        let path = PathBuf::from("/dp/my_project");
        assert!(
            is_within_sync_topology(&path, &policy),
            "paths under /dp alias should be accepted"
        );
    }

    #[test]
    fn test_is_within_sync_topology_rejects_outside_paths() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        assert!(
            !is_within_sync_topology(Path::new("/tmp/evil"), &policy),
            "/tmp paths should be rejected"
        );
        assert!(
            !is_within_sync_topology(Path::new("/home/user/project"), &policy),
            "/home paths should be rejected"
        );
        assert!(
            !is_within_sync_topology(Path::new("/var/lib/data"), &policy),
            "/var paths should be rejected"
        );
    }

    #[test]
    fn test_build_sync_closure_plan_excludes_out_of_topology_roots() {
        let _guard = test_guard!();
        // Use paths under /data/projects (canonical root) for valid paths,
        // and a /tmp path for the invalid one. Since these dirs may not exist
        // on the test runner, the canonicalization will fall back to the raw
        // path, which is exactly what we want to test.
        let project_root = PathBuf::from("/data/projects/test_proj");
        let valid_dep = PathBuf::from("/data/projects/valid_dep");
        let invalid_dep = PathBuf::from("/tmp/not_allowed");

        let plan = build_sync_closure_plan(
            &[valid_dep.clone(), invalid_dep.clone(), project_root.clone()],
            &project_root,
            "topo_hash",
            &PathTopologyPolicy::default(),
        );

        // The plan should contain the primary root and valid dep, but NOT the invalid dep.
        let plan_paths: Vec<_> = plan.iter().map(|e| &e.local_root).collect();
        assert!(
            plan_paths
                .iter()
                .any(|p| p.starts_with("/data/projects/test_proj")),
            "primary root must be in plan"
        );
        assert!(
            plan_paths
                .iter()
                .any(|p| p.starts_with("/data/projects/valid_dep")),
            "valid dependency root must be in plan"
        );
        assert!(
            !plan_paths.iter().any(|p| p.starts_with("/tmp")),
            "out-of-topology dependency must be excluded from plan"
        );
    }

    #[test]
    fn test_build_sync_closure_plan_topology_filter_preserves_primary() {
        let _guard = test_guard!();
        // Even with all deps invalid, the primary root must survive.
        let project_root = PathBuf::from("/data/projects/primary_proj");
        let bad_dep_a = PathBuf::from("/home/user/dep_a");
        let bad_dep_b = PathBuf::from("/var/lib/dep_b");

        let plan = build_sync_closure_plan(
            &[bad_dep_a, bad_dep_b],
            &project_root,
            "lonely_hash",
            &PathTopologyPolicy::default(),
        );

        assert_eq!(plan.len(), 1, "only the primary root should remain");
        assert!(
            plan[0].is_primary,
            "surviving entry must be the primary root"
        );
    }

    // ── bd-3jjc.6: canonicalize_sync_root_for_plan() edge cases ─────────

    #[test]
    fn test_canonicalize_existing_path() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let dir = temp_dir.path().join("real_dir");
        std::fs::create_dir_all(&dir).expect("create dir");

        let result = canonicalize_sync_root_for_plan(&dir, &policy);
        // Should be a canonical absolute path containing the dir name.
        assert!(result.is_absolute());
        assert!(
            result.to_string_lossy().contains("real_dir"),
            "canonicalized path should contain dir name: {}",
            result.display()
        );
    }

    #[test]
    fn test_canonicalize_nonexistent_path() {
        let _guard = test_guard!();
        let path = PathBuf::from("/data/projects/does_not_exist_xyz_12345");
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        let result = canonicalize_sync_root_for_plan(&path, &policy);
        // Fallback: should return original path since normalize and canonicalize both fail.
        assert_eq!(result, path);
    }

    #[test]
    fn test_canonicalize_trailing_slash() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let dir = temp_dir.path().join("trail");
        std::fs::create_dir_all(&dir).expect("create dir");

        let with_trailing = PathBuf::from(format!("{}/", dir.display()));
        let without_trailing = canonicalize_sync_root_for_plan(&dir, &policy);
        let with_result = canonicalize_sync_root_for_plan(&with_trailing, &policy);
        // Both should resolve to the same canonical path.
        assert_eq!(with_result, without_trailing);
    }

    #[cfg(unix)]
    #[test]
    fn test_canonicalize_symlink() {
        let _guard = test_guard!();
        use std::os::unix::fs::symlink;

        let (temp_dir, policy) = topology_tempdir();
        let real_dir = temp_dir.path().join("real");
        let link_dir = temp_dir.path().join("link");
        std::fs::create_dir_all(&real_dir).expect("create real dir");
        symlink(&real_dir, &link_dir).expect("create symlink");

        let from_real = canonicalize_sync_root_for_plan(&real_dir, &policy);
        let from_link = canonicalize_sync_root_for_plan(&link_dir, &policy);
        assert_eq!(
            from_real, from_link,
            "symlink and real path should canonicalize to the same path"
        );
    }

    #[test]
    fn test_canonicalize_dp_alias() {
        let _guard = test_guard!();
        // /dp is an alias for /data/projects on the maintainer's dev host.
        // This test is environment-dependent: only meaningful when BOTH the
        // alias and the canonical target exist and the concrete subdir
        // (`remote_compilation_helper`) is present under each.
        //
        // Using `Path::exists()` alone isn't robust — CI runners occasionally
        // have a `/dp` inode that doesn't resolve through `canonicalize`
        // (broken or partially-populated mount). Guard on canonicalization
        // success of the actual input path instead, and skip otherwise.
        let dp_path = PathBuf::from("/dp/remote_compilation_helper");
        let canonical_expected = PathBuf::from("/data/projects/remote_compilation_helper");
        let (Ok(dp_canonical), true) =
            (std::fs::canonicalize(&dp_path), canonical_expected.exists())
        else {
            return;
        };
        if dp_canonical != canonical_expected {
            // Alias target exists but points somewhere else on this host —
            // nothing to assert here.
            return;
        }

        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        let result = canonicalize_sync_root_for_plan(&dp_path, &policy);
        assert_eq!(
            result, canonical_expected,
            "/dp alias should resolve to /data/projects"
        );
    }

    // ── bd-3jjc.7: is_within_sync_topology() edge cases ─────────────────

    #[test]
    fn test_topology_deeply_nested_accepted() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        let path = PathBuf::from("/data/projects/a/b/c/d/e/f/g");
        assert!(
            is_within_sync_topology(&path, &policy),
            "deeply nested /data/projects subpaths should be accepted"
        );
    }

    #[test]
    fn test_topology_exact_root_match() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        // The exact root (/data/projects itself) should be accepted.
        assert!(
            is_within_sync_topology(Path::new("/data/projects"), &policy),
            "/data/projects itself should be accepted"
        );
        assert!(
            is_within_sync_topology(Path::new("/dp"), &policy),
            "/dp itself should be accepted"
        );
    }

    #[test]
    fn test_topology_parent_of_root_rejected() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        assert!(
            !is_within_sync_topology(Path::new("/data"), &policy),
            "/data (parent of root) should be rejected"
        );
    }

    #[test]
    fn test_topology_prefix_collision_rejected() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        // /data/projects_extra starts with /data/projects as a string prefix
        // but is NOT a child path. Path::starts_with uses component-based matching.
        assert!(
            !is_within_sync_topology(Path::new("/data/projects_extra"), &policy),
            "/data/projects_extra should be rejected (not a child path)"
        );
    }

    #[test]
    fn test_topology_empty_path_rejected() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        assert!(
            !is_within_sync_topology(Path::new(""), &policy),
            "empty path should be rejected"
        );
    }

    #[test]
    fn test_topology_root_slash_rejected() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        assert!(
            !is_within_sync_topology(Path::new("/"), &policy),
            "root path (/) should be rejected"
        );
    }

    // ── bd-3jjc.8: build_sync_closure_plan() edge cases ─────────────────

    #[test]
    fn test_plan_empty_sync_roots() {
        let _guard = test_guard!();
        let project_root = PathBuf::from("/data/projects/solo_project");
        let plan = build_sync_closure_plan(
            &[],
            &project_root,
            "solo_hash",
            &PathTopologyPolicy::default(),
        );
        assert_eq!(
            plan.len(),
            1,
            "empty sync_roots should produce single primary entry"
        );
        assert!(plan[0].is_primary);
        assert_eq!(plan[0].root_hash, "solo_hash");
    }

    #[test]
    fn test_plan_primary_is_only_root() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("only");
        std::fs::create_dir_all(&project_root).expect("create dir");

        let plan = build_sync_closure_plan(
            std::slice::from_ref(&project_root),
            &project_root,
            "only_hash",
            &policy,
        );
        assert_eq!(plan.len(), 1);
        assert!(plan[0].is_primary);
        assert_eq!(plan[0].root_hash, "only_hash");
    }

    #[test]
    fn test_plan_large_root_set() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("main_proj");
        std::fs::create_dir_all(&project_root).expect("create main");

        let mut roots = Vec::new();
        for i in 0..100u32 {
            let dep = temp_dir.path().join(format!("dep_{i:04}"));
            std::fs::create_dir_all(&dep).expect("create dep");
            roots.push(dep);
        }
        roots.push(project_root.clone());

        let start = std::time::Instant::now();
        let plan = build_sync_closure_plan(&roots, &project_root, "large_hash", &policy);
        let elapsed = start.elapsed();

        // 100 deps + 1 primary (deduped) = 101 entries.
        assert_eq!(plan.len(), 101);
        assert!(
            elapsed.as_millis() < 500,
            "plan build took too long: {elapsed:?}"
        );

        // Verify lexicographic ordering.
        for window in plan.windows(2) {
            assert!(
                window[0].local_root <= window[1].local_root,
                "plan should be lexicographically ordered: {} > {}",
                window[0].local_root.display(),
                window[1].local_root.display(),
            );
        }
    }

    #[test]
    fn test_plan_duplicate_roots_deduped() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("proj");
        let dep = temp_dir.path().join("dep");
        std::fs::create_dir_all(&project_root).expect("create proj");
        std::fs::create_dir_all(&dep).expect("create dep");

        let plan = build_sync_closure_plan(
            &[dep.clone(), dep.clone(), dep.clone(), project_root.clone()],
            &project_root,
            "dup_hash",
            &policy,
        );

        // dep appears 3 times in input but should be deduped to 1 entry + primary = 2.
        assert_eq!(plan.len(), 2, "duplicate roots should be deduped");
    }

    #[test]
    fn test_plan_primary_via_dp_alias_canonical() {
        let _guard = test_guard!();
        // Verify /dp/X resolves to /data/projects/X — but only when the
        // maintainer's alias layout is actually present. `Path::exists`
        // alone is too permissive (some CI images have a broken `/dp`
        // node that `canonicalize` refuses).
        let dp_path = PathBuf::from("/dp/remote_compilation_helper");
        let Ok(canonical) = std::fs::canonicalize(&dp_path) else {
            return;
        };
        let plan =
            build_sync_closure_plan(&[], &dp_path, "dp_hash", &PathTopologyPolicy::default());
        assert_eq!(plan.len(), 1);
        assert!(plan[0].is_primary);
        assert_eq!(
            plan[0].local_root, canonical,
            "primary via /dp alias should canonicalize to the alias target"
        );
        assert_eq!(
            plan[0].remote_root, "/data/projects/remote_compilation_helper",
            "remote root should stay in worker canonical topology"
        );
    }

    #[test]
    fn test_build_sync_closure_plan_maps_alias_target_roots_to_worker_canonical_topology() {
        let _guard = test_guard!();
        if let Ok(local_projects_root) = std::fs::canonicalize("/dp") {
            let project_root = local_projects_root.join("frankenterm");
            let dep_root = local_projects_root.join("frankentui");

            let plan = build_sync_closure_plan(
                &[dep_root.clone(), project_root.clone()],
                &project_root,
                "mapped_hash",
                &PathTopologyPolicy::default(),
            );

            assert!(
                plan.iter().any(|entry| entry.local_root == project_root
                    && entry.remote_root == "/data/projects/frankenterm"),
                "primary root should map back to worker canonical topology"
            );
            assert!(
                plan.iter().any(|entry| entry.local_root == dep_root
                    && entry.remote_root == "/data/projects/frankentui"),
                "dependency root should map back to worker canonical topology"
            );
        }
    }

    #[test]
    fn test_plan_entry_ordering_is_lexicographic() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("proj");
        let dep_z = temp_dir.path().join("z_dep");
        let dep_a = temp_dir.path().join("a_dep");
        let dep_m = temp_dir.path().join("m_dep");
        std::fs::create_dir_all(&project_root).expect("create proj");
        std::fs::create_dir_all(&dep_z).expect("create dep_z");
        std::fs::create_dir_all(&dep_a).expect("create dep_a");
        std::fs::create_dir_all(&dep_m).expect("create dep_m");

        let plan = build_sync_closure_plan(
            &[dep_z, dep_a, dep_m, project_root.clone()],
            &project_root,
            "order_hash",
            &policy,
        );

        for window in plan.windows(2) {
            assert!(
                window[0].local_root <= window[1].local_root,
                "entries must be lexicographically sorted"
            );
        }
    }

    // ── bd-3jjc.9: build_sync_closure_manifest() edge cases ─────────────

    #[test]
    fn test_manifest_empty_plan() {
        let _guard = test_guard!();
        let project_root = PathBuf::from("/data/projects/empty_proj");
        let manifest = build_sync_closure_manifest(&[], &project_root);
        assert_eq!(manifest.entries.len(), 0);
        assert_eq!(manifest.project_root, "/data/projects/empty_proj");
        assert_eq!(manifest.schema_version, "rch.sync_closure_manifest.v2");
    }

    #[test]
    fn test_manifest_generated_at_is_recent() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("proj");
        std::fs::create_dir_all(&project_root).expect("create proj");

        let before_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let plan = build_sync_closure_plan(
            std::slice::from_ref(&project_root),
            &project_root,
            "ts_hash",
            &policy,
        );
        let manifest = build_sync_closure_manifest(&plan, &project_root);
        let after_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        assert!(
            manifest.generated_at_unix_ms >= before_ms,
            "generated_at should be >= start time"
        );
        assert!(
            manifest.generated_at_unix_ms <= after_ms,
            "generated_at should be <= end time"
        );
    }

    #[test]
    fn test_manifest_order_field_sequential() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let project_root = temp_dir.path().join("proj");
        std::fs::create_dir_all(&project_root).expect("create proj");

        let mut roots = Vec::new();
        for i in 0..10u32 {
            let dep = temp_dir.path().join(format!("dep_{i:02}"));
            std::fs::create_dir_all(&dep).expect("create dep");
            roots.push(dep);
        }
        roots.push(project_root.clone());

        let plan = build_sync_closure_plan(&roots, &project_root, "seq_hash", &policy);
        let manifest = build_sync_closure_manifest(&plan, &project_root);

        // Order field should be 1-indexed and sequential.
        for (idx, entry) in manifest.entries.iter().enumerate() {
            assert_eq!(
                entry.order,
                idx + 1,
                "order should be 1-indexed sequential, got {} at position {}",
                entry.order,
                idx
            );
        }
    }

    #[test]
    fn test_manifest_unicode_paths() {
        let _guard = test_guard!();
        // Use synthetic plan entries with unicode paths.
        let entries = vec![SyncClosurePlanEntry {
            local_root: PathBuf::from("/data/projects/日本語プロジェクト"),
            remote_root: "/data/projects/日本語プロジェクト".to_string(),
            project_id: "日本語".to_string(),
            root_hash: "unicode_hash".to_string(),
            is_primary: true,
            mode: SyncClosureMode::Full,
        }];
        let manifest =
            build_sync_closure_manifest(&entries, Path::new("/data/projects/日本語プロジェクト"));
        assert_eq!(manifest.entries.len(), 1);
        assert!(manifest.entries[0].local_root.contains("日本語"));

        // Verify JSON serialization handles unicode.
        let json = serde_json::to_string(&manifest).expect("should serialize unicode");
        assert!(json.contains("日本語"));
    }

    #[test]
    fn test_manifest_long_strings() {
        let _guard = test_guard!();
        let long_id = "x".repeat(10_000);
        let long_hash = "h".repeat(10_000);
        let entries = vec![SyncClosurePlanEntry {
            local_root: PathBuf::from("/data/projects/long_test"),
            remote_root: "/data/projects/long_test".to_string(),
            project_id: long_id.clone(),
            root_hash: long_hash.clone(),
            is_primary: true,
            mode: SyncClosureMode::Full,
        }];
        let manifest = build_sync_closure_manifest(&entries, Path::new("/data/projects/long_test"));
        assert_eq!(
            manifest.entries[0].project_id, long_id,
            "project_id should not be truncated"
        );
        assert_eq!(
            manifest.entries[0].root_hash, long_hash,
            "root_hash should not be truncated"
        );
    }

    // ── bd-3jjc.10: SyncRootOutcome variant coverage ────────────────────

    #[test]
    fn test_sync_root_outcome_all_synced() {
        let _guard = test_guard!();
        let outcomes: Vec<SyncRootOutcome> = (0..5).map(|_| SyncRootOutcome::Synced).collect();
        let non_synced = outcomes
            .iter()
            .filter(|o| !matches!(o, SyncRootOutcome::Synced))
            .count();
        assert_eq!(non_synced, 0);
    }

    #[test]
    fn test_sync_root_outcome_all_failed() {
        let _guard = test_guard!();
        let outcomes: Vec<SyncRootOutcome> = (0..3)
            .map(|i| SyncRootOutcome::Failed {
                error: format!("error_{i}"),
            })
            .collect();
        let failed_count = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Failed { .. }))
            .count();
        assert_eq!(failed_count, 3);

        // Verify error messages are preserved.
        let errors: Vec<&str> = outcomes
            .iter()
            .filter_map(|o| match o {
                SyncRootOutcome::Failed { error } => Some(error.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(errors, vec!["error_0", "error_1", "error_2"]);
    }

    #[test]
    fn test_sync_root_outcome_all_skipped() {
        let _guard = test_guard!();
        let outcomes: Vec<SyncRootOutcome> = (0..4)
            .map(|i| SyncRootOutcome::Skipped {
                reason: format!("reason_{i}"),
            })
            .collect();
        let skipped_count = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Skipped { .. }))
            .count();
        assert_eq!(skipped_count, 4);
    }

    #[test]
    fn test_sync_root_outcome_empty_collection() {
        let _guard = test_guard!();
        let outcomes: Vec<SyncRootOutcome> = vec![];
        let synced = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Synced))
            .count();
        let failed = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Failed { .. }))
            .count();
        let skipped = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Skipped { .. }))
            .count();
        assert_eq!(synced, 0);
        assert_eq!(failed, 0);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn test_sync_root_outcome_mixed_with_reasons() {
        let _guard = test_guard!();
        let outcomes = [
            SyncRootOutcome::Synced,
            SyncRootOutcome::Synced,
            SyncRootOutcome::Skipped {
                reason: "stale".to_string(),
            },
            SyncRootOutcome::Failed {
                error: "timeout".to_string(),
            },
            SyncRootOutcome::Skipped {
                reason: "denied".to_string(),
            },
        ];

        let synced = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Synced))
            .count();
        let failed = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Failed { .. }))
            .count();
        let skipped = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Skipped { .. }))
            .count();

        assert_eq!(synced, 2);
        assert_eq!(failed, 1);
        assert_eq!(skipped, 2);

        // Verify reason extraction.
        let skip_reasons: Vec<&str> = outcomes
            .iter()
            .filter_map(|o| match o {
                SyncRootOutcome::Skipped { reason } => Some(reason.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(skip_reasons, vec!["stale", "denied"]);

        let error_msgs: Vec<&str> = outcomes
            .iter()
            .filter_map(|o| match o {
                SyncRootOutcome::Failed { error } => Some(error.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(error_msgs, vec!["timeout"]);
    }

    // ── bd-3jjc.13: E2E sync closure plan + manifest generation ─────────

    #[test]
    fn test_e2e_sync_closure_plan_and_manifest() {
        let _guard = test_guard!();
        let (temp_dir, policy) = topology_tempdir();
        let primary = temp_dir.path().join("primary_project");
        let dep_a = temp_dir.path().join("dep_a");
        let dep_b = temp_dir.path().join("dep_b");
        std::fs::create_dir_all(&primary).expect("create primary");
        std::fs::create_dir_all(&dep_a).expect("create dep_a");
        std::fs::create_dir_all(&dep_b).expect("create dep_b");

        // Step 2: Build plan with valid deps + an out-of-topology sentinel
        // that must be filtered. Pick any path that lies outside the
        // `topology_tempdir` root — `/var/empty` exists on Linux & macOS
        // and is not under our scratch area.
        let out_of_topology = PathBuf::from("/var/empty/invalid_dep");
        let plan = build_sync_closure_plan(
            &[
                primary.clone(),
                dep_a.clone(),
                dep_b.clone(),
                out_of_topology.clone(),
            ],
            &primary,
            "e2e_hash",
            &policy,
        );

        // Step 3: 3 entries (primary, dep_a, dep_b), out-of-topology excluded.
        assert_eq!(
            plan.len(),
            3,
            "plan should have 3 entries (primary + 2 deps), got {}",
            plan.len()
        );
        let out_of_topology_str = out_of_topology.to_string_lossy().to_string();
        assert!(
            !plan
                .iter()
                .any(|e| e.local_root.to_string_lossy() == out_of_topology_str),
            "out-of-topology dep should be excluded by topology filter"
        );

        // Step 4: Verify lexicographic ordering.
        for window in plan.windows(2) {
            assert!(
                window[0].local_root <= window[1].local_root,
                "plan entries should be lexicographically sorted"
            );
        }

        // Step 5: Primary entry has is_primary=true with correct hash.
        let primary_entry = plan
            .iter()
            .find(|e| e.is_primary)
            .expect("primary must exist");
        assert_eq!(primary_entry.root_hash, "e2e_hash");
        let non_primary: Vec<_> = plan.iter().filter(|e| !e.is_primary).collect();
        assert_eq!(non_primary.len(), 2, "should have 2 non-primary entries");

        // Step 6-7: Generate manifest.
        let before_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let manifest = build_sync_closure_manifest(&plan, &primary);
        let after_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        assert_eq!(manifest.schema_version, "rch.sync_closure_manifest.v2");
        assert_eq!(manifest.entries.len(), 3);
        assert!(manifest.generated_at_unix_ms >= before_ms);
        assert!(manifest.generated_at_unix_ms <= after_ms);

        // Step 8-9: JSON roundtrip.
        let json = serde_json::to_string_pretty(&manifest).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        let entries = parsed["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 3);

        // Step 10: Verify order fields are 1-indexed sequential.
        for (idx, entry) in manifest.entries.iter().enumerate() {
            assert_eq!(entry.order, idx + 1, "order should be 1-indexed sequential");
            assert_eq!(entry.is_primary, plan[idx].is_primary);
            assert_eq!(entry.root_hash, plan[idx].root_hash);
        }
    }

    // ── bd-3jjc.15: E2E topology validation with symlinks ───────────────

    #[cfg(unix)]
    #[test]
    fn test_e2e_topology_validation_with_symlinks() {
        let _guard = test_guard!();
        use std::os::unix::fs::symlink;

        let (temp_dir, policy) = topology_tempdir();
        let valid_root = temp_dir.path().join("valid_root");
        let valid_sub = valid_root.join("sub");
        std::fs::create_dir_all(&valid_sub).expect("create valid_root/sub");

        let primary = temp_dir.path().join("primary");
        std::fs::create_dir_all(&primary).expect("create primary");

        // Create symlink alias within the same tempdir.
        let alias_link = temp_dir.path().join("alias_for_valid");
        symlink(&valid_root, &alias_link).expect("create symlink");

        // Build plan with mixed valid/invalid/alias paths. Rejection paths
        // are deliberately under system roots that won't overlap with the
        // `topology_tempdir` scratch area (which itself lives under
        // `/tmp/.tmpXXXX` on Linux or `/var/folders/...` on macOS).
        let reject_a = PathBuf::from("/etc/rch_should_reject");
        let reject_b = PathBuf::from("/usr/local/fake_project");
        let reject_c = PathBuf::from("/opt/fake_thing");
        let plan = build_sync_closure_plan(
            &[
                valid_root.clone(),
                alias_link.clone(), // should dedup with valid_root
                reject_a.clone(),
                reject_b.clone(),
                reject_c.clone(),
                primary.clone(),
            ],
            &primary,
            "topo_e2e_hash",
            &policy,
        );

        // Should contain primary + valid_root (deduped with alias) = 2 entries.
        assert_eq!(
            plan.len(),
            2,
            "plan should have 2 entries (primary + deduped valid_root), got {}",
            plan.len()
        );

        // Verify the three explicit rejection paths were excluded.
        let reject_strs: Vec<String> = [reject_a, reject_b, reject_c]
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        for entry in &plan {
            let path_str = entry.local_root.to_string_lossy().to_string();
            assert!(
                !reject_strs.contains(&path_str),
                "out-of-topology path should not appear in plan: {}",
                path_str
            );
        }

        // Verify alias was deduplicated (only one entry for valid_root).
        let valid_canonical = std::fs::canonicalize(&valid_root).expect("canonicalize");
        let matching_entries = plan
            .iter()
            .filter(|e| {
                std::fs::canonicalize(&e.local_root)
                    .map(|c| c == valid_canonical)
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            matching_entries, 1,
            "symlink alias should be deduplicated with canonical path"
        );

        // Verify primary is present.
        assert!(
            plan.iter().any(|e| e.is_primary),
            "primary root must always be in plan"
        );
    }

    // =========================================================================
    // Regression suite: Classification timing budget & edge cases (bd-vvmd.2.9)
    // =========================================================================

    /// Verify classification completes well within the 5ms panic threshold for
    /// compilation commands, and within 1ms for non-compilation commands.
    /// This acts as a regression gate: if any code change blows the budget,
    /// this test catches it.
    #[test]
    fn test_classification_timing_budget_non_compilation() {
        let _guard = test_guard!();
        let non_compilation_cmds = [
            "ls -la",
            "pwd",
            "git status",
            "echo hello world",
            "cat Cargo.toml",
            "npm install",
            "python main.py",
            "docker build -t myapp .",
            "mkdir -p build",
            "rm -rf target/",
        ];

        for cmd in non_compilation_cmds {
            let start = std::time::Instant::now();
            for _ in 0..100 {
                let _ = classify_command(cmd);
            }
            let elapsed = start.elapsed();
            let per_call_us = elapsed.as_micros() / 100;
            // Non-compilation: budget <1ms, panic at 5ms
            // We check the median is under 1ms (1000us)
            assert!(
                per_call_us < 1000,
                "Non-compilation command {:?} exceeded 1ms budget: {}us per call",
                cmd,
                per_call_us
            );
        }
    }

    #[test]
    fn test_classification_timing_budget_compilation() {
        let _guard = test_guard!();
        let compilation_cmds = [
            "cargo build --release",
            "cargo test --workspace",
            "cargo clippy --all-targets",
            "gcc -c main.c -o main.o",
            "make -j8",
            "bun test",
            "rustc main.rs",
            "ninja -j4",
        ];

        for cmd in compilation_cmds {
            let start = std::time::Instant::now();
            for _ in 0..100 {
                let _ = classify_command(cmd);
            }
            let elapsed = start.elapsed();
            let per_call_us = elapsed.as_micros() / 100;
            // Compilation: budget <5ms, panic at 10ms
            assert!(
                per_call_us < 5000,
                "Compilation command {:?} exceeded 5ms budget: {}us per call",
                cmd,
                per_call_us
            );
        }
    }

    /// Verify that process_hook handles compilation commands correctly when
    /// daemon is absent — the classification MUST work, and the hook MUST
    /// fail-open to allow local execution.
    #[tokio::test]
    async fn test_hook_classification_fail_open_all_compilation_kinds() {
        let _lock = test_lock().lock().await;
        mock::set_mock_enabled_override(Some(false));

        let compilation_commands = [
            ("cargo build --release", "CargoBuild"),
            ("cargo test --workspace", "CargoTest"),
            ("cargo check --all-targets", "CargoCheck"),
            ("cargo clippy", "CargoClippy"),
            ("cargo doc --no-deps", "CargoDoc"),
            ("cargo run", "CargoRun"),
            ("cargo bench", "CargoBench"),
            ("cargo nextest run", "CargoNextest"),
            ("bun test", "BunTest"),
            ("bun typecheck", "BunTypecheck"),
        ];

        for (cmd, label) in compilation_commands {
            let input = HookInput {
                tool_name: "Bash".to_string(),
                tool_input: ToolInput {
                    command: cmd.to_string(),
                    description: None,
                },
                session_id: None,
            };

            let output = process_hook(input).await;
            assert!(
                output.is_allow(),
                "Hook should fail-open for {} ({}) when daemon absent",
                label,
                cmd
            );
        }

        mock::set_mock_enabled_override(None);
    }

    /// Verify that non-compilation commands pass through the hook immediately
    /// (are allowed without daemon interaction).
    #[tokio::test]
    async fn test_hook_non_compilation_passthrough() {
        let non_compilation = [
            "ls -la",
            "git status",
            "cargo fmt --check",
            "cargo install ripgrep",
            "bun install",
            "bun run dev",
            "echo hello",
            "cat Cargo.toml",
        ];

        for cmd in non_compilation {
            let input = HookInput {
                tool_name: "Bash".to_string(),
                tool_input: ToolInput {
                    command: cmd.to_string(),
                    description: None,
                },
                session_id: None,
            };

            let output = process_hook(input).await;
            assert!(
                output.is_allow(),
                "Non-compilation command {:?} should pass through the hook (Allow)",
                cmd
            );
        }
    }

    /// Verify that non-Bash tool invocations are always allowed.
    #[tokio::test]
    async fn test_hook_non_bash_tools_always_allowed() {
        let tools = ["Read", "Write", "Edit", "Glob", "Grep", "WebSearch"];

        for tool in tools {
            let input = HookInput {
                tool_name: tool.to_string(),
                tool_input: ToolInput {
                    command: "cargo build".to_string(), // Even compilation keyword
                    description: None,
                },
                session_id: None,
            };

            let output = process_hook(input).await;
            assert!(
                output.is_allow(),
                "Non-Bash tool {:?} should always be allowed, even with compilation keyword",
                tool
            );
        }
    }

    /// Verify that classify_command_detailed produces valid structured output
    /// for every tier decision path, enabling structured logging.
    #[test]
    fn test_structured_log_output_per_tier() {
        let _guard = test_guard!();

        // Tier 0 reject: empty command
        let d = classify_command_detailed("");
        assert_eq!(d.tiers.len(), 1);
        assert_eq!(d.tiers[0].tier, 0);
        assert_eq!(d.tiers[0].decision, TierDecision::Reject);
        assert!(!d.tiers[0].reason.is_empty());

        // Tier 1 reject: piped command
        let d = classify_command_detailed("cargo build | tee log");
        assert!(
            d.tiers
                .iter()
                .any(|t| t.tier == 1 && t.decision == TierDecision::Reject)
        );

        // Tier 2 reject: no keyword
        let d = classify_command_detailed("ls -la");
        assert!(
            d.tiers
                .iter()
                .any(|t| t.tier == 2 && t.decision == TierDecision::Reject)
        );

        // Tier 3 reject: never-intercept
        let d = classify_command_detailed("cargo install serde");
        assert!(
            d.tiers
                .iter()
                .any(|t| t.tier == 3 && t.decision == TierDecision::Reject)
        );

        // Tier 4 pass: full classification
        let d = classify_command_detailed("cargo build --release");
        assert!(
            d.tiers
                .iter()
                .any(|t| t.tier == 4 && t.decision == TierDecision::Pass)
        );
        assert!(d.classification.is_compilation);
        assert!(d.classification.confidence > 0.0);
        assert!(d.classification.kind.is_some());

        // Tier 4 reject: keyword present but no matching pattern
        let d = classify_command_detailed("cargo tree");
        assert!(
            d.tiers
                .iter()
                .any(|t| t.tier == 4 && t.decision == TierDecision::Reject)
        );
    }
}
