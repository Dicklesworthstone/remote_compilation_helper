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
    CompilationKind, ControlState, DependencyClosurePlan, HookInput, HookOutput, IncidentEvent,
    IncidentEventType, IncidentLedger, IncidentLedgerConfig, IncidentReasonCode, IncidentSource,
    OutputVisibility, REPO_UPDATER_CANONICAL_PROJECTS_ROOT, RepoUpdaterAdapterCommand,
    RepoUpdaterAdapterContract, RepoUpdaterAdapterRequest, RepoUpdaterOutputFormat,
    RequiredRuntime, SelectedMode, SelectedWorker, SelectionReason, SelectionResponse,
    SelfHealingConfig, ToolchainInfo, TransferConfig, WorkerConfig, WorkerId,
    build_dependency_closure_plan_with_policy, build_invocation, classify_command,
    declined_compilation_due_to_structure, default_socket_path, mock,
    normalize_project_path_with_policy,
    path_topology::PathTopologyPolicy,
    redaction::{redact_path, redact_secrets},
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

/// Process exit code returned when the remote compile SUCCEEDED but the build
/// artifacts could NOT be transferred back, leaving the local build incomplete
/// (no binary/lib where the agent expects one). From the caller's perspective the
/// build did not actually complete, so this must be a NON-zero, build-failure-class
/// code rather than the remote command's exit 0 — re-running locally is the right
/// recovery, exactly like the AGENTS.md "Build failed (remote compilation)" case.
/// Pairs with the `RCH-E309 BuildArtifactMissing` diagnostic on stderr.
const EXIT_ARTIFACT_TRANSFER_FAILED: i32 = 102;

const RCH_CARGO_WRAPPER_BYPASS_ENV: &str = "RCH_CARGO_WRAPPER_BYPASS";
const RCH_REQUIRE_REMOTE_ENV: &str = "RCH_REQUIRE_REMOTE";
const RCH_WORKER_ENV: &str = "RCH_WORKER";
const RCH_WORKERS_ENV: &str = "RCH_WORKERS";

/// Opt-out knob for remote target-dir REUSE. When set to a truthy value the hook
/// falls back to the legacy unique-per-job remote target dir name
/// (`remote_cargo_target_dir_name`) instead of the stable pooled name, for users
/// who hit problems with the shared pool.
const RCH_DISABLE_TARGET_REUSE_ENV: &str = "RCH_DISABLE_TARGET_REUSE";

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

// ---------------------------------------------------------------------------
// Hook daemon-recovery: socket-failure classification, configured-vs-canonical
// socket mismatch detection, and durable structured-incident emission
// (bd-session-history-remediation-ocv9i.3.1).
//
// When the hook cannot reach the daemon it must record *why* — a missing,
// refused, or stale socket, or a configured-vs-canonical socket-path mismatch —
// as a durable structured incident, attempt a bounded daemon autostart and one
// selection retry, then either proceed remotely or fall back / refuse (proof
// mode) loudly. All of this lives on the slow recovery path; the fast
// non-compilation classification budget is never touched.
//
// The decision cores are pure so the six bead scenarios (refused / stale /
// wrong-configured socket, daemon start success / failure, proof-mode refusal)
// are unit-testable without spawning a daemon; the side effects (autostart,
// ledger append) are thin wrappers around them.
// ---------------------------------------------------------------------------

/// Why the hook could not reach the daemon over its Unix socket. Reported in
/// the `socket_failure` incident detail so postmortems can tell a never-started
/// daemon (`missing`) from a crashed one (`refused`/`stale`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketFailureKind {
    /// The socket file does not exist (daemon never created it, or wrong path).
    Missing,
    /// The socket exists but refused the connection (no live listener).
    Refused,
    /// The socket exists and connected but the daemon did not respond in time.
    Stale,
    /// Any other daemon-query failure (protocol/read error, malformed response).
    Other,
}

impl SocketFailureKind {
    fn as_str(self) -> &'static str {
        match self {
            SocketFailureKind::Missing => "missing",
            SocketFailureKind::Refused => "refused",
            SocketFailureKind::Stale => "stale",
            SocketFailureKind::Other => "other",
        }
    }
}

/// Classify a [`query_daemon`] failure for incident reporting. Pure: inspects
/// the error chain plus whether the socket file is present on disk.
fn classify_socket_failure(err: &anyhow::Error, socket_exists: bool) -> SocketFailureKind {
    // Explicit daemon-side signals from query_daemon.
    if let Some(daemon_err) = err.downcast_ref::<DaemonError>() {
        match daemon_err {
            DaemonError::SocketNotFound { .. } | DaemonError::NotRunning => {
                return SocketFailureKind::Missing;
            }
            DaemonError::ConnectionFailed { .. } | DaemonError::SocketPermissionDenied { .. } => {
                return SocketFailureKind::Refused;
            }
            _ => {}
        }
    }
    // Raw std::io errors surfaced from UnixStream::connect (wrapped by `?`).
    for cause in err.chain() {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            return match io_err.kind() {
                std::io::ErrorKind::NotFound => SocketFailureKind::Missing,
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::PermissionDenied => {
                    SocketFailureKind::Refused
                }
                std::io::ErrorKind::TimedOut => SocketFailureKind::Stale,
                _ if socket_exists => SocketFailureKind::Stale,
                _ => SocketFailureKind::Other,
            };
        }
    }
    // The 5s connect timeout is an anyhow string error with no io::Error source.
    if err.to_string().contains("timed out") {
        return SocketFailureKind::Stale;
    }
    if socket_exists {
        SocketFailureKind::Stale
    } else {
        SocketFailureKind::Missing
    }
}

/// A configured-vs-canonical socket-path disagreement. Like the daemon's
/// startup-consistency probe, the hook reports this drift but **never** rewrites
/// operator-owned config — detection and loud reporting only.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketPathMismatch {
    configured: String,
    canonical: String,
    /// Whether the canonical default socket exists (a live daemon there is the
    /// likely reason the hook missed it on the configured path).
    canonical_exists: bool,
}

/// Lexical socket-path equivalence (trims surrounding whitespace; exact match
/// otherwise — mirrors the daemon startup-consistency `PathBuf` comparison).
fn socket_paths_equivalent(a: &str, b: &str) -> bool {
    a.trim() == b.trim()
}

/// Detect a "wrong configured socket" condition: the configured socket path
/// differs from the canonical default. Returns `None` when they agree. Pure —
/// the caller supplies `canonical` and `canonical_exists` so this is testable
/// without filesystem or environment access.
fn detect_socket_path_mismatch(
    configured: &str,
    canonical: &str,
    canonical_exists: bool,
) -> Option<SocketPathMismatch> {
    if socket_paths_equivalent(configured, canonical) {
        return None;
    }
    Some(SocketPathMismatch {
        configured: configured.to_string(),
        canonical: canonical.to_string(),
        canonical_exists,
    })
}

/// Terminal action after a daemon-socket failure plus a bounded autostart and
/// one selection retry. Pure so the bead's daemon-start-success / failure /
/// proof-mode-refusal scenarios are unit-testable without spawning a daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonRecoveryAction {
    /// The daemon answered after autostart + retry — proceed remotely.
    ProceedRemote,
    /// Fail-open: run the command locally (records `LocalFallback`, RCH-I011).
    LocalFallback,
    /// Proof mode: refuse local fallback (records `ProofRefusal`, RCH-I012) and
    /// exit fail-closed.
    Refuse,
}

/// Decide the terminal action. `retry_succeeded` is whether the post-autostart
/// selection retry produced a usable daemon response. A successful retry always
/// wins; otherwise proof mode refuses and convenience mode falls back.
fn decide_recovery_action(retry_succeeded: bool, strict_remote: bool) -> DaemonRecoveryAction {
    if retry_succeeded {
        DaemonRecoveryAction::ProceedRemote
    } else if strict_remote {
        DaemonRecoveryAction::Refuse
    } else {
        DaemonRecoveryAction::LocalFallback
    }
}

/// Current wall-clock time as Unix epoch milliseconds. The hook is a real
/// process, so wall-clock is appropriate here (unlike the clock-free pure
/// rch-common modules); a pre-epoch clock — impossible in practice — yields 0.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Build the structured incident for a daemon-socket failure (RCH-I010). The
/// `selected_mode` is recorded as `Local` because at detection time the build
/// has not yet been steered; the terminal local-fallback / proof-refusal
/// incident records the final disposition.
fn build_socket_failure_incident(
    kind: SocketFailureKind,
    mismatch: Option<&SocketPathMismatch>,
    project: &str,
    command_fingerprint: &str,
    strict_remote: bool,
    now_ms: u64,
) -> IncidentEvent {
    let mut event = IncidentEvent::new(
        IncidentEventType::Selection,
        IncidentReasonCode::DaemonSocketRefused,
        IncidentSource::Hook,
        project,
        command_fingerprint,
        SelectedMode::Local,
        !strict_remote,
        now_ms,
    )
    .with_detail("socket_failure", kind.as_str())
    .with_control(ControlState {
        strict_remote_policy: strict_remote,
        ..ControlState::default()
    });
    if let Some(m) = mismatch {
        event = event
            .with_detail("socket_path_mismatch", "true")
            .with_detail("configured_socket", redact_path(&m.configured))
            .with_detail("canonical_socket", redact_path(&m.canonical))
            .with_detail("canonical_socket_exists", m.canonical_exists.to_string());
    }
    event
}

/// Build the terminal incident after autostart + retry could not restore the
/// daemon: `ProofRefusal` (RCH-I012) when proof mode forbids local fallback,
/// else `LocalFallback` (RCH-I011).
fn build_recovery_terminal_incident(
    strict_remote: bool,
    project: &str,
    command_fingerprint: &str,
    detail_reason: &str,
    now_ms: u64,
) -> IncidentEvent {
    let (reason_code, event_type) = if strict_remote {
        (IncidentReasonCode::ProofRefusal, IncidentEventType::Proof)
    } else {
        (
            IncidentReasonCode::LocalFallback,
            IncidentEventType::Fallback,
        )
    };
    IncidentEvent::new(
        event_type,
        reason_code,
        IncidentSource::Hook,
        project,
        command_fingerprint,
        SelectedMode::Local,
        !strict_remote,
        now_ms,
    )
    .with_detail("reason", detail_reason.to_string())
    .with_control(ControlState {
        strict_remote_policy: strict_remote,
        ..ControlState::default()
    })
}

/// Append `event` to the durable incident ledger, best-effort. Incident logging
/// must never break a build, so a write failure is logged and swallowed. A
/// tracing breadcrumb is always emitted so the incident is visible even when the
/// ledger write fails. The ledger lives off the hot path, so the append cost
/// (one buffered line) does not affect the classification budgets.
fn record_hook_incident(event: &IncidentEvent) {
    warn!(
        target: "rch::hook::incident",
        reason_code = %event.reason_code,
        failure_class = event.reason_code.failure_class(),
        selected_mode = ?event.selected_mode,
        local_fallback_allowed = event.local_fallback_allowed,
        "hook incident recorded",
    );
    let ledger = IncidentLedger::new(IncidentLedgerConfig::default());
    if let Err(e) = ledger.append(event) {
        warn!(
            target: "rch::hook::incident",
            error = %e,
            "failed to append incident to ledger (continuing)",
        );
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
            warn!("Failed to query daemon: {}, attempting recovery", e);

            // Classify the failure and detect a configured-vs-canonical socket
            // mismatch, then record a durable structured incident (RCH-I010)
            // so postmortems can see *why* the hook could not reach the daemon.
            let socket_path = config.general.socket_path.clone();
            let socket_exists = Path::new(&socket_path).exists();
            let failure_kind = classify_socket_failure(&e, socket_exists);
            let strict_remote = exec_requires_remote();
            let canonical_socket = default_socket_path();
            let canonical_exists = Path::new(&canonical_socket).exists();
            let mismatch =
                detect_socket_path_mismatch(&socket_path, &canonical_socket, canonical_exists);
            // Privacy-safe fingerprint (secrets and home paths masked).
            let command_fingerprint = redact_secrets(&command);

            record_hook_incident(&build_socket_failure_incident(
                failure_kind,
                mismatch.as_ref(),
                &project,
                &command_fingerprint,
                strict_remote,
                now_unix_ms(),
            ));

            // Attempt a bounded daemon autostart, then retry selection ONCE.
            let retry =
                if auto_start::try_auto_start_daemon(&config.self_healing, Path::new(&socket_path))
                    .await
                    .is_ok()
                {
                    query_daemon(
                        &socket_path,
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
                    .ok()
                } else {
                    None
                };

            match decide_recovery_action(retry.is_some(), strict_remote) {
                // Daemon came back after autostart + retry — proceed remotely.
                // ProceedRemote implies `retry` is Some; fail open defensively
                // rather than panicking if that invariant is ever violated.
                DaemonRecoveryAction::ProceedRemote => retry.unwrap_or_else(|| {
                    reporter.summary("[RCH] local (daemon unavailable)");
                    exit_with_local_fallback(&command, &reporter, "daemon unavailable");
                }),
                // Fail-open convenience lane: record the fallback and run local.
                DaemonRecoveryAction::LocalFallback => {
                    record_hook_incident(&build_recovery_terminal_incident(
                        false,
                        &project,
                        &command_fingerprint,
                        "daemon unavailable",
                        now_unix_ms(),
                    ));
                    reporter.summary("[RCH] local (daemon unavailable)");
                    exit_with_local_fallback(&command, &reporter, "daemon unavailable");
                }
                // Proof lane: record the refusal and fail closed.
                // exit_with_local_fallback also refuses under proof mode and
                // prints the explicit "remote required" refusal summary.
                DaemonRecoveryAction::Refuse => {
                    record_hook_incident(&build_recovery_terminal_incident(
                        true,
                        &project,
                        &command_fingerprint,
                        "daemon unavailable",
                        now_unix_ms(),
                    ));
                    exit_with_local_fallback(&command, &reporter, "daemon unavailable");
                }
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
                let evidence_summary = preflight_err.evidence_summary();
                warn!(
                    "Dependency preflight blocked remote execution [{}]: {}; evidence='{}'",
                    preflight_err.reason_code, preflight_err.remediation, evidence_summary
                );
                reporter.summary(&format!(
                    "[RCH] local (dependency preflight {}: {}; evidence: {})",
                    preflight_err.reason_code, preflight_err.remediation, evidence_summary
                ));
                reporter.verbose(&format!(
                    "[RCH] dependency preflight report: {}",
                    preflight_err.report_json()
                ));
                let fallback_reason = format!("dependency preflight failed: {evidence_summary}");
                exit_with_local_fallback(&command, &reporter, &fallback_reason);
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

// ============================================================================
// Daemon Auto-Start (Self-Healing)
// ============================================================================
//
// The bounded daemon-autostart cluster (lock/cooldown/spawn/health-probe/
// socket-wait) lives in the `auto_start` submodule. `try_auto_start_daemon`
// is its only cross-module entry point (called from `run_exec` below).
mod auto_start;

// The build-heartbeat / progress-reporting cluster (the periodic snapshot, the
// background loop, the progress-counter bump, and the socket send) lives in the
// `progress_reporting` submodule. Its `BuildHeartbeatLoop` /
// `mark_heartbeat_progress` are consumed by `execute_remote_compilation`, which
// now lives in the sibling `transfer_orchestration` submodule and imports them
// directly.
mod progress_reporting;

// The remote-build execution pipeline (`execute_remote_compilation` plus its leaf
// telemetry-forwarding helpers) lives in the `transfer_orchestration` submodule.
// `execute_remote_compilation` is imported so `run_hook` / `run_exec` call it
// unqualified.
mod transfer_orchestration;
use transfer_orchestration::execute_remote_compilation;

// The repo_updater pre-sync subsystem (closure-convergence orchestration +
// adapter invocation + contract/auth resolution + sync-root detection) lives in
// the `repo_updater` submodule. Its `maybe_sync_repo_set_with_repo_updater` entry
// point is consumed by `execute_remote_compilation` in the sibling
// `transfer_orchestration` submodule, which imports it directly.
mod repo_updater;

// The offload-pipeline SSH primitives (`run_offload_ssh_command`, the remote
// topology-enforcement preflight, and the mock-mode skip gate) live in the
// `ssh` submodule. They are consumed only by the sibling submodules
// (`dependency_closure`, `transfer_orchestration`, `repo_updater`), which import
// what they need directly from `super::ssh` — `hook` itself no longer calls them.
mod ssh;

// The dependency-closure sync planning + remote dependency-preflight cluster
// (sync-closure plan/manifest, sync-topology predicates, cargo manifest/workspace
// parsers, and the remote dependency-manifest verifier) lives in the
// `dependency_closure` submodule. The dependency-preflight types/consts below are
// consumed by `build_dependency_runtime_fail_open_report` and the `run_hook` /
// `run_exec` error downcasts; the sibling `transfer_orchestration` imports the
// sync-closure planners + verifier directly from `super::dependency_closure`.
mod dependency_closure;
use dependency_closure::{
    DEPENDENCY_PREFLIGHT_CODE_POLICY, DEPENDENCY_PREFLIGHT_CODE_TIMEOUT,
    DEPENDENCY_PREFLIGHT_CODE_UNKNOWN, DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY,
    DEPENDENCY_PREFLIGHT_REMEDIATION_TIMEOUT, DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN,
    DEPENDENCY_PREFLIGHT_SCHEMA_VERSION, DependencyPreflightEvidence, DependencyPreflightFailure,
    DependencyPreflightReport, DependencyPreflightStatus,
};

// The remote-execution result type (`RemoteExecutionResult`) and the outcome
// classifiers that interpret it live in the `remote_result` submodule. The four
// classifier fns below are consumed by `run_hook` / `run_exec`; the sibling
// `transfer_orchestration` constructs and returns `RemoteExecutionResult`
// directly from `super::remote_result`.
mod remote_result;
use remote_result::{
    detect_worker_system_dependency_failure, is_signal_killed, is_toolchain_failure, signal_name,
};

// The remote cargo target-dir resolution / naming / command-rewrite cluster
// (CARGO_TARGET_DIR forwarding, the unique-per-job + stable-pooled remote dir
// names, and the helpers that strip a local target-dir from a delegated command)
// lives in the `cargo_target_dir` submodule. `run_hook` / `run_exec` call
// `resolve_forwarded_cargo_target_dir` + `rewrite_cargo_target_dir_command_for_remote`,
// and `add_cargo_isolation` shares `sanitize_cargo_home_token`, so those three are
// imported here; the sibling `transfer_orchestration` imports the dir-naming / env
// helpers it needs directly from `super::cargo_target_dir`.
mod cargo_target_dir;
use cargo_target_dir::{
    resolve_forwarded_cargo_target_dir, rewrite_cargo_target_dir_command_for_remote,
    sanitize_cargo_home_token,
};

// The remote artifact-pattern selection cluster (which files travel back from a
// worker, keyed on `CompilationKind`) lives in the `artifact_patterns` submodule.
// `get_artifact_patterns` / `get_custom_target_artifact_patterns` /
// `kind_produces_transferable_artifacts` have no non-test caller in `hook` itself —
// they are consumed by the sibling `transfer_orchestration`
// (`execute_remote_compilation`), which imports them directly, so nothing is
// re-exported into the non-test hook namespace here.
mod artifact_patterns;

// The daemon selection-response wire-deserialization cluster (the `*Wire` DTOs,
// their `From` conversions into the `rch_common` domain types, and the
// protocol-version-checked parse entry point) lives in the `selection_response`
// submodule. `parse_selection_response` is the only cross-module item —
// `run_hook` / `run_exec` call it — so it is re-exported here; the wire types and
// validation helpers stay private to that submodule.
mod selection_response;
use selection_response::parse_selection_response;

// Build-timing history (persistence + offload-gating estimation) lives in the
// `timing_history` submodule. `record_build_timing` is the only item the hook
// hot path calls (two sites in the remote-classification path), so it is
// re-exported here; the on-disk model, the process-global cache, and the
// estimator surface stay `pub(super)` for the test suite and otherwise private.
mod timing_history;
use timing_history::record_build_timing;

// The daemon IPC client (worker-selection / release / build-record requests
// over the `rchd` Unix socket, plus request-timeout + queue-when-busy policy
// helpers) lives in the `daemon_ipc` submodule. `query_daemon` / `release_worker`
// are re-exported `pub(crate)` because `commands::status` also calls them;
// `record_build` / `queue_when_busy_enabled` are re-exported for the hook hot
// path. The timeout helpers and `urlencoding_encode` stay `pub(super)` for tests.
mod daemon_ipc;
pub(crate) use daemon_ipc::{query_daemon, release_worker};
use daemon_ipc::{queue_when_busy_enabled, record_build};

// Command-string parsing utilities (tokenization + cargo flag/env analyzers +
// offload core estimation) live in the `command_parsing` submodule.
// `cargo_job_count_for_command` / `estimate_cores_for_command` are re-exported
// `pub(crate)` because `commands::status` also calls them; the `--test-threads` /
// `-j` / `--ignored` / `--exact` / filtered-test detectors stay `pub(super)` for
// the test suite, and the numeric `parse_*` helpers stay module-private.
mod command_parsing;
pub(crate) use command_parsing::{cargo_job_count_for_command, estimate_cores_for_command};

// Human-facing job-output rendering (compile-summary panel, job banner, and the
// duration/speed/profile/target formatting + detection helpers) lives in the
// `formatting` submodule. `format_duration_ms` / `estimate_local_time_ms` are
// re-exported for the hook hot path; `emit_job_banner` / `render_compile_summary`
// / `cache_hit` / `detect_target_label` are pub(super) and imported directly by
// the sibling transfer-orchestration (and cargo_target_dir) modules.
mod formatting;
use formatting::{estimate_local_time_ms, format_duration_ms};

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

        // Issue #24, item 3: surface a hint when we decline a command that is a
        // compilation command in disguise but whose pipe/redirect/background/
        // subshell structure we can't safely offload. On an orchestrator with
        // force_remote=true this would otherwise be an *invisible* local
        // fallback (a silent rustc/cc storm). Only loads config on this rare
        // path to avoid touching the hot non-compilation path.
        if let Some(structure_reason) = declined_compilation_due_to_structure(command) {
            let force_remote = load_config()
                .map(|cfg| cfg.general.force_remote)
                .unwrap_or(false);
            if force_remote {
                warn!(
                    "⚠️ RCH: declined to offload compilation command due to shell structure \
                     ({structure_reason}) while force_remote=true — running LOCALLY: '{command}'. \
                     Run it as a bare command (no unsupported pipe/subshell) so it can be offloaded."
                );
            } else {
                debug!(
                    "RCH: declined to offload compilation command due to shell structure \
                     ({structure_reason}): '{command}'"
                );
            }
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
                let evidence_summary = preflight_err.evidence_summary();
                info!(
                    "Dependency preflight blocked remote execution [{}], falling back to local; evidence='{}'",
                    preflight_err.reason_code, evidence_summary
                );
                reporter.summary(&format!(
                    "[RCH] local (dependency preflight {}: {}; evidence: {})",
                    preflight_err.reason_code, preflight_err.remediation, evidence_summary
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

#[cfg(test)]
mod tests;
