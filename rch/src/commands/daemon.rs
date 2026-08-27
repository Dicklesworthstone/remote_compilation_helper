//! Daemon lifecycle management commands.
//!
//! This module contains commands for starting, stopping, restarting, and managing
//! the RCH daemon process.

use crate::status_types::extract_json_body;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::{Context, Result};
use rch_common::{ApiError, ApiResponse, ErrorCode};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

use super::helpers::configured_socket_path;
use super::types::{
    DaemonActionResponse, DaemonLogsResponse, DaemonReloadResponse, DaemonStatusResponse,
};
use super::{config_dir, send_daemon_command};

#[derive(Debug, Deserialize)]
struct ReloadApiResponse {
    #[serde(default = "reload_success_default")]
    success: bool,
    #[serde(default)]
    added: usize,
    #[serde(default)]
    updated: usize,
    #[serde(default)]
    removed: usize,
    #[serde(default)]
    warnings: Vec<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RestartAdmissionResponse {
    restart_permitted: bool,
    active_build_ids: Vec<u64>,
    queued_build_ids: Vec<u64>,
    #[serde(default)]
    client_lease_ids: Vec<String>,
    #[serde(default)]
    client_lease_scan_error: Option<String>,
}

fn reload_success_default() -> bool {
    true
}

async fn require_restart_admission() -> Result<()> {
    let response = send_daemon_command("POST /restart-admission\n")
        .await
        .context("daemon did not acknowledge restart admission barrier")?;
    let body =
        extract_json_body(&response).context("restart admission response was missing JSON")?;
    let admission: RestartAdmissionResponse =
        serde_json::from_str(body).context("restart admission response was malformed")?;
    if admission.restart_permitted {
        return Ok(());
    }
    // The POST above CLOSED the barrier as a side effect; a refused restart
    // must reopen it, otherwise this failed attempt leaves the daemon
    // refusing every subsequent worker selection (restart_admission_barrier_active)
    // until someone manually hits the release endpoint. Best-effort: if the
    // release itself fails we still surface the refusal below.
    if let Err(release_error) = send_daemon_command("POST /restart-admission/release\n").await {
        tracing::warn!(
            "failed to release the restart-admission barrier after a refused restart: {release_error}; \
             worker selection may refuse builds until `POST /restart-admission/release` succeeds"
        );
    }
    anyhow::bail!(
        "restart blocked by daemon admission barrier: active builds {:?}, queued builds {:?}, client leases {:?}, lease scan {:?}",
        admission.active_build_ids,
        admission.queued_build_ids,
        admission.client_lease_ids,
        admission.client_lease_scan_error,
    );
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Helper to get rchd path.
fn which_rchd() -> PathBuf {
    // Try to find rchd in same directory as current executable
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(dir) = exe_path.parent()
    {
        let rchd = dir.join("rchd");
        if rchd.exists() {
            return rchd;
        }
    }

    // Fallback to path lookup
    which::which("rchd").unwrap_or_else(|_| PathBuf::from("rchd"))
}

fn daemon_start_args(socket_path: &Path) -> [&std::ffi::OsStr; 2] {
    [std::ffi::OsStr::new("--socket"), socket_path.as_os_str()]
}

/// Which systemd scope, if any, manages `rchd.service` on this host.
///
/// Mirrors the daemon-side detection (`rchd::rchd_systemd_unit_present`,
/// which probes `systemctl --user is-enabled rchd`) so that `rch daemon
/// restart` cycles the unit the same way `rch update`'s restart step does
/// instead of fighting it with a manual shutdown + `nohup rchd` spawn.
///
/// On systemd hosts the manual spawn path is doomed: any rchd launched
/// outside the unit calls `defer_to_systemd_if_managed()` and exits, while
/// systemd's `Restart=always` respawns the unit's *own* process — leaving the
/// old (possibly deleted-on-disk) binary running. `systemctl restart` is the
/// only thing that re-execs the unit from the freshly installed binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// On non-Linux hosts `detect_rchd_systemd_scope` always returns `None`, so the
// variants are never constructed there; they are live on Linux.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum SystemdUnitScope {
    /// `systemctl --user is-enabled rchd` succeeds.
    User,
    /// `systemctl is-enabled rchd` (system scope) succeeds.
    System,
}

impl SystemdUnitScope {
    /// The scope-selecting flag to pass to `systemctl` (empty for system scope).
    fn systemctl_scope_args(self) -> &'static [&'static str] {
        match self {
            SystemdUnitScope::User => &["--user"],
            SystemdUnitScope::System => &[],
        }
    }
}

/// Detect whether an `rchd.service` systemd unit manages the daemon here, and
/// in which scope. Returns `None` on non-Linux hosts (e.g. macOS launchd) and
/// on Linux hosts with no such unit (manual / nohup management) — both of which
/// keep the legacy shutdown+spawn restart path.
#[cfg(target_os = "linux")]
fn detect_rchd_systemd_scope() -> Option<SystemdUnitScope> {
    // Prefer the user scope: that is what `rch daemon start`/the hook/`rch
    // update` interact with on dev hosts (trj/css/csd/ts1). System-scope units
    // (vmi root daemons) are checked second.
    let probe = |scope_args: &[&str]| -> bool {
        std::process::Command::new("systemctl")
            .args(scope_args)
            .args(["is-enabled", "rchd"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };

    if probe(&["--user"]) {
        Some(SystemdUnitScope::User)
    } else if probe(&[]) {
        Some(SystemdUnitScope::System)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn detect_rchd_systemd_scope() -> Option<SystemdUnitScope> {
    None
}

/// Restart the daemon via its systemd unit and wait for the socket to come
/// back live. Returns `Err` (with a human message) on any failure so the
/// caller can fall back to the manual shutdown+spawn path.
async fn restart_via_systemd(scope: SystemdUnitScope) -> std::result::Result<(), String> {
    let status = Command::new("systemctl")
        .args(scope.systemctl_scope_args())
        .args(["restart", "rchd"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|e| format!("failed to invoke systemctl: {e}"))?;

    if !status.success() {
        return Err(format!("systemctl restart rchd exited {status}"));
    }

    // Confirm a live listener actually came back, not just that systemctl
    // returned 0 (the unit could fail its own start). wait_for_daemon_ready
    // polls the configured socket for up to ~2s.
    if wait_for_daemon_ready().await {
        Ok(())
    } else {
        Err("systemd restarted rchd but no daemon responded on the socket".to_string())
    }
}

fn ensure_socket_parent(socket_path: &Path) -> Result<()> {
    if let Some(parent) = socket_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create daemon socket parent directory {}",
                parent.display()
            )
        })?;
    }
    Ok(())
}

async fn daemon_responds_on_configured_socket() -> bool {
    send_daemon_command("GET /health\n").await.is_ok()
}

async fn wait_for_daemon_ready() -> bool {
    for _ in 0..20 {
        if daemon_responds_on_configured_socket().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}

// =============================================================================
// Daemon Commands
// =============================================================================

/// Check daemon status.
pub async fn daemon_status(ctx: &OutputContext) -> Result<()> {
    let socket_path_str = configured_socket_path()?;
    let socket_path = Path::new(&socket_path_str);
    let style = ctx.theme();

    let socket_exists = socket_path.exists();
    let running = socket_exists && daemon_responds_on_configured_socket().await;
    let uptime_seconds = if running {
        std::fs::metadata(socket_path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs())
    } else {
        None
    };

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "daemon status",
            DaemonStatusResponse {
                running,
                socket_path: socket_path_str.clone(),
                uptime_seconds,
            },
        ));
        return Ok(());
    }

    println!("{}", style.format_header("RCH Daemon Status"));
    println!();

    if running {
        println!(
            "  {} {} {}",
            style.key("Status"),
            style.muted(":"),
            StatusIndicator::Success.with_label(style, "Running")
        );
        println!(
            "  {} {} {}",
            style.key("Socket"),
            style.muted(":"),
            style.value(&socket_path_str)
        );

        if let Some(secs) = uptime_seconds {
            let hours = secs / 3600;
            let mins = (secs % 3600) / 60;
            println!(
                "  {} {} ~{}h {}m",
                style.key("Uptime"),
                style.muted(":"),
                hours,
                mins
            );
        }
    } else {
        let socket_note = if socket_exists {
            "(stale or unreachable)"
        } else {
            "(not found)"
        };
        println!(
            "  {} {} {}",
            style.key("Status"),
            style.muted(":"),
            StatusIndicator::Error.with_label(style, "Not running")
        );
        println!(
            "  {} {} {} {}",
            style.key("Socket"),
            style.muted(":"),
            style.muted(&socket_path_str),
            style.muted(socket_note)
        );
        println!();
        println!(
            "  {} Start with: {}",
            StatusIndicator::Info.display(style),
            style.highlight("rch daemon start")
        );
    }

    Ok(())
}

/// Start the daemon.
pub async fn daemon_start(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    let socket_path_str = configured_socket_path()?;
    let socket_path = Path::new(&socket_path_str);

    if socket_path.exists() && daemon_responds_on_configured_socket().await {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok(
                "daemon start",
                DaemonActionResponse {
                    action: "start".to_string(),
                    success: false,
                    socket_path: socket_path_str.clone(),
                    message: Some("Daemon already running".to_string()),
                },
            ));
        } else {
            println!(
                "{} Daemon appears to already be running.",
                StatusIndicator::Warning.display(style)
            );
            println!(
                "  {} {} {}",
                style.key("Socket"),
                style.muted(":"),
                style.value(&socket_path_str)
            );
            println!(
                "\n{} Use {} to restart it.",
                StatusIndicator::Info.display(style),
                style.highlight("rch daemon restart")
            );
        }
        return Ok(());
    }
    if socket_path.exists() && !ctx.is_json() {
        println!(
            "{} Found stale daemon socket at {}; starting rchd will replace it.",
            StatusIndicator::Warning.display(style),
            style.value(&socket_path_str)
        );
    }

    // Check if rchd binary exists
    let rchd_path = which_rchd();

    if !ctx.is_json() {
        println!("Starting RCH daemon...");
    }
    tracing::debug!("Using rchd binary: {:?}", rchd_path);
    ensure_socket_parent(socket_path)?;

    // Spawn rchd in background using nohup to detach from terminal
    // This avoids needing unsafe code for setsid()
    let mut cmd = Command::new("nohup");
    let daemon_args = daemon_start_args(socket_path);
    cmd.arg(&rchd_path)
        .args(daemon_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(false);

    match cmd.spawn() {
        Ok(_child) => {
            if wait_for_daemon_ready().await {
                if ctx.is_json() {
                    let _ = ctx.json(&ApiResponse::ok(
                        "daemon start",
                        DaemonActionResponse {
                            action: "start".to_string(),
                            success: true,
                            socket_path: socket_path_str.clone(),
                            message: Some("Daemon started successfully".to_string()),
                        },
                    ));
                } else {
                    println!(
                        "{}",
                        StatusIndicator::Success.with_label(style, "Daemon started successfully.")
                    );
                    println!(
                        "  {} {} {}",
                        style.key("Socket"),
                        style.muted(":"),
                        style.value(&socket_path_str)
                    );
                }
            } else if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "daemon start",
                    DaemonActionResponse {
                        action: "start".to_string(),
                        success: false,
                        socket_path: socket_path_str.clone(),
                        message: Some("Process started but daemon did not respond".to_string()),
                    },
                ));
            } else {
                println!(
                    "{} Daemon process started but did not respond on its configured socket.",
                    StatusIndicator::Warning.display(style)
                );
                println!(
                    "  {} Check logs with: {}",
                    StatusIndicator::Info.display(style),
                    style.highlight("rch daemon logs")
                );
            }
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "daemon start",
                    ApiError::internal(e.to_string()),
                ));
            } else {
                println!(
                    "{} Failed to start daemon: {}",
                    StatusIndicator::Error.display(style),
                    style.muted(&e.to_string())
                );
                println!(
                    "\n{} Make sure {} is in your PATH or installed.",
                    StatusIndicator::Info.display(style),
                    style.highlight("rchd")
                );
            }
        }
    }

    Ok(())
}

/// How `rch daemon stop|restart` treats in-flight work (issue #54).
///
/// The daemon refuses `POST /shutdown` while admission is open or builds are
/// active/queued (`shutdown_blocked`), so a stop must first raise the
/// admission barrier and then either wait for the work to finish (`drain`) or
/// deliberately interrupt it (`force`). Neither happens implicitly: `yes`
/// only skips the interactive confirmation, it never authorises interrupting
/// someone else's build.
#[derive(Debug, Clone, Copy, Default)]
pub struct StopOptions {
    /// Skip the interactive confirmation prompt.
    pub yes: bool,
    /// Close admission and wait for active/queued builds to finish first.
    pub drain: bool,
    /// Upper bound for `drain`, in seconds (0 = no waiting, just close
    /// admission and re-check once).
    pub drain_timeout_secs: u64,
    /// Interrupt active builds (after the drain window, if `drain` is set).
    pub force: bool,
}

/// In-flight work the daemon reported when asked about admission.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DaemonWorkload {
    active_build_ids: Vec<u64>,
    queued_build_ids: Vec<u64>,
    client_lease_ids: Vec<String>,
    client_lease_scan_error: Option<String>,
}

impl DaemonWorkload {
    fn from_admission(response: RestartAdmissionResponse) -> Self {
        Self {
            active_build_ids: response.active_build_ids,
            queued_build_ids: response.queued_build_ids,
            client_lease_ids: response.client_lease_ids,
            client_lease_scan_error: response.client_lease_scan_error,
        }
    }

    /// True when stopping now interrupts nothing. A lease-scan failure counts
    /// as busy: the zero-state proof is unprovable, so fail closed.
    fn is_idle(&self) -> bool {
        self.active_build_ids.is_empty()
            && self.queued_build_ids.is_empty()
            && self.client_lease_ids.is_empty()
            && self.client_lease_scan_error.is_none()
    }

    fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.active_build_ids.is_empty() {
            parts.push(format!("active builds {:?}", self.active_build_ids));
        }
        if !self.queued_build_ids.is_empty() {
            parts.push(format!("queued builds {:?}", self.queued_build_ids));
        }
        if !self.client_lease_ids.is_empty() {
            parts.push(format!("client leases {:?}", self.client_lease_ids));
        }
        if let Some(error) = &self.client_lease_scan_error {
            parts.push(format!("lease scan failed: {error}"));
        }
        if parts.is_empty() {
            "idle".to_string()
        } else {
            parts.join("; ")
        }
    }
}

/// What a stop/restart should do given the daemon's workload and the flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopDecision {
    /// Nothing in flight: shut down now.
    Proceed,
    /// Close admission and wait for the workload to finish.
    Drain,
    /// Interrupt the in-flight work (operator asked for `--force`).
    Interrupt,
    /// Refuse: work is in flight and neither `--drain` nor `--force` was given.
    Refuse,
}

fn decide_stop_action(workload: &DaemonWorkload, opts: &StopOptions) -> StopDecision {
    if workload.is_idle() {
        StopDecision::Proceed
    } else if opts.drain {
        StopDecision::Drain
    } else if opts.force {
        StopDecision::Interrupt
    } else {
        StopDecision::Refuse
    }
}

/// Outcome of the drain wait.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DrainOutcome {
    Drained,
    TimedOut(DaemonWorkload),
}

/// Response to `POST /shutdown`: either `shutting_down` or `shutdown_blocked`
/// with the work that blocked it.
#[derive(Debug, Deserialize)]
struct ShutdownApiResponse {
    status: String,
    #[serde(default)]
    active_build_ids: Vec<u64>,
    #[serde(default)]
    queued_build_ids: Vec<u64>,
}

fn parse_admission_response(response: &str) -> Result<RestartAdmissionResponse> {
    let body = extract_json_body(response).context("admission response was missing JSON")?;
    serde_json::from_str(body).context("admission response was malformed")
}

/// Raise the admission barrier (stop the daemon accepting new builds) and
/// return the workload it reported.
async fn close_admission() -> Result<DaemonWorkload> {
    let response = send_daemon_command("POST /restart-admission\n")
        .await
        .context("daemon did not acknowledge the admission barrier")?;
    Ok(DaemonWorkload::from_admission(parse_admission_response(
        &response,
    )?))
}

/// Snapshot the workload without touching the barrier.
async fn fetch_workload() -> Result<DaemonWorkload> {
    let response = send_daemon_command("GET /restart-admission\n")
        .await
        .context("daemon did not answer the admission status query")?;
    Ok(DaemonWorkload::from_admission(parse_admission_response(
        &response,
    )?))
}

/// Reopen admission after a refused/aborted stop. A closed barrier makes the
/// daemon refuse every worker selection, so every failure path must call
/// this; best-effort, the caller's own error still surfaces.
async fn release_admission() {
    if let Err(error) = send_daemon_command("POST /restart-admission/release\n").await {
        tracing::warn!(
            "failed to release the admission barrier after an aborted stop: {error}; \
             worker selection may refuse builds until `POST /restart-admission/release` succeeds"
        );
    }
}

/// Wait (admission already closed) until the daemon is idle or the timeout
/// elapses. Polls once per second; the barrier is left closed on success and
/// released on timeout.
async fn drain_until_idle(
    timeout: std::time::Duration,
    ctx: &OutputContext,
) -> Result<DrainOutcome> {
    let started = std::time::Instant::now();
    let mut last_report: Option<String> = None;
    loop {
        let workload = fetch_workload().await?;
        if workload.is_idle() {
            return Ok(DrainOutcome::Drained);
        }
        if started.elapsed() >= timeout {
            release_admission().await;
            return Ok(DrainOutcome::TimedOut(workload));
        }
        if !ctx.is_json() {
            let report = workload.describe();
            if last_report.as_deref() != Some(report.as_str()) {
                println!(
                    "  {} draining: waiting for {} ({}s left)",
                    StatusIndicator::Info.display(ctx.theme()),
                    report,
                    timeout.saturating_sub(started.elapsed()).as_secs()
                );
                last_report = Some(report);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Emit a refusal in the active output mode and return the error that makes
/// the process exit non-zero. In JSON mode the structured error is printed
/// here (with the blocking ids in `details`) and the process exits directly,
/// so the top-level handler cannot re-render it as an internal-state error.
fn refuse_stop(
    command: &str,
    code: ErrorCode,
    message: &str,
    workload: &DaemonWorkload,
    remediation: &[&str],
    ctx: &OutputContext,
) -> anyhow::Error {
    let details = workload.describe();
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::<()>::err(
            command,
            ApiError::new(code, message)
                .with_details(details)
                .with_context(
                    "active_build_ids",
                    serde_json::to_string(&workload.active_build_ids).unwrap_or_default(),
                )
                .with_context(
                    "queued_build_ids",
                    serde_json::to_string(&workload.queued_build_ids).unwrap_or_default(),
                )
                .with_remediation(remediation.iter().copied()),
        ));
        std::process::exit(1);
    }
    // Text mode: the message itself is carried by the returned error (the
    // top-level handler prints it); only the evidence and remediation go here.
    let style = ctx.theme();
    println!("  {} {}", style.key("In flight"), details);
    for step in remediation {
        println!(
            "  {} {}",
            StatusIndicator::Info.display(style),
            style.highlight(step)
        );
    }
    anyhow::anyhow!("{message}: {details}")
}

/// Ask the running daemon for its PID via `GET /status`.
async fn daemon_pid() -> Option<u32> {
    let response = send_daemon_command("GET /status\n").await.ok()?;
    let json = extract_json_body(&response)?;
    serde_json::from_str::<crate::status_types::DaemonFullStatusResponse>(json)
        .ok()
        .map(|status| status.daemon.pid)
}

/// Interrupt in-flight builds by terminating the daemon process. The socket
/// API refuses to shut down while builds are active by design, so a forced
/// stop has to go through the OS — but to the daemon's own PID, never a
/// name match that could hit an unrelated process.
async fn terminate_daemon_process(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let output = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .output()
            .await
            .context("failed to run kill")?;
        if !output.status.success() {
            anyhow::bail!(
                "kill -TERM {pid} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        anyhow::bail!("forced stop is not supported on this platform; use --drain");
    }
}

/// Whether a process with this PID still exists (signal 0 probe).
fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(true)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Wait up to ~`attempts` x 100ms for the daemon socket to disappear.
async fn wait_for_socket_gone(socket_path: &Path, attempts: u32) -> bool {
    for _ in 0..attempts {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if !socket_path.exists() {
            return true;
        }
    }
    false
}

fn report_stopped(
    command: &str,
    action: &str,
    socket_path_str: &str,
    how: &str,
    ctx: &OutputContext,
) {
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            command,
            DaemonActionResponse {
                action: action.to_string(),
                success: true,
                socket_path: socket_path_str.to_string(),
                message: Some(how.to_string()),
            },
        ));
    } else {
        println!(
            "{}",
            StatusIndicator::Success.with_label(ctx.theme(), "Daemon stopped.")
        );
    }
}

/// Stop the daemon.
///
/// Raises the admission barrier, then shuts down only when nothing is in
/// flight — or after `--drain` waited for it, or when `--force` explicitly
/// authorised interrupting it. `-y` alone never interrupts a build.
pub async fn daemon_stop(opts: StopOptions, ctx: &OutputContext) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();
    let socket_path_str = configured_socket_path()?;
    let socket_path = Path::new(&socket_path_str);

    if !socket_path.exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok(
                "daemon stop",
                DaemonActionResponse {
                    action: "stop".to_string(),
                    success: true,
                    socket_path: socket_path_str.clone(),
                    message: Some("Daemon was not running".to_string()),
                },
            ));
        } else {
            println!(
                "{} Daemon is not running {}",
                StatusIndicator::Pending.display(style),
                style.muted("(socket not found)")
            );
        }
        return Ok(());
    }

    // Raise the admission barrier first: /shutdown is refused while admission
    // is open, and closing it is what stops new builds landing mid-stop.
    let workload = match close_admission().await {
        Ok(workload) => workload,
        Err(error) => {
            // No usable API (stale socket, wedged daemon). Fall back to the
            // legacy process-level stop rather than leaving a stale socket.
            return stop_unresponsive_daemon(socket_path, &socket_path_str, error, ctx).await;
        }
    };

    let mut decision = decide_stop_action(&workload, &opts);
    if decision == StopDecision::Drain {
        if !ctx.is_json() {
            println!(
                "{} Admission closed; draining {} (timeout {}s)...",
                StatusIndicator::Info.display(style),
                workload.describe(),
                opts.drain_timeout_secs
            );
        }
        match drain_until_idle(std::time::Duration::from_secs(opts.drain_timeout_secs), ctx).await?
        {
            DrainOutcome::Drained => decision = StopDecision::Proceed,
            DrainOutcome::TimedOut(remaining) => {
                if opts.force {
                    // Barrier was released by the timeout path; close it
                    // again so nothing new lands while we interrupt.
                    let _ = close_admission().await;
                    decision = StopDecision::Interrupt;
                } else {
                    return Err(refuse_stop(
                        "daemon stop",
                        ErrorCode::CancelTimeoutExceeded,
                        &format!(
                            "drain timed out after {}s; daemon left running with admission reopened",
                            opts.drain_timeout_secs
                        ),
                        &remaining,
                        &[
                            "rch daemon stop --drain --drain-timeout <more seconds>",
                            "rch daemon stop --force   # interrupts the listed builds",
                        ],
                        ctx,
                    ));
                }
            }
        }
    }

    match decision {
        StopDecision::Refuse => {
            release_admission().await;
            return Err(refuse_stop(
                "daemon stop",
                ErrorCode::WorkerAtCapacity,
                "refusing to stop: builds are in flight (pass --drain to wait or --force to interrupt)",
                &workload,
                &[
                    "rch daemon stop --drain [--drain-timeout N]",
                    "rch daemon stop --force",
                ],
                ctx,
            ));
        }
        StopDecision::Interrupt => {
            if !opts.yes && !ctx.is_json() {
                println!(
                    "{} {} will be interrupted.",
                    StatusIndicator::Warning.display(style),
                    style.highlight(&workload.describe())
                );
                let confirmed = Confirm::new()
                    .with_prompt("Stop the daemon anyway?")
                    .default(false)
                    .interact()?;
                if !confirmed {
                    release_admission().await;
                    println!("{} Aborted.", StatusIndicator::Info.display(style));
                    return Ok(());
                }
            }
            if !ctx.is_json() {
                println!("Stopping RCH daemon (interrupting in-flight builds)...");
            }
            let Some(pid) = daemon_pid().await else {
                release_admission().await;
                anyhow::bail!("could not determine the daemon PID for a forced stop");
            };
            if let Err(error) = terminate_daemon_process(pid).await {
                release_admission().await;
                return Err(error);
            }
            let socket_gone = wait_for_socket_gone(socket_path, 100).await;
            // A daemon that died without its shutdown path (no signal handler
            // engaged) leaves the socket file behind; treat a dead PID with a
            // lingering socket as stopped and clear the stale socket.
            if socket_gone || !process_alive(pid) {
                if !socket_gone {
                    let _ = tokio::fs::remove_file(socket_path).await;
                }
                report_stopped(
                    "daemon stop",
                    "stop",
                    &socket_path_str,
                    "Daemon stopped (forced; in-flight builds interrupted)",
                    ctx,
                );
                return Ok(());
            }
            release_admission().await;
            anyhow::bail!("sent SIGTERM to daemon pid {pid} but it is still running");
        }
        StopDecision::Proceed => {}
        StopDecision::Drain => unreachable!("drain resolves to Proceed or Interrupt above"),
    }

    if !ctx.is_json() {
        println!("Stopping RCH daemon...");
    }

    let response = match send_daemon_command("POST /shutdown\n").await {
        Ok(response) => response,
        Err(error) => {
            return stop_unresponsive_daemon(socket_path, &socket_path_str, error, ctx).await;
        }
    };
    let parsed = extract_json_body(&response)
        .and_then(|json| serde_json::from_str::<ShutdownApiResponse>(json).ok());
    match parsed {
        Some(shutdown) if shutdown.status == "shutdown_blocked" => {
            // A build was admitted between our barrier and the shutdown (or
            // the barrier is not ours). Report exactly what blocked it.
            release_admission().await;
            let blocked = DaemonWorkload {
                active_build_ids: shutdown.active_build_ids,
                queued_build_ids: shutdown.queued_build_ids,
                ..Default::default()
            };
            return Err(refuse_stop(
                "daemon stop",
                ErrorCode::WorkerAtCapacity,
                "daemon refused to shut down: builds are in flight",
                &blocked,
                &[
                    "rch daemon stop --drain [--drain-timeout N]",
                    "rch daemon stop --force",
                ],
                ctx,
            ));
        }
        _ => {}
    }

    if wait_for_socket_gone(socket_path, 50).await {
        report_stopped(
            "daemon stop",
            "stop",
            &socket_path_str,
            "Daemon stopped",
            ctx,
        );
        return Ok(());
    }

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "daemon stop",
            DaemonActionResponse {
                action: "stop".to_string(),
                success: false,
                socket_path: socket_path_str.clone(),
                message: Some(
                    "Daemon acknowledged shutdown but its socket is still present".to_string(),
                ),
            },
        ));
    } else {
        println!(
            "{} Daemon acknowledged shutdown but may still be shutting down...",
            StatusIndicator::Warning.display(style)
        );
    }
    Ok(())
}

/// Legacy stop for a daemon that no longer answers its socket: terminate by
/// process name and clear the stale socket. Only reached when the API is
/// unusable, so there is no workload to protect.
async fn stop_unresponsive_daemon(
    socket_path: &Path,
    socket_path_str: &str,
    api_error: anyhow::Error,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();
    if !ctx.is_json() {
        println!(
            "{} Daemon did not answer its socket ({api_error:#}).",
            StatusIndicator::Warning.display(style)
        );
        println!("Attempting to find and kill daemon process...");
    }

    let output = Command::new("pkill").arg("-f").arg("rchd").output().await;
    match output {
        Ok(o) if o.status.success() => {
            // Remove stale socket
            let _ = tokio::fs::remove_file(socket_path).await;
            report_stopped(
                "daemon stop",
                "stop",
                socket_path_str,
                "Daemon stopped via pkill",
                ctx,
            );
            Ok(())
        }
        _ => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "daemon stop",
                    ApiError::internal("Could not stop daemon"),
                ));
            } else {
                println!(
                    "{} Could not stop daemon. You may need to kill it manually.",
                    StatusIndicator::Error.display(style)
                );
                println!(
                    "  {} Try: {}",
                    StatusIndicator::Info.display(style),
                    style.highlight("pkill -9 rchd")
                );
            }
            Ok(())
        }
    }
}

/// Restart the daemon.
///
/// Same in-flight contract as [`daemon_stop`]: refuse while builds are in
/// flight unless `--drain` waits them out or `--force` interrupts them.
pub async fn daemon_restart(opts: StopOptions, ctx: &OutputContext) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();
    let socket_path_str = configured_socket_path()?;
    let socket_path = Path::new(&socket_path_str);

    // Establish the in-flight contract while the daemon is still reachable.
    // `admission_proven` records that the barrier is closed AND the daemon
    // was proven idle, which is the precondition `require_restart_admission`
    // otherwise establishes (it cannot be re-run after a drain: the barrier
    // is already closed, so it would refuse and release it).
    let mut interrupting = false;
    let mut admission_proven = false;
    if socket_path.exists()
        && let Ok(workload) = fetch_workload().await
    {
        match decide_stop_action(&workload, &opts) {
            StopDecision::Proceed => {}
            StopDecision::Drain => {
                close_admission().await?;
                if !ctx.is_json() {
                    println!(
                        "{} Admission closed; draining {} (timeout {}s)...",
                        StatusIndicator::Info.display(style),
                        workload.describe(),
                        opts.drain_timeout_secs
                    );
                }
                match drain_until_idle(std::time::Duration::from_secs(opts.drain_timeout_secs), ctx)
                    .await?
                {
                    DrainOutcome::Drained => admission_proven = true,
                    DrainOutcome::TimedOut(remaining) => {
                        if opts.force {
                            interrupting = true;
                        } else {
                            return Err(refuse_stop(
                                "daemon restart",
                                ErrorCode::CancelTimeoutExceeded,
                                &format!(
                                    "drain timed out after {}s; daemon left running with admission reopened",
                                    opts.drain_timeout_secs
                                ),
                                &remaining,
                                &[
                                    "rch daemon restart --drain --drain-timeout <more seconds>",
                                    "rch daemon restart --force   # interrupts the listed builds",
                                ],
                                ctx,
                            ));
                        }
                    }
                }
            }
            StopDecision::Interrupt => interrupting = true,
            StopDecision::Refuse => {
                return Err(refuse_stop(
                    "daemon restart",
                    ErrorCode::WorkerAtCapacity,
                    "refusing to restart: builds are in flight (pass --drain to wait or --force to interrupt)",
                    &workload,
                    &[
                        "rch daemon restart --drain [--drain-timeout N]",
                        "rch daemon restart --force",
                    ],
                    ctx,
                ));
            }
        }
        if interrupting && !opts.yes && !ctx.is_json() {
            println!(
                "{} {} will be interrupted.",
                StatusIndicator::Warning.display(style),
                style.highlight(&workload.describe())
            );
            let confirmed = Confirm::new()
                .with_prompt("Restart the daemon anyway?")
                .default(false)
                .interact()?;
            if !confirmed {
                println!("{} Aborted.", StatusIndicator::Info.display(style));
                return Ok(());
            }
        }
    }

    if socket_path.exists() && !interrupting && !admission_proven {
        require_restart_admission().await?;
    }

    if !ctx.is_json() {
        println!(
            "{} Restarting RCH daemon...\n",
            StatusIndicator::Info.display(style)
        );
    }

    // When rchd is managed by a systemd unit, the manual shutdown+spawn path
    // does NOT reliably cycle it: a `nohup rchd` spawned outside the unit
    // defers to systemd and exits, while systemd's `Restart=always` respawns
    // the unit's own process — keeping the OLD (possibly already-deleted)
    // binary running. Only `systemctl restart` re-execs the unit from the
    // freshly installed binary. Route through it (reusing the same detection
    // `rch update`'s restart step relies on) and only fall back to the legacy
    // path if the unit restart fails.
    if let Some(scope) = detect_rchd_systemd_scope() {
        match restart_via_systemd(scope).await {
            Ok(()) => {
                let socket_path_str = configured_socket_path()?;
                if ctx.is_json() {
                    let _ = ctx.json(&ApiResponse::ok(
                        "daemon restart",
                        DaemonActionResponse {
                            action: "restart".to_string(),
                            success: true,
                            socket_path: socket_path_str,
                            message: Some(format!(
                                "Daemon restarted via systemctl{} restart rchd",
                                match scope {
                                    SystemdUnitScope::User => " --user",
                                    SystemdUnitScope::System => "",
                                }
                            )),
                        },
                    ));
                } else {
                    println!(
                        "{}",
                        StatusIndicator::Success
                            .with_label(style, "Daemon restarted via its systemd unit.")
                    );
                    println!(
                        "  {} {} {}",
                        style.key("Unit"),
                        style.muted(":"),
                        style.value(match scope {
                            SystemdUnitScope::User => "systemctl --user rchd.service",
                            SystemdUnitScope::System => "systemctl rchd.service",
                        })
                    );
                }
                return Ok(());
            }
            Err(reason) => {
                // Log to stderr so deploy issues are diagnosable, then fall
                // through to the manual path (e.g. for a defined-but-broken
                // unit on a host that can still run a bare daemon).
                eprintln!(
                    "rch: systemd unit restart did not complete ({reason}); \
                     falling back to manual stop+start"
                );
            }
        }
    }

    // Manual path: user-launched daemon (no unit) and macOS launchd hosts.
    // Pass true for skip_confirm since we already prompted above.
    daemon_stop(
        StopOptions {
            yes: true,
            drain: false,
            drain_timeout_secs: 0,
            force: interrupting,
        },
        ctx,
    )
    .await?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    daemon_start(ctx).await?;
    Ok(())
}

/// Reload daemon configuration without restart.
pub async fn daemon_reload(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    let socket_path_str = configured_socket_path()?;

    // Check if daemon is running
    if !Path::new(&socket_path_str).exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "daemon reload",
                ApiError::new(ErrorCode::InternalDaemonNotRunning, "Daemon is not running"),
            ));
        } else {
            println!(
                "{} Daemon is not running. Start it with {}",
                StatusIndicator::Error.display(style),
                style.highlight("rch daemon start")
            );
        }
        return Ok(());
    }

    if !ctx.is_json() {
        println!(
            "{} Reloading daemon configuration...",
            StatusIndicator::Info.display(style)
        );
    }

    // Send reload command to daemon
    match send_daemon_command("POST /reload\n").await {
        Ok(response) => {
            let json = extract_json_body(&response)
                .unwrap_or(response.as_str())
                .trim();
            match serde_json::from_str::<ReloadApiResponse>(json) {
                Ok(reload) => {
                    if !reload.success {
                        let error_msg = reload
                            .error
                            .unwrap_or_else(|| "unknown reload error".to_string());
                        if ctx.is_json() {
                            let _ = ctx.json(&ApiResponse::<()>::err(
                                "daemon reload",
                                ApiError::internal(format!("Reload failed: {}", error_msg)),
                            ));
                        } else {
                            println!(
                                "{} Reload failed: {}",
                                StatusIndicator::Error.display(style),
                                error_msg
                            );
                        }
                        return Ok(());
                    }

                    let has_changes = reload.added > 0 || reload.updated > 0 || reload.removed > 0;

                    if ctx.is_json() {
                        let _ = ctx.json(&ApiResponse::ok(
                            "daemon reload",
                            DaemonReloadResponse {
                                success: true,
                                added: reload.added,
                                updated: reload.updated,
                                removed: reload.removed,
                                warnings: reload.warnings.clone(),
                                message: if has_changes {
                                    Some(format!(
                                        "Configuration reloaded: {} added, {} updated, {} removed",
                                        reload.added, reload.updated, reload.removed
                                    ))
                                } else {
                                    Some("No configuration changes detected".to_string())
                                },
                            },
                        ));
                    } else {
                        if has_changes {
                            println!(
                                "{} Configuration reloaded",
                                StatusIndicator::Success.display(style)
                            );
                            println!(
                                "  {} workers added, {} updated, {} removed",
                                reload.added, reload.updated, reload.removed
                            );
                        } else {
                            println!(
                                "{} No configuration changes detected",
                                StatusIndicator::Info.display(style)
                            );
                        }

                        for warning in &reload.warnings {
                            println!("{} {}", StatusIndicator::Warning.display(style), warning);
                        }
                    }
                }
                Err(e) => {
                    if ctx.is_json() {
                        let _ = ctx.json(&ApiResponse::<()>::err(
                            "daemon reload",
                            ApiError::internal(format!("Failed to parse reload response: {}", e)),
                        ));
                    } else {
                        println!(
                            "{} Failed to parse reload response: {}",
                            StatusIndicator::Error.display(style),
                            e
                        );
                    }
                }
            }
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "daemon reload",
                    ApiError::internal(format!("Failed to communicate with daemon: {}", e)),
                ));
            } else {
                println!(
                    "{} Failed to communicate with daemon: {}",
                    StatusIndicator::Error.display(style),
                    e
                );
            }
        }
    }

    Ok(())
}

/// Show daemon logs.
pub fn daemon_logs(lines: usize, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    // Try common log file locations first
    let log_paths = vec![
        PathBuf::from("/tmp/rchd.log"),
        config_dir()
            .map(|d| d.join("daemon.log"))
            .unwrap_or_default(),
        config_dir()
            .map(|d| d.join("logs").join("daemon.log"))
            .unwrap_or_default(),
        dirs::cache_dir()
            .map(|d| d.join("rch").join("daemon.log"))
            .unwrap_or_default(),
    ];

    for path in &log_paths {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let all_lines: Vec<&str> = content.lines().collect();
            let start = all_lines.len().saturating_sub(lines);
            let log_lines: Vec<String> = all_lines[start..].iter().map(|s| s.to_string()).collect();

            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "daemon logs",
                    DaemonLogsResponse {
                        log_file: Some(path.display().to_string()),
                        lines: log_lines,
                        found: true,
                    },
                ));
            } else {
                println!(
                    "{} {} {}\n",
                    style.key("Log file"),
                    style.muted(":"),
                    style.value(&path.display().to_string())
                );

                for line in &all_lines[start..] {
                    println!("{}", line);
                }
            }

            return Ok(());
        }
    }

    // No log files found - try journald (for systemd service)
    if let Ok(output) = std::process::Command::new("journalctl")
        .args([
            "--user",
            "-u",
            "rchd",
            "-n",
            &lines.to_string(),
            "--no-pager",
        ])
        .output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let log_lines: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();

        // Check if we got actual log output (not just "No entries")
        if !log_lines.is_empty()
            && !stdout.contains("-- No entries --")
            && !stdout.contains("No journal files were found")
        {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "daemon logs",
                    DaemonLogsResponse {
                        log_file: Some("journalctl --user -u rchd".to_string()),
                        lines: log_lines,
                        found: true,
                    },
                ));
            } else {
                println!(
                    "{} {} {}\n",
                    style.key("Log source"),
                    style.muted(":"),
                    style.value("journalctl --user -u rchd")
                );

                for line in &log_lines {
                    println!("{}", line);
                }
            }

            return Ok(());
        }
    }

    // No logs found anywhere
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "daemon logs",
            DaemonLogsResponse {
                log_file: None,
                lines: vec![],
                found: false,
            },
        ));
    } else {
        println!(
            "{} No log file found.",
            StatusIndicator::Warning.display(style)
        );
        println!("\n{}", style.key("Checked locations:"));
        for path in &log_paths {
            if !path.as_os_str().is_empty() {
                println!("  {}", style.muted(&format!("• {}", path.display())));
            }
        }
        println!("  {}", style.muted("• journalctl --user -u rchd"));
        println!();
        println!(
            "{} If running via systemd, use: {}",
            StatusIndicator::Info.display(style),
            style.highlight("journalctl --user -u rchd -f")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    #[test]
    fn daemon_start_args_pin_configured_socket_path() {
        let _guard = test_guard!();
        let socket_path = Path::new("/tmp/rch-custom.sock");
        let args = daemon_start_args(socket_path);

        assert_eq!(args[0], std::ffi::OsStr::new("--socket"));
        assert_eq!(args[1], socket_path.as_os_str());
    }

    #[test]
    fn reload_api_response_parses_http_10_with_headers() {
        let _guard = test_guard!();
        let response = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"added\":1,\"updated\":2,\"removed\":3,\"warnings\":[\"warn\"]}\n";
        let json = extract_json_body(response).unwrap().trim();
        let parsed: ReloadApiResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.added, 1);
        assert_eq!(parsed.updated, 2);
        assert_eq!(parsed.removed, 3);
        assert_eq!(parsed.warnings, vec!["warn".to_string()]);
    }

    #[test]
    fn reload_api_response_uses_default_success_for_legacy_payloads() {
        let _guard = test_guard!();
        let response = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"added\":0,\"updated\":0,\"removed\":0,\"warnings\":[]}\n";
        let json = extract_json_body(response).unwrap().trim();
        let parsed: ReloadApiResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.added, 0);
        assert_eq!(parsed.updated, 0);
        assert_eq!(parsed.removed, 0);
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn reload_api_response_parses_failure_payload() {
        let _guard = test_guard!();
        let response = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"error\":\"bad config\"}\n";
        let json = extract_json_body(response).unwrap().trim();
        let parsed: ReloadApiResponse = serde_json::from_str(json).unwrap();
        assert!(!parsed.success);
        assert_eq!(parsed.error.as_deref(), Some("bad config"));
    }

    #[test]
    fn systemd_user_scope_passes_user_flag() {
        let _guard = test_guard!();
        assert_eq!(
            SystemdUnitScope::User.systemctl_scope_args(),
            &["--user"],
            "user-scope restart must target the per-user systemd manager"
        );
    }

    #[test]
    fn systemd_system_scope_passes_no_scope_flag() {
        let _guard = test_guard!();
        assert!(
            SystemdUnitScope::System.systemctl_scope_args().is_empty(),
            "system-scope restart must use the default (system) systemd manager"
        );
    }

    fn busy_workload() -> DaemonWorkload {
        DaemonWorkload {
            active_build_ids: vec![41, 42],
            queued_build_ids: vec![43],
            client_lease_ids: Vec::new(),
            client_lease_scan_error: None,
        }
    }

    /// Issue #54: `-y` alone must never interrupt in-flight builds.
    #[test]
    fn stop_with_yes_alone_refuses_while_builds_are_in_flight() {
        let _guard = test_guard!();
        let opts = StopOptions {
            yes: true,
            ..Default::default()
        };
        assert_eq!(
            decide_stop_action(&busy_workload(), &opts),
            StopDecision::Refuse
        );
        assert_eq!(
            decide_stop_action(&DaemonWorkload::default(), &opts),
            StopDecision::Proceed
        );
    }

    #[test]
    fn stop_drain_takes_precedence_over_force_and_force_alone_interrupts() {
        let _guard = test_guard!();
        let both = StopOptions {
            drain: true,
            force: true,
            ..Default::default()
        };
        assert_eq!(
            decide_stop_action(&busy_workload(), &both),
            StopDecision::Drain
        );
        let force = StopOptions {
            force: true,
            ..Default::default()
        };
        assert_eq!(
            decide_stop_action(&busy_workload(), &force),
            StopDecision::Interrupt
        );
    }

    /// A failed lease scan makes idleness unprovable, so it must count as busy.
    #[test]
    fn workload_with_lease_scan_error_is_not_idle() {
        let _guard = test_guard!();
        let workload = DaemonWorkload {
            client_lease_scan_error: Some("permission denied".to_string()),
            ..Default::default()
        };
        assert!(!workload.is_idle());
        assert!(workload.describe().contains("lease scan failed"));
        let leases = DaemonWorkload {
            client_lease_ids: vec!["lease-1".to_string()],
            ..Default::default()
        };
        assert!(!leases.is_idle());
        assert_eq!(DaemonWorkload::default().describe(), "idle");
    }

    #[test]
    fn shutdown_blocked_response_parses_blocking_ids() {
        let _guard = test_guard!();
        let response = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"shutdown_blocked\",\"admission_closed\":true,\"active_build_ids\":[7],\"queued_build_ids\":[8,9]}\n";
        let json = extract_json_body(response).unwrap().trim();
        let parsed: ShutdownApiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.status, "shutdown_blocked");
        assert_eq!(parsed.active_build_ids, vec![7]);
        assert_eq!(parsed.queued_build_ids, vec![8, 9]);

        let ok = "HTTP/1.0 200 OK\r\n\r\n{\"status\":\"shutting_down\"}\n";
        let parsed: ShutdownApiResponse =
            serde_json::from_str(extract_json_body(ok).unwrap().trim()).unwrap();
        assert_eq!(parsed.status, "shutting_down");
        assert!(parsed.active_build_ids.is_empty());
    }

    #[test]
    fn admission_response_maps_to_workload() {
        let _guard = test_guard!();
        let response = "HTTP/1.0 200 OK\r\n\r\n{\"admission_closed\":true,\"restart_permitted\":false,\"active_build_ids\":[1],\"queued_build_ids\":[],\"client_lease_ids\":[\"l1\"]}\n";
        let admission = parse_admission_response(response).unwrap();
        assert!(!admission.restart_permitted);
        let workload = DaemonWorkload::from_admission(admission);
        assert_eq!(workload.active_build_ids, vec![1]);
        assert_eq!(workload.client_lease_ids, vec!["l1".to_string()]);
        assert!(!workload.is_idle());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_hosts_have_no_systemd_unit() {
        let _guard = test_guard!();
        // macOS (launchd) and other non-Linux hosts must never route restart
        // through systemctl, preserving the manual stop+start path.
        assert_eq!(detect_rchd_systemd_scope(), None);
    }
}
