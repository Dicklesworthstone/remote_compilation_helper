//! Daemon lifecycle management commands.
//!
//! This module contains commands for starting, stopping, restarting, and managing
//! the RCH daemon process.

use crate::status_types::extract_json_body;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::{Context, Result};
use rch_common::process_identity::{
    OwnerPresence, ProcessIdentity, ProcessObservation, observe_process, owner_presence,
};
use rch_common::{ApiError, ApiResponse, ErrorCode, RestartAdmissionResponse};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

use super::helpers::configured_socket_path;
use super::types::{
    DaemonActionResponse, DaemonLogsResponse, DaemonReloadResponse, DaemonStatusResponse,
};
use super::{config_dir, send_daemon_command};

#[cfg(target_os = "linux")]
mod force_stop;

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

fn reload_success_default() -> bool {
    true
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
/// Mirrors the daemon's unit detection so a confirmed, fenced shutdown is
/// followed by a service start rather than an unmanaged competing process.
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
async fn detect_rchd_systemd_scope() -> Option<SystemdUnitScope> {
    // Prefer the user scope: that is what `rch daemon start`/the hook/`rch
    // update` interact with on dev hosts (trj/css/csd/ts1). System-scope units
    // (vmi root daemons) are checked second.
    async fn probe(scope_args: &[&str]) -> bool {
        tokio::time::timeout(
            Duration::from_secs(2),
            Command::new("systemctl")
                .args(scope_args)
                .args(["is-enabled", "rchd"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await
        .is_ok_and(|result| result.is_ok_and(|status| status.success()))
    }

    if probe(&["--user"]).await {
        Some(SystemdUnitScope::User)
    } else if probe(&[]).await {
        Some(SystemdUnitScope::System)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
async fn detect_rchd_systemd_scope() -> Option<SystemdUnitScope> {
    None
}

#[cfg(target_os = "linux")]
struct SystemdServiceState {
    pid: u32,
    restart: String,
    active: String,
    sub: String,
}

#[cfg(target_os = "linux")]
fn systemd_manager_present(scope: SystemdUnitScope) -> Result<bool> {
    match scope {
        SystemdUnitScope::System => Ok(Path::new("/run/systemd/system").try_exists()?
            || Path::new("/run/systemd/private").try_exists()?),
        SystemdUnitScope::User => {
            if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some_and(|value| !value.is_empty()) {
                return Ok(true);
            }
            let runtime = std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(format!("/run/user/{}", rustix::process::geteuid().as_raw()))
                });
            Ok(runtime.join("systemd/private").try_exists()?)
        }
    }
}

#[cfg(target_os = "linux")]
async fn systemd_service_state(scope: SystemdUnitScope) -> Result<Option<SystemdServiceState>> {
    let output = tokio::time::timeout(
        Duration::from_secs(2),
        Command::new("systemctl")
            .args(scope.systemctl_scope_args())
            .args([
                "show",
                "rchd",
                "--property=MainPID",
                "--property=Restart",
                "--property=ActiveState",
                "--property=SubState",
                "--property=LoadState",
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("systemd service state query timed out; no service stop was verified")?;
    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            if String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line == "LoadState=not-found")
                || !systemd_manager_present(scope)?
            {
                return Ok(None);
            }
            anyhow::bail!(
                "systemd service state query failed ({}); manager ownership is unknown; no admission or shutdown change was attempted",
                output.status
            );
        }
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound && !systemd_manager_present(scope)? =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let text = std::str::from_utf8(&output.stdout).context("non-UTF-8 systemd service state")?;
    let properties: std::collections::HashMap<_, _> = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    if properties.get("LoadState") == Some(&"not-found") {
        return Ok(None);
    }
    let pid = properties
        .get("MainPID")
        .and_then(|pid| pid.parse().ok())
        .context("systemd did not report its daemon PID; stop ownership is unknown")?;
    Ok(Some(SystemdServiceState {
        pid,
        restart: properties.get("Restart").unwrap_or(&"").to_string(),
        active: properties.get("ActiveState").unwrap_or(&"").to_string(),
        sub: properties.get("SubState").unwrap_or(&"").to_string(),
    }))
}

/// Only the unit whose live MainPID is the captured daemon peer may be used
/// to start its successor. An enabled unit serving another socket is unrelated.
#[cfg(target_os = "linux")]
async fn bound_systemd_scope(process: &DaemonProcess) -> Result<Option<SystemdUnitScope>> {
    bound_systemd_scope_with(process, systemd_service_state).await
}

#[cfg(target_os = "linux")]
async fn bound_systemd_scope_with<F, Fut>(
    process: &DaemonProcess,
    mut inspect: F,
) -> Result<Option<SystemdUnitScope>>
where
    F: FnMut(SystemdUnitScope) -> Fut,
    Fut: std::future::Future<Output = Result<Option<SystemdServiceState>>>,
{
    for scope in [SystemdUnitScope::User, SystemdUnitScope::System] {
        let state = inspect(scope).await?;
        process.require_live()?;
        if state.is_some_and(|state| state.pid == process.pid) {
            return Ok(Some(scope));
        }
    }
    Ok(None)
}

#[cfg(not(target_os = "linux"))]
async fn bound_systemd_scope(_process: &DaemonProcess) -> Result<Option<SystemdUnitScope>> {
    Ok(None)
}

/// A delayed `systemctl stop` could kill a replacement which already admitted
/// work. A persistent supervisor must instead be handled explicitly before
/// this CLI mutates admission. Clean on-failure units can use normal shutdown.
#[cfg(target_os = "linux")]
async fn inspect_stop_supervisor(process: &DaemonProcess) -> Result<Option<SystemdUnitScope>> {
    for scope in [SystemdUnitScope::User, SystemdUnitScope::System] {
        if let Some(state) = systemd_service_state(scope).await?
            && state.pid == process.pid
        {
            anyhow::ensure!(
                matches!(
                    state.restart.as_str(),
                    "no" | "on-failure" | "on-abnormal" | "on-abort" | "on-watchdog"
                ),
                "rchd is managed by systemd with Restart={}; a persistent stop cannot be confirmed. No shutdown or admission change was attempted; stop the service through its supervisor",
                if state.restart.is_empty() {
                    "unknown"
                } else {
                    &state.restart
                }
            );
            return Ok(Some(scope));
        }
    }
    Ok(None)
}

#[cfg(not(target_os = "linux"))]
async fn inspect_stop_supervisor(_process: &DaemonProcess) -> Result<Option<SystemdUnitScope>> {
    if tokio::time::timeout(Duration::from_secs(5), detect_rchd_launchd_target())
        .await
        .context("launchd service state query timed out; no shutdown attempted")?
        .is_some()
    {
        anyhow::bail!(
            "rchd is managed by launchd; a persistent stop cannot be confirmed. No shutdown or admission change was attempted; stop the service through its supervisor"
        );
    }
    Ok(None)
}

async fn verify_stopped_supervisor(scope: Option<SystemdUnitScope>) -> Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(scope) = scope {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let state = systemd_service_state(scope)
                .await?
                .context("systemd daemon state disappeared; service stop is unconfirmed")?;
            if state.pid == 0 && state.active == "inactive" && state.sub == "dead" {
                return Ok(());
            }
            anyhow::ensure!(
                state.active == "deactivating" && tokio::time::Instant::now() < deadline,
                "original daemon exited, but systemd service stop is unconfirmed (PID {}, state {}/{}, Restart={}); a replacement may be running or pending",
                state.pid,
                state.active,
                state.sub,
                state.restart
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = scope;
    Ok(())
}

/// Start the unit after fenced shutdown. `start` preserves a replacement
/// daemon that the unit may already have spawned and that may have new work.
async fn start_via_systemd(scope: SystemdUnitScope) -> std::result::Result<(), String> {
    let status = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new("systemctl")
            .args(scope.systemctl_scope_args())
            .args(["start", "rchd"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(|_| "systemctl start timed out; daemon startup is unconfirmed".to_string())?
    .map_err(|e| format!("failed to invoke systemctl: {e}"))?;

    if !status.success() {
        return Err(format!("systemctl start rchd exited {status}"));
    }

    Ok(())
}

/// The launchd agent that `rch daemon install`-style setups (and the fleet's
/// Macs) use to keep rchd alive: `~/Library/LaunchAgents/com.rch.daemon.plist`,
/// `KeepAlive = true`.
#[cfg(target_os = "macos")]
const RCHD_LAUNCHD_LABEL: &str = "com.rch.daemon";

/// The loaded launchd service target (`gui/<uid>/com.rch.daemon`) managing
/// rchd on this Mac, if any (bd-5pmwm). Like the systemd case, the manual
/// shutdown + `nohup rchd` spawn fights KeepAlive's own respawn, so Mac
/// rollouts used launchctl directly, without draining, and killed queued
/// builds. Restarting through launchd keeps `--drain` meaningful on Macs.
#[cfg(target_os = "macos")]
async fn detect_rchd_launchd_target() -> Option<String> {
    // Effective UID without unsafe code: the kernel reports our own
    // credentials on our own socket pair.
    let (socket, _peer) = tokio::net::UnixStream::pair().ok()?;
    let uid = socket.peer_cred().ok()?.uid();
    let target = format!("gui/{uid}/{RCHD_LAUNCHD_LABEL}");
    let printed = Command::new("/bin/launchctl")
        .args(["print", &target])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .ok()
        .filter(|output| output.status.success())?;
    // Only a job whose live process listens on the configured socket is the
    // daemon being restarted. Without this check, a CLI pointed at another
    // socket (a second daemon, a test sandbox) kickstarted the user's rchd.
    let pid = launchd_job_pid(&String::from_utf8_lossy(&printed.stdout))?;
    let socket = configured_socket_path().ok()?;
    process_listens_on_unix_socket(pid, std::path::Path::new(&socket))
        .await
        .then_some(target)
}

/// The job's own `pid = N` line (one tab deep) in `launchctl print` output.
#[cfg(target_os = "macos")]
fn launchd_job_pid(printed: &str) -> Option<u32> {
    printed
        .lines()
        .find_map(|line| line.strip_prefix("\tpid = ")?.trim().parse().ok())
}

/// Whether `pid` holds a Unix socket bound at `socket`, per `lsof -Fn`.
#[cfg(target_os = "macos")]
async fn process_listens_on_unix_socket(pid: u32, socket: &std::path::Path) -> bool {
    let Ok(output) = Command::new("/usr/sbin/lsof")
        .args(["-a", "-p", &pid.to_string(), "-U", "-Fn"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
    else {
        return false;
    };
    let wanted = [Some(socket.to_path_buf()), socket.canonicalize().ok()];
    String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        line.strip_prefix('n').is_some_and(|name| {
            wanted
                .iter()
                .flatten()
                .any(|path| path.as_os_str() == std::ffi::OsStr::new(name))
        })
    })
}

#[cfg(not(target_os = "macos"))]
async fn detect_rchd_launchd_target() -> Option<String> {
    None
}

/// Start the agent without `-k`: a respawned daemon may already have new work.
async fn start_via_launchd(target: &str) -> std::result::Result<(), String> {
    let status = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new("/bin/launchctl")
            .args(["kickstart", target])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(|_| "launchctl kickstart timed out; daemon startup is unconfirmed".to_string())?
    .map_err(|e| format!("failed to invoke launchctl: {e}"))?;
    if !status.success() {
        return Err(format!("launchctl kickstart {target} exited {status}"));
    }
    Ok(())
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
    let admission = if running {
        Some(admission_status_at(socket_path).await)
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
                admission: admission.as_ref().map(|result| match result {
                    Ok(value) => serde_json::to_value(value).unwrap_or_default(),
                    Err(error) => {
                        serde_json::json!({"status": "unknown", "error": format!("{error:#}")})
                    }
                }),
            },
        ));
        return Ok(());
    }

    eprintln!("{}", style.format_header("RCH Daemon Status"));
    eprintln!();

    if running {
        eprintln!(
            "  {} {} {}",
            style.key("Status"),
            style.muted(":"),
            StatusIndicator::Success.with_label(style, "Running")
        );
        eprintln!(
            "  {} {} {}",
            style.key("Socket"),
            style.muted(":"),
            style.value(&socket_path_str)
        );

        if let Some(secs) = uptime_seconds {
            let hours = secs / 3600;
            let mins = (secs % 3600) / 60;
            eprintln!(
                "  {} {} ~{}h {}m",
                style.key("Uptime"),
                style.muted(":"),
                hours,
                mins
            );
        }
        match admission {
            Some(Ok(admission)) => {
                for line in crate::status_types::admission_diagnostic_lines(&admission) {
                    eprintln!("  {line}");
                }
            }
            Some(Err(error)) => eprintln!("  Admission: unknown ({error:#})"),
            None => {}
        }
    } else {
        let socket_note = if socket_exists {
            "(stale or unreachable)"
        } else {
            "(not found)"
        };
        eprintln!(
            "  {} {} {}",
            style.key("Status"),
            style.muted(":"),
            StatusIndicator::Error.with_label(style, "Not running")
        );
        eprintln!(
            "  {} {} {} {}",
            style.key("Socket"),
            style.muted(":"),
            style.muted(&socket_path_str),
            style.muted(socket_note)
        );
        eprintln!();
        eprintln!(
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

/// A transport response is not a shutdown acknowledgement. Refuse HTTP errors,
/// partial JSON, unknown states and contradictory success evidence before
/// interpreting socket disappearance as an orderly stop.
fn parse_shutdown_response(response: &str) -> Result<ShutdownApiResponse> {
    let (header, body) = response
        .split_once("\r\n\r\n")
        .or_else(|| response.split_once("\n\n"))
        .context("shutdown response was incomplete")?;
    let mut status = header.lines().next().unwrap_or_default().split_whitespace();
    anyhow::ensure!(
        matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) && status.next() == Some("200"),
        "daemon refused the shutdown request"
    );
    let shutdown: ShutdownApiResponse =
        serde_json::from_str(body).context("shutdown response was malformed")?;
    anyhow::ensure!(
        matches!(
            shutdown.status.as_str(),
            "shutting_down" | "shutdown_blocked"
        ),
        "unrecognized shutdown state: {}",
        shutdown.status
    );
    anyhow::ensure!(
        shutdown.status != "shutting_down"
            || (shutdown.active_build_ids.is_empty() && shutdown.queued_build_ids.is_empty()),
        "shutdown acknowledgement contradicts outstanding builds"
    );
    Ok(shutdown)
}

/// Missing IPC evidence never authorizes a process-name kill or socket removal.
/// Return the error to the CLI so JSON is rendered once and the exit is nonzero.
/// In particular, restart must not proceed to its start step after this error.
fn unconfirmed_stop(socket_path: &Path, cause: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!(
        "daemon stop is unconfirmed at {}: {cause}; no fallback process was killed or socket removed; \
         inspect `rch daemon admission status` before retrying maintenance",
        socket_path.display()
    )
}

pub(crate) fn parse_admission_response(response: &str) -> Result<RestartAdmissionResponse> {
    let (header, body) = response
        .split_once("\r\n\r\n")
        .or_else(|| response.split_once("\n\n"))
        .context("admission response was incomplete")?;
    let mut status = header.lines().next().unwrap_or_default().split_whitespace();
    anyhow::ensure!(
        matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) && status.next() == Some("200"),
        "daemon refused the admission request: {}",
        body.trim()
    );
    serde_json::from_str(body).context("admission response was malformed")
}

/// The client chooses its unguessable operation token BEFORE acquisition. A
/// lost acquisition reply can therefore be cleaned up without ever releasing
/// another caller's operation. Tokens are additionally bound by the daemon to
/// the actual socket peer's PID and process birth identity. Supplying our own
/// birth claim closes the gap when a peer exits and its PID is reused before
/// the server accepts the connection; later requests retain the original fence.
#[derive(Debug, Clone)]
pub(crate) struct MaintenanceFence {
    pub(crate) daemon_incarnation: String,
    pub(crate) token: String,
    owner_identity: ProcessIdentity,
}

impl MaintenanceFence {
    pub(crate) fn new(status: &RestartAdmissionResponse) -> Result<Self> {
        anyhow::ensure!(
            uuid::Uuid::parse_str(&status.daemon_incarnation).is_ok(),
            "daemon did not supply a valid maintenance incarnation; upgrade the daemon"
        );
        let owner_identity = rch_common::process_identity::current_process_identity()
            .filter(ProcessIdentity::is_valid)
            .context("cannot establish this maintenance client's process birth identity; admission was not changed")?;
        Ok(Self {
            daemon_incarnation: status.daemon_incarnation.clone(),
            token: uuid::Uuid::new_v4().to_string(),
            owner_identity,
        })
    }

    pub(crate) fn command(&self, endpoint: &str) -> String {
        format!(
            "POST {endpoint}?daemon_incarnation={}&token={}\n",
            self.daemon_incarnation, self.token
        )
    }

    pub(crate) fn acquire_command(&self, purpose: &str) -> String {
        format!(
            "POST /restart-admission?daemon_incarnation={}&token={}&purpose={purpose}&owner_identity={}\n",
            self.daemon_incarnation,
            self.token,
            self.owner_identity
                .to_record()
                .expect("maintenance fence retains a validated identity")
        )
    }

    pub(crate) fn require_owned(&self, admission: &RestartAdmissionResponse) -> Result<()> {
        anyhow::ensure!(
            admission.success
                && admission.daemon_incarnation == self.daemon_incarnation
                && admission.maintenance_closed
                && admission.admission_closed
                && !admission.shutdown_committed
                && !admission.ownership_failed
                && admission.maintenance_owner.as_ref().is_some_and(|owner| {
                    owner.token == self.token
                        && owner.pid == std::process::id()
                        && owner.process_identity == self.owner_identity
                }),
            "maintenance ownership is unconfirmed or changed: {}",
            serde_json::to_string(admission).unwrap_or_default()
        );
        Ok(())
    }

    pub(crate) fn require_shutdown(
        &self,
        admission: &RestartAdmissionResponse,
        force: bool,
    ) -> Result<()> {
        anyhow::ensure!(
            admission.success
                && admission.status == "shutting_down"
                && admission.daemon_incarnation == self.daemon_incarnation
                && admission.admission_closed
                && admission.shutdown_committed
                && (force
                    || (!admission.ownership_failed
                        && admission.active_build_ids.is_empty()
                        && admission.queued_build_ids.is_empty()
                        && admission.client_lease_ids.is_empty()
                        && admission.client_lease_scan_error.is_none()))
                && admission.maintenance_owner.as_ref().is_some_and(|owner| {
                    owner.token == self.token
                        && owner.pid == std::process::id()
                        && owner.process_identity == self.owner_identity
                }),
            "daemon did not acknowledge an owned shutdown commitment: {}",
            serde_json::to_string(admission).unwrap_or_default()
        );
        Ok(())
    }

    pub(crate) fn verify_open(&self, admission: &RestartAdmissionResponse) -> Result<&'static str> {
        anyhow::ensure!(
            admission.success
                && uuid::Uuid::parse_str(&admission.daemon_incarnation).is_ok()
                && !admission.admission_closed
                && !admission.maintenance_closed
                && !admission.shutdown_committed
                && !admission.ownership_failed
                && admission.maintenance_owner.is_none(),
            "admission reopening was not confirmed; observed state {}",
            serde_json::to_string(admission).unwrap_or_default()
        );
        Ok(if admission.daemon_incarnation == self.daemon_incarnation {
            "admission reopened and verified"
        } else {
            "replacement daemon observed with open admission; prior lease retired"
        })
    }
}

/// Install both handlers before any admission mutation. SIGKILL, task abort,
/// runtime loss and machine crashes are covered by the daemon's bounded lease.
pub(crate) struct MaintenanceSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

/// The kernel peer and its birth marker are captured while the daemon is
/// answering the original admission query. Socket disappearance alone cannot
/// establish process exit, and a later numeric PID may name a replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaemonProcess {
    pub(crate) pid: u32,
    pub(crate) identity: ProcessIdentity,
}

impl DaemonProcess {
    #[cfg(unix)]
    pub(crate) fn from_peer(stream: &tokio::net::UnixStream) -> Result<Self> {
        let credentials = stream.peer_cred().context("cannot inspect daemon peer")?;
        anyhow::ensure!(
            credentials.uid() == rustix::process::geteuid().as_raw(),
            "daemon socket belongs to another user"
        );
        let pid = credentials
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 1)
            .context("daemon peer PID is unavailable")?;
        let ProcessObservation::Present(identity) = observe_process(pid) else {
            anyhow::bail!("daemon process birth identity is unavailable; maintenance refused");
        };
        Ok(Self { pid, identity })
    }

    pub(crate) fn presence(&self) -> OwnerPresence {
        owner_presence(self.pid, Some(&self.identity))
    }

    pub(crate) fn require_live(&self) -> Result<()> {
        anyhow::ensure!(
            self.presence() == OwnerPresence::Live,
            "original daemon process identity changed or could not be confirmed"
        );
        Ok(())
    }
}

impl MaintenanceSignals {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .context("cannot install maintenance interrupt handler")?,
            #[cfg(unix)]
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("cannot install maintenance termination handler")?,
        })
    }

    pub(crate) async fn cancelled(&mut self) {
        #[cfg(unix)]
        tokio::select! {
            _ = self.interrupt.recv() => {},
            _ = self.terminate.recv() => {},
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    }

    /// Give the signal driver a turn before entering a synchronous mutation.
    /// Publication then completes as one safe boundary; a signal received
    /// during it is observed by the following bounded recovery phase.
    pub(crate) async fn cancellation_pending(&mut self) -> bool {
        tokio::select! {
            biased;
            _ = self.cancelled() => true,
            _ = tokio::time::sleep(Duration::ZERO) => false,
        }
    }
}

const MAINTENANCE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(unix)]
async fn maintenance_request_with_peer(
    path: &Path,
    command: &str,
) -> Result<(String, DaemonProcess)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(MAINTENANCE_REQUEST_TIMEOUT, async {
        let mut stream = tokio::net::UnixStream::connect(path).await?;
        let process = DaemonProcess::from_peer(&stream)?;
        stream.write_all(command.as_bytes()).await?;
        stream.shutdown().await?;
        let mut response = String::new();
        stream
            .take(1024 * 1024 + 1)
            .read_to_string(&mut response)
            .await?;
        anyhow::ensure!(
            response.len() <= 1024 * 1024,
            "oversized maintenance response"
        );
        process.require_live()?;
        Ok((response, process))
    })
    .await
    .context("maintenance identity request timed out")?
}

async fn maintenance_request(path: &Path, command: &str) -> Result<String> {
    #[cfg(unix)]
    {
        tokio::time::timeout(
            MAINTENANCE_REQUEST_TIMEOUT,
            super::send_daemon_command_to_socket(path, command),
        )
        .await
        .context("maintenance request timed out")?
    }
    #[cfg(not(unix))]
    {
        let _ = (path, command);
        anyhow::bail!("daemon maintenance requires Unix sockets")
    }
}

async fn admission_status_at(path: &Path) -> Result<RestartAdmissionResponse> {
    let response = maintenance_request(path, "GET /restart-admission\n").await?;
    parse_admission_response(&response)
}

struct MaintenanceLease {
    path: PathBuf,
    fence: MaintenanceFence,
    process: DaemonProcess,
    cleanup_on_drop: bool,
}

impl MaintenanceLease {
    async fn prepare(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        let (status, process) = {
            let (response, process) =
                maintenance_request_with_peer(path, "GET /restart-admission\n").await?;
            (parse_admission_response(&response)?, process)
        };
        #[cfg(not(unix))]
        let (status, process): (RestartAdmissionResponse, DaemonProcess) = {
            let _ = path;
            anyhow::bail!("daemon maintenance requires Unix sockets");
        };
        anyhow::ensure!(
            status.success
                && !status.admission_closed
                && !status.maintenance_closed
                && !status.ownership_failed
                && !status.shutdown_committed
                && status.maintenance_owner.is_none(),
            "admission is already closed; another maintenance operation or ownership error must recover first: {}. Run `rch daemon admission status`",
            serde_json::to_string(&status).unwrap_or_default()
        );
        Ok(Self {
            path: path.to_owned(),
            fence: MaintenanceFence::new(&status)?,
            process,
            cleanup_on_drop: false,
        })
    }

    async fn acquire(&mut self, purpose: &str) -> Result<DaemonWorkload> {
        // Set this before sending: cancellation may arrive after the daemon
        // acted but before the reply becomes available to this task.
        self.cleanup_on_drop = true;
        let response =
            maintenance_request(&self.path, &self.fence.acquire_command(purpose)).await?;
        let admission = parse_admission_response(&response)?;
        self.fence.require_owned(&admission)?;
        Ok(DaemonWorkload::from_admission(admission))
    }

    async fn renew(&self) -> Result<DaemonWorkload> {
        let response =
            maintenance_request(&self.path, &self.fence.command("/restart-admission/renew"))
                .await?;
        let admission = parse_admission_response(&response)?;
        self.fence.require_owned(&admission)?;
        Ok(DaemonWorkload::from_admission(admission))
    }

    async fn release_verified(&self) -> Result<&'static str> {
        let release = maintenance_request(
            &self.path,
            &self.fence.command("/restart-admission/release"),
        )
        .await
        .and_then(|response| parse_admission_response(&response));
        // Read back even after a lost or erroneous release acknowledgement:
        // only a fresh state observation can prove admission is available.
        let observed = admission_status_at(&self.path).await;
        match observed {
            Ok(status) => self.fence.verify_open(&status).with_context(|| format!(
                "release acknowledgement: {:?}; run `rch daemon admission status` and `rch daemon admission recover` after the owner expires",
                release.as_ref().map(|value| &value.status).map_err(|error| error.to_string())
            )),
            Err(error) => anyhow::bail!(
                "admission reopening was not confirmed: {error:#}; release acknowledgement: {:?}; this operation's uncommitted lease expires without renewal; inspect `rch daemon admission status` when communication is restored",
                release.as_ref().map(|value| &value.status).map_err(|error| error.to_string())
            ),
        }
    }

    async fn cleanup(&mut self) -> Result<&'static str> {
        if !self.cleanup_on_drop {
            return Ok("no admission mutation remains pending");
        }
        let result = self.release_verified().await;
        self.cleanup_on_drop = false;
        result
    }
}

impl Drop for MaintenanceLease {
    fn drop(&mut self) {
        if !self.cleanup_on_drop {
            return;
        }
        // Normal cancellation/errors await cleanup explicitly. This fallback
        // covers a cancelled task while its runtime is still alive; lease
        // expiry covers runtime/process loss and a dropped cleanup future.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let lease = Self {
                path: self.path.clone(),
                fence: self.fence.clone(),
                process: self.process.clone(),
                cleanup_on_drop: false,
            };
            runtime.spawn(async move {
                if let Err(error) = lease.release_verified().await {
                    tracing::warn!("aborted maintenance cleanup unconfirmed: {error:#}");
                }
            });
        }
    }
}

/// Renew this operation's lease while waiting. A timeout leaves its fence
/// owned until the caller either commits a forced shutdown or awaits cleanup.
async fn drain_until_idle(
    lease: &MaintenanceLease,
    timeout: Duration,
    ctx: &OutputContext,
) -> Result<DrainOutcome> {
    let started = std::time::Instant::now();
    let mut last_report: Option<String> = None;
    loop {
        let workload = lease.renew().await?;
        if workload.is_idle() {
            return Ok(DrainOutcome::Drained);
        }
        if started.elapsed() >= timeout {
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
                .with_context(
                    "client_lease_ids",
                    serde_json::to_string(&workload.client_lease_ids).unwrap_or_default(),
                )
                .with_context(
                    "client_lease_scan_error",
                    serde_json::to_string(&workload.client_lease_scan_error).unwrap_or_default(),
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

/// Validate the reported status before committing a force stop. The PID from
/// JSON is never authority to signal: it must match the original kernel peer,
/// its birth identity and the exact configured socket path.
#[cfg(target_os = "linux")]
async fn verify_force_target(lease: &MaintenanceLease) -> Result<()> {
    let (response, process) = maintenance_request_with_peer(&lease.path, "GET /status\n").await?;
    anyhow::ensure!(
        process == lease.process,
        "daemon peer changed before force shutdown"
    );
    let mut http_status = response
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    anyhow::ensure!(
        matches!(http_status.next(), Some("HTTP/1.0" | "HTTP/1.1"))
            && http_status.next() == Some("200"),
        "daemon status was not acknowledged"
    );
    let json = extract_json_body(&response).context("daemon status is incomplete")?;
    let status: crate::status_types::DaemonFullStatusResponse =
        serde_json::from_str(json).context("daemon status is malformed")?;
    anyhow::ensure!(
        status.daemon.pid == process.pid && Path::new(&status.daemon.socket_path) == lease.path,
        "daemon status does not match the original kernel peer and configured socket"
    );
    lease.fence.require_owned(
        status
            .admission
            .as_ref()
            .context("daemon status lacks the original maintenance fence")?,
    )?;
    Ok(())
}

/// Linux binds a stable pidfd before rechecking the actual socket peer. Other
/// platforms rely on the fenced shutdown request and daemon exit deadline;
/// delayed numeric signals would remain vulnerable to PID reuse.
#[cfg(target_os = "linux")]
async fn terminate_daemon_process(lease: &MaintenanceLease) -> Result<()> {
    anyhow::ensure!(
        lease.process.pid > 1 && lease.process.pid != std::process::id(),
        "refusing unsafe daemon PID {}",
        lease.process.pid
    );
    force_stop::stop(&lease.path, &lease.process, &lease.fence.daemon_incarnation).await
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
async fn stop_owned(
    lease: &mut MaintenanceLease,
    opts: StopOptions,
    restarting: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();
    let command_name = if restarting {
        "daemon restart"
    } else {
        "daemon stop"
    };
    let workload = lease
        .acquire(if restarting { "restart" } else { "stop" })
        .await?;

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
        match drain_until_idle(lease, Duration::from_secs(opts.drain_timeout_secs), ctx).await? {
            DrainOutcome::Drained => decision = StopDecision::Proceed,
            DrainOutcome::TimedOut(remaining) => {
                if opts.force {
                    decision = StopDecision::Interrupt;
                } else {
                    let cleanup = lease.cleanup().await?;
                    return Err(refuse_stop(
                        command_name,
                        ErrorCode::CancelTimeoutExceeded,
                        &format!(
                            "drain timed out after {}s; {cleanup}",
                            opts.drain_timeout_secs,
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
            lease.cleanup().await?;
            return Err(refuse_stop(
                command_name,
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
            if !ctx.is_json() {
                println!("Stopping RCH daemon (interrupting in-flight builds)...");
            }
            #[cfg(target_os = "linux")]
            verify_force_target(lease).await?;
            // Once committed, admission cannot reopen while a paused force
            // client resumes its pidfd signal. A renewal alone is not a fence.
            let request = format!(
                "{}&force=true\n",
                lease.fence.command("/shutdown").trim_end()
            );
            let response = maintenance_request(&lease.path, &request).await?;
            let admission = parse_admission_response(&response)?;
            lease.fence.require_shutdown(&admission, true)?;
            #[cfg(target_os = "linux")]
            if lease.process.presence() == OwnerPresence::Live
                && let Err(error) = terminate_daemon_process(lease).await
            {
                // A committed daemon may close its listener before the
                // helper can revalidate /status. Never relax the helper's
                // identity checks. The daemon's shutdown deadline still
                // permits bounded, signal-free proof of original process exit.
                tracing::debug!("force helper did not confirm a signal: {error:#}");
            }
        }
        StopDecision::Proceed => {
            let response =
                maintenance_request(&lease.path, &lease.fence.command("/shutdown")).await?;
            let shutdown = parse_shutdown_response(&response)?;
            if shutdown.status == "shutdown_blocked" {
                anyhow::bail!(
                    "daemon refused shutdown: active builds {:?}, queued builds {:?}",
                    shutdown.active_build_ids,
                    shutdown.queued_build_ids
                );
            }
            lease
                .fence
                .require_shutdown(&parse_admission_response(&response)?, false)?;
        }
        StopDecision::Drain => unreachable!("drain resolves to Proceed or Interrupt above"),
    }
    let retirement_timeout = if decision == StopDecision::Interrupt {
        Duration::from_secs(31)
    } else {
        Duration::from_secs(5)
    };
    wait_for_maintenance_retirement(lease, restarting, retirement_timeout).await?;
    lease.cleanup_on_drop = false;
    Ok(())
}

async fn wait_for_maintenance_retirement(
    lease: &MaintenanceLease,
    restarting: bool,
    budget: Duration,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let presence = lease.process.presence();
        let endpoint_present = lease.path.try_exists()?;
        if presence == OwnerPresence::Absent && !endpoint_present {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!(
                "daemon acknowledged shutdown but process exit and endpoint retirement are unconfirmed: original PID {} is {:?}; endpoint present={endpoint_present}",
                lease.process.pid,
                presence
            );
        }
        if endpoint_present
            && let Ok(Ok(status)) =
                tokio::time::timeout(remaining, admission_status_at(&lease.path)).await
            && status.daemon_incarnation != lease.fence.daemon_incarnation
        {
            anyhow::ensure!(
                lease.process.presence() == OwnerPresence::Absent,
                "a replacement daemon appeared while original process exit is unconfirmed"
            );
            anyhow::ensure!(
                restarting,
                "the original daemon exited but a replacement is running; the service remains active; admission state {}",
                serde_json::to_string(&status).unwrap_or_default()
            );
            lease.fence.verify_open(&status)?;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100).min(remaining)).await;
    }
}

async fn restart_ready(path: &Path, previous: Option<&str>) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut last = "daemon endpoint has not appeared".to_string();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        anyhow::ensure!(
            !remaining.is_zero(),
            "restart readiness unconfirmed: {last}"
        );
        match tokio::time::timeout(remaining, admission_status_at(path)).await {
            Ok(Ok(status)) => {
                if status.success
                    && !status.admission_closed
                    && !status.maintenance_closed
                    && !status.shutdown_committed
                    && !status.ownership_failed
                    && status.maintenance_owner.is_none()
                    && uuid::Uuid::parse_str(&status.daemon_incarnation).is_ok()
                    && previous != Some(status.daemon_incarnation.as_str())
                {
                    return Ok(());
                }
                last = serde_json::to_string(&status).unwrap_or_default();
            }
            Ok(Err(error)) => last = error.to_string(),
            Err(_) => anyhow::bail!("restart readiness timed out: {last}"),
        }
        tokio::time::sleep(Duration::from_millis(100).min(remaining)).await;
    }
}

async fn start_after_maintenance(
    path: &Path,
    previous: Option<&str>,
    systemd: Option<SystemdUnitScope>,
    launchd: Option<&str>,
) -> Result<()> {
    // A service manager may have already restarted the daemon. Never kill or
    // cycle that new process: it can have accepted unrelated builds already.
    if path.try_exists()? {
        return restart_ready(path, previous).await;
    }
    if let Some(scope) = systemd {
        start_via_systemd(scope).await.map_err(anyhow::Error::msg)?;
    } else if let Some(target) = launchd {
        start_via_launchd(target)
            .await
            .map_err(anyhow::Error::msg)?;
    } else {
        ensure_socket_parent(path)?;
        Command::new("nohup")
            .arg(which_rchd())
            .args(daemon_start_args(path))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(false)
            .spawn()
            .context("failed to start daemon after confirmed shutdown")?;
    }
    restart_ready(path, previous).await
}

async fn daemon_maintenance(
    opts: StopOptions,
    restarting: bool,
    ctx: &OutputContext,
) -> Result<()> {
    use dialoguer::Confirm;

    let socket_path_str = configured_socket_path()?;
    let socket_path = Path::new(&socket_path_str);
    let command_name = if restarting {
        "daemon restart"
    } else {
        "daemon stop"
    };
    // Confirmation happens before closing admission; a person can take longer
    // than the lease deadline to answer without blocking anyone's build.
    if opts.force
        && !opts.yes
        && !ctx.is_json()
        && socket_path.exists()
        && !Confirm::new()
            .with_prompt("Interrupt in-flight builds if needed?")
            .default(false)
            .interact()?
    {
        println!("{} Aborted.", StatusIndicator::Info.display(ctx.theme()));
        return Ok(());
    }
    let mut signals = MaintenanceSignals::new()?;
    let mut systemd = None;
    let mut launchd = None;
    let mut previous = None;
    let mut stopped_supervisor = None;
    if socket_path.try_exists()? {
        let mut lease = tokio::select! {
            biased;
            _ = signals.cancelled() => anyhow::bail!("maintenance cancelled before admission changed"),
            result = MaintenanceLease::prepare(socket_path) => result
                .map_err(|error| unconfirmed_stop(socket_path, format!("admission failed: {error:#}")))?,
        };
        if restarting {
            systemd = tokio::select! {
                biased;
                _ = signals.cancelled() => anyhow::bail!("maintenance cancelled before admission changed"),
                result = bound_systemd_scope(&lease.process) => result?,
            };
            if systemd.is_none() {
                launchd = tokio::select! {
                    biased;
                    _ = signals.cancelled() => anyhow::bail!("maintenance cancelled before admission changed"),
                    result = tokio::time::timeout(Duration::from_secs(5), detect_rchd_launchd_target()) => result.context("launchd ownership query timed out; no admission change was attempted")?,
                };
            }
        } else {
            stopped_supervisor = tokio::select! {
                biased;
                _ = signals.cancelled() => anyhow::bail!("maintenance cancelled before admission changed"),
                result = inspect_stop_supervisor(&lease.process) => result?,
            };
        }
        previous = Some(lease.fence.daemon_incarnation.clone());
        let result = tokio::select! {
            biased;
            _ = signals.cancelled() => Err(anyhow::anyhow!("maintenance cancelled by signal")),
            result = stop_owned(&mut lease, opts, restarting, ctx) => result,
        };
        if let Err(error) = result {
            let cleanup = lease.cleanup().await;
            let detail = match cleanup {
                Ok(cleanup) => format!("{error:#}; {cleanup}"),
                Err(cleanup) => format!("{error:#}; {cleanup:#}"),
            };
            return Err(unconfirmed_stop(socket_path, detail));
        }
    } else if restarting {
        // There is no prior peer to bind in this case. Preserve the ordinary
        // startup preference, and let readiness verify any racing daemon.
        systemd = tokio::select! {
            biased;
            _ = signals.cancelled() => anyhow::bail!("maintenance cancelled before admission changed"),
            result = detect_rchd_systemd_scope() => result,
        };
        if systemd.is_none() {
            launchd = tokio::select! {
                biased;
                _ = signals.cancelled() => anyhow::bail!("maintenance cancelled before admission changed"),
                result = tokio::time::timeout(Duration::from_secs(5), detect_rchd_launchd_target()) => result.context("launchd startup ownership query timed out")?,
            };
        }
    } else {
        anyhow::bail!(
            "no daemon endpoint is present at {}; process exit and supervisor state cannot be verified; no shutdown or admission change was attempted",
            socket_path.display()
        );
    }

    if restarting {
        tokio::select! {
            biased;
            _ = signals.cancelled() => anyhow::bail!("restart cancelled after confirmed shutdown; run `rch daemon start`"),
            result = start_after_maintenance(socket_path, previous.as_deref(), systemd, launchd.as_deref()) => result?,
        }
        if ctx.is_json() {
            ctx.json(&ApiResponse::ok(
                command_name,
                DaemonActionResponse {
                    action: "restart".into(),
                    success: true,
                    socket_path: socket_path_str,
                    message: Some(
                        "Daemon restarted; new incarnation and open admission verified".into(),
                    ),
                },
            ))?;
        } else {
            println!(
                "{}",
                StatusIndicator::Success
                    .with_label(ctx.theme(), "Daemon restarted; open admission verified.")
            );
        }
    } else {
        tokio::select! {
            biased;
            _ = signals.cancelled() => anyhow::bail!("stop cancelled after original daemon exit; supervisor state remains unconfirmed"),
            result = verify_stopped_supervisor(stopped_supervisor) => result?,
        }
        report_stopped(
            command_name,
            "stop",
            &socket_path_str,
            "Daemon stopped",
            ctx,
        );
    }
    Ok(())
}

/// Stop with one bounded, peer-owned maintenance lease across drain and shutdown.
pub async fn daemon_stop(opts: StopOptions, ctx: &OutputContext) -> Result<()> {
    daemon_maintenance(opts, false, ctx).await
}

/// Restart after verifying shutdown, then verify a new incarnation admits work.
pub async fn daemon_restart(opts: StopOptions, ctx: &OutputContext) -> Result<()> {
    daemon_maintenance(opts, true, ctx).await
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
            let json = extract_json_body(response.as_str())
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

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_job_pid_reads_only_the_job_line() {
        let printed = "gui/501/com.rch.daemon = {\n\tactive count = 1\n\tstate = running\n\
                       \tendpoints = {\n\t\tpid = 99\n\t}\n\tpid = 10447\n}\n";
        assert_eq!(super::launchd_job_pid(printed), Some(10447));
        assert_eq!(super::launchd_job_pid("\tstate = not running\n"), None);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_process_without_the_socket_is_not_its_listener() {
        let socket = std::path::Path::new("/nonexistent/rch-test/daemon.sock");
        assert!(!super::process_listens_on_unix_socket(std::process::id(), socket).await);
    }

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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn restart_selects_only_systemd_scope_bound_to_captured_peer() {
        let process = DaemonProcess {
            pid: std::process::id(),
            identity: rch_common::process_identity::current_process_identity().unwrap(),
        };
        let state = |pid| SystemdServiceState {
            pid,
            restart: "on-failure".into(),
            active: "active".into(),
            sub: "running".into(),
        };
        let selected = bound_systemd_scope_with(&process, |scope| {
            std::future::ready(Ok(Some(state(match scope {
                SystemdUnitScope::User => process.pid + 1,
                SystemdUnitScope::System => process.pid,
            }))))
        })
        .await
        .unwrap();
        assert_eq!(selected, Some(SystemdUnitScope::System));

        let unrelated = bound_systemd_scope_with(&process, |scope| {
            std::future::ready(Ok(match scope {
                SystemdUnitScope::User => Some(state(process.pid + 1)),
                SystemdUnitScope::System => None,
            }))
        })
        .await
        .unwrap();
        assert_eq!(
            unrelated, None,
            "an enabled unrelated unit must not replace manual startup"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn restart_manager_uncertainty_never_falls_back_to_unmanaged_start() {
        let process = DaemonProcess {
            pid: std::process::id(),
            identity: rch_common::process_identity::current_process_identity().unwrap(),
        };
        let mut probes = 0;
        let result = bound_systemd_scope_with(&process, |_| {
            probes += 1;
            std::future::ready(Err(anyhow::anyhow!("manager inspection timed out")))
        })
        .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("inspection timed out")
        );
        assert_eq!(
            probes, 1,
            "unknown ownership must not be interpreted as absence"
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
    fn shutdown_acknowledgement_requires_a_recognized_successful_reply() {
        for response in [
            "",
            "{\"status\":\"shutting_down\"}",
            "HTTP/1.1 200 OK\r\n\r\n",
            "HTTP/1.1 200 OK\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"queued\"}",
            "HTTP/1.1 503 Unavailable\r\n\r\n{\"status\":\"shutting_down\"}",
            "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"shutting_down\",\"active_build_ids\":[7]}",
            "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"shutting_down\",\"queued_build_ids\":[8]}",
            "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"shutting_down\"}trailing",
        ] {
            assert!(parse_shutdown_response(response).is_err(), "{response:?}");
        }
        for response in [
            "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"shutting_down\"}",
            "HTTP/1.0 200 OK\n\n{\"status\":\"shutting_down\",\"active_build_ids\":[],\"queued_build_ids\":[]}",
        ] {
            assert_eq!(
                parse_shutdown_response(response).unwrap().status,
                "shutting_down"
            );
        }
        assert_eq!(
            parse_shutdown_response(
                "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"shutdown_blocked\",\"active_build_ids\":[7]}"
            )
            .unwrap()
            .active_build_ids,
            vec![7]
        );
    }

    #[test]
    fn admission_response_maps_to_workload() {
        let _guard = test_guard!();
        let mut admission = open_admission();
        admission.admission_closed = true;
        admission.active_build_ids.push(1);
        admission.client_lease_ids.push("l1".into());
        let response = format!(
            "HTTP/1.0 200 OK\r\n\r\n{}",
            serde_json::to_string(&admission).unwrap()
        );
        let admission = parse_admission_response(&response).unwrap();
        assert!(!admission.restart_permitted);
        let workload = DaemonWorkload::from_admission(admission);
        assert_eq!(workload.active_build_ids, vec![1]);
        assert_eq!(workload.client_lease_ids, vec!["l1".to_string()]);
        assert!(!workload.is_idle());
    }

    fn open_admission() -> RestartAdmissionResponse {
        RestartAdmissionResponse {
            success: true,
            status: "open".into(),
            daemon_incarnation: "a12ca740-4c39-4486-9872-1490f0b6c263".into(),
            ..Default::default()
        }
    }

    fn owned_admission(fence: &MaintenanceFence) -> RestartAdmissionResponse {
        RestartAdmissionResponse {
            status: "maintenance_active".into(),
            admission_closed: true,
            maintenance_closed: true,
            maintenance_owner: Some(rch_common::MaintenanceOwner {
                token: fence.token.clone(),
                pid: std::process::id(),
                process_identity: fence.owner_identity.clone(),
                purpose: "restart".into(),
                generation: 1,
                acquired_unix_ms: 100,
                deadline_unix_ms: 30100,
                remaining_ms: 30000,
                owner_presence: "live".into(),
            }),
            ..open_admission()
        }
    }

    #[test]
    fn maintenance_admission_requires_complete_http_and_fenced_state_evidence() {
        for response in [
            "HTTP/1.1 200 OK\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\n\r\n{\"admission_closed\":false,\"restart_permitted\":true,\"active_build_ids\":[],\"queued_build_ids\":[],\"client_lease_ids\":[]}",
            "{\"admission_closed\":false}",
        ] {
            assert!(parse_admission_response(response).is_err(), "{response}");
        }
        let body = serde_json::to_string(&open_admission()).unwrap();
        assert!(
            parse_admission_response(&format!("HTTP/1.1 503 Unavailable\r\n\r\n{body}")).is_err()
        );
        assert!(parse_admission_response(&format!("HTTP/1.1 200 OK\r\n\r\n{body}")).is_ok());
    }

    #[test]
    fn maintenance_fence_cannot_adopt_another_operation_or_daemon_incarnation() {
        let fence = MaintenanceFence::new(&open_admission()).unwrap();
        let owned = owned_admission(&fence);
        fence.require_owned(&owned).unwrap();
        let mut wrong = owned.clone();
        wrong.maintenance_owner.as_mut().unwrap().token = uuid::Uuid::new_v4().to_string();
        assert!(fence.require_owned(&wrong).is_err());
        wrong = owned.clone();
        wrong.maintenance_owner.as_mut().unwrap().pid += 1;
        assert!(fence.require_owned(&wrong).is_err());
        wrong = owned.clone();
        wrong.daemon_incarnation = uuid::Uuid::new_v4().to_string();
        assert!(fence.require_owned(&wrong).is_err());
        wrong = owned.clone();
        wrong.maintenance_owner = None;
        assert!(fence.require_owned(&wrong).is_err());
        wrong = owned;
        wrong.ownership_failed = true;
        assert!(fence.require_owned(&wrong).is_err());
    }

    #[test]
    fn maintenance_acquisition_retains_one_canonical_process_birth_claim() {
        let fence = MaintenanceFence::new(&open_admission()).unwrap();
        let current = rch_common::process_identity::current_process_identity().unwrap();
        assert_eq!(fence.owner_identity, current);
        let expected = format!(
            "POST /restart-admission?daemon_incarnation={}&token={}&purpose=restart&owner_identity={}\n",
            fence.daemon_incarnation,
            fence.token,
            current.to_record().unwrap()
        );
        assert_eq!(fence.acquire_command("restart"), expected);
        // Retrying a lost acquisition response carries the same claim/token;
        // all later mutations rely on the server's stored owner birth fence.
        assert_eq!(fence.acquire_command("restart"), expected);
        for endpoint in [
            "/restart-admission/renew",
            "/restart-admission/release",
            "/shutdown",
        ] {
            assert!(!fence.command(endpoint).contains("owner_identity="));
        }
    }

    #[test]
    fn maintenance_receipts_reject_matching_pid_with_wrong_process_birth() {
        use rch_common::process_identity::ProcessStart;

        let fence = MaintenanceFence::new(&open_admission()).unwrap();
        let mut old_boot = fence.owner_identity.clone();
        old_boot.boot_id = if old_boot.boot_id == "1beb4d17-d7a6-44ae-811f-96e47a1ebc62" {
            "655283ed-1dc5-41ba-b97d-e33da948dbd1"
        } else {
            "1beb4d17-d7a6-44ae-811f-96e47a1ebc62"
        }
        .into();
        let mut recycled = fence.owner_identity.clone();
        match &mut recycled.start {
            ProcessStart::Linux { ticks } => *ticks = ticks.wrapping_add(1),
            ProcessStart::Darwin { microseconds, .. } => {
                *microseconds = (*microseconds + 1) % 1_000_000;
            }
        }
        for wrong_birth in [old_boot, recycled] {
            let mut receipt = owned_admission(&fence);
            receipt.maintenance_owner.as_mut().unwrap().process_identity = wrong_birth;
            assert!(fence.require_owned(&receipt).is_err());
            receipt.status = "shutting_down".into();
            receipt.shutdown_committed = true;
            assert!(fence.require_shutdown(&receipt, false).is_err());
            assert!(fence.require_shutdown(&receipt, true).is_err());
        }
    }

    #[test]
    fn maintenance_release_readback_distinguishes_replacement_and_closed_admission() {
        let fence = MaintenanceFence::new(&open_admission()).unwrap();
        assert_eq!(
            fence.verify_open(&open_admission()).unwrap(),
            "admission reopened and verified"
        );
        assert!(fence.verify_open(&owned_admission(&fence)).is_err());
        let mut status = open_admission();
        status.ownership_failed = true;
        assert!(fence.verify_open(&status).is_err());
        status = open_admission();
        status.shutdown_committed = true;
        assert!(fence.verify_open(&status).is_err());
        status = open_admission();
        status.daemon_incarnation = uuid::Uuid::new_v4().to_string();
        assert!(
            fence
                .verify_open(&status)
                .unwrap()
                .contains("replacement daemon observed")
        );
        status.daemon_incarnation.clear();
        assert!(fence.verify_open(&status).is_err());
    }

    #[test]
    fn shutdown_acknowledgement_requires_owned_commitment_and_quiescence_unless_forced() {
        let fence = MaintenanceFence::new(&open_admission()).unwrap();
        let mut committed = owned_admission(&fence);
        committed.shutdown_committed = true;
        committed.status = "shutting_down".into();
        fence.require_shutdown(&committed, false).unwrap();
        for busy in [
            RestartAdmissionResponse {
                active_build_ids: vec![41],
                ..committed.clone()
            },
            RestartAdmissionResponse {
                queued_build_ids: vec![42],
                ..committed.clone()
            },
            RestartAdmissionResponse {
                client_lease_ids: vec!["live-owner".into()],
                ..committed.clone()
            },
            RestartAdmissionResponse {
                client_lease_scan_error: Some("inspection failed".into()),
                ..committed.clone()
            },
        ] {
            assert!(fence.require_shutdown(&busy, false).is_err());
            fence.require_shutdown(&busy, true).unwrap();
        }
        committed.shutdown_committed = false;
        assert!(fence.require_shutdown(&committed, true).is_err());
        committed.shutdown_committed = true;
        committed.maintenance_owner.as_mut().unwrap().token = uuid::Uuid::new_v4().to_string();
        assert!(fence.require_shutdown(&committed, true).is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn non_linux_hosts_have_no_systemd_unit() {
        let _guard = test_guard!();
        // macOS (launchd) and other non-Linux hosts must never route restart
        // through systemctl, preserving the manual stop+start path.
        assert_eq!(detect_rchd_systemd_scope().await, None);
    }
}
