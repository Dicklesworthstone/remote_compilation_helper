//! Remote Compilation Helper - Local Daemon
//!
//! The daemon manages the worker fleet, tracks slot availability,
//! and provides the Unix socket API for the hook CLI.

#![forbid(unsafe_code)]

mod admission;
mod alerts;
mod api;
mod benchmark_queue;
mod benchmark_scheduler;
mod build_root_policy;
mod bypass_recovery_service;
mod cache_cleanup;
mod cancellation;
mod cleanup;
mod config;
#[cfg(test)]
mod disk_full_prevention_tests;
mod disk_pressure;
mod events;
mod headroom;
mod health;
mod history;
mod http_api;
mod metrics;
mod process_triage;
mod reclaim;
mod reliability;
mod reload;
mod repo_convergence;
mod selection;
mod self_test;
mod stale_target_reap;
mod startup_consistency;
mod telemetry;
mod ui;
mod workers;

use anyhow::{Context, Result, bail};
use chrono::{Duration as ChronoDuration, Local};
use clap::{CommandFactory, FromArgMatches, Parser};
use rch_common::{LogConfig, SelfTestConfig, init_logging};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

use benchmark_queue::BenchmarkQueue;
use benchmark_scheduler::{BenchmarkScheduler, BenchmarkTriggerHandle, SchedulerConfig};
use bypass_recovery_service::{BypassRecoveryConfig, BypassRecoveryService, SshRecoveryProber};
use disk_pressure::{DiskPressureMonitor, DiskPressurePolicyConfig};
use events::EventBus;
use history::BuildHistory;
use rch_common::bypass_record::{
    AdminDisableStore, BypassRecordStore, default_admin_disable_path, default_bypass_record_path,
};
use rch_telemetry::storage::TelemetryStorage;
use selection::WorkerSelector;
use self_test::{DEFAULT_RESULT_CAPACITY, DEFAULT_RUN_CAPACITY, SelfTestHistory, SelfTestService};
use telemetry::{TelemetryPoller, TelemetryPollerConfig, TelemetryStore};
use ui::{DaemonBanner, MetricsDashboard, WorkerStatusPanel};

#[derive(Parser)]
#[command(name = "rchd")]
#[command(
    author,
    version = rch_common::build_version_value_static(),
    about = "RCH daemon - worker fleet orchestration"
)]
struct Cli {
    /// Socket pin; otherwise use socket environment overrides and config.toml [general].socket_path
    #[arg(short, long, default_value_os_t = crate::config::default_socket_path())]
    socket: PathBuf,

    /// Path to workers configuration
    #[arg(short, long)]
    workers_config: Option<PathBuf>,

    /// Path to build history file (JSONL format)
    #[arg(long)]
    history_file: Option<PathBuf>,

    /// Maximum build history entries to retain
    #[arg(long, default_value = "100")]
    history_capacity: usize,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,

    /// Port for HTTP metrics/health endpoints (0 to disable)
    #[arg(long, default_value = "9100")]
    metrics_port: u16,

    /// Reset interval for metrics dashboard window, in seconds
    #[arg(long, default_value = "300")]
    metrics_reset_interval: u64,

    /// Emit worker selection routing decisions to stderr
    #[arg(long)]
    debug_routing: bool,

    /// Disable hot-reload of configuration files
    #[arg(long)]
    no_hot_reload: bool,

    /// Serve the status API over TCP for the tailnet: "tailscale",
    /// "tailscale:PORT", or "IP:PORT". Overrides `[api] bind` in config.toml.
    #[arg(long)]
    api_bind: Option<String>,

    /// File holding the bearer token for the status API. Overrides
    /// `[api] token_file` in config.toml.
    #[arg(long)]
    api_token_file: Option<String>,
}

/// Resolve the listener and the client's effective shared endpoint before
/// service-manager delegation or binding (#69). Keep an explicit CLI pin
/// distinct from clap's default, even when their path strings are equal.
fn daemon_socket_for_startup(
    matches: &clap::ArgMatches,
    configured: &str,
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<(PathBuf, String)> {
    // Match rch::config's canonical-over-alias precedence. An explicitly empty
    // value wins too: it must fail validation, not select another daemon.
    let client_socket = ["RCH_SOCKET_PATH", "RCH_DAEMON_SOCKET"]
        .into_iter()
        .find_map(&mut lookup)
        .unwrap_or_else(|| configured.to_owned());
    let socket = if matches.value_source("socket") == Some(clap::parser::ValueSource::CommandLine) {
        matches
            .get_one::<PathBuf>("socket")
            .cloned()
            .context("missing --socket value")?
    } else {
        PathBuf::from(&client_socket)
    };
    anyhow::ensure!(
        socket.is_absolute()
            && socket.file_name().is_some()
            && !socket.to_string_lossy().chars().any(char::is_control),
        "daemon socket must be an absolute file path without control characters: {}; set --socket, RCH_SOCKET_PATH, or config.toml [general].socket_path",
        socket.display()
    );
    Ok((socket, client_socket))
}

/// Build the selector used by daemon startup with disk admission enabled.
fn daemon_worker_selector(
    config: &rch_common::RchConfig,
    history: Arc<BuildHistory>,
    ssh_pool: Option<Arc<rch_common::SshPool>>,
) -> WorkerSelector {
    let mut selector =
        WorkerSelector::with_config(config.selection.clone(), config.circuit.clone());
    let headroom = Arc::new(headroom::HeadroomEstimator::new(
        history,
        headroom::HeadroomConfig {
            floor_free_gb: config.selection.min_free_gb.unwrap_or(0.0),
            ..Default::default()
        },
    ));
    selector.set_admission_gate(Arc::new(admission::AdmissionGate::new(
        admission::AdmissionConfig {
            min_free_gb: config.selection.min_free_gb,
            ..Default::default()
        },
        headroom,
    )));
    selector.set_ssh_pool(ssh_pool);
    selector
}

/// A minimal `DaemonContext` for unit tests in other modules (the tailnet API
/// router tests in `http_api`). Mirrors `api::tests::make_test_context`.
#[cfg(test)]
pub(crate) fn test_daemon_context(pool: workers::WorkerPool) -> DaemonContext {
    use chrono::Duration as ChronoDuration;
    let self_test_history = Arc::new(self_test::SelfTestHistory::new(
        self_test::DEFAULT_RUN_CAPACITY,
        self_test::DEFAULT_RESULT_CAPACITY,
    ));
    let self_test_service = Arc::new(SelfTestService::new(
        pool.clone(),
        rch_common::SelfTestConfig::default(),
        self_test_history,
    ));
    let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
    let events = EventBus::new(16);
    let (scheduler, benchmark_trigger) = benchmark_scheduler::BenchmarkScheduler::new(
        benchmark_scheduler::SchedulerConfig::default(),
        pool.clone(),
        telemetry.clone(),
        events.clone(),
    );
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(Arc::new(scheduler).run());
    }
    let history = Arc::new(BuildHistory::new(100));
    DaemonContext {
        pool,
        worker_selector: Arc::new(daemon_worker_selector(
            &rch_common::RchConfig::default(),
            history.clone(),
            None,
        )),
        history,
        telemetry,
        benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
        benchmark_trigger,
        repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
            events.clone(),
        )),
        cancellation: Arc::new(cancellation::CancellationOrchestrator::new(
            cancellation::CancellationConfig::default(),
            events.clone(),
        )),
        events,
        self_test: self_test_service,
        alert_manager: Arc::new(alerts::AlertManager::new(alerts::AlertConfig::default())),
        started_at: Instant::now(),
        socket_path: "/tmp/test.sock".to_string(),
        version: "0.1.0-test",
        pid: 1234,
        queue_timeout_secs: 300,
        bypass_store: None,
        admin_disable_store: None,
        workers_config_path: None,
        admission_barrier: Arc::new(tokio::sync::RwLock::new(false)),
    }
}

/// Shared daemon context passed to all API handlers.
#[derive(Clone)]
pub struct DaemonContext {
    /// Worker pool.
    pub pool: workers::WorkerPool,
    /// Worker selector with cache tracking.
    pub worker_selector: Arc<WorkerSelector>,
    /// Build history.
    pub history: Arc<BuildHistory>,
    /// Telemetry store.
    pub telemetry: Arc<TelemetryStore>,
    /// Benchmark trigger queue.
    pub benchmark_queue: Arc<BenchmarkQueue>,
    /// Live benchmark scheduler trigger handle.
    pub benchmark_trigger: BenchmarkTriggerHandle,
    /// Event broadcast bus.
    pub events: EventBus,
    /// Self-test service.
    pub self_test: Arc<SelfTestService>,
    /// Alert manager for worker health alerting.
    pub alert_manager: Arc<alerts::AlertManager>,
    /// Repo convergence service for worker fleet sync tracking.
    pub repo_convergence: Arc<repo_convergence::RepoConvergenceService>,
    /// Cancellation orchestrator for deterministic build cancellation.
    pub cancellation: Arc<cancellation::CancellationOrchestrator>,
    /// Daemon start time.
    pub started_at: Instant,
    /// Socket path (for status reporting).
    pub socket_path: String,
    /// Daemon version.
    pub version: &'static str,
    /// Daemon process ID.
    pub pid: u32,
    /// Maximum time a build can wait in queue (seconds) before timing out.
    pub queue_timeout_secs: u64,
    /// Durable bypass-record store (shared with the bypass recovery service).
    /// `handle_worker_enable` deletes a worker's record here so an operator
    /// re-enable is durable — otherwise `reconcile_on_start` re-quarantines the
    /// worker from the persisted record on the next daemon restart. `None` in
    /// test contexts that don't exercise bypass recovery.
    pub bypass_store: Option<Arc<tokio::sync::Mutex<BypassRecordStore>>>,
    /// Durable admin-disable store (bd-8zxz7). `handle_worker_disable` writes a
    /// record and `handle_worker_enable` removes it, so both operator disables
    /// and the cpu-capability-fault quarantine survive daemon restarts (startup
    /// re-applies surviving records to the pool). `None` in test contexts.
    pub admin_disable_store: Option<Arc<tokio::sync::Mutex<AdminDisableStore>>>,
    /// The `--workers-config` path the daemon was launched with, if any. The
    /// socket `reload` handler must load from here — resolving the config dir
    /// afresh can pick a different file (bd-xqg58: a macOS daemon launched
    /// with the legacy Application Support path reloaded `~/.config/rch`
    /// instead, so edits to the file it was actually running from were
    /// silently ignored). `None` means "resolve the default", exactly as at
    /// startup.
    pub workers_config_path: Option<std::path::PathBuf>,
    /// Stops new worker selection while a restart remediator proves quiescence.
    /// This is shared with the socket API so check-and-close admission occurs
    /// in the daemon rather than in a racy CLI preflight.
    pub admission_barrier: Arc<RwLock<bool>>,
}

/// Result of one bind attempt — distinguishes "socket is held by another
/// daemon" (a normal state we wait out under systemd) from real errors.
enum BindAttempt {
    Bound(UnixListener),
    SocketHeld,
}

/// Send a sd_notify(3) message to systemd if NOTIFY_SOCKET is set. Silently
/// no-op on macOS, on hosts without systemd, and for Type=simple units
/// (which don't set NOTIFY_SOCKET — the current rchd.service config).
///
/// Adding this means the daemon also works under Type=notify without
/// TimeoutStartSec killing it: we send READY=1 once the socket is bound,
/// and STATUS=... updates while we're in the wait-for-socket loop.
///
/// Path-form sockets (the default on Debian/Ubuntu/etc.) are supported.
/// Abstract sockets (env var starts with '@') need a libc::sendto with a
/// sockaddr_un to encode the leading NUL byte — to avoid the new dep we
/// skip them and let the operator know via debug! log. They're rare in
/// practice; the unit can use Type=simple as a workaround.
fn sd_notify(message: &str) {
    #[cfg(target_os = "linux")]
    {
        let Some(raw) = std::env::var("NOTIFY_SOCKET").ok() else {
            return;
        };
        if raw.is_empty() {
            return;
        }
        if raw.starts_with('@') {
            tracing::debug!(
                "sd_notify: abstract NOTIFY_SOCKET not supported (would send {message:?})"
            );
            return;
        }
        if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
            let _ = sock.send_to(message.as_bytes(), raw);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = message;
    }
}

/// True iff `/proc/self/cgroup` content indicates we are the rchd.service unit.
#[allow(dead_code)] // used under cfg(linux) and in tests
fn cgroup_contains_rchd_unit(cgroup: &str) -> bool {
    cgroup.contains("rchd.service")
}

/// `Some(true)`/`Some(false)` once we can read our cgroup and decide whether we
/// are the rchd.service unit's own process; `None` if the cgroup is unreadable
/// (callers treat `None` conservatively to avoid any restart storm).
fn cgroup_says_rchd_unit() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/cgroup")
            .ok()
            .map(|c| cgroup_contains_rchd_unit(&c))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Some(false)
    }
}

/// Is a systemd --user `rchd.service` unit configured (enabled/static) here?
#[cfg(target_os = "linux")]
fn rchd_systemd_unit_present() -> bool {
    std::process::Command::new("systemctl")
        .args(["--user", "is-enabled", "rchd"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// On systemd hosts, enforce exactly one rchd. If `rchd.service` manages the
/// daemon here and we are NOT that unit's process (a duplicate spawned by hook
/// auto-start, `rch daemon start/restart`, or `rch update`), make sure the unit
/// is running and exit. systemd (Restart=always) is then the single source of
/// truth, eliminating duplicate/orphan rchd regardless of how it was launched.
/// No-op on macOS and on Linux hosts with no rchd.service (manual management).
/// An explicitly separate socket AND worker configuration designate an isolated
/// pool. Its operator must first drain those workers from any shared daemon.
fn defer_to_systemd_if_managed(
    socket: &Path,
    workers_config: Option<&Path>,
    shared_socket: &Path,
) {
    #[cfg(target_os = "linux")]
    {
        if isolated_worker_pool(socket, workers_config, shared_socket) {
            return;
        }
        // Only defer when we can CONFIRM we are not the unit's own process.
        // `Some(true)` (we ARE the unit) or `None` (cgroup unreadable) -> proceed,
        // so we never make the real unit exit-loop under systemd Restart=always.
        if cgroup_says_rchd_unit() != Some(false) {
            return;
        }
        if !rchd_systemd_unit_present() {
            return;
        }
        info!(
            "rchd is managed by the systemd --user rchd.service unit here; starting it and exiting to avoid a duplicate daemon"
        );
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "start", "rchd"])
            .status();
        std::process::exit(0);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (socket, workers_config, shared_socket);
}

fn isolated_worker_pool(
    socket: &Path,
    workers_config: Option<&Path>,
    shared_socket: &Path,
) -> bool {
    // A configured shared endpoint is not an isolated pool merely because it
    // differs from the compiled default (#69).
    socket != shared_socket && workers_config.is_some()
}

#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod launchd {
    use super::*;
    use std::process::{Output, Stdio};
    use tokio::io::AsyncReadExt;

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Ownership {
        Standalone,
        Managed,
        Delegated,
    }

    /// A successful exit alone does not prove enumeration succeeded: launchctl
    /// can emit an error instead of a table with exit zero.
    pub(super) fn listed_pid(table: &str, label: &str) -> Result<Option<Option<u32>>> {
        let mut lines = table.lines().filter(|line| !line.trim().is_empty());
        if lines
            .next()
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            != Some(vec!["PID", "Status", "Label"])
        {
            bail!("launchctl list did not return its PID/Status/Label table");
        }
        let mut found = None;
        for line in lines {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 3 || fields[1].parse::<i32>().is_err() {
                bail!("malformed launchctl list row");
            }
            let pid = if fields[0] == "-" {
                None
            } else {
                Some(positive_pid(fields[0])?)
            };
            if fields[2] == label {
                if found.is_some() {
                    bail!("ambiguous duplicate launchd label {label}");
                }
                found = Some(pid);
            }
        }
        Ok(found)
    }

    fn positive_pid(value: &str) -> Result<u32> {
        let pid = value.parse::<u32>().context("invalid launchd PID")?;
        anyhow::ensure!(pid > 0, "launchd PID must be positive");
        Ok(pid)
    }

    pub(super) fn kickstart_pid(output: &str, target: &str) -> Result<u32> {
        let output = output.trim();
        let value = output
            .strip_prefix(target)
            .and_then(|value| value.strip_prefix(':'))
            .map_or(output, str::trim);
        positive_pid(value)
    }

    pub(super) fn ownership(pid: u32, self_pid: u32) -> Ownership {
        if pid == self_pid {
            Ownership::Managed
        } else {
            Ownership::Delegated
        }
    }

    /// One deadline covers all probes and the start request. Read both pipes
    /// concurrently with bounded buffers and retain ownership of the child on
    /// every timeout/error path.
    pub(super) async fn command(
        program: &Path,
        args: &[&str],
        deadline: tokio::time::Instant,
    ) -> Result<Output> {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "service-manager startup deadline expired"
        );
        let mut child = tokio::process::Command::new(program) // ubs:ignore — fixed /bin/launchctl in production; only tests inject executables.
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("spawn service-manager command")?;
        let stdout = child.stdout.take().context("missing manager stdout")?;
        let stderr = child.stderr.take().context("missing manager stderr")?;
        let result = tokio::time::timeout_at(deadline, async {
            let (out, err, status) =
                tokio::try_join!(read_bounded(stdout), read_bounded(stderr), async {
                    child
                        .wait()
                        .await
                        .context("wait for service-manager command")
                })?;
            Ok::<_, anyhow::Error>(Output {
                status,
                stdout: out,
                stderr: err,
            })
        })
        .await
        .map_err(|_| anyhow::anyhow!("service-manager startup deadline expired"))
        .and_then(std::convert::identity);
        if result.is_err() {
            let _ = child.start_kill();
            let _ = timeout(Duration::from_secs(1), child.wait()).await;
        }
        result
    }

    async fn read_bounded(reader: impl tokio::io::AsyncRead + Unpin) -> Result<Vec<u8>> {
        const LIMIT: u64 = 1024 * 1024;
        let mut bytes = Vec::new();
        reader.take(LIMIT + 1).read_to_end(&mut bytes).await?;
        anyhow::ensure!(
            bytes.len() <= LIMIT as usize,
            "service-manager output exceeded limit"
        );
        Ok(bytes)
    }

    async fn list(
        program: &Path,
        label: &str,
        deadline: tokio::time::Instant,
    ) -> Result<Option<Option<u32>>> {
        let output = command(program, &["list"], deadline).await?;
        anyhow::ensure!(
            output.status.success(),
            "launchctl list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        listed_pid(std::str::from_utf8(&output.stdout)?, label)
    }

    /// Resolve only the current user's GUI/user domains (plus system for root).
    /// SSH runs in a different bootstrap context from a GUI LaunchAgent, so a
    /// valid empty current-context listing alone does not establish absence.
    pub(super) async fn resolve(
        program: &Path,
        label: &str,
        uid: u32,
        self_pid: u32,
        custom_socket: bool,
        deadline: tokio::time::Instant,
    ) -> Result<Ownership> {
        let (listed, list_error) = match list(program, label, deadline).await {
            Ok(listed) => (listed, None),
            Err(error) => (None, Some(error)),
        };
        if listed == Some(Some(self_pid)) {
            return Ok(Ownership::Managed);
        }
        if listed.is_some() && custom_socket {
            bail!(
                "cannot delegate a custom socket to launchd without a separate workers configuration"
            );
        }
        if let Some(Some(_)) = listed {
            // Already running. Never restart or kill it to satisfy an autostart.
            return Ok(Ownership::Delegated);
        }
        if listed == Some(None) {
            let started = command(program, &["start", label], deadline).await?;
            anyhow::ensure!(
                started.status.success(),
                "launchctl start failed: {}",
                String::from_utf8_lossy(&started.stderr)
            );
            loop {
                match list(program, label, deadline).await? {
                    Some(Some(pid)) => return Ok(ownership(pid, self_pid)),
                    Some(None) => tokio::time::sleep(Duration::from_millis(100)).await,
                    None => bail!("launchd service disappeared during startup"),
                }
            }
        }
        let mut targets = vec![format!("gui/{uid}/{label}"), format!("user/{uid}/{label}")];
        if uid == 0 {
            targets.push(format!("system/{label}"));
        }
        let mut registered = Vec::new();
        for target in targets {
            let probe = command(program, &["print", &target], deadline).await?;
            if probe.status.success() {
                registered.push(target);
            } else if probe.status.code() != Some(113) {
                // launchctl's 113 is the explicit absent service/domain result.
                // Permission, transport and syntax errors are not absence.
                bail!(
                    "cannot establish launchd service presence for {target}: {}",
                    String::from_utf8_lossy(&probe.stderr)
                );
            }
        }
        let target = match registered.as_slice() {
            [] => return list_error.map_or(Ok(Ownership::Standalone), Err),
            [target] => target,
            _ => bail!("RCH is registered in multiple launchd domains; refusing ambiguous startup"),
        };
        anyhow::ensure!(
            !custom_socket,
            "cannot delegate a custom socket to launchd without a separate workers configuration"
        );
        // Deliberately no -k: -p returns the existing PID without replacing an
        // active daemon. Do not parse the undocumented `print` output fields.
        let started = command(program, &["kickstart", "-p", target], deadline).await?;
        anyhow::ensure!(
            started.status.success(),
            "launchctl kickstart failed: {}",
            String::from_utf8_lossy(&started.stderr)
        );
        Ok(ownership(
            kickstart_pid(std::str::from_utf8(&started.stdout)?, target)?,
            self_pid,
        ))
    }
}

async fn bind_daemon_socket(socket: &Path, managed_by_launchd: bool) -> Result<UnixListener> {
    // "Managed by systemd" only if THIS process is the rchd.service unit's own
    // main process (our cgroup is rchd.service) -- NOT merely because
    // INVOCATION_ID was inherited from a parent scope (e.g. an agent's `rch`
    // auto-spawned us). The genuine unit waits out a transiently-held socket
    // (avoids a restart storm); any other rchd bails. A non-unit rchd on a
    // systemd host has already exited via defer_to_systemd_if_managed().
    let managed = managed_by_launchd || cgroup_says_rchd_unit() == Some(true);
    bind_daemon_socket_with_mode(socket, managed, Duration::from_secs(5)).await
}

/// Inner bind routine taking an explicit `managed` flag and
/// `wait_backoff` (parameterized for tests).
///
/// If the socket is currently held by another rchd (e.g. an agent's `rch
/// exec` auto-spawned a detached one during a momentary daemon outage),
/// exiting with FAILURE causes the service manager to restart-storm — which is what
/// happened on css/ts2 (NRestarts in the tens of thousands). When
/// managed by systemd or launchd, wait for the other process to free the
/// socket instead; this keeps the managed process alive and avoids the
/// storm entirely.
///
/// We also retry on *any* error from the inner attempt when managed
/// (probe timeouts, races on remove/bind, permission glitches): a one-shot
/// failure must never crash-loop the unit. Standalone invocations preserve
/// the original fail-fast behavior.
async fn bind_daemon_socket_with_mode(
    socket: &Path,
    managed: bool,
    wait_backoff: Duration,
) -> Result<UnixListener> {
    let mut waited_logged = false;

    loop {
        match try_bind_daemon_socket(socket).await {
            Ok(BindAttempt::Bound(listener)) => return Ok(listener),
            Ok(BindAttempt::SocketHeld) => {
                if managed {
                    if !waited_logged {
                        warn!(
                            "daemon socket {} already serving; waiting for it to free \
                             (service-managed, will take over when the current owner exits)",
                            socket.display()
                        );
                        // Visible via `systemctl --user status rchd` so
                        // operators can tell *why* the unit looks idle.
                        sd_notify("STATUS=waiting for another rchd to release the socket");
                        waited_logged = true;
                    }
                    tokio::time::sleep(wait_backoff).await;
                    continue;
                }
                bail!(
                    "daemon socket already accepts connections at {}; refusing to start a second rchd",
                    socket.display()
                );
            }
            Err(e) if managed => {
                // Don't restart-storm on transient errors. The most realistic
                // one is the 300ms connect-probe timeout in
                // socket_has_live_listener firing under load on the box that
                // currently holds the socket.
                warn!(
                    "daemon socket bind attempt failed (service-managed, retrying in {}s): {e:#}",
                    wait_backoff.as_secs()
                );
                tokio::time::sleep(wait_backoff).await;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn try_bind_daemon_socket(socket: &Path) -> Result<BindAttempt> {
    use std::os::unix::fs::FileTypeExt;

    match std::fs::symlink_metadata(socket) {
        Ok(metadata) => {
            // A typo in a socket pin must never turn stale-socket cleanup into
            // deletion of an operator's regular file, directory, or symlink.
            anyhow::ensure!(
                metadata.file_type().is_socket(),
                "refusing to replace non-socket path {}",
                socket.display()
            );
            if socket_has_live_listener(socket).await? {
                return Ok(BindAttempt::SocketHeld);
            }
            std::fs::remove_file(socket).with_context(|| {
                format!("failed to remove stale daemon socket {}", socket.display())
            })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect daemon socket {}", socket.display()));
        }
    }

    let listener = UnixListener::bind(socket)
        .with_context(|| format!("failed to bind daemon socket {}", socket.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).with_context(
            || {
                format!(
                    "failed to set daemon socket permissions {}",
                    socket.display()
                )
            },
        )?;
    }

    Ok(BindAttempt::Bound(listener))
}

async fn socket_has_live_listener(socket: &Path) -> Result<bool> {
    match timeout(Duration::from_millis(300), UnixStream::connect(socket)).await {
        Ok(Ok(_stream)) => Ok(true),
        Ok(Err(error)) if is_stale_socket_connect_error(&error) => Ok(false),
        Ok(Err(error)) => Err(error).with_context(|| {
            format!(
                "daemon socket {} exists but could not be probed safely",
                socket.display()
            )
        }),
        Err(_) => bail!(
            "daemon socket {} exists but the connection probe timed out; refusing to start a second rchd",
            socket.display()
        ),
    }
}

fn is_stale_socket_connect_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
    )
}

/// Finish request observations before shutting down their metric provider.
async fn drain_connections(connections: &mut tokio::task::JoinSet<()>, grace: Duration) {
    let drained = tokio::time::timeout(grace, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        connections.abort_all();
        // Await cancellation so request guards have run before the final export.
        while connections.join_next().await.is_some() {}
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches)?;
    let startup_started = Instant::now();

    if cli.debug_routing {
        // Avoid env var mutation (unsafe in Rust 2024); use an in-process override.
        crate::ui::workers::set_debug_routing_enabled(true);
    }

    // Initialize logging
    let mut log_config = LogConfig::from_env("info");
    if cli.verbose {
        log_config = log_config.with_level("debug");
    }
    let _logging_guards = init_logging(&log_config)?;

    info!("Starting RCH daemon...");

    // #69: resolve the endpoint before delegation or binding, not after the
    // listener is already live. Invalid configuration must not silently launch
    // a daemon on a different endpoint. Operator-owned files are not rewritten.
    let mut rch_config = config::load_rch_config()
        .context("could not resolve RCH configuration before binding the daemon socket")?;
    rch_config.self_healing = rch_config.self_healing.with_env_overrides();
    let (socket, client_socket) = daemon_socket_for_startup(
        &matches,
        &rch_config.general.socket_path,
        |name| std::env::var(name).ok(),
    )?;
    cli.socket = socket;
    rch_config.general.socket_path = client_socket;
    let shared_socket = PathBuf::from(&rch_config.general.socket_path);

    // Enforce single-instance on systemd hosts before we touch the socket.
    defer_to_systemd_if_managed(&cli.socket, cli.workers_config.as_deref(), &shared_socket);
    #[cfg(target_os = "macos")]
    let managed_by_launchd = if isolated_worker_pool(
        &cli.socket,
        cli.workers_config.as_deref(),
        &shared_socket,
    ) {
        false
    } else {
        match launchd::resolve(
            Path::new("/bin/launchctl"),
            "com.rch.daemon",
            nix::unistd::Uid::effective().as_raw(),
            std::process::id(),
            cli.socket != shared_socket,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await?
        {
            launchd::Ownership::Standalone => false,
            launchd::Ownership::Managed => true,
            launchd::Ownership::Delegated => {
                info!(
                    "launchd owns rchd; leaving startup and active builds with the registered service"
                );
                return Ok(());
            }
        }
    };
    #[cfg(not(target_os = "macos"))]
    let managed_by_launchd = false;
    let listener = bind_daemon_socket(&cli.socket, managed_by_launchd).await?;
    info!("Listening on {:?}", cli.socket);
    // Inform systemd we're ready. No-op for Type=simple (the current unit)
    // and on macOS; essential if anyone ever switches to Type=notify.
    sd_notify("READY=1");

    // Register Prometheus metrics
    if let Err(e) = metrics::register_metrics() {
        warn!("Failed to register some metrics: {}", e);
    }
    metrics::set_daemon_info(env!("CARGO_PKG_VERSION"));

    // Register remediation-state observability (bead 14.5) into the same served
    // registry and install the process-global handle so daemon decision points
    // can record via `rch_telemetry::remediation::record_*`. Best-effort: a
    // construction/registration failure must never block the daemon.
    match rch_telemetry::remediation::RemediationMetrics::new() {
        Ok(remediation) => {
            if let Err(e) = remediation.register(&metrics::REGISTRY) {
                warn!("Failed to register remediation metrics: {}", e);
            }
            rch_telemetry::remediation::init_global(remediation);
        }
        Err(e) => warn!("Failed to construct remediation metrics: {}", e),
    }

    // Load worker configuration
    let workers = config::load_workers(cli.workers_config.as_deref())?;
    let worker_count = workers.len();
    let total_slots: u32 = workers.iter().map(|worker| worker.total_slots).sum();
    info!("Loaded {} workers from configuration", workers.len());

    // Install the disk-slot policy before adding workers so later config reloads
    // inherit the same budget as workers present at startup.
    let worker_pool = workers::WorkerPool::with_selection_config(&rch_config.selection);
    for worker_config in workers {
        info!(
            "Adding worker: {} ({}@{}, {} slots)",
            worker_config.id, worker_config.user, worker_config.host, worker_config.total_slots
        );
        worker_pool.add_worker(worker_config).await;
    }

    // Startup self-consistency check (bd-...-3.2): verify the daemon's bound
    // socket, the hook/CLI's configured socket, and the installed Claude Code
    // hook agree, reporting any drift as structured events. Read-only — it
    // never rewrites operator-owned config.
    {
        let hook_config_socket = {
            let configured = rch_config.general.socket_path.trim();
            (!configured.is_empty()).then(|| PathBuf::from(configured))
        };
        let _ = startup_consistency::gather_and_log(cli.socket.clone(), hook_config_socket);
    }

    // Verify and install Claude Code hook if needed (self-healing)
    if rch_config.self_healing.daemon_installs_hooks {
        match rch_common::verify_and_install_claude_code_hook() {
            Ok(rch_common::HookResult::AlreadyInstalled) => {
                tracing::debug!("Claude Code hook already installed");
            }
            Ok(rch_common::HookResult::Installed) => {
                info!("Claude Code hook installed automatically");
            }
            Ok(rch_common::HookResult::NotApplicable) => {
                tracing::debug!("Claude Code not detected, skipping hook installation");
            }
            Ok(rch_common::HookResult::Skipped(reason)) => {
                tracing::debug!("Hook installation skipped: {}", reason);
            }
            Err(e) => {
                warn!("Failed to verify/install Claude Code hook: {}", e);
            }
        }
    } else {
        tracing::debug!("Hook auto-installation disabled via config");
    }

    // Load daemon config for queue + cache cleanup settings
    let daemon_config = match config::load_daemon_config(None) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to load daemon config: {}, using defaults", e);
            config::DaemonConfig::default()
        }
    };

    // Shared SSH connection pool for the daemon's per-worker background
    // subsystems (health, telemetry, cache cleanup, stale-target reap, reclaim,
    // toolchain probe). Historically each of these opened a throwaway
    // `SshClient` per poll — a fresh ControlMaster spawned (and, with the
    // openssh default ControlPersist, LEAKED) every ~30s per worker, flooding
    // sshd and eventually tripping workers falsely DOWN. One warm master per
    // worker is reused instead. Gated on the (previously dead) `connection_pooling`
    // flag so it can be turned off if a site hits mux trouble; when `None` each
    // subsystem falls back to its legacy throwaway path.
    //
    // The pool keeps a BOUNDED-idle master (ControlPersist=IdleFor(60)); the
    // openssh crate's Forever default is deliberately avoided (see
    // `control_persist_mode` — that default is exactly what leaked masters).
    let ssh_pool: Option<Arc<rch_common::SshPool>> = if daemon_config.connection_pooling {
        let pool_options = rch_common::SshOptions {
            control_master: true,
            control_persist_idle: Some(Duration::from_secs(60)),
            ..Default::default()
        };
        info!("SSH connection pooling enabled (warm ControlMaster reuse)");
        Some(Arc::new(rch_common::SshPool::new(pool_options)))
    } else {
        info!("SSH connection pooling disabled (per-call SSH sessions)");
        None
    };

    // Initialize build history
    let history = if let Some(ref path) = cli.history_file {
        if path.exists() {
            match BuildHistory::load_from_file(path, cli.history_capacity) {
                Ok(h) => {
                    info!("Loaded build history from {:?} ({} entries)", path, h.len());
                    Arc::new(h.with_max_queue_depth(daemon_config.queue.max_depth))
                }
                Err(e) => {
                    warn!("Failed to load history from {:?}: {}", path, e);
                    Arc::new(
                        BuildHistory::new(cli.history_capacity)
                            .with_persistence(path.clone())
                            .with_max_queue_depth(daemon_config.queue.max_depth),
                    )
                }
            }
        } else {
            info!("Creating new build history at {:?}", path);
            Arc::new(
                BuildHistory::new(cli.history_capacity)
                    .with_persistence(path.clone())
                    .with_max_queue_depth(daemon_config.queue.max_depth),
            )
        }
    } else {
        info!("Build history in-memory only (no persistence)");
        Arc::new(
            BuildHistory::new(cli.history_capacity)
                .with_max_queue_depth(daemon_config.queue.max_depth),
        )
    };

    // Admission uses the same persisted build history as the API. Attach it
    // before sharing the selector so normal startup cannot omit the gate.
    let worker_selector = Arc::new(daemon_worker_selector(
        &rch_config,
        history.clone(),
        ssh_pool.clone(),
    ));

    // Initialize self-test config and history
    let self_test_config = match config::load_self_test_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to load self-test config: {}", e);
            SelfTestConfig::default()
        }
    };

    let self_test_history = match self_test::default_history_path() {
        Ok(path) => match SelfTestHistory::load_from_file(
            &path,
            DEFAULT_RUN_CAPACITY,
            DEFAULT_RESULT_CAPACITY,
        ) {
            Ok(history) => Arc::new(history),
            Err(e) => {
                warn!("Failed to load self-test history from {:?}: {}", path, e);
                Arc::new(
                    SelfTestHistory::new(DEFAULT_RUN_CAPACITY, DEFAULT_RESULT_CAPACITY)
                        .with_persistence(path),
                )
            }
        },
        Err(e) => {
            warn!("Failed to determine self-test history path: {}", e);
            Arc::new(SelfTestHistory::new(
                DEFAULT_RUN_CAPACITY,
                DEFAULT_RESULT_CAPACITY,
            ))
        }
    };

    let self_test_service = Arc::new(SelfTestService::new(
        worker_pool.clone(),
        self_test_config,
        self_test_history,
    ));
    if let Err(e) = self_test_service.clone().start().await {
        warn!("Failed to start self-test scheduler: {}", e);
    }

    // Start cache cleanup scheduler
    let cache_cleanup_scheduler = Arc::new(
        cache_cleanup::CacheCleanupScheduler::new(worker_pool.clone(), daemon_config.cache_cleanup)
            .with_ssh_pool(ssh_pool.clone()),
    );
    let _cache_cleanup_handle = cache_cleanup_scheduler.start();

    // Start the worker-side stale per-job target dir reaper. The orchestrator hook
    // only reaps the single repo being built; this periodic daemon sweep reclaims
    // abandoned `.rch-target-*-job-*` dirs across ALL repos on each worker using
    // the same idle predicate (shared via rch_common::stale_target_reap).
    // Default-off for canary safety; env-overridable / opt-in via config.
    let stale_target_reaper = Arc::new(
        stale_target_reap::StaleTargetReaper::new(
            worker_pool.clone(),
            // bd-28xs5: source the reaper config from the central remediation config
            // (remediation.pooled_target) rather than rchd-local defaults; env knobs
            // still override on top.
            config::StaleTargetReapConfig::from_remediation(&rch_config.remediation)
                .with_env_overrides(),
        )
        .with_ssh_pool(ssh_pool.clone()),
    );
    let _stale_target_reaper_handle = stale_target_reaper.start();

    // Create daemon context
    let telemetry_storage = match telemetry::default_telemetry_db_path() {
        Ok(path) => match TelemetryStorage::new(&path, 30, 24, 365, 100) {
            Ok(storage) => {
                info!("Telemetry storage initialized at {:?}", path);
                Some(Arc::new(storage))
            }
            Err(e) => {
                warn!(
                    "Failed to initialize telemetry storage at {:?}: {}",
                    path, e
                );
                None
            }
        },
        Err(e) => {
            warn!("Failed to resolve telemetry storage path: {}", e);
            None
        }
    };

    let event_bus = EventBus::new(256);

    let telemetry_store = Arc::new(TelemetryStore::with_event_bus(
        Duration::from_secs(300),
        telemetry_storage.clone(),
        event_bus.clone(),
    ));

    let benchmark_queue = Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5)));
    let (benchmark_scheduler, benchmark_trigger) = BenchmarkScheduler::new(
        SchedulerConfig::default(),
        worker_pool.clone(),
        telemetry_store.clone(),
        event_bus.clone(),
    );
    let benchmark_scheduler = Arc::new(benchmark_scheduler);
    let _benchmark_scheduler_handle = tokio::spawn(benchmark_scheduler.run());
    info!("Benchmark scheduler started");

    // Initialize alert manager for worker health alerting
    let suppress_secs = rch_config
        .alerts
        .suppress_duplicates_secs
        .min(i64::MAX as u64) as i64;

    // Convert webhook config from rch_common to alerts module format
    let webhook_config = rch_config
        .alerts
        .webhook
        .as_ref()
        .map(|w| alerts::WebhookConfig {
            url: w.url.clone(),
            secret: w.secret.clone(),
            timeout_secs: w.timeout_secs,
            retry_count: w.retry_count,
            events: w.events.clone(),
        });

    let cleared_retention_secs = rch_config
        .alerts
        .cleared_retention_secs
        .min(i64::MAX as u64) as i64;

    let alert_config = alerts::AlertConfig {
        enabled: rch_config.alerts.enabled,
        suppress_duplicates: ChronoDuration::seconds(suppress_secs),
        cleared_retention: ChronoDuration::seconds(cleared_retention_secs),
        webhook: webhook_config,
    };
    let alert_manager = Arc::new(alerts::AlertManager::new(alert_config));

    // bd-28xs5: source reconciliation windows/bounds from the central remediation
    // config (remediation.reconciliation) rather than rchd module constants.
    let repo_convergence = Arc::new(
        repo_convergence::RepoConvergenceService::with_reconciliation(
            event_bus.clone(),
            rch_config.remediation.reconciliation,
        ),
    );

    let cancellation_orchestrator = Arc::new(cancellation::CancellationOrchestrator::new(
        cancellation::CancellationConfig::default(),
        event_bus.clone(),
    ));

    // The durable bypass-record store is shared between the bypass recovery
    // service (which reads/writes records) and the DaemonContext (so
    // `handle_worker_enable` can delete a record on operator re-enable). Create
    // it here so both hold the same Arc.
    let bypass_store = Arc::new(Mutex::new(BypassRecordStore::load(
        default_bypass_record_path(),
    )));

    // Durable admin disables (bd-8zxz7): re-apply persisted disables to the
    // freshly-loaded pool BEFORE serving, so an operator disable or a
    // cpu-capability-fault quarantine survives daemon restarts. A record for a
    // worker no longer in workers.toml is inert (kept until an enable removes
    // it, harmless meanwhile).
    let admin_disable_store = Arc::new(Mutex::new(AdminDisableStore::load(
        default_admin_disable_path(),
    )));
    {
        let store = admin_disable_store.lock().await;
        for record in store.all() {
            let worker_id = rch_common::WorkerId::new(&record.worker_id);
            if let Some(worker) = worker_pool.get(&worker_id).await {
                worker.disable(record.reason.clone()).await;
                info!(
                    "Re-applied durable admin disable for worker {} (reason: {})",
                    record.worker_id,
                    record.reason.as_deref().unwrap_or("none recorded"),
                );
            }
        }
    }

    let context = DaemonContext {
        pool: worker_pool.clone(),
        worker_selector: worker_selector.clone(),
        history,
        telemetry: telemetry_store.clone(),
        benchmark_queue: benchmark_queue.clone(),
        benchmark_trigger: benchmark_trigger.clone(),
        events: event_bus.clone(),
        self_test: self_test_service.clone(),
        alert_manager: alert_manager.clone(),
        repo_convergence,
        cancellation: cancellation_orchestrator,
        started_at: Instant::now(),
        socket_path: cli.socket.to_string_lossy().to_string(),
        version: env!("CARGO_PKG_VERSION"),
        pid: std::process::id(),
        queue_timeout_secs: daemon_config.queue.timeout_secs,
        bypass_store: Some(bypass_store.clone()),
        admin_disable_store: Some(admin_disable_store.clone()),
        workers_config_path: cli.workers_config.clone(),
        admission_barrier: Arc::new(RwLock::new(false)),
    };

    // Start active build cleanup background task
    let active_cleanup = cleanup::ActiveBuildCleanup::new(context.clone());
    let _active_cleanup_handle = active_cleanup.start();

    let worker_status_panel = Arc::new(Mutex::new(
        WorkerStatusPanel::new()
            .with_verbose(cli.verbose)
            .with_debug_routing(cli.debug_routing),
    ));
    let metrics_interval = Duration::from_secs(cli.metrics_reset_interval.max(1));
    let metrics_dashboard = Arc::new(Mutex::new(MetricsDashboard::new(metrics_interval)));

    // Health checks get their OWN dedicated ControlMaster pool, independent of
    // the shared build/telemetry `ssh_pool`. The health probe is what opens the
    // circuit that quarantines a worker out of scheduling; routing it through the
    // shared pool means a single wedged/leaked ControlMaster socket false-fails
    // EVERY health probe and can quarantine the whole fleet at once (a trigger of
    // the 2026-07-16 offload meltdown). A separate pool (separate control sockets)
    // keeps a build/telemetry-pool wedge from cascading into fleet-wide bypass,
    // while still giving health checks warm-connection reuse.
    let health_ssh_pool: Option<Arc<rch_common::SshPool>> = if daemon_config.connection_pooling {
        let pool_options = rch_common::SshOptions {
            control_master: true,
            control_persist_idle: Some(Duration::from_secs(60)),
            ..Default::default()
        };
        Some(Arc::new(rch_common::SshPool::new(pool_options)))
    } else {
        None
    };

    // Start health monitor with alert manager integration
    // The health monitor and the telemetry poller both write the authoritative
    // worker circuit; they must share the operator's `[circuit]` settings
    // (previously the monitor silently used built-in defaults, so the
    // configured thresholds only ever reached the selector's read side).
    let health_config = health::HealthConfig {
        circuit: rch_config.circuit.clone(),
        ..health::HealthConfig::default()
    };
    let health_monitor = health::HealthMonitor::new(worker_pool.clone(), health_config)
        .with_status_panel(worker_status_panel.clone())
        .with_alert_manager(alert_manager.clone())
        .with_ssh_pool(health_ssh_pool.clone());
    let health_handle = health_monitor.start();
    info!("Health monitor started with alerting enabled");

    // Start telemetry poller
    let telemetry_poller = TelemetryPoller::new(
        worker_pool.clone(),
        telemetry_store.clone(),
        TelemetryPollerConfig {
            circuit: rch_config.circuit.clone(),
            ..TelemetryPollerConfig::default()
        },
    )
    .with_ssh_pool(ssh_pool.clone());
    let _telemetry_handle = telemetry_poller.start();
    info!("Telemetry poller started");

    // Start daemon-side disk pressure monitor + policy evaluator (bd-vvmd.4.2)
    let disk_pressure_monitor = DiskPressureMonitor::new(
        worker_pool.clone(),
        telemetry_store.clone(),
        DiskPressurePolicyConfig::default(),
    );
    let _disk_pressure_handle = disk_pressure_monitor.start();
    info!("Disk pressure monitor started");

    // Start background convergence loop (bd-vvmd.3.4)
    let convergence_loop = repo_convergence::ConvergenceLoop::new(
        context.repo_convergence.clone(),
        worker_pool.clone(),
        event_bus.clone(),
        repo_convergence::ConvergenceLoopConfig::default(),
    );
    let _convergence_loop_handle = convergence_loop.start();
    info!("Convergence loop started");

    // Start the bypass recovery service (bd-session-history-remediation-ocv9i.1.3):
    // quarantines plainly-unreachable workers into temporary bypass, then probes
    // them (capabilities/disk/load/telemetry) and runs a canary before any
    // auto-rejoin. The durable bypass records persist alongside incidents and are
    // reconciled into live worker lifecycle on startup.
    // bd-28xs5: source recovery knobs from the central remediation config
    // (remediation.auto_rejoin + remediation.telemetry_freshness) rather than
    // rchd-local defaults.
    let bypass_config = BypassRecoveryConfig::from_remediation(&rch_config.remediation);
    let bypass_prober = SshRecoveryProber::new(telemetry_store.clone(), bypass_config.clone());
    let bypass_recovery = BypassRecoveryService::new(
        worker_pool.clone(),
        bypass_store.clone(),
        bypass_prober,
        bypass_config,
    );
    let _bypass_recovery_handle = bypass_recovery.start();
    info!("Bypass recovery service started");

    let metrics_pool = worker_pool.clone();
    let metrics_history = context.history.clone();
    let metrics_selector = worker_selector.clone();
    let metrics_dashboard_handle = metrics_dashboard.clone();
    let mut metrics_handle: Option<tokio::task::JoinHandle<()>> = Some(tokio::spawn(async move {
        let mut ticker = interval(metrics_interval);
        loop {
            ticker.tick().await;
            let mut dashboard = metrics_dashboard_handle.lock().await;
            dashboard
                .emit_update(&metrics_pool, &metrics_history, &metrics_selector)
                .await;
        }
    }));

    // Start background cleanup for drained workers
    let cleanup_pool = worker_pool.clone();
    let mut cleanup_handle: Option<tokio::task::JoinHandle<()>> = Some(tokio::spawn(async move {
        // Check every minute
        let mut ticker = interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            let pruned = cleanup_pool.prune_drained().await;
            if pruned > 0 {
                info!("Background cleanup: pruned {} drained workers", pruned);
            }
        }
    }));

    if let Some(storage) = telemetry_storage {
        let _maintenance = telemetry::start_storage_maintenance(storage);
        info!("Telemetry storage maintenance started");
    }

    // Start HTTP server for metrics/health endpoints (if enabled)
    let _http_handle = if cli.metrics_port > 0 {
        let http_state = http_api::HttpState {
            pool: worker_pool.clone(),
            version: env!("CARGO_PKG_VERSION"),
            started_at: context.started_at,
            pid: context.pid,
        };
        Some(http_api::start_server(cli.metrics_port, http_state).await)
    } else {
        info!("HTTP metrics endpoint disabled (port 0)");
        None
    };

    // Tailnet status API (bd-2f5ms): the socket's /status over TCP for agents
    // and the fleet dashboard on other machines. Off unless configured. A bad
    // [api] section is logged with its fix and the daemon carries on — a
    // dashboard knob must never stop builds.
    let _api_handle = {
        let api_http_state = http_api::HttpState {
            pool: worker_pool.clone(),
            version: env!("CARGO_PKG_VERSION"),
            started_at: context.started_at,
            pid: context.pid,
        };
        match http_api::start_api_server(
            &rch_config.api,
            cli.api_bind.as_deref(),
            cli.api_token_file.as_deref(),
            context.clone(),
            api_http_state,
        )
        .await
        {
            Ok(handle) => handle,
            Err(reason) => {
                error!("Tailnet status API not started: {}", reason);
                None
            }
        }
    };

    let commit_hash = rch_common::build_commit().map(|value| value.to_string());

    // Register request metrics after fallible startup, before accepting clients.
    // Exporter construction configures OTLP; it does not verify connectivity.
    let otel_guard = match metrics::tracing::init_otel() {
        Ok(guard) => Some(guard),
        Err(e) => {
            warn!("Failed to initialize OpenTelemetry: {}", e);
            None
        }
    };
    let otel_enabled = otel_guard
        .as_ref()
        .is_some_and(metrics::tracing::OtelGuard::otel_enabled);

    let banner = DaemonBanner::new(
        env!("CARGO_PKG_VERSION"),
        option_env!("PROFILE").map(|value| value.to_string()),
        option_env!("TARGET").map(|value| value.to_string()),
        commit_hash,
        cli.socket.to_string_lossy().to_string(),
        worker_count,
        total_slots,
        cli.metrics_port,
        true,
        otel_enabled,
        context.pid,
        Local::now(),
        startup_started.elapsed(),
    );
    banner.show();

    // Start config hot-reload watcher (unless disabled)
    let reload_tx = if !cli.no_hot_reload {
        match reload::start_config_watcher(worker_pool.clone(), cli.workers_config.clone()).await {
            Ok((handle, tx)) => {
                info!("Configuration hot-reload enabled");
                // Store handle to keep watcher alive
                let _reload_handle = handle;
                Some(tx)
            }
            Err(e) => {
                warn!("Failed to start config watcher: {}", e);
                None
            }
        }
    } else {
        info!("Configuration hot-reload disabled");
        None
    };

    // Set up SIGHUP handler for manual reload (Unix only)
    #[cfg(unix)]
    let mut sighup = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");
    #[cfg(unix)]
    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");
    #[cfg(unix)]
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");

    // Shutdown channel
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    let mut connections = tokio::task::JoinSet::new();

    // Main accept loop - platform-specific due to SIGHUP handling
    #[cfg(unix)]
    {
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            let ctx = context.clone();
                            let tx = shutdown_tx.clone();
                            connections.spawn(async move {
                                if let Err(e) = api::handle_connection(stream, ctx, tx).await {
                                    if e.downcast_ref::<std::io::Error>()
                                        .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::BrokenPipe)
                                    {
                                        debug!("Client disconnected (broken pipe)");
                                    } else {
                                        warn!("Connection error: {}", e);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            warn!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    break;
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
                _ = sigint.recv() => {
                    info!("SIGINT received, shutting down");
                    break;
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received, shutting down");
                    break;
                }
                _ = sighup.recv() => {
                    info!("SIGHUP received, triggering configuration reload");
                    if let Some(ref tx) = reload_tx {
                        if let Err(e) = tx.send(reload::ReloadMessage::ManualReload).await {
                            warn!("Failed to trigger reload: {}", e);
                        }
                    } else {
                        // Hot-reload disabled, perform inline reload
                        match reload::reload_workers(
                            &worker_pool,
                            cli.workers_config.as_deref(),
                            true,
                        ).await {
                            Ok(result) => {
                                if result.has_changes() {
                                    info!("SIGHUP reload: {} added, {} updated, {} removed",
                                        result.added, result.updated, result.removed);
                                } else {
                                    info!("SIGHUP reload: no configuration changes");
                                }
                            }
                            Err(e) => {
                                warn!("SIGHUP reload failed: {}", e);
                            }
                        }
                    }
                }
                // Monitor background tasks for unexpected termination (panics)
                // Use Option to avoid polling completed handles repeatedly
                result = async { metrics_handle.as_mut().unwrap().await }, if metrics_handle.is_some() => {
                    metrics_handle = None; // Don't poll again
                    match result {
                        Ok(_) => error!("Metrics task unexpectedly terminated"),
                        Err(e) => error!("Metrics task panicked: {}", e),
                    }
                    // Task is non-critical, continue running daemon
                }
                result = async { cleanup_handle.as_mut().unwrap().await }, if cleanup_handle.is_some() => {
                    cleanup_handle = None; // Don't poll again
                    match result {
                        Ok(_) => error!("Cleanup task unexpectedly terminated"),
                        Err(e) => error!("Cleanup task panicked: {}", e),
                    }
                    // Task is non-critical, continue running daemon
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            let ctx = context.clone();
                            let tx = shutdown_tx.clone();
                            connections.spawn(async move {
                                if let Err(e) = api::handle_connection(stream, ctx, tx).await {
                                    if e.downcast_ref::<std::io::Error>()
                                        .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::BrokenPipe)
                                    {
                                        debug!("Client disconnected (broken pipe)");
                                    } else {
                                        warn!("Connection error: {}", e);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            warn!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    break;
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl-C received, shutting down");
                    break;
                }
                // Monitor background tasks for unexpected termination (panics)
                result = async { metrics_handle.as_mut().unwrap().await }, if metrics_handle.is_some() => {
                    metrics_handle = None; // Don't poll again
                    match result {
                        Ok(_) => error!("Metrics task unexpectedly terminated"),
                        Err(e) => error!("Metrics task panicked: {}", e),
                    }
                    // Task is non-critical, continue running daemon
                }
                result = async { cleanup_handle.as_mut().unwrap().await }, if cleanup_handle.is_some() => {
                    cleanup_handle = None; // Don't poll again
                    match result {
                        Ok(_) => error!("Cleanup task unexpectedly terminated"),
                        Err(e) => error!("Cleanup task panicked: {}", e),
                    }
                    // Task is non-critical, continue running daemon
                }
            }
        }
    }

    // The accept loop has stopped, so clients can no longer refresh heartbeats.
    // Stop cancellation before awaiting health probes: a slow probe must not
    // turn a still-running client's quiet build into a false stuck-job signal.
    cleanup::stop_before_shutdown(&mut cleanup_handle, async {
        info!("Stopping health monitor...");
        health_monitor.stop().await;
        let _ = health_handle.await;
    })
    .await;

    drain_connections(&mut connections, Duration::from_secs(1)).await;

    // Abort background tasks that have no cancellation mechanism
    info!("Stopping background tasks...");
    if let Some(handle) = metrics_handle {
        handle.abort();
    }

    // Close the shared SSH connection pool so warm ControlMasters are torn down
    // cleanly on shutdown rather than lingering until their idle timeout.
    if let Some(pool) = &ssh_pool {
        info!("Closing SSH connection pool...");
        if let Err(e) = pool.close_all().await {
            warn!("Error closing SSH connection pool: {}", e);
        }
    }

    // Clean up socket
    if std::path::Path::new(&context.socket_path).exists() {
        let _ = std::fs::remove_file(&context.socket_path);
    }

    // Flush the metric provider while its Tokio transport runtime is alive.
    if let Some(guard) = otel_guard {
        guard.shutdown().await;
    }

    info!("Daemon stopped");
    Ok(())
}

// Global test logging initialization - enables JSONL output for all unit tests
#[cfg(test)]
fn init_test_logging() {
    rch_common::testing::init_global_test_logging();
}

#[cfg(test)]
fn socket_test_dir() -> PathBuf {
    // Remote jobs can set TMPDIR longer than sockaddr_un can represent.
    // Keep private socket paths short and retain them for failure inspection.
    tempfile::Builder::new()
        .prefix("rch-socket-")
        .tempdir_in("/tmp")
        .unwrap()
        .keep()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_startup_honors_config_and_client_environment_precedence() {
        let matches = Cli::command().try_get_matches_from(["rchd"]).unwrap();
        let (socket, client) =
            daemon_socket_for_startup(&matches, "/configured.sock", |_| None).unwrap();
        assert_eq!(socket, PathBuf::from("/configured.sock"));
        assert_eq!(client, "/configured.sock");
        let (socket, client) = daemon_socket_for_startup(&matches, "/configured.sock", |name| {
            (name == "RCH_DAEMON_SOCKET").then(|| "/alias.sock".to_owned())
        })
        .unwrap();
        assert_eq!(socket, PathBuf::from("/alias.sock"));
        assert_eq!(client, "/alias.sock");
        let (socket, client) = daemon_socket_for_startup(&matches, "/configured.sock", |name| {
            Some(if name == "RCH_SOCKET_PATH" { "/canonical.sock" } else { "/alias.sock" }.to_owned())
        })
        .unwrap();
        assert_eq!(socket, PathBuf::from("/canonical.sock"));
        assert_eq!(client, "/canonical.sock");
    }

    #[test]
    fn socket_startup_cli_pin_wins_even_when_equal_to_parser_default() {
        let default = crate::config::default_socket_path();
        for flag in ["--socket", "-s"] {
            let matches = Cli::command()
                .try_get_matches_from([
                    std::ffi::OsStr::new("rchd"),
                    std::ffi::OsStr::new(flag),
                    default.as_os_str(),
                ])
                .unwrap();
            let (socket, client) = daemon_socket_for_startup(&matches, "/configured.sock", |_| {
                Some("/environment.sock".to_owned())
            })
            .unwrap();
            assert_eq!(socket, default);
            assert_eq!(client, "/environment.sock");
        }
    }

    #[test]
    fn socket_startup_invalid_pin_does_not_fall_back_to_another_endpoint() {
        let matches = Cli::command().try_get_matches_from(["rchd"]).unwrap();
        for invalid in ["", "relative.sock", "~/rch.sock", "/", "/tmp/rch\n.sock"] {
            assert!(daemon_socket_for_startup(&matches, invalid, |_| None).is_err());
            assert!(daemon_socket_for_startup(&matches, "/configured.sock", |name| {
                Some(if name == "RCH_SOCKET_PATH" { invalid } else { "/alias.sock" }.to_owned())
            })
            .is_err());
        }
    }

    #[tokio::test]
    async fn socket_binding_preserves_non_socket_entries() {
        let root = socket_test_dir();
        let file = root.join("operator-file");
        std::fs::write(&file, "must survive socket misconfiguration").unwrap();
        let link = root.join("socket-link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let dangling = root.join("dangling-link");
        std::os::unix::fs::symlink(root.join("absent"), &dangling).unwrap();
        for path in [&file, &link, &dangling, &root] {
            assert!(try_bind_daemon_socket(path).await.is_err());
        }
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "must survive socket misconfiguration");
        assert_eq!(std::fs::read_link(&link).unwrap(), file);
        assert_eq!(std::fs::read_link(&dangling).unwrap(), root.join("absent"));
    }

    #[tokio::test]
    async fn connection_drain_waits_for_completed_request() {
        let (finished_tx, mut finished_rx) = tokio::sync::oneshot::channel();
        let mut connections = tokio::task::JoinSet::new();
        connections.spawn(async move {
            tokio::task::yield_now().await;
            finished_tx.send(()).unwrap();
        });
        drain_connections(&mut connections, Duration::from_secs(1)).await;
        assert!(connections.is_empty());
        assert_eq!(finished_rx.try_recv(), Ok(()));
    }

    #[tokio::test]
    async fn connection_drain_runs_pending_request_guards_before_returning() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct ObservationOnDrop(Arc<AtomicBool>);
        impl Drop for ObservationOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let observed = Arc::new(AtomicBool::new(false));
        let observation = observed.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut connections = tokio::task::JoinSet::new();
        connections.spawn(async move {
            let _observation = ObservationOnDrop(observation);
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        drain_connections(&mut connections, Duration::from_millis(5)).await;
        assert!(connections.is_empty());
        assert!(observed.load(Ordering::SeqCst));
    }

    #[test]
    fn isolated_pool_requires_both_a_separate_socket_and_explicit_workers() {
        for shared in [crate::config::default_socket_path(), PathBuf::from("/configured.sock")] {
            let isolated = shared.with_extension("isolated-test.sock");
            let workers = Path::new("/tmp/isolated-workers.toml");
            assert!(!isolated_worker_pool(&shared, None, &shared));
            assert!(!isolated_worker_pool(&shared, Some(workers), &shared));
            assert!(!isolated_worker_pool(&isolated, None, &shared));
            assert!(isolated_worker_pool(&isolated, Some(workers), &shared));
        }
    }
    use rch_common::test_guard;

    fn make_test_telemetry() -> Arc<TelemetryStore> {
        Arc::new(TelemetryStore::new(Duration::from_secs(300), None))
    }

    fn make_test_self_test(pool: workers::WorkerPool) -> Arc<SelfTestService> {
        let history = Arc::new(SelfTestHistory::new(
            crate::self_test::DEFAULT_RUN_CAPACITY,
            crate::self_test::DEFAULT_RESULT_CAPACITY,
        ));
        Arc::new(SelfTestService::new(
            pool,
            SelfTestConfig::default(),
            history,
        ))
    }

    fn make_test_alert_manager() -> Arc<crate::alerts::AlertManager> {
        Arc::new(crate::alerts::AlertManager::new(
            crate::alerts::AlertConfig::default(),
        ))
    }

    fn make_test_cancellation() -> Arc<cancellation::CancellationOrchestrator> {
        Arc::new(cancellation::CancellationOrchestrator::new(
            cancellation::CancellationConfig::default(),
            EventBus::new(16),
        ))
    }

    fn make_test_benchmark_trigger(pool: workers::WorkerPool) -> BenchmarkTriggerHandle {
        let (scheduler, trigger) = BenchmarkScheduler::new(
            SchedulerConfig::default(),
            pool,
            make_test_telemetry(),
            EventBus::new(16),
        );
        let scheduler = Arc::new(scheduler);
        tokio::spawn(scheduler.run());
        trigger
    }

    // =========================================================================
    // test_cli_parsing - CLI argument parsing sanity checks
    // =========================================================================

    #[test]
    fn test_cli_parsing_defaults() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rchd"]).unwrap();

        assert_eq!(cli.socket, crate::config::default_socket_path());
        assert_eq!(cli.history_capacity, 100);
        assert_eq!(cli.metrics_port, 9100);
        assert_eq!(cli.metrics_reset_interval, 300);

        assert!(!cli.verbose);
        assert!(!cli.foreground);
        assert!(!cli.debug_routing);
        assert!(!cli.no_hot_reload);
    }

    #[test]
    fn test_cli_parsing_overrides() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from([
            "rchd",
            "--socket",
            "/tmp/rch-test.sock",
            "--workers-config",
            "/tmp/workers.toml",
            "--history-file",
            "/tmp/history.jsonl",
            "--history-capacity",
            "250",
            "--metrics-port",
            "0",
            "--metrics-reset-interval",
            "60",
            "--debug-routing",
            "--no-hot-reload",
            "--verbose",
            "--foreground",
        ])
        .unwrap();

        assert_eq!(cli.socket, std::path::PathBuf::from("/tmp/rch-test.sock"));
        assert_eq!(
            cli.workers_config,
            Some(std::path::PathBuf::from("/tmp/workers.toml"))
        );
        assert_eq!(
            cli.history_file,
            Some(std::path::PathBuf::from("/tmp/history.jsonl"))
        );
        assert_eq!(cli.history_capacity, 250);
        assert_eq!(cli.metrics_port, 0);
        assert_eq!(cli.metrics_reset_interval, 60);
        assert!(cli.debug_routing);
        assert!(cli.no_hot_reload);
        assert!(cli.verbose);
        assert!(cli.foreground);
    }

    #[tokio::test]
    async fn test_bind_daemon_socket_creates_listener() {
        let _guard = test_guard!();
        let temp_dir = socket_test_dir();
        let socket_path = temp_dir.join("rch.sock");

        let listener = bind_daemon_socket(&socket_path, false).await.unwrap();

        assert!(socket_path.exists());
        drop(listener);
    }

    #[tokio::test]
    async fn test_bind_daemon_socket_refuses_live_listener() {
        let _guard = test_guard!();
        let temp_dir = socket_test_dir();
        let socket_path = temp_dir.join("rch.sock");
        let _existing = UnixListener::bind(&socket_path).unwrap();

        // Use the explicit-flag inner function (managed_by_systemd = false)
        // so this test is deterministic regardless of whether the test
        // runner itself happens to be inside a systemd unit (which would
        // set INVOCATION_ID and make the public bind_daemon_socket wait
        // forever instead of bailing — i.e. the test would hang).
        let error = bind_daemon_socket_with_mode(&socket_path, false, Duration::from_secs(5))
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("refusing to start a second rchd"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn test_bind_daemon_socket_replaces_stale_socket() {
        let _guard = test_guard!();
        let temp_dir = socket_test_dir();
        let socket_path = temp_dir.join("rch.sock");
        let stale_listener = UnixListener::bind(&socket_path).unwrap();
        drop(stale_listener);

        let listener = bind_daemon_socket(&socket_path, false).await.unwrap();

        assert!(socket_path.exists());
        drop(listener);
    }

    /// When systemd-managed and the socket is held by another process,
    /// bind_daemon_socket must WAIT (never returning, never erroring), not
    /// bail. This is the regression test for the css/ts2 restart-storm
    /// (NRestarts → tens of thousands). We use the explicit-flag inner
    /// function to avoid the test having to mutate process-global env vars.
    #[tokio::test]
    async fn test_bind_daemon_socket_waits_when_systemd_managed() {
        let _guard = test_guard!();
        let temp_dir = socket_test_dir();
        let socket_path = temp_dir.join("rch.sock");
        let _holder = UnixListener::bind(&socket_path).unwrap();

        // 50 ms backoff (vs the 5 s production value) so the test is quick.
        // We use timeout to assert the function is still waiting after the
        // bail path would have returned. If the function ever returned (Ok
        // or Err) within the timeout, the wait-loop is broken.
        let result = tokio::time::timeout(
            Duration::from_millis(400),
            bind_daemon_socket_with_mode(&socket_path, true, Duration::from_millis(50)),
        )
        .await;

        assert!(
            result.is_err(),
            "bind_daemon_socket_with_mode returned within the timeout instead \
             of waiting; that means systemd-managed mode would crash-loop. \
             Got: {result:?}"
        );
    }

    /// And once the holder releases the socket, the waiting bind should take
    /// over cleanly — proving the "current owner exits → systemd rchd binds"
    /// transition we depend on in production.
    #[tokio::test]
    async fn test_bind_daemon_socket_takes_over_after_holder_exits() {
        let _guard = test_guard!();
        let temp_dir = socket_test_dir();
        let socket_path = temp_dir.join("rch.sock");
        let holder = UnixListener::bind(&socket_path).unwrap();

        let bind_path = socket_path.clone();
        let bind_task = tokio::spawn(async move {
            bind_daemon_socket_with_mode(&bind_path, true, Duration::from_millis(50)).await
        });

        // Give the waiter a couple of iterations on the held socket, then
        // release it. The waiter should bind on its next loop iteration.
        tokio::time::sleep(Duration::from_millis(150)).await;
        drop(holder);
        // The stale-socket file may still be present — that's fine, the
        // waiter's try_bind_daemon_socket will probe (stale) → remove → bind.

        let listener = tokio::time::timeout(Duration::from_secs(2), bind_task)
            .await
            .expect("timed out waiting for bind takeover")
            .expect("bind_task panicked")
            .expect("bind_daemon_socket_with_mode returned Err");
        drop(listener);
    }

    // =========================================================================
    // test_daemon_context_creation - DaemonContext initialization tests
    // =========================================================================

    #[tokio::test]
    async fn test_daemon_context_creation_basic() {
        init_test_logging();

        let pool = workers::WorkerPool::new();
        let selector = Arc::new(WorkerSelector::new());
        let history = Arc::new(BuildHistory::new(100));
        let started_at = Instant::now();

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history: history.clone(),
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
                EventBus::new(16),
            )),
            cancellation: make_test_cancellation(),
            started_at,
            socket_path: "/tmp/test.sock".to_string(),
            version: "0.1.0-test",
            pid: std::process::id(),
            queue_timeout_secs: 300,
            bypass_store: None,
            admin_disable_store: None,
            workers_config_path: None,
            admission_barrier: Arc::new(RwLock::new(false)),
        };

        assert_eq!(context.socket_path, "/tmp/test.sock");
        assert_eq!(context.version, "0.1.0-test");
        assert!(context.pid > 0);
        assert!(context.pool.is_empty());
        assert!(context.history.is_empty());
    }

    #[tokio::test]
    async fn test_daemon_context_with_workers() {
        init_test_logging();

        let pool = workers::WorkerPool::new();

        // Add a worker
        let worker_config = rch_common::WorkerConfig {
            id: rch_common::WorkerId::new("test-worker"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec!["rust".to_string()],
        };
        pool.add_worker(worker_config).await;

        let selector = Arc::new(WorkerSelector::new());
        let history = Arc::new(BuildHistory::new(100));
        let started_at = Instant::now();

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history,
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
                EventBus::new(16),
            )),
            cancellation: make_test_cancellation(),
            started_at,
            socket_path: rch_common::default_socket_path(),
            version: env!("CARGO_PKG_VERSION"),
            pid: std::process::id(),
            queue_timeout_secs: 300,
            bypass_store: None,
            admin_disable_store: None,
            workers_config_path: None,
            admission_barrier: Arc::new(RwLock::new(false)),
        };

        assert_eq!(context.pool.len(), 1);
        let workers = context.pool.all_workers().await;
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].config.read().await.id.as_str(), "test-worker");
    }

    #[tokio::test]
    async fn test_daemon_context_with_history() {
        init_test_logging();

        let pool = workers::WorkerPool::new();
        let selector = Arc::new(WorkerSelector::new());
        let history = Arc::new(BuildHistory::new(100));

        // Add a build record
        let record = rch_common::BuildRecord {
            id: 1,
            started_at: "2024-01-01T00:00:00Z".to_string(),
            completed_at: "2024-01-01T00:01:00Z".to_string(),
            project_id: "test-project".to_string(),
            worker_id: Some("worker-1".to_string()),
            command: "cargo build".to_string(),
            exit_code: 0,
            duration_ms: 60000,
            location: rch_common::BuildLocation::Remote,
            bytes_transferred: Some(1024),
            timing: None,
            cancellation: None,
        };
        history.record(record);

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history,
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
                EventBus::new(16),
            )),
            cancellation: make_test_cancellation(),
            started_at: Instant::now(),
            socket_path: rch_common::default_socket_path(),
            version: "0.1.0",
            pid: 12345,
            queue_timeout_secs: 300,
            bypass_store: None,
            admin_disable_store: None,
            workers_config_path: None,
            admission_barrier: Arc::new(RwLock::new(false)),
        };

        assert_eq!(context.history.len(), 1);
        let recent = context.history.recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].project_id, "test-project");
    }

    #[tokio::test]
    async fn test_daemon_context_clone() {
        init_test_logging();

        let pool = workers::WorkerPool::new();
        let selector = Arc::new(WorkerSelector::new());
        let history = Arc::new(BuildHistory::new(100));

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history: history.clone(),
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
                EventBus::new(16),
            )),
            cancellation: make_test_cancellation(),
            started_at: Instant::now(),
            socket_path: rch_common::default_socket_path(),
            version: "0.1.0",
            pid: 1234,
            queue_timeout_secs: 300,
            bypass_store: None,
            admin_disable_store: None,
            workers_config_path: None,
            admission_barrier: Arc::new(RwLock::new(false)),
        };

        // Clone the context
        let context_clone = context.clone();

        // Both should share the same underlying data
        assert_eq!(context.socket_path, context_clone.socket_path);
        assert_eq!(context.version, context_clone.version);
        assert_eq!(context.pid, context_clone.pid);

        // Add a worker via original - should be visible in clone
        let worker_config = rch_common::WorkerConfig {
            id: rch_common::WorkerId::new("shared-worker"),
            host: "192.168.1.200".to_string(),
            user: "admin".to_string(),
            identity_file: "~/.ssh/key".to_string(),
            total_slots: 4,
            priority: 50,
            tags: vec![],
        };
        context.pool.add_worker(worker_config).await;

        // Clone should see the worker
        assert_eq!(context_clone.pool.len(), 1);
    }

    #[tokio::test]
    async fn test_daemon_context_uptime() {
        init_test_logging();

        let pool = workers::WorkerPool::new();
        let selector = Arc::new(WorkerSelector::new());
        let history = Arc::new(BuildHistory::new(100));
        let started_at = Instant::now();

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history,
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
                EventBus::new(16),
            )),
            cancellation: make_test_cancellation(),
            started_at,
            socket_path: rch_common::default_socket_path(),
            version: "0.1.0",
            pid: 1234,
            queue_timeout_secs: 300,
            bypass_store: None,
            admin_disable_store: None,
            workers_config_path: None,
            admission_barrier: Arc::new(RwLock::new(false)),
        };

        // Wait a small amount
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Uptime should be measurable
        let uptime = context.started_at.elapsed();
        assert!(uptime.as_millis() >= 10);
    }

    #[tokio::test]
    async fn test_daemon_context_multiple_workers() {
        init_test_logging();

        let pool = workers::WorkerPool::new();

        // Add multiple workers
        for i in 1..=5 {
            let worker_config = rch_common::WorkerConfig {
                id: rch_common::WorkerId::new(format!("worker-{}", i)),
                host: format!("192.168.1.{}", 100 + i),
                user: "ubuntu".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: (i * 4) as u32,
                priority: 100 - i as u32,
                tags: vec![format!("tag-{}", i)],
            };
            pool.add_worker(worker_config).await;
        }

        let selector = Arc::new(WorkerSelector::new());
        let history = Arc::new(BuildHistory::new(100));

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history,
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
                EventBus::new(16),
            )),
            cancellation: make_test_cancellation(),
            started_at: Instant::now(),
            socket_path: rch_common::default_socket_path(),
            version: "0.1.0",
            pid: 1234,
            queue_timeout_secs: 300,
            bypass_store: None,
            admin_disable_store: None,
            workers_config_path: None,
            admission_barrier: Arc::new(RwLock::new(false)),
        };

        assert_eq!(context.pool.len(), 5);
    }

    // =========================================================================
    // test_daemon_build_history - BuildHistory integration tests
    // =========================================================================

    #[test]
    fn test_daemon_build_history_capacity() {
        let _guard = test_guard!();
        init_test_logging();

        // Test that BuildHistory respects capacity limits
        let history = BuildHistory::new(3);

        for i in 1..=5 {
            let record = rch_common::BuildRecord {
                id: i,
                started_at: format!("2024-01-01T00:0{}:00Z", i),
                completed_at: format!("2024-01-01T00:0{}:30Z", i),
                project_id: "test-project".to_string(),
                worker_id: None,
                command: format!("cargo build {}", i),
                exit_code: 0,
                duration_ms: 1000,
                location: rch_common::BuildLocation::Local,
                bytes_transferred: None,
                timing: None,
                cancellation: None,
            };
            history.record(record);
        }

        // Should only retain last 3 entries
        assert_eq!(history.len(), 3);
        let recent = history.recent(10);
        assert_eq!(recent[0].id, 5); // Most recent
        assert_eq!(recent[2].id, 3); // Oldest retained
    }

    #[test]
    fn test_daemon_build_history_stats() {
        let _guard = test_guard!();
        init_test_logging();

        let history = BuildHistory::new(100);

        // Add mixed success/failure, remote/local builds
        let records = vec![
            (1, 0, rch_common::BuildLocation::Remote, 1000),
            (2, 0, rch_common::BuildLocation::Remote, 2000),
            (3, 1, rch_common::BuildLocation::Local, 500),
            (4, 0, rch_common::BuildLocation::Local, 1500),
        ];

        for (id, exit_code, location, duration_ms) in records {
            let record = rch_common::BuildRecord {
                id,
                started_at: "2024-01-01T00:00:00Z".to_string(),
                completed_at: "2024-01-01T00:00:30Z".to_string(),
                project_id: "test".to_string(),
                worker_id: None,
                command: "cargo test".to_string(),
                exit_code,
                duration_ms,
                location,
                bytes_transferred: None,
                timing: None,
                cancellation: None,
            };
            history.record(record);
        }

        let stats = history.stats();
        assert_eq!(stats.total_builds, 4);
        assert_eq!(stats.success_count, 3);
        assert_eq!(stats.failure_count, 1);
        assert_eq!(stats.remote_count, 2);
        assert_eq!(stats.local_count, 2);
        assert_eq!(stats.avg_duration_ms, 1250); // (1000+2000+500+1500)/4
    }
}

#[cfg(test)]
mod systemd_singleton_tests {
    use super::*;

    #[test]
    fn cgroup_detects_rchd_service_unit() {
        assert!(cgroup_contains_rchd_unit(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/rchd.service"
        ));
    }

    #[test]
    fn cgroup_rejects_session_and_agent_scopes() {
        assert!(!cgroup_contains_rchd_unit(
            "0::/user.slice/user-1000.slice/session-18017.scope"
        ));
        assert!(!cgroup_contains_rchd_unit(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/some-agent.scope"
        ));
    }
}

#[cfg(test)]
mod launchd_singleton_tests {
    use super::*;

    // Scripted protocol fixtures exercise error/ordering contracts. These are
    // not evidence of live launchd integration; native validation is separate.
    fn manager_fixture(body: &str) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let retained = tempfile::tempdir().unwrap().keep();
        let program = retained.join("manager");
        let calls = retained.join("calls");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\n{body}\n",
                shell_escape::escape(calls.to_string_lossy())
            ),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        (program, calls)
    }

    async fn resolve_fixture(program: &Path, custom: bool) -> Result<launchd::Ownership> {
        launchd::resolve(
            program,
            "com.rch.daemon",
            501,
            41,
            custom,
            tokio::time::Instant::now() + Duration::from_secs(3),
        )
        .await
    }

    #[tokio::test]
    async fn launchd_unknown_listing_uses_verified_domain_without_forced_restart() {
        let (program, calls) = manager_fixture(
            "case \"$*\" in\nlist) echo 'Could not enumerate';;\n'print gui/501/com.rch.daemon') exit 0;;\n'print user/501/com.rch.daemon') exit 113;;\n'kickstart -p gui/501/com.rch.daemon') echo 41;;\n*) exit 99;;\nesac",
        );
        assert_eq!(
            resolve_fixture(&program, false).await.unwrap(),
            launchd::Ownership::Managed
        );
        assert_eq!(
            std::fs::read_to_string(calls).unwrap(),
            "list\nprint gui/501/com.rch.daemon\nprint user/501/com.rch.daemon\nkickstart -p gui/501/com.rch.daemon\n"
        );
    }

    #[tokio::test]
    async fn launchd_only_proven_absence_allows_standalone() {
        for (listing, allowed) in [
            ("printf 'PID Status Label\\n'", true),
            ("echo 'enumeration failed'", false),
        ] {
            let (program, calls) = manager_fixture(&format!(
                "case \"$1\" in\nlist) {listing};;\nprint) exit 113;;\n*) exit 99;;\nesac"
            ));
            let result = resolve_fixture(&program, false).await;
            if allowed {
                assert_eq!(result.unwrap(), launchd::Ownership::Standalone);
            } else {
                assert!(result.is_err());
            }
            assert!(
                !std::fs::read_to_string(calls)
                    .unwrap()
                    .contains("kickstart")
            );
        }
    }

    #[tokio::test]
    async fn launchd_ambiguous_domains_and_custom_socket_never_start_a_service() {
        for custom in [false, true] {
            let (program, calls) = manager_fixture(
                "case \"$1\" in\nlist) printf 'PID Status Label\\n';;\nprint) exit 0;;\n*) exit 99;;\nesac",
            );
            assert!(resolve_fixture(&program, custom).await.is_err());
            assert!(
                !std::fs::read_to_string(calls)
                    .unwrap()
                    .contains("kickstart")
            );
        }
        let (program, calls) =
            manager_fixture("printf 'PID Status Label\\n42 0 com.rch.daemon\\n'");
        assert!(resolve_fixture(&program, true).await.is_err());
        assert_eq!(std::fs::read_to_string(calls).unwrap(), "list\n");
    }

    #[tokio::test]
    async fn launchd_live_owner_is_not_restarted_and_stopped_owner_is_started_once() {
        let (program, calls) =
            manager_fixture("printf 'PID Status Label\\n42 0 com.rch.daemon\\n'");
        assert_eq!(
            resolve_fixture(&program, false).await.unwrap(),
            launchd::Ownership::Delegated
        );
        assert_eq!(std::fs::read_to_string(calls).unwrap(), "list\n");
        let (program, calls) = manager_fixture(
            "case \"$1\" in\nlist) if [ -f \"$0.started\" ]; then printf 'PID Status Label\\n42 0 com.rch.daemon\\n'; else printf 'PID Status Label\\n- 0 com.rch.daemon\\n'; fi;;\nstart) printf started > \"$0.started\";;\n*) exit 99;;\nesac",
        );
        assert_eq!(
            resolve_fixture(&program, false).await.unwrap(),
            launchd::Ownership::Delegated
        );
        assert_eq!(
            std::fs::read_to_string(calls).unwrap(),
            "list\nstart com.rch.daemon\nlist\n"
        );
    }

    #[tokio::test]
    async fn launchd_failed_start_or_invalid_pid_never_authorizes_binding() {
        for action in ["exit 7", "echo 0", "echo 'wrong-target: 41'"] {
            let (program, _) = manager_fixture(&format!(
                "case \"$*\" in\nlist) printf 'PID Status Label\\n';;\n'print gui/501/com.rch.daemon') exit 0;;\n'print user/501/com.rch.daemon') exit 113;;\n'kickstart -p gui/501/com.rch.daemon') {action};;\n*) exit 99;;\nesac"
            ));
            assert!(resolve_fixture(&program, false).await.is_err());
        }
    }

    #[tokio::test]
    async fn launchd_expired_budget_cannot_execute_a_manager_action() {
        let (program, calls) = manager_fixture("exit 0");
        assert!(
            launchd::command(
                &program,
                &["start", "com.rch.daemon"],
                tokio::time::Instant::now()
            )
            .await
            .is_err()
        );
        assert!(!calls.exists());
    }

    #[tokio::test]
    async fn launchd_excess_output_is_refused_before_the_command_deadline() {
        let result = timeout(
            Duration::from_secs(3),
            launchd::command(
                Path::new("/bin/cat"),
                &["/dev/zero"],
                tokio::time::Instant::now() + Duration::from_secs(10),
            ),
        )
        .await
        .expect("oversized output must not wait for the ten-second deadline");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("output exceeded limit")
        );
    }

    #[test]
    fn launchd_table_distinguishes_absence_stopped_and_live_exact_labels() {
        let table = "PID\tStatus\tLabel\n-\t0\tcom.rch.daemon.extra\n41\t-15\tother\n";
        assert_eq!(launchd::listed_pid(table, "com.rch.daemon").unwrap(), None);
        assert_eq!(launchd::listed_pid(table, "other").unwrap(), Some(Some(41)));
        assert_eq!(
            launchd::listed_pid(table, "com.rch.daemon.extra").unwrap(),
            Some(None)
        );
        assert_eq!(
            launchd::listed_pid("PID Status Label\n", "com.rch.daemon").unwrap(),
            None
        );
        assert_eq!(launchd::ownership(41, 41), launchd::Ownership::Managed);
        assert_eq!(launchd::ownership(42, 41), launchd::Ownership::Delegated);
    }

    #[test]
    fn launchd_table_refuses_failed_or_ambiguous_enumeration() {
        for table in [
            "",
            "Could not connect to launchd",
            "PID Label Status\n",
            "PID Status Label\n0 0 com.rch.daemon\n",
            "PID Status Label\n-1 0 com.rch.daemon\n",
            "PID Status Label\n1 invalid com.rch.daemon\n",
            "PID Status Label\n1 0 com.rch.daemon trailing\n",
            "PID Status Label\n- 0 com.rch.daemon\n1 0 com.rch.daemon\n",
            "PID Status Label\n1 0 com.rch.daemon\nmalformed unrelated row\n",
        ] {
            assert!(
                launchd::listed_pid(table, "com.rch.daemon").is_err(),
                "accepted {table:?}"
            );
        }
    }

    #[test]
    fn launchd_kickstart_accepts_only_a_positive_pid_for_the_requested_target() {
        let target = "gui/501/com.rch.daemon";
        assert_eq!(launchd::kickstart_pid("42\n", target).unwrap(), 42);
        assert_eq!(
            launchd::kickstart_pid("gui/501/com.rch.daemon: 42\n", target).unwrap(),
            42
        );
        for output in [
            "",
            "0",
            "-42",
            "42\n43",
            "other: 42",
            "failed 42",
            "4294967296",
        ] {
            assert!(launchd::kickstart_pid(output, target).is_err());
        }
    }

    #[tokio::test]
    async fn launchd_command_deadline_reaps_its_owned_child() {
        let retained = tempfile::tempdir().unwrap().keep();
        let pid_path = retained.join("manager.pid");
        let command = format!(
            "printf '%s' \"$$\" > {}; exec sleep 60",
            shell_escape::escape(pid_path.to_string_lossy())
        );
        let result = launchd::command(
            Path::new("/bin/sh"),
            &["-c", &command],
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("deadline expired"));
        let pid: i32 = std::fs::read_to_string(&pid_path).unwrap().parse().unwrap();
        assert_eq!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH)
        );
    }

    #[tokio::test]
    async fn launchd_command_preserves_failure_output() {
        let output = launchd::command(
            Path::new("/bin/sh"),
            &["-c", "printf stdout; printf stderr >&2; exit 7"],
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"stdout");
        assert_eq!(output.stderr, b"stderr");
    }

    #[tokio::test]
    async fn launchd_managed_owner_waits_without_replacing_a_live_socket() {
        let retained = socket_test_dir();
        let socket = retained.join("rch.sock");
        let holder = UnixListener::bind(&socket).unwrap();
        let managed = launchd::ownership(std::process::id(), std::process::id())
            == launchd::Ownership::Managed;
        assert!(
            timeout(
                Duration::from_millis(200),
                bind_daemon_socket(&socket, managed)
            )
            .await
            .is_err()
        );
        let connection = UnixStream::connect(&socket).await.unwrap();
        assert!(
            timeout(Duration::from_secs(1), holder.accept())
                .await
                .is_ok()
        );
        drop(connection);
        assert!(socket.exists());
    }

    /// A real, uniquely named GUI-domain launchd job executes this same test
    /// binary. No shared RCH service is changed; all files and sockets remain
    /// retained, and the parent unloads its job before reporting any failure.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn launchd_native_private_job_preserves_pid_and_waits_for_socket() -> Result<()> {
        async fn wait_for(path: &Path) -> Result<()> {
            timeout(Duration::from_secs(15), async {
                while !path.try_exists()? {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .with_context(|| format!("waiting for {}", path.display()))?
        }

        async fn manager(retained: &Path, args: &[&str]) -> Result<std::process::Output> {
            use std::io::Write;
            let output = launchd::command(
                Path::new("/bin/launchctl"),
                args,
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await?;
            let mut log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(retained.join("manager.log"))?;
            writeln!(log, "launchctl {args:?}: {}", output.status)?;
            log.write_all(&output.stdout)?;
            log.write_all(&output.stderr)?;
            Ok(output)
        }

        fn xml(value: &str) -> String {
            value
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        }

        let uid = nix::unistd::Uid::effective().as_raw();
        if let Ok(label) = std::env::var("RCH_LAUNCHD_NATIVE_LABEL") {
            anyhow::ensure!(
                label.starts_with("com.rch.native-test."),
                "unexpected private label"
            );
            let retained = PathBuf::from(std::env::var("RCH_LAUNCHD_NATIVE_DIR")?);
            let ownership = launchd::resolve(
                Path::new("/bin/launchctl"),
                &label,
                uid,
                std::process::id(),
                false,
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await?;
            anyhow::ensure!(
                ownership == launchd::Ownership::Managed,
                "job did not recognize its actual managed PID"
            );
            std::fs::write(
                retained.join("managed.pending"),
                std::process::id().to_string(),
            )?;
            std::fs::rename(
                retained.join("managed.pending"),
                retained.join("managed.pid"),
            )?;
            let listener = timeout(
                Duration::from_secs(15),
                bind_daemon_socket(&retained.join("rch.sock"), true),
            )
            .await??;
            std::fs::write(
                retained.join("bound.pending"),
                std::process::id().to_string(),
            )?;
            std::fs::rename(retained.join("bound.pending"), retained.join("bound.pid"))?;
            wait_for(&retained.join("parent-finished")).await?;
            drop(listener);
            return Ok(());
        }

        // /tmp keeps Unix socket names below macOS's sockaddr_un length limit.
        let retained = tempfile::Builder::new()
            .prefix("rch-launchd-")
            .tempdir_in("/tmp")?
            .keep();
        let label = format!("com.rch.native-test.{}", uuid::Uuid::new_v4());
        // A readable user domain does not imply bootstrap permission. The
        // GUI domain is where the installed per-user RCH LaunchAgent runs.
        let domain = format!("gui/{uid}");
        let domain_probe = manager(&retained, &["print", &domain]).await?;
        anyhow::ensure!(
            domain_probe.status.success(),
            "native fixture requires the user's GUI domain: {domain_probe:?}"
        );
        let target = format!("{domain}/{label}");
        let absent = manager(&retained, &["print", &target]).await?;
        anyhow::ensure!(
            absent.status.code() == Some(113),
            "private job must not exist before bootstrap: {absent:?}"
        );
        let socket = retained.join("rch.sock");
        let holder = UnixListener::bind(&socket)?;
        let plist = retained.join("job.plist");
        let executable = std::env::current_exe()?;
        std::fs::write(
            &plist,
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n\
             <key>Label</key><string>{label}</string>\n\
             <key>ProgramArguments</key><array><string>{executable}</string>\n\
             <string>--exact</string><string>launchd_singleton_tests::launchd_native_private_job_preserves_pid_and_waits_for_socket</string>\n\
             <string>--nocapture</string><string>--test-threads=1</string></array>\n\
             <key>RunAtLoad</key><true/>\n\
             <key>EnvironmentVariables</key><dict>\n\
             <key>RCH_LAUNCHD_NATIVE_LABEL</key><string>{label}</string>\n\
             <key>RCH_LAUNCHD_NATIVE_DIR</key><string>{directory}</string></dict>\n\
             <key>StandardOutPath</key><string>{directory}/child.stdout</string>\n\
             <key>StandardErrorPath</key><string>{directory}/child.stderr</string>\n\
             </dict></plist>\n",
                executable = xml(executable
                    .to_str()
                    .context("test executable is not UTF-8")?),
                directory = xml(retained
                    .to_str()
                    .context("retained directory is not UTF-8")?),
            ),
        )?;
        eprintln!(
            "native launchd fixture retained at {} ({target})",
            retained.display()
        );

        // Every fallible assertion after bootstrap stays inside this Result so
        // even partial bootstrap or child failure reaches the owned bootout.
        let result: Result<()> = async {
            let started = manager(
                &retained,
                &[
                    "bootstrap",
                    &domain,
                    plist.to_str().context("plist path is not UTF-8")?,
                ],
            )
            .await?;
            anyhow::ensure!(started.status.success(), "bootstrap failed: {started:?}");
            wait_for(&retained.join("managed.pid")).await?;
            let pid: u32 = std::fs::read_to_string(retained.join("managed.pid"))?.parse()?;
            tokio::time::sleep(Duration::from_millis(200)).await;
            anyhow::ensure!(
                !retained.join("bound.pid").exists(),
                "managed child replaced the held listener"
            );
            let connection = UnixStream::connect(&socket).await?;
            timeout(Duration::from_secs(1), holder.accept()).await??;
            drop(connection);
            for _ in 0..2 {
                let output = manager(&retained, &["kickstart", "-p", &target]).await?;
                anyhow::ensure!(output.status.success(), "kickstart failed: {output:?}");
                anyhow::ensure!(
                    launchd::kickstart_pid(std::str::from_utf8(&output.stdout)?, &target)? == pid,
                    "non-forced kickstart changed the managed PID"
                );
            }
            anyhow::ensure!(
                launchd::resolve(
                    Path::new("/bin/launchctl"),
                    &label,
                    uid,
                    std::process::id(),
                    false,
                    tokio::time::Instant::now() + Duration::from_secs(5)
                )
                .await?
                    == launchd::Ownership::Delegated,
                "parent must delegate to its live private job"
            );
            // Preserve the old socket inode instead of deleting it. The child
            // sees the active pathname become absent and binds on its retry.
            std::fs::rename(&socket, retained.join("held-socket.retained"))?;
            drop(holder);
            wait_for(&retained.join("bound.pid")).await?;
            anyhow::ensure!(
                std::fs::read_to_string(retained.join("bound.pid"))?.parse::<u32>()? == pid,
                "takeover changed PID"
            );
            let connection = UnixStream::connect(&socket).await?;
            drop(connection);
            std::fs::write(retained.join("parent-finished"), "done")?;
            Ok(())
        }
        .await;
        let cleanup = manager(&retained, &["bootout", &target]).await;
        let absent = manager(&retained, &["print", &target]).await;
        if result.is_err() {
            eprintln!(
                "native fixture failure: {result:?}; bootout: {cleanup:?}; absence: {absent:?}"
            );
        }
        result?;
        let cleanup = cleanup?;
        anyhow::ensure!(
            cleanup.status.success(),
            "private bootout failed: {cleanup:?}"
        );
        let absent = absent?;
        anyhow::ensure!(
            absent.status.code() == Some(113),
            "private job still registered: {absent:?}"
        );
        Ok(())
    }
}
