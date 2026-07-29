//! `rch fleet doctor --reliability` — fleet-wide reliability fan-out.
//!
//! Runs `rch doctor --reliability --json` on every configured worker over SSH
//! in parallel, then aggregates the per-worker verdicts into a single
//! fleet-level envelope. The fleet verdict is the WORST per-worker verdict, and
//! an `unreachable` worker counts as `failing` (you cannot prove a worker you
//! could not reach is healthy).
//!
//! Scope (per bead t29): subcommand surface, parallel fan-out with bounded
//! concurrency + per-worker timeout, worst-verdict aggregation, per-worker
//! drill-down, `--workers` subset, `--scope` forwarding, and the `--fix`
//! safety gate (`--fleet-confirm`). `--watch`/webhook compounding is tracked
//! as follow-up.

use std::time::{Duration, Instant};

use anyhow::Result;
use futures::stream::{self, StreamExt};
use rch_common::{ApiResponse, WorkerConfig};
use serde::Serialize;
use uuid::Uuid;

use crate::fleet::ssh::SshExecutor;
use crate::ui::context::OutputContext;

/// Maximum simultaneous SSH sessions during fan-out (protects the SSH pool /
/// remote sshd from a thundering herd on large fleets).
const MAX_CONCURRENT_PROBES: usize = 16;

/// Default per-worker probe timeout.
const DEFAULT_WORKER_TIMEOUT_SECS: u64 = 10;

/// Verdict tokens, matching the single-worker doctor's `summary.overall`
/// (`snake_case`). `unreachable` is fleet-doctor-only.
const VERDICT_HEALTHY: &str = "healthy";
const VERDICT_DEGRADED: &str = "degraded";
const VERDICT_FAILING: &str = "failing";
const VERDICT_UNREACHABLE: &str = "unreachable";

/// Options for a fleet reliability run.
#[derive(Debug, Clone)]
pub struct FleetDoctorOptions {
    /// Probe scopes forwarded to each worker (`["all"]` = full suite).
    pub scope: Vec<String>,
    /// Apply remediations (requires `fleet_confirm`).
    pub fix: bool,
    /// Safety gate that must accompany `fix` to actually execute.
    pub fleet_confirm: bool,
    /// Keep fixing other workers after one worker's fix fails.
    pub continue_on_failure: bool,
    /// Restrict the run to a comma-separated worker name subset.
    pub workers: Option<String>,
    /// Per-worker timeout in seconds.
    pub worker_timeout_secs: u64,
}

impl Default for FleetDoctorOptions {
    fn default() -> Self {
        Self {
            scope: vec!["all".to_string()],
            fix: false,
            fleet_confirm: false,
            continue_on_failure: false,
            workers: None,
            worker_timeout_secs: DEFAULT_WORKER_TIMEOUT_SECS,
        }
    }
}

/// One worker's contribution to the fleet report.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PerWorkerEntry {
    /// Worker id (matches `workers.toml`).
    pub worker: String,
    /// `healthy` / `degraded` / `failing` / `unreachable`.
    pub overall: String,
    /// Raw per-worker diagnostics (passed through from the worker's doctor
    /// envelope). Empty for healthy or unreachable workers.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub diagnostics: Vec<serde_json::Value>,
    /// Populated only when `overall == "unreachable"`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ssh_error: Option<String>,
    /// Wall-clock time spent probing this worker.
    pub duration_ms: u64,
}

/// Fleet-level rollup counts.
#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct FleetSummary {
    pub configured_workers: usize,
    /// Workers that returned a verdict (= attempted − unreachable).
    pub probed_workers: usize,
    pub healthy_workers: usize,
    pub degraded_workers: usize,
    pub failing_workers: usize,
    pub unreachable_workers: usize,
}

/// The `data` payload of the fleet doctor envelope.
#[derive(Debug, Clone, Serialize)]
pub struct FleetDoctorResponse {
    pub schema_version: String,
    pub scope: Vec<String>,
    /// Worst per-worker verdict (unreachable folds into `failing`).
    pub overall: String,
    pub fleet: FleetSummary,
    pub per_worker: Vec<PerWorkerEntry>,
    pub request_id: String,
}

/// Verdict severity for worst-wins comparison. Unreachable ranks at the top
/// because an unverifiable worker is at least as bad as a failing one.
fn verdict_severity(verdict: &str) -> u8 {
    match verdict {
        VERDICT_HEALTHY => 0,
        VERDICT_DEGRADED => 1,
        VERDICT_FAILING => 2,
        VERDICT_UNREACHABLE => 3,
        // Unknown tokens are treated as failing — never silently healthy.
        _ => 2,
    }
}

/// Map a worst-severity back to the fleet verdict vocabulary. Unreachable
/// (severity 3) folds into `failing` for the headline verdict.
fn fleet_verdict_from_severity(severity: u8) -> &'static str {
    match severity {
        0 => VERDICT_HEALTHY,
        1 => VERDICT_DEGRADED,
        _ => VERDICT_FAILING,
    }
}

/// Aggregate per-worker entries into `(fleet_verdict, summary)`.
///
/// `configured` is the number of workers in `workers.toml` (may exceed
/// `entries.len()` when a `--workers` subset is used).
pub fn aggregate(configured: usize, entries: &[PerWorkerEntry]) -> (String, FleetSummary) {
    let mut summary = FleetSummary {
        configured_workers: configured,
        ..FleetSummary::default()
    };
    let mut worst = 0u8;
    for entry in entries {
        match entry.overall.as_str() {
            VERDICT_HEALTHY => summary.healthy_workers += 1,
            VERDICT_DEGRADED => summary.degraded_workers += 1,
            VERDICT_UNREACHABLE => summary.unreachable_workers += 1,
            // failing + any unknown token
            _ => summary.failing_workers += 1,
        }
        worst = worst.max(verdict_severity(&entry.overall));
    }
    summary.probed_workers = entries.len() - summary.unreachable_workers;
    (fleet_verdict_from_severity(worst).to_string(), summary)
}

/// Select the workers to probe from the full config, honoring an optional
/// comma-separated `--workers` filter. Returns `(selected, unknown_names)`;
/// unknown names are reported, not fatal.
pub fn select_workers<'a>(
    all: &'a [WorkerConfig],
    filter: Option<&str>,
) -> (Vec<&'a WorkerConfig>, Vec<String>) {
    let Some(spec) = filter else {
        return (all.iter().collect(), Vec::new());
    };
    let mut selected = Vec::new();
    let mut unknown = Vec::new();
    for name in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match all.iter().find(|w| w.id.as_str() == name || w.host == name) {
            Some(worker) => selected.push(worker),
            None => unknown.push(name.to_string()),
        }
    }
    (selected, unknown)
}

/// Build the remote `rch doctor` command line for one worker.
fn build_remote_command(opts: &FleetDoctorOptions) -> String {
    let mut cmd = String::from("rch doctor --reliability --json");
    // Forward a non-default scope so an operator can run a fleet-wide narrow
    // check. `["all"]` is the implicit default, so omit it.
    let is_all = opts.scope.is_empty() || (opts.scope.len() == 1 && opts.scope[0] == "all");
    if !is_all {
        cmd.push_str(" --scope=");
        cmd.push_str(&opts.scope.join(","));
    }
    // Only forward --fix when the operator has explicitly confirmed fleet-wide
    // application. Without confirmation the remote runs check-only (a preview).
    if opts.fix && opts.fleet_confirm {
        cmd.push_str(" --fix");
    }
    cmd
}

/// Construct an `unreachable` entry for a worker that could not be probed.
fn unreachable_entry(worker: &str, error: String, started: Instant) -> PerWorkerEntry {
    PerWorkerEntry {
        worker: worker.to_string(),
        overall: VERDICT_UNREACHABLE.to_string(),
        diagnostics: Vec::new(),
        ssh_error: Some(error),
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

/// Parse a worker's `rch doctor --reliability --json` stdout into an entry.
/// The doctor envelope is `{ "command": ..., "data": { "summary": { "overall" },
/// "diagnostics": [...] } }` (see `ApiResponse::ok("doctor.reliability", ..)`).
fn parse_worker_output(worker: &str, stdout: &str, started: Instant) -> PerWorkerEntry {
    let duration_ms = started.elapsed().as_millis() as u64;
    let value: serde_json::Value = match serde_json::from_str(stdout.trim()) {
        Ok(v) => v,
        Err(e) => {
            return unreachable_entry(worker, format!("unparseable doctor output: {e}"), started);
        }
    };
    let data = &value["data"];
    let overall = data["summary"]["overall"]
        .as_str()
        .unwrap_or(VERDICT_FAILING)
        .to_string();
    let diagnostics = data["diagnostics"].as_array().cloned().unwrap_or_default();
    PerWorkerEntry {
        worker: worker.to_string(),
        overall,
        diagnostics,
        ssh_error: None,
        duration_ms,
    }
}

/// Probe a single worker over SSH, with an outer timeout guard so a stalled
/// connection becomes `unreachable` rather than hanging the fan-out.
async fn probe_worker(
    worker: WorkerConfig,
    remote_cmd: String,
    timeout: Duration,
) -> PerWorkerEntry {
    let started = Instant::now();
    let worker_name = worker.id.as_str().to_string();

    tracing::debug!(
        target: "rch::fleet::doctor",
        worker_name = %worker_name,
        "fleet.doctor.worker.start",
    );

    let executor = SshExecutor::with_timeout(&worker, timeout);
    let entry = match tokio::time::timeout(timeout, executor.run_command(&remote_cmd)).await {
        Err(_) => unreachable_entry(
            &worker_name,
            format!("timeout {}s", timeout.as_secs()),
            started,
        ),
        Ok(Err(e)) => unreachable_entry(&worker_name, e.to_string(), started),
        Ok(Ok(output)) => {
            // A non-zero exit with empty stdout is a transport/exec failure, not
            // a doctor verdict (doctor always emits JSON, even when Failing).
            if output.stdout.trim().is_empty() {
                unreachable_entry(
                    &worker_name,
                    format!("no doctor output (exit {})", output.exit_code),
                    started,
                )
            } else {
                parse_worker_output(&worker_name, &output.stdout, started)
            }
        }
    };

    if entry.ssh_error.is_some() {
        tracing::warn!(
            target: "rch::fleet::doctor",
            worker_name = %worker_name,
            error = entry.ssh_error.as_deref().unwrap_or(""),
            "fleet.doctor.worker.unreachable",
        );
    } else {
        tracing::info!(
            target: "rch::fleet::doctor",
            worker_name = %worker_name,
            verdict = %entry.overall,
            duration_ms = entry.duration_ms,
            "fleet.doctor.worker.complete",
        );
    }
    entry
}

/// Fan out over `workers` with bounded concurrency, returning per-worker
/// entries. Generic over the prober so tests can inject a mock without SSH.
async fn fanout<F, Fut>(
    workers: Vec<WorkerConfig>,
    max_concurrent: usize,
    prober: F,
) -> Vec<PerWorkerEntry>
where
    F: Fn(WorkerConfig) -> Fut,
    Fut: std::future::Future<Output = PerWorkerEntry>,
{
    stream::iter(workers)
        .map(prober)
        .buffer_unordered(max_concurrent.max(1))
        .collect()
        .await
}

/// Entry point for `rch fleet doctor --reliability`.
pub async fn run(ctx: &OutputContext, opts: FleetDoctorOptions) -> Result<()> {
    let request_id = Uuid::new_v4().to_string();

    // `--fix` is a fleet-wide mutation; require explicit confirmation.
    if opts.fix && !opts.fleet_confirm {
        tracing::error!(
            target: "rch::fleet::doctor",
            request_id = %request_id,
            "fleet.doctor.fix.confirmation_required",
        );
        let msg = "Fleet-wide --fix requires --fleet-confirm. \
             First preview with `rch fleet doctor --reliability` (check-only), \
             then re-run with `--fix --fleet-confirm` to apply.";
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "fleet.doctor.reliability",
                rch_common::ApiError::new(rch_common::ErrorCode::ConfigValidationError, msg),
            ));
        } else {
            ctx.error(msg);
        }
        anyhow::bail!("fleet --fix requires --fleet-confirm");
    }

    let all_workers = crate::commands::load_workers_from_config()?;
    let (selected, unknown) = select_workers(&all_workers, opts.workers.as_deref());

    for name in &unknown {
        tracing::warn!(
            target: "rch::fleet::doctor",
            worker_name = %name,
            "fleet.doctor.unknown_worker",
        );
        if !ctx.is_json() {
            ctx.warning(&format!(
                "Unknown worker '{name}' (not in workers.toml) — skipping"
            ));
        }
    }

    let configured = all_workers.len();
    let selected_owned: Vec<WorkerConfig> = selected.into_iter().cloned().collect();

    tracing::info!(
        target: "rch::fleet::doctor",
        worker_count = selected_owned.len(),
        scope = ?opts.scope,
        intent = if opts.fix { "fix" } else { "check" },
        request_id = %request_id,
        "fleet.doctor.start",
    );

    let remote_cmd = build_remote_command(&opts);
    let timeout = Duration::from_secs(opts.worker_timeout_secs.max(1));
    let wallclock = Instant::now();

    let entries = fanout(selected_owned, MAX_CONCURRENT_PROBES, |worker| {
        let cmd = remote_cmd.clone();
        async move { probe_worker(worker, cmd, timeout).await }
    })
    .await;

    let (overall, summary) = aggregate(configured, &entries);

    tracing::info!(
        target: "rch::fleet::doctor",
        fleet_verdict = %overall,
        healthy = summary.healthy_workers,
        degraded = summary.degraded_workers,
        failing = summary.failing_workers,
        unreachable = summary.unreachable_workers,
        wallclock_ms = wallclock.elapsed().as_millis() as u64,
        request_id = %request_id,
        "fleet.doctor.complete",
    );

    let response = FleetDoctorResponse {
        schema_version: "1.0.0".to_string(),
        scope: opts.scope.clone(),
        overall: overall.clone(),
        fleet: summary,
        per_worker: entries,
        request_id,
    };

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("fleet.doctor.reliability", &response));
    } else {
        render_human(ctx, &response);
    }

    Ok(())
}

/// Render a compact human-readable fleet report.
fn render_human(ctx: &OutputContext, response: &FleetDoctorResponse) {
    let f = &response.fleet;
    ctx.info(&format!(
        "Fleet reliability: {} ({} healthy, {} degraded, {} failing, {} unreachable of {} configured)",
        response.overall.to_uppercase(),
        f.healthy_workers,
        f.degraded_workers,
        f.failing_workers,
        f.unreachable_workers,
        f.configured_workers,
    ));
    for entry in &response.per_worker {
        if entry.overall == VERDICT_HEALTHY {
            continue;
        }
        match &entry.ssh_error {
            Some(err) => ctx.warning(&format!("  {} — unreachable: {}", entry.worker, err)),
            None => ctx.warning(&format!(
                "  {} — {} ({} diagnostic{})",
                entry.worker,
                entry.overall,
                entry.diagnostics.len(),
                if entry.diagnostics.len() == 1 {
                    ""
                } else {
                    "s"
                },
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(worker: &str, overall: &str) -> PerWorkerEntry {
        PerWorkerEntry {
            worker: worker.to_string(),
            overall: overall.to_string(),
            diagnostics: Vec::new(),
            ssh_error: if overall == VERDICT_UNREACHABLE {
                Some("err".to_string())
            } else {
                None
            },
            duration_ms: 1,
        }
    }

    fn worker(id: &str, host: &str) -> WorkerConfig {
        WorkerConfig {
            id: rch_common::WorkerId(id.to_string()),
            host: host.to_string(),
            ..WorkerConfig::default()
        }
    }

    #[test]
    fn test_aggregate_fleet_verdict_worst_wins() {
        let entries = vec![
            entry("a", VERDICT_HEALTHY),
            entry("b", VERDICT_HEALTHY),
            entry("c", VERDICT_HEALTHY),
            entry("d", VERDICT_HEALTHY),
            entry("e", VERDICT_HEALTHY),
            entry("f", VERDICT_DEGRADED),
            entry("g", VERDICT_DEGRADED),
            entry("h", VERDICT_FAILING),
        ];
        let (verdict, _) = aggregate(8, &entries);
        assert_eq!(verdict, VERDICT_FAILING);
    }

    #[test]
    fn test_aggregate_fleet_verdict_with_unreachable() {
        let entries = vec![
            entry("a", VERDICT_HEALTHY),
            entry("b", VERDICT_HEALTHY),
            entry("c", VERDICT_HEALTHY),
            entry("d", VERDICT_HEALTHY),
            entry("e", VERDICT_UNREACHABLE),
        ];
        // Unreachable folds into failing for the headline verdict.
        let (verdict, summary) = aggregate(5, &entries);
        assert_eq!(verdict, VERDICT_FAILING);
        assert_eq!(summary.unreachable_workers, 1);
    }

    #[test]
    fn test_aggregate_all_healthy() {
        let entries = vec![entry("a", VERDICT_HEALTHY), entry("b", VERDICT_HEALTHY)];
        let (verdict, _) = aggregate(2, &entries);
        assert_eq!(verdict, VERDICT_HEALTHY);
    }

    #[test]
    fn test_aggregate_summary_counts() {
        let entries = vec![
            entry("a", VERDICT_HEALTHY),
            entry("b", VERDICT_HEALTHY),
            entry("c", VERDICT_HEALTHY),
            entry("d", VERDICT_DEGRADED),
            entry("e", VERDICT_DEGRADED),
            entry("f", VERDICT_FAILING),
            entry("g", VERDICT_UNREACHABLE),
            entry("h", VERDICT_UNREACHABLE),
        ];
        let (_, s) = aggregate(8, &entries);
        assert_eq!(s.healthy_workers, 3);
        assert_eq!(s.degraded_workers, 2);
        assert_eq!(s.failing_workers, 1);
        assert_eq!(s.unreachable_workers, 2);
        assert_eq!(s.configured_workers, 8);
        // probed = attempted (8) − unreachable (2)
        assert_eq!(s.probed_workers, 6);
    }

    #[test]
    fn test_workers_filter_selects_subset() {
        let all = vec![
            worker("css", "css.example"),
            worker("bil", "bil.example"),
            worker("fra", "fra.example"),
        ];
        let (selected, unknown) = select_workers(&all, Some("css,bil"));
        assert_eq!(selected.len(), 2);
        assert!(unknown.is_empty());
        assert_eq!(selected[0].id.as_str(), "css");
        assert_eq!(selected[1].id.as_str(), "bil");
    }

    #[test]
    fn test_workers_filter_unknown_name_warns() {
        let all = vec![worker("css", "css.example")];
        let (selected, unknown) = select_workers(&all, Some("nonexistent"));
        assert!(selected.is_empty());
        assert_eq!(unknown, vec!["nonexistent".to_string()]);
    }

    #[test]
    fn test_workers_filter_none_selects_all() {
        let all = vec![worker("css", "css.example"), worker("bil", "bil.example")];
        let (selected, unknown) = select_workers(&all, None);
        assert_eq!(selected.len(), 2);
        assert!(unknown.is_empty());
    }

    #[test]
    fn test_workers_filter_matches_host() {
        let all = vec![worker("css", "css.example")];
        let (selected, _) = select_workers(&all, Some("css.example"));
        assert_eq!(selected.len(), 1);
    }

    #[test]
    fn test_build_remote_command_default() {
        let cmd = build_remote_command(&FleetDoctorOptions::default());
        assert_eq!(cmd, "rch doctor --reliability --json");
    }

    #[test]
    fn test_build_remote_command_with_scope() {
        let opts = FleetDoctorOptions {
            scope: vec!["pressure".to_string(), "topology".to_string()],
            ..FleetDoctorOptions::default()
        };
        assert_eq!(
            build_remote_command(&opts),
            "rch doctor --reliability --json --scope=pressure,topology"
        );
    }

    #[test]
    fn test_build_remote_command_fix_requires_confirm() {
        // --fix without confirm: do NOT forward --fix (check-only preview).
        let preview = FleetDoctorOptions {
            fix: true,
            fleet_confirm: false,
            ..FleetDoctorOptions::default()
        };
        assert!(!build_remote_command(&preview).contains("--fix"));
        // --fix with confirm: forward --fix.
        let apply = FleetDoctorOptions {
            fix: true,
            fleet_confirm: true,
            ..FleetDoctorOptions::default()
        };
        assert!(build_remote_command(&apply).contains("--fix"));
    }

    #[test]
    fn test_parse_worker_output_extracts_verdict_and_diagnostics() {
        let stdout = r#"{
            "command": "doctor.reliability",
            "data": {
                "summary": {"overall": "degraded"},
                "diagnostics": [{"code": "RCH-R001", "severity": "warning"}]
            }
        }"#;
        let entry = parse_worker_output("css", stdout, Instant::now());
        assert_eq!(entry.overall, "degraded");
        assert_eq!(entry.diagnostics.len(), 1);
        assert!(entry.ssh_error.is_none());
    }

    #[test]
    fn test_parse_worker_output_unparseable_is_unreachable() {
        let entry = parse_worker_output("css", "not json at all", Instant::now());
        assert_eq!(entry.overall, VERDICT_UNREACHABLE);
        assert!(entry.ssh_error.is_some());
    }

    #[test]
    fn test_parse_worker_output_missing_verdict_defaults_failing() {
        // Valid JSON envelope but no summary.overall → fail safe, not healthy.
        let entry = parse_worker_output("css", r#"{"data":{}}"#, Instant::now());
        assert_eq!(entry.overall, VERDICT_FAILING);
    }

    #[tokio::test]
    async fn test_fanout_runs_every_worker() {
        let workers = vec![worker("a", "a"), worker("b", "b"), worker("c", "c")];
        let entries = fanout(workers, 16, |w| async move {
            PerWorkerEntry {
                worker: w.id.as_str().to_string(),
                overall: VERDICT_HEALTHY.to_string(),
                diagnostics: Vec::new(),
                ssh_error: None,
                duration_ms: 0,
            }
        })
        .await;
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn test_fanout_per_worker_timeout_marks_unreachable() {
        // A prober that stalls past the timeout must surface as unreachable, not
        // hang the fan-out.
        let timeout = Duration::from_millis(50);
        let workers = vec![worker("slow", "slow")];
        let entries = fanout(workers, 16, |w| async move {
            let started = Instant::now();
            let probe = async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                PerWorkerEntry {
                    worker: w.id.as_str().to_string(),
                    overall: VERDICT_HEALTHY.to_string(),
                    diagnostics: Vec::new(),
                    ssh_error: None,
                    duration_ms: 0,
                }
            };
            match tokio::time::timeout(timeout, probe).await {
                Ok(e) => e,
                Err(_) => unreachable_entry(w.id.as_str(), "timeout 0s".to_string(), started),
            }
        })
        .await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].overall, VERDICT_UNREACHABLE);
        assert!(entries[0].ssh_error.as_deref().unwrap().contains("timeout"));
    }
}
