//! Accounting for the legacy self-test canary endpoint.
//!
//! `/self-test/run` returns canary history, not scheduler admission receipts.
//! Its local reference build, requested worker and elapsed time are not evidence
//! of local fallback, scheduler selection, queueing or slot ownership. Keep the
//! diagnostic results, but never promote them to qualified live load evidence.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::status_types::{
    DaemonFullStatusResponse, SelfTestResultRecordFromApi, SelfTestRunResponseFromApi,
    WorkerStatusFromApi, extract_json_body,
};
use crate::ui::context::OutputContext;

use super::{send_daemon_command, urlencoding_encode};

const LOAD_BEAD_ID: &str = "bd-session-history-remediation-ocv9i.10.4";
const DEFAULT_CONCURRENCY: usize = 8;
const DEFAULT_WAVES: usize = 3;
const MAX_CONCURRENCY: usize = 64;
const MAX_JOBS: usize = 1024;
const MISSING_SCHEDULER_EVIDENCE: &str = "load_scheduler_evidence_unavailable";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct LoadJobSpec {
    /// Client correlation only. This is NOT an attachable wrapper/build ID.
    submission_id: String,
    requested_worker: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LoadState {
    CanaryPassed,
    CanaryFailed,
    Unknown,
    /// The observer was cancelled; this does NOT prove remote cancellation.
    ObserverCancelled,
    /// The client refused to issue the request, before daemon admission.
    ClientRefused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct LoadOutcome {
    submission_id: String,
    requested_worker: String,
    state: LoadState,
    /// Whether the client attempted the request, not whether the daemon got it.
    request_attempted: bool,
    /// Diagnostic history namespace. Never copied into `remote_job_id`.
    self_test_history_id: Option<String>,
    reported_worker: Option<String>,
    reported_canary_passed: Option<bool>,
    reported_remote_time_ms: Option<u64>,
    reported_local_hash: Option<String>,
    reported_remote_hash: Option<String>,
    /// Includes client-side semaphore waiting; it is NOT scheduler queue time.
    client_elapsed_ms: Option<u64>,
    /// The legacy endpoint cannot attest any of these fields.
    remote_job_id: Option<u64>,
    selected_worker: Option<String>,
    admitted_slots: Option<u32>,
    queue_depth: Option<u32>,
    queue_wait_ms: Option<u64>,
    artifact_verified_for_admitted_job: Option<bool>,
    local_fallback_executed: Option<bool>,
    reason_code: String,
    detail: Option<String>,
}

impl LoadOutcome {
    fn unobserved(spec: &LoadJobSpec, state: LoadState, reason: &str, detail: String) -> Self {
        Self {
            submission_id: spec.submission_id.clone(),
            requested_worker: spec.requested_worker.clone(),
            state,
            request_attempted: false,
            self_test_history_id: None,
            reported_worker: None,
            reported_canary_passed: None,
            reported_remote_time_ms: None,
            reported_local_hash: None,
            reported_remote_hash: None,
            client_elapsed_ms: None,
            remote_job_id: None,
            selected_worker: None,
            admitted_slots: None,
            queue_depth: None,
            queue_wait_ms: None,
            artifact_verified_for_admitted_job: None,
            local_fallback_executed: None,
            reason_code: reason.to_string(),
            detail: Some(detail),
        }
    }
}

fn worker_is_diagnostic_target(worker: &WorkerStatusFromApi) -> bool {
    worker.bypass.is_none()
        && worker.circuit_state.eq_ignore_ascii_case("closed")
        && matches!(
            worker.status.to_ascii_lowercase().as_str(),
            "healthy" | "ready" | "busy" | "degraded"
        )
}

fn resolve_load_params(
    schedulable: usize,
    env: impl Fn(&str) -> Option<String>,
) -> Result<(usize, usize)> {
    let read = |key: &str, default: usize, maximum: usize| -> Result<usize> {
        let Some(raw) = env(key) else {
            return Ok(default);
        };
        let value = raw
            .parse::<usize>()
            .with_context(|| format!("Invalid {key}: {raw}"))?;
        anyhow::ensure!(
            (1..=maximum).contains(&value),
            "{key} must be between 1 and {maximum}"
        );
        Ok(value)
    };
    let waves = read("RCH_LOAD_WAVES", DEFAULT_WAVES, MAX_JOBS)?;
    let default_concurrency = schedulable.saturating_mul(2).clamp(1, DEFAULT_CONCURRENCY);
    let concurrency = read("RCH_LOAD_CONCURRENCY", default_concurrency, MAX_CONCURRENCY)?;
    Ok((waves, concurrency))
}

fn plan_load_jobs(
    workers: &[WorkerStatusFromApi],
    selected: Option<&str>,
    waves: usize,
) -> Result<Vec<LoadJobSpec>> {
    let targets: Vec<_> = workers
        .iter()
        .filter(|worker| worker_is_diagnostic_target(worker))
        .filter(|worker| selected.is_none_or(|id| worker.id == id))
        .collect();
    let total = targets
        .len()
        .checked_mul(waves)
        .context("Load job count overflow")?;
    anyhow::ensure!(
        total <= MAX_JOBS,
        "Load plan exceeds the {MAX_JOBS}-job limit"
    );
    let mut jobs = Vec::with_capacity(total);
    for _ in 0..waves {
        for worker in &targets {
            jobs.push(LoadJobSpec {
                submission_id: format!("rch-load-{}", uuid::Uuid::new_v4()),
                requested_worker: worker.id.clone(),
            });
        }
    }
    Ok(jobs)
}

fn classify_load_outcome(spec: &LoadJobSpec, result: SelfTestResultRecordFromApi) -> LoadOutcome {
    let mut outcome = LoadOutcome::unobserved(
        spec,
        LoadState::Unknown,
        "canary_evidence_incomplete",
        "A canary verdict without a remote duration and returned hash is incomplete".to_string(),
    );
    outcome.request_attempted = true;
    outcome.self_test_history_id = Some(result.run_id.to_string());
    outcome.reported_worker = Some(result.worker_id);
    outcome.reported_canary_passed = Some(result.passed);
    outcome.reported_remote_time_ms = result.remote_time_ms;
    outcome.reported_local_hash = result.local_hash;
    outcome.reported_remote_hash = result.remote_hash;
    if !result.passed {
        outcome.state = LoadState::CanaryFailed;
        outcome.reason_code = "canary_failed".to_string();
        outcome.detail = Some(
            result
                .error
                .unwrap_or_else(|| "The daemon reported a failed canary".to_string()),
        );
    } else if outcome.reported_remote_time_ms.is_some()
        && outcome
            .reported_remote_hash
            .as_deref()
            .is_some_and(|hash| !hash.is_empty())
    {
        outcome.state = LoadState::CanaryPassed;
        outcome.reason_code = MISSING_SCHEDULER_EVIDENCE.to_string();
        outcome.detail = Some(
            "Canary passed; admitted execution and scheduler behavior remain unverified"
                .to_string(),
        );
    }
    outcome
}

fn decode_load_response(spec: &LoadJobSpec, response: &str) -> Result<LoadOutcome> {
    if response.starts_with("HTTP/") {
        let status = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1));
        anyhow::ensure!(
            status == Some("200"),
            "Unsuccessful self-test HTTP response"
        );
    }
    let json = extract_json_body(response).context("Missing self-test response body")?;
    let run: SelfTestRunResponseFromApi =
        serde_json::from_str(json).context("Invalid self-test response")?;
    // A targeted call must have exactly one result. Picking the first matching
    // row would conceal duplicated, unrelated or replayed records.
    anyhow::ensure!(
        run.results.len() == 1,
        "Expected one targeted canary result, got {}",
        run.results.len()
    );
    let result = run
        .results
        .into_iter()
        .next()
        .context("Missing targeted canary result")?;
    anyhow::ensure!(
        result.worker_id == spec.requested_worker,
        "Canary result belongs to a different worker"
    );
    anyhow::ensure!(
        result.run_id > 0 && result.run_id == run.run.id,
        "Canary history identity mismatch"
    );
    anyhow::ensure!(
        run.run.workers_tested == 1
            && run.run.workers_passed == usize::from(result.passed)
            && run.run.workers_failed == usize::from(!result.passed),
        "Canary summary contradicts its result"
    );
    Ok(classify_load_outcome(spec, result))
}

/// Repeated diagnostic history is ambiguous evidence, not distinct remote jobs.
/// Keep every row and the raw verdicts so the ambiguity remains inspectable.
fn reject_duplicate_history(outcomes: &mut [LoadOutcome]) {
    let mut counts = BTreeMap::new();
    for outcome in outcomes.iter() {
        if let Some(id) = outcome.self_test_history_id.as_ref() {
            *counts.entry(id.clone()).or_insert(0usize) += 1;
        }
    }
    for outcome in outcomes {
        if outcome
            .self_test_history_id
            .as_ref()
            .is_some_and(|id| counts[id] > 1)
        {
            outcome.state = LoadState::Unknown;
            outcome.reason_code = "duplicate_self_test_history_identity".to_string();
            outcome.detail = Some(
                "Multiple submissions returned the same self-test history identity; no unique admission was established"
                    .to_string(),
            );
        }
    }
}

struct LoadTask {
    spec: LoadJobSpec,
    attempted: Arc<AtomicBool>,
    handle: JoinHandle<LoadOutcome>,
}

impl Drop for LoadTask {
    fn drop(&mut self) {
        // Cancels only the local observer. Remote execution remains unknown;
        // the retained plan must not be rewritten as a remote cancellation.
        self.handle.abort();
    }
}

async fn collect_load_outcomes(tasks: Vec<LoadTask>) -> Vec<LoadOutcome> {
    let mut outcomes = Vec::with_capacity(tasks.len());
    for mut task in tasks {
        let mut outcome = match (&mut task.handle).await {
            Ok(outcome)
                if outcome.submission_id == task.spec.submission_id
                    && outcome.requested_worker == task.spec.requested_worker =>
            {
                outcome
            }
            Ok(_) => LoadOutcome::unobserved(
                &task.spec,
                LoadState::Unknown,
                "observer_identity_mismatch",
                "Observer returned an outcome for a different submission".to_string(),
            ),
            Err(error) => LoadOutcome::unobserved(
                &task.spec,
                if error.is_cancelled() {
                    LoadState::ObserverCancelled
                } else {
                    LoadState::Unknown
                },
                if error.is_cancelled() {
                    "observer_cancelled"
                } else {
                    "observer_failed"
                },
                format!("{error}; remote execution/cancellation is unknown"),
            ),
        };
        // Read after joining: the task may have started the request while the
        // collector was awaiting it. This is client dispatch only.
        outcome.request_attempted = task.attempted.load(Ordering::Acquire);
        outcomes.push(outcome);
    }
    reject_duplicate_history(&mut outcomes);
    outcomes
}

async fn execute_load_swarm_with<F, Fut>(
    specs: &[LoadJobSpec],
    timeout: u64,
    concurrency: usize,
    request: F,
) -> Vec<LoadOutcome>
where
    F: Fn(String) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = Result<String>> + Send + 'static,
{
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = Vec::with_capacity(specs.len());
    for spec in specs {
        let owned_spec = spec.clone();
        let semaphore = semaphore.clone();
        let attempted = Arc::new(AtomicBool::new(false));
        let task_attempted = attempted.clone();
        let request = request.clone();
        let handle = tokio::spawn(async move {
            let started = std::time::Instant::now();
            let permit = semaphore.acquire_owned().await;
            let Ok(_permit) = permit else {
                return LoadOutcome::unobserved(
                    &owned_spec,
                    LoadState::ClientRefused,
                    "client_admission_closed",
                    "Client concurrency limiter closed before dispatch".to_string(),
                );
            };
            let command = format!(
                "POST /self-test/run?worker={}&timeout={}&debug=true&retries=0\n",
                urlencoding_encode(&owned_spec.requested_worker),
                timeout,
            );
            task_attempted.store(true, Ordering::Release);
            let result = match request(command).await {
                Ok(response) => decode_load_response(&owned_spec, &response),
                Err(error) => Err(error),
            };
            let mut outcome = result.unwrap_or_else(|error| {
                LoadOutcome::unobserved(
                    &owned_spec,
                    LoadState::Unknown,
                    "self_test_result_unavailable",
                    format!("{error:#}"),
                )
            });
            outcome.request_attempted = true;
            outcome.client_elapsed_ms =
                Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
            outcome
        });
        tasks.push(LoadTask {
            spec: spec.clone(),
            attempted,
            handle,
        });
    }
    collect_load_outcomes(tasks).await
}

async fn request_canary(command: String) -> Result<String> {
    // Never use this legacy transport for an unqualified live load run. Keep
    // the check at the dispatch boundary as well as before task submission.
    require_load_execution_contract()?;
    send_daemon_command(&command).await
}

/// A qualification run requires all three guarantees, independently of the
/// operator's default fail-open settings. The legacy canary transport provides
/// none of them: history IDs are not admissions, it builds a local reference,
/// and its source/temporary-file lifecycle is not retain-all (GH#95, GH#101).
/// Replacing this refusal requires an admitted-job transport, not a flag that
/// merely asserts safety. Never weaken it to allow simulated qualification.
fn require_load_execution_contract() -> Result<()> {
    anyhow::bail!(
        "Load execution refused: the legacy canary endpoint does not support scheduler-admitted, strict-remote, retain-all execution; no build requests were dispatched"
    )
}

/// Retained, exclusive-create trace. The complete plan is synchronized before
/// any task is spawned, so an interrupted observer cannot erase the denominator.
/// A planned row without an outcome is unknown, never a success or fallback.
struct LoadTrace {
    file: File,
    path: String,
}

impl LoadTrace {
    fn start(run_id: &str, specs: &[LoadJobSpec]) -> Result<Self> {
        uuid::Uuid::parse_str(run_id).context("Invalid load run identity")?;
        let dir = dirs::cache_dir()
            .context("No cache directory for retained load evidence")?
            .join("rch")
            .join("load");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{run_id}.jsonl"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("Cannot create retained trace {}", path.display()))?;
        let mut trace = Self {
            file,
            path: path.display().to_string(),
        };
        trace.record(&serde_json::json!({
            "record": "plan", "schema_version": 2, "run_id": run_id,
            "bead_id": LOAD_BEAD_ID, "planned_jobs": specs.len(), "qualified": false,
        }))?;
        for spec in specs {
            trace.record(&serde_json::json!({"record": "planned_job", "job": spec}))?;
        }
        trace.file.sync_all()?;
        Ok(trace)
    }

    fn record(&mut self, value: &impl Serialize) -> Result<()> {
        serde_json::to_writer(&mut self.file, value)?;
        self.file.write_all(b"\n")?;
        Ok(())
    }

    fn finish(&mut self, outcomes: &[LoadOutcome]) -> Result<()> {
        for outcome in outcomes {
            self.record(&serde_json::json!({"record": "outcome", "outcome": outcome}))?;
        }
        self.file.sync_all()?;
        Ok(())
    }
}

fn load_summary(outcomes: &[LoadOutcome]) -> serde_json::Value {
    let count = |state| {
        outcomes
            .iter()
            .filter(|outcome| outcome.state == state)
            .count()
    };
    serde_json::json!({
        "total_jobs": outcomes.len(),
        "client_requests_attempted": outcomes.iter().filter(|outcome| outcome.request_attempted).count(),
        "canary_passed": count(LoadState::CanaryPassed),
        "canary_failed": count(LoadState::CanaryFailed),
        "unknown": count(LoadState::Unknown),
        "observer_cancelled": count(LoadState::ObserverCancelled),
        "client_refused": count(LoadState::ClientRefused),
        "remote_successes": null, "local_fallbacks": null, "proof_refusals": null,
        "cancellations": null, "queue_timeouts": null, "p95_queue_wait_ms": null,
        "per_worker_slot_utilization": null,
    })
}

fn scheduler_evidence() -> serde_json::Value {
    serde_json::json!({
        "qualified": false, "passed": false,
        "reason_code": MISSING_SCHEDULER_EVIDENCE,
        "admitted_job_identities": "not_observed",
        "worker_selection": "client_requested_not_scheduler_observed",
        "queue_contention": "not_observed",
        "slot_admission_and_release": "not_observed",
        "fairness": "not_observed",
        "artifact_binding_to_admitted_job": "not_observed",
        "strict_remote_execution": "not_attested",
        "retain_all_source_handling": "not_attested",
        "native_fleet_validation": "not_performed",
    })
}

pub(super) async fn run_load_storm(
    run_id: &str,
    selected_worker: Option<&str>,
    timeout: u64,
    dry_run: bool,
    daemon_reachable: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let worker_result: Result<Vec<WorkerStatusFromApi>> = async {
        let response = send_daemon_command("GET /status\n").await?;
        let json = extract_json_body(&response).context("Missing daemon status body")?;
        let status: DaemonFullStatusResponse = serde_json::from_str(json)?;
        Ok(status.workers)
    }
    .await;
    let (workers, mut problem) = match worker_result {
        Ok(workers) => (workers, None),
        Err(error) => (
            Vec::new(),
            Some(format!("Daemon status unavailable: {error:#}")),
        ),
    };
    let schedulable = workers
        .iter()
        .filter(|worker| worker_is_diagnostic_target(worker))
        .count();
    let (waves, concurrency) = resolve_load_params(schedulable, |key| std::env::var(key).ok())?;
    let specs = plan_load_jobs(&workers, selected_worker, waves)?;
    if specs.is_empty() && problem.is_none() {
        problem =
            Some("No eligible diagnostic targets matched the requested worker/fleet".to_string());
    }
    let mut trace = None;
    let mut outcomes = Vec::new();
    if !dry_run && !specs.is_empty() {
        match LoadTrace::start(run_id, &specs) {
            Ok(started) => trace = Some(started),
            Err(error) => {
                problem = Some(format!("Cannot retain the complete load plan: {error:#}"));
            }
        }
        if problem.is_none()
            && let Err(error) = require_load_execution_contract()
        {
            problem = Some(format!("{error:#}"));
        }
        if let Some(detail) = problem.as_ref() {
            outcomes = refuse_load_plan(&specs, detail);
        } else {
            outcomes = execute_load_swarm_with(&specs, timeout, concurrency, request_canary).await;
        }
    }
    let log_path = trace.as_ref().map(|trace| trace.path.clone());
    if let Some(trace) = trace.as_mut()
        && let Err(error) = trace.finish(&outcomes)
    {
        problem = Some(format!("Incomplete retained load trace: {error:#}"));
    }
    // All tasks are joined and evidence synchronized before reporting/exiting.
    drop(trace);
    let summary = load_summary(&outcomes);
    let payload = serde_json::json!({
        "schema_version": 2,
        "run_id": run_id, "bead_id": LOAD_BEAD_ID, "mode": "load",
        "execution_kind": "load_preflight",
        "dry_run": dry_run, "daemon_reachable": daemon_reachable,
        "diagnostic_targets": schedulable, "planned_jobs": specs.len(),
        "waves": waves, "concurrency": concurrency,
        "timeout_secs": timeout,
        "executed": outcomes.iter().any(|outcome| outcome.request_attempted),
        "qualified": false, "passed": false,
        "reason_code": MISSING_SCHEDULER_EVIDENCE,
        "problem": problem, "summary": summary, "outcomes": outcomes,
        "scheduler_evidence": scheduler_evidence(), "log_path": log_path,
    });
    if ctx.is_json() {
        ctx.json(&payload)?;
        if !dry_run {
            // Match `check`: the top-level error renderer would otherwise append
            // a second JSON document. No task or evidence writer remains open.
            std::process::exit(1);
        }
        return Ok(());
    }
    println!(
        "{}",
        ctx.style()
            .format_header("Load preflight — NOT fleet qualification")
    );
    println!(
        "  planned: {} · accounted: {} · diagnostic results are not admission evidence",
        specs.len(),
        outcomes.len()
    );
    println!("  {}", summary);
    println!(
        "  Admission identities, queue contention, slots, fairness and native artifacts: NOT OBSERVED"
    );
    if let Some(problem) = problem {
        println!("  {problem}");
    }
    if let Some(path) = log_path {
        println!("  retained trace: {path}");
    }
    if dry_run {
        return Ok(());
    }
    anyhow::bail!(
        "{MISSING_SCHEDULER_EVIDENCE}: legacy canary diagnostics cannot qualify a live fleet"
    )
}

fn refuse_load_plan(specs: &[LoadJobSpec], detail: &str) -> Vec<LoadOutcome> {
    specs
        .iter()
        .map(|spec| {
            LoadOutcome::unobserved(
                spec,
                LoadState::ClientRefused,
                "load_preflight_refused",
                detail.to_string(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(id: &str) -> LoadJobSpec {
        LoadJobSpec {
            submission_id: id.to_string(),
            requested_worker: "worker-1".to_string(),
        }
    }

    fn result(passed: bool) -> SelfTestResultRecordFromApi {
        SelfTestResultRecordFromApi {
            run_id: 42,
            worker_id: "worker-1".to_string(),
            passed,
            local_hash: Some("local-hash".to_string()),
            remote_hash: Some("remote-hash".to_string()),
            local_time_ms: Some(9),
            remote_time_ms: Some(7),
            error: (!passed).then(|| "Cannot read returned marker".to_string()),
        }
    }

    #[test]
    fn failed_canary_with_timing_and_hash_is_not_a_remote_success() {
        let outcome = classify_load_outcome(&spec("one"), result(false));
        assert_eq!(outcome.state, LoadState::CanaryFailed);
        assert_eq!(outcome.remote_job_id, None);
        assert_eq!(outcome.local_fallback_executed, None);
        assert!(outcome.detail.as_deref().unwrap().contains("marker"));
    }

    #[test]
    fn canary_history_and_timing_never_establish_admission_or_queue_evidence() {
        let outcome = classify_load_outcome(&spec("one"), result(true));
        assert_eq!(outcome.state, LoadState::CanaryPassed);
        assert_eq!(outcome.self_test_history_id.as_deref(), Some("42"));
        assert_eq!(outcome.remote_job_id, None);
        assert_eq!(outcome.selected_worker, None);
        assert_eq!(outcome.admitted_slots, None);
        assert_eq!(outcome.queue_depth, None);
        assert_eq!(outcome.queue_wait_ms, None);
        assert_eq!(outcome.artifact_verified_for_admitted_job, None);
        assert_eq!(scheduler_evidence()["qualified"], false);
        assert_eq!(scheduler_evidence()["queue_contention"], "not_observed");
    }

    #[test]
    fn passing_verdict_with_missing_artifact_evidence_is_unknown() {
        let mut missing = result(true);
        missing.remote_hash = None;
        assert_eq!(
            classify_load_outcome(&spec("one"), missing).state,
            LoadState::Unknown
        );
        let mut empty = result(true);
        empty.remote_hash = Some(String::new());
        assert_eq!(
            classify_load_outcome(&spec("two"), empty).state,
            LoadState::Unknown
        );
    }

    #[test]
    fn duplicate_history_is_not_replaced_with_invented_unique_build_ids() {
        let mut outcomes = vec![
            classify_load_outcome(&spec("one"), result(true)),
            classify_load_outcome(&spec("two"), result(true)),
        ];
        reject_duplicate_history(&mut outcomes);
        assert_eq!(outcomes.len(), 2);
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.state == LoadState::Unknown)
        );
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.remote_job_id.is_none())
        );
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.self_test_history_id.as_deref() == Some("42"))
        );
        assert_eq!(load_summary(&outcomes)["total_jobs"], 2);
    }

    #[tokio::test]
    async fn unavailable_results_preserve_every_submission_without_fallback_claims() {
        let specs = vec![spec("one"), spec("two"), spec("three")];
        let outcomes = execute_load_swarm_with(&specs, 1, 2, |_| async {
            anyhow::bail!("transport unavailable")
        })
        .await;
        assert_eq!(outcomes.len(), specs.len());
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.state == LoadState::Unknown)
        );
        assert!(outcomes.iter().all(|outcome| outcome.request_attempted));
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.local_fallback_executed.is_none())
        );
        assert_eq!(load_summary(&outcomes)["unknown"], 3);
        assert!(load_summary(&outcomes)["remote_successes"].is_null());
        assert!(load_summary(&outcomes)["local_fallbacks"].is_null());
    }

    #[tokio::test]
    async fn panicked_and_cancelled_observers_stay_in_the_denominator() {
        let failed = tokio::spawn(async { panic!("observer panic") });
        let cancelled = tokio::spawn(std::future::pending::<LoadOutcome>());
        cancelled.abort();
        let tasks = vec![
            LoadTask {
                spec: spec("one"),
                attempted: Arc::new(AtomicBool::new(true)),
                handle: failed,
            },
            LoadTask {
                spec: spec("two"),
                attempted: Arc::new(AtomicBool::new(false)),
                handle: cancelled,
            },
        ];
        let outcomes = collect_load_outcomes(tasks).await;
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].state, LoadState::Unknown);
        assert!(outcomes[0].request_attempted);
        assert_eq!(outcomes[1].state, LoadState::ObserverCancelled);
        assert!(!outcomes[1].request_attempted);
        assert_eq!(load_summary(&outcomes)["observer_cancelled"], 1);
        assert!(load_summary(&outcomes)["cancellations"].is_null());
    }

    #[test]
    fn client_refusals_are_counted_but_not_reported_as_daemon_proof_refusals() {
        let outcomes = vec![LoadOutcome::unobserved(
            &spec("one"),
            LoadState::ClientRefused,
            "load_preflight_refused",
            "cannot retain evidence".to_string(),
        )];
        let summary = load_summary(&outcomes);
        assert_eq!(summary["total_jobs"], 1);
        assert_eq!(summary["client_refused"], 1);
        assert!(summary["proof_refusals"].is_null());
    }

    #[test]
    fn diagnostic_limits_reject_invalid_or_unbounded_overrides() {
        assert_eq!(resolve_load_params(3, |_| None).unwrap(), (3, 6));
        assert_eq!(resolve_load_params(50, |_| None).unwrap(), (3, 8));
        assert!(resolve_load_params(3, |_| Some("0".to_string())).is_err());
        assert!(resolve_load_params(3, |_| Some(usize::MAX.to_string())).is_err());
    }

    #[test]
    fn unsupported_execution_contract_refuses_the_complete_plan() {
        let error = require_load_execution_contract().unwrap_err();
        let specs = vec![spec("one"), spec("two"), spec("three")];
        let outcomes = refuse_load_plan(&specs, &error.to_string());
        assert_eq!(outcomes.len(), specs.len());
        for (spec, outcome) in specs.iter().zip(&outcomes) {
            assert_eq!(outcome.submission_id, spec.submission_id);
            assert_eq!(outcome.state, LoadState::ClientRefused);
            assert!(!outcome.request_attempted);
            assert!(outcome.remote_job_id.is_none());
        }
        assert_eq!(load_summary(&outcomes)["client_refused"], 3);
        assert_eq!(scheduler_evidence()["passed"], false);
    }

    fn response_value(result: SelfTestResultRecordFromApi) -> serde_json::Value {
        serde_json::json!({
            "run": {
                "id": result.run_id, "run_type": "manual", "started_at": "test",
                "completed_at": "test", "workers_tested": 1,
                "workers_passed": usize::from(result.passed),
                "workers_failed": usize::from(!result.passed), "duration_ms": 10,
            },
            "results": [result],
        })
    }

    #[test]
    fn malformed_missing_duplicated_or_misattributed_results_are_rejected() {
        let spec = spec("one");
        let valid = response_value(result(true));
        assert!(decode_load_response(&spec, &valid.to_string()).is_ok());
        assert!(decode_load_response(&spec, "not json").is_err());
        assert!(decode_load_response(&spec, "").is_err());
        assert!(
            decode_load_response(
                &spec,
                &format!("HTTP/1.1 500 Internal Server Error\r\n\r\n{valid}")
            )
            .is_err()
        );

        let mut missing = valid.clone();
        missing["results"] = serde_json::json!([]);
        let mut duplicated = valid.clone();
        duplicated["results"] = serde_json::json!([result(true), result(true)]);
        let mut wrong_worker = valid.clone();
        wrong_worker["results"][0]["worker_id"] = serde_json::json!("someone-else");
        let mut wrong_history = valid.clone();
        wrong_history["run"]["id"] = serde_json::json!(99);
        let mut inconsistent = valid;
        inconsistent["run"]["workers_passed"] = serde_json::json!(0);
        for bad in [
            missing,
            duplicated,
            wrong_worker,
            wrong_history,
            inconsistent,
        ] {
            assert!(decode_load_response(&spec, &bad.to_string()).is_err());
        }
    }

    /// This is a LOCAL observer-concurrency regression, not a native worker or
    /// daemon queue test. A real semaphore wait must never be called scheduler
    /// contention or used to qualify the fleet.
    #[tokio::test]
    async fn concurrent_client_requests_do_not_fabricate_scheduler_contention() {
        use std::sync::atomic::AtomicUsize;
        use std::time::Duration;
        use tokio::sync::Barrier;

        let barrier = Arc::new(Barrier::new(2));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let sequence = Arc::new(AtomicUsize::new(1));
        let request = {
            let active = active.clone();
            let peak = peak.clone();
            move |_| {
                let barrier = barrier.clone();
                let active = active.clone();
                let peak = peak.clone();
                let sequence = sequence.clone();
                async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(current, Ordering::SeqCst);
                    // Synthetic history values are decoder inputs only. They
                    // must remain distinct from daemon-issued admission IDs.
                    let mut record = result(true);
                    record.run_id = sequence.fetch_add(1, Ordering::SeqCst) as u64;
                    barrier.wait().await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(response_value(record).to_string())
                }
            }
        };
        let specs = vec![spec("1"), spec("2"), spec("3"), spec("4")];
        let outcomes = tokio::time::timeout(
            Duration::from_secs(5),
            execute_load_swarm_with(&specs, 1, 2, request),
        )
        .await
        .expect("bounded client concurrency must make progress");
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(outcomes.len(), specs.len());
        assert!(outcomes.iter().all(|outcome| {
            outcome.state == LoadState::CanaryPassed
                && outcome.remote_job_id.is_none()
                && outcome.queue_depth.is_none()
                && outcome.queue_wait_ms.is_none()
                && outcome.admitted_slots.is_none()
        }));
        assert_eq!(scheduler_evidence()["qualified"], false);
        assert_eq!(scheduler_evidence()["queue_contention"], "not_observed");
    }
}
