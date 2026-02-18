//! Bounded remediation pipeline for stuck/runaway processes on workers.
//!
//! Implements escalation from observe → TERM → KILL with auditing,
//! safety guardrails, and policy evaluation per the process-triage contract.

#![allow(dead_code)] // Initial integration surface; consumers land in follow-on beads.

use crate::events::EventBus;
use chrono::Utc;
use rch_common::e2e::process_triage::{
    ProcessTriageActionClass, ProcessTriageActionOutcome, ProcessTriageActionResult,
    ProcessTriageAuditRecord, ProcessTriageContract, ProcessTriageEscalationLevel,
    ProcessTriageFailure, ProcessTriageFailureKind, ProcessTriageRequest,
    ProcessTriageResponse, ProcessTriageResponseStatus,
    evaluate_triage_action, PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of escalation steps per process in a single pipeline run.
const MAX_ESCALATION_STEPS: u32 = 3;

/// Grace period after TERM before escalating to KILL.
const TERM_GRACE_PERIOD: Duration = Duration::from_secs(10);

/// Maximum total pipeline execution time per invocation.
const PIPELINE_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum concurrent remediation pipelines across the fleet.
const MAX_CONCURRENT_PIPELINES: u32 = 2;

/// Cooldown between pipeline runs for the same worker.
const WORKER_PIPELINE_COOLDOWN: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Pipeline state tracking
// ---------------------------------------------------------------------------

/// Per-worker remediation tracking state.
#[derive(Debug, Clone, Default)]
pub(crate) struct WorkerRemediationState {
    /// Total actions executed against this worker.
    total_actions: u32,
    /// Total hard terminations executed.
    hard_terminations: u32,
    /// Last pipeline completion time.
    last_pipeline_at: Option<Instant>,
    /// Consecutive failed pipeline runs.
    consecutive_failures: u32,
}

/// Escalation step in the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationStep {
    Observe,
    SoftTerminate,
    HardTerminate,
}

impl EscalationStep {
    fn next(self) -> Option<Self> {
        match self {
            Self::Observe => Some(Self::SoftTerminate),
            Self::SoftTerminate => Some(Self::HardTerminate),
            Self::HardTerminate => None,
        }
    }

    fn action_class(self) -> ProcessTriageActionClass {
        match self {
            Self::Observe => ProcessTriageActionClass::ObserveOnly,
            Self::SoftTerminate => ProcessTriageActionClass::SoftTerminate,
            Self::HardTerminate => ProcessTriageActionClass::HardTerminate,
        }
    }

    fn signal(self) -> Option<&'static str> {
        match self {
            Self::Observe => None,
            Self::SoftTerminate => Some("TERM"),
            Self::HardTerminate => Some("KILL"),
        }
    }
}

// ---------------------------------------------------------------------------
// Pipeline audit events
// ---------------------------------------------------------------------------

/// Audit event emitted for every pipeline action.
#[derive(Debug, Clone, Serialize)]
pub struct RemediationAuditEvent {
    pub correlation_id: String,
    pub worker_id: String,
    pub pid: u32,
    pub escalation_step: EscalationStep,
    pub action_class: ProcessTriageActionClass,
    pub outcome: ProcessTriageActionOutcome,
    pub decision_code: String,
    pub signal: Option<String>,
    pub evidence: RemediationEvidence,
    pub timestamp_unix_ms: i64,
}

/// Evidence captured for the audit trail.
#[derive(Debug, Clone, Serialize)]
pub struct RemediationEvidence {
    pub command: String,
    pub classification: String,
    pub cpu_percent_milli: u32,
    pub rss_mb: u32,
    pub runtime_secs: u64,
    pub detector_confidence_percent: u8,
    pub trigger: String,
}

/// Summary of a single pipeline run.
#[derive(Debug, Clone, Serialize)]
pub struct PipelineRunSummary {
    pub correlation_id: String,
    pub worker_id: String,
    pub trigger: String,
    pub processes_evaluated: u32,
    pub actions_executed: u32,
    pub actions_skipped: u32,
    pub actions_escalated: u32,
    pub actions_failed: u32,
    pub total_duration_ms: u64,
    pub aborted: bool,
    pub abort_reason: Option<String>,
    pub timestamp_unix_ms: i64,
}

// ---------------------------------------------------------------------------
// Pipeline configuration
// ---------------------------------------------------------------------------

/// Configuration for the remediation pipeline.
#[derive(Debug, Clone)]
pub struct RemediationPipelineConfig {
    /// Maximum escalation steps per process.
    pub max_escalation_steps: u32,
    /// Grace period after TERM before KILL.
    pub term_grace_period: Duration,
    /// Total pipeline timeout.
    pub pipeline_timeout: Duration,
    /// Maximum concurrent pipelines.
    pub max_concurrent_pipelines: u32,
    /// Per-worker cooldown between runs.
    pub worker_cooldown: Duration,
    /// Whether to actually send signals (false = dry-run).
    pub dry_run: bool,
}

impl Default for RemediationPipelineConfig {
    fn default() -> Self {
        Self {
            max_escalation_steps: MAX_ESCALATION_STEPS,
            term_grace_period: TERM_GRACE_PERIOD,
            pipeline_timeout: PIPELINE_TOTAL_TIMEOUT,
            max_concurrent_pipelines: MAX_CONCURRENT_PIPELINES,
            worker_cooldown: WORKER_PIPELINE_COOLDOWN,
            dry_run: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Remediation pipeline
// ---------------------------------------------------------------------------

/// Bounded remediation pipeline with TERM/KILL escalation and auditing.
///
/// Evaluates stuck/runaway processes against the process-triage contract,
/// applies bounded escalation, and emits full audit trails via EventBus.
pub struct RemediationPipeline {
    contract: ProcessTriageContract,
    events: EventBus,
    config: RemediationPipelineConfig,
    worker_states: Arc<RwLock<HashMap<String, WorkerRemediationState>>>,
    active_pipelines: Arc<std::sync::atomic::AtomicU32>,
}

impl RemediationPipeline {
    /// Create a new remediation pipeline.
    pub fn new(
        contract: ProcessTriageContract,
        events: EventBus,
        config: RemediationPipelineConfig,
    ) -> Self {
        Self {
            contract,
            events,
            config,
            worker_states: Arc::new(RwLock::new(HashMap::new())),
            active_pipelines: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    /// Execute remediation pipeline for a set of candidate processes on a worker.
    ///
    /// Returns a ProcessTriageResponse with full audit record. The pipeline:
    /// 1. Validates the request against the contract
    /// 2. Evaluates each action against safe-action policy
    /// 3. Executes permitted actions with bounded escalation
    /// 4. Aborts if confidence drops or safety checks fail
    /// 5. Emits audit events for every decision
    pub async fn execute(
        &self,
        request: &ProcessTriageRequest,
    ) -> ProcessTriageResponse {
        let pipeline_start = Instant::now();
        let now_ms = Utc::now().timestamp_millis();

        // Emit pipeline start event
        self.events.emit(
            "process_triage.pipeline_started",
            &serde_json::json!({
                "correlation_id": request.correlation_id,
                "worker_id": request.worker_id,
                "trigger": format!("{:?}", request.trigger),
                "candidate_count": request.candidate_processes.len(),
                "action_count": request.requested_actions.len(),
                "confidence": request.detector_confidence_percent,
            }),
        );

        // Gate: validate request
        if let Err(e) = request.validate() {
            let response = self.build_failure_response(
                request,
                ProcessTriageFailureKind::InvalidRequest,
                "PT_INVALID_REQUEST",
                &format!("Request validation failed: {e}"),
                now_ms,
            );
            self.emit_pipeline_summary(request, &response, pipeline_start, false, None);
            return response;
        }

        // Gate: concurrent pipeline limit
        let prev = self.active_pipelines.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if prev >= self.config.max_concurrent_pipelines {
            self.active_pipelines.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            let response = self.build_failure_response(
                request,
                ProcessTriageFailureKind::ExecutorRuntimeError,
                "PT_CONCURRENT_LIMIT",
                &format!(
                    "Concurrent pipeline limit reached ({}/{})",
                    prev + 1,
                    self.config.max_concurrent_pipelines
                ),
                now_ms,
            );
            self.emit_pipeline_summary(request, &response, pipeline_start, true,
                Some("concurrent pipeline limit".to_string()));
            return response;
        }

        // Gate: per-worker cooldown
        {
            let states = self.worker_states.read().await;
            if let Some(state) = states.get(&request.worker_id)
                && let Some(last) = state.last_pipeline_at
                && last.elapsed() < self.config.worker_cooldown
            {
                self.active_pipelines.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                let response = self.build_failure_response(
                    request,
                    ProcessTriageFailureKind::ExecutorRuntimeError,
                    "PT_WORKER_COOLDOWN",
                    &format!(
                        "Worker {} is in cooldown ({}s remaining)",
                        request.worker_id,
                        (self.config.worker_cooldown - last.elapsed()).as_secs()
                    ),
                    now_ms,
                );
                self.emit_pipeline_summary(request, &response, pipeline_start, true,
                    Some("worker cooldown".to_string()));
                return response;
            }
        }

        // Execute actions with escalation
        let mut action_results = Vec::new();
        let mut any_executed = false;
        let mut any_escalated = false;
        let mut any_failed = false;
        let mut aborted = false;
        let mut abort_reason = None;
        let mut highest_escalation = ProcessTriageEscalationLevel::Automatic;

        for action_req in &request.requested_actions {
            // Timeout check
            if pipeline_start.elapsed() > self.config.pipeline_timeout {
                aborted = true;
                abort_reason = Some("pipeline timeout exceeded".to_string());
                action_results.push(ProcessTriageActionResult {
                    pid: action_req.pid,
                    action_class: action_req.action_class,
                    outcome: ProcessTriageActionOutcome::Skipped,
                    note: Some("Pipeline timeout exceeded".to_string()),
                });
                break;
            }

            // Evaluate policy
            let decision = evaluate_triage_action(request, &self.contract, action_req);

            // Find the process descriptor for evidence
            let proc_desc = request.candidate_processes.iter()
                .find(|p| p.pid == action_req.pid);

            let evidence = proc_desc.map(|p| RemediationEvidence {
                command: p.command.clone(),
                classification: format!("{:?}", p.classification),
                cpu_percent_milli: p.cpu_percent_milli,
                rss_mb: p.rss_mb,
                runtime_secs: p.runtime_secs,
                detector_confidence_percent: request.detector_confidence_percent,
                trigger: format!("{:?}", request.trigger),
            });

            if !decision.permitted {
                // Action blocked by policy
                let outcome = if decision.escalation_level == ProcessTriageEscalationLevel::ManualReview
                    || decision.escalation_level == ProcessTriageEscalationLevel::Blocked
                {
                    any_escalated = true;
                    ProcessTriageActionOutcome::Escalated
                } else {
                    ProcessTriageActionOutcome::Skipped
                };

                // Update highest escalation
                if escalation_rank(decision.escalation_level) > escalation_rank(highest_escalation) {
                    highest_escalation = decision.escalation_level;
                }

                // Emit audit event
                if let Some(ev) = &evidence {
                    self.emit_action_audit(&RemediationAuditEvent {
                        correlation_id: request.correlation_id.clone(),
                        worker_id: request.worker_id.clone(),
                        pid: action_req.pid,
                        escalation_step: EscalationStep::Observe,
                        action_class: action_req.action_class,
                        outcome,
                        decision_code: decision.decision_code.clone(),
                        signal: None,
                        evidence: ev.clone(),
                        timestamp_unix_ms: Utc::now().timestamp_millis(),
                    });
                }

                action_results.push(ProcessTriageActionResult {
                    pid: action_req.pid,
                    action_class: action_req.action_class,
                    outcome,
                    note: Some(decision.reason.clone()),
                });

                // If blocked, check if we should abort the whole pipeline
                if decision.escalation_level == ProcessTriageEscalationLevel::Blocked {
                    warn!(
                        correlation_id = %request.correlation_id,
                        worker = %request.worker_id,
                        pid = action_req.pid,
                        decision_code = %decision.decision_code,
                        "Action blocked by policy — skipping"
                    );
                }

                continue;
            }

            // Action is permitted — execute with escalation ladder
            let effective_action = decision.effective_action.unwrap_or(action_req.action_class);
            let step = match effective_action {
                ProcessTriageActionClass::ObserveOnly => EscalationStep::Observe,
                ProcessTriageActionClass::SoftTerminate => EscalationStep::SoftTerminate,
                ProcessTriageActionClass::HardTerminate => EscalationStep::HardTerminate,
                ProcessTriageActionClass::ReclaimDisk => EscalationStep::Observe,
            };

            let (outcome, signal_sent) = self.execute_escalation_step(
                step,
                action_req.pid,
                &request.worker_id,
            ).await;

            if outcome == ProcessTriageActionOutcome::Executed {
                any_executed = true;
            } else if outcome == ProcessTriageActionOutcome::Failed {
                any_failed = true;
            }

            // Update highest escalation
            if escalation_rank(decision.escalation_level) > escalation_rank(highest_escalation) {
                highest_escalation = decision.escalation_level;
            }

            // Emit audit event
            if let Some(ev) = &evidence {
                self.emit_action_audit(&RemediationAuditEvent {
                    correlation_id: request.correlation_id.clone(),
                    worker_id: request.worker_id.clone(),
                    pid: action_req.pid,
                    escalation_step: step,
                    action_class: effective_action,
                    outcome,
                    decision_code: decision.decision_code.clone(),
                    signal: signal_sent.map(|s| s.to_string()),
                    evidence: ev.clone(),
                    timestamp_unix_ms: Utc::now().timestamp_millis(),
                });
            }

            action_results.push(ProcessTriageActionResult {
                pid: action_req.pid,
                action_class: effective_action,
                outcome,
                note: signal_sent.map(|s| format!("Signal {} sent", s)),
            });
        }

        // Decrement active pipeline count
        self.active_pipelines.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

        // Update per-worker state
        {
            let mut states = self.worker_states.write().await;
            let state = states.entry(request.worker_id.clone()).or_default();
            state.last_pipeline_at = Some(Instant::now());
            state.total_actions += action_results.iter()
                .filter(|r| r.outcome == ProcessTriageActionOutcome::Executed)
                .count() as u32;
            state.hard_terminations += action_results.iter()
                .filter(|r| r.outcome == ProcessTriageActionOutcome::Executed
                    && r.action_class == ProcessTriageActionClass::HardTerminate)
                .count() as u32;

            if any_failed && !any_executed {
                state.consecutive_failures += 1;
            } else {
                state.consecutive_failures = 0;
            }
        }

        // Determine response status
        let status = if aborted {
            ProcessTriageResponseStatus::Failed
        } else if any_escalated && !any_executed {
            ProcessTriageResponseStatus::EscalatedNoAction
        } else if any_executed && (any_failed || any_escalated) {
            ProcessTriageResponseStatus::PartiallyApplied
        } else if any_executed {
            ProcessTriageResponseStatus::Applied
        } else {
            ProcessTriageResponseStatus::RejectedByPolicy
        };

        let failure = if aborted {
            Some(ProcessTriageFailure {
                kind: ProcessTriageFailureKind::Timeout,
                code: "PT_PIPELINE_TIMEOUT".to_string(),
                message: abort_reason.clone().unwrap_or_default(),
                remediation: vec![
                    "Increase pipeline timeout budget".to_string(),
                    "Reduce number of candidate processes per run".to_string(),
                ],
            })
        } else {
            None
        };

        let response = ProcessTriageResponse {
            schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
            correlation_id: request.correlation_id.clone(),
            status,
            escalation_level: highest_escalation,
            executed_actions: action_results,
            failure,
            audit: ProcessTriageAuditRecord {
                policy_version: self.contract.safe_action_policy.policy_version.clone(),
                evaluated_by: "rchd_remediation_pipeline".to_string(),
                evaluated_at_unix_ms: Utc::now().timestamp_millis(),
                decision_code: format!("PT_PIPELINE_{}", format!("{:?}", status).to_ascii_uppercase()),
                requires_operator_ack: highest_escalation == ProcessTriageEscalationLevel::ManualReview
                    || highest_escalation == ProcessTriageEscalationLevel::Blocked,
                audit_required: self.contract.safe_action_policy.require_audit_record,
            },
        };

        self.emit_pipeline_summary(request, &response, pipeline_start, aborted, abort_reason);

        response
    }

    /// Execute a single escalation step against a process.
    async fn execute_escalation_step(
        &self,
        step: EscalationStep,
        pid: u32,
        worker_id: &str,
    ) -> (ProcessTriageActionOutcome, Option<&'static str>) {
        if step == EscalationStep::Observe {
            debug!(
                worker = %worker_id,
                pid,
                "Observe-only step — no signal sent"
            );
            return (ProcessTriageActionOutcome::Executed, None);
        }

        let signal = step.signal().unwrap_or("TERM");

        if self.config.dry_run {
            info!(
                worker = %worker_id,
                pid,
                signal,
                "Dry-run: would send signal"
            );
            return (ProcessTriageActionOutcome::Executed, Some(signal));
        }

        // Check if process is alive before signaling
        if !is_process_alive(pid) {
            debug!(
                worker = %worker_id,
                pid,
                "Process already dead — skipping signal"
            );
            return (ProcessTriageActionOutcome::Skipped, None);
        }

        // Send the signal
        let result = send_signal(pid, signal);
        match result {
            Ok(()) => {
                info!(
                    worker = %worker_id,
                    pid,
                    signal,
                    "Signal sent successfully"
                );
                (ProcessTriageActionOutcome::Executed, Some(signal))
            }
            Err(e) => {
                warn!(
                    worker = %worker_id,
                    pid,
                    signal,
                    error = %e,
                    "Failed to send signal"
                );
                (ProcessTriageActionOutcome::Failed, Some(signal))
            }
        }
    }

    /// Build a failure response with audit record.
    fn build_failure_response(
        &self,
        request: &ProcessTriageRequest,
        kind: ProcessTriageFailureKind,
        code: &str,
        message: &str,
        now_ms: i64,
    ) -> ProcessTriageResponse {
        ProcessTriageResponse {
            schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
            correlation_id: request.correlation_id.clone(),
            status: ProcessTriageResponseStatus::Failed,
            escalation_level: ProcessTriageEscalationLevel::Blocked,
            executed_actions: vec![],
            failure: Some(ProcessTriageFailure {
                kind,
                code: code.to_string(),
                message: message.to_string(),
                remediation: vec![
                    "Check pipeline configuration and retry".to_string(),
                ],
            }),
            audit: ProcessTriageAuditRecord {
                policy_version: self.contract.safe_action_policy.policy_version.clone(),
                evaluated_by: "rchd_remediation_pipeline".to_string(),
                evaluated_at_unix_ms: now_ms,
                decision_code: code.to_string(),
                requires_operator_ack: true,
                audit_required: self.contract.safe_action_policy.require_audit_record,
            },
        }
    }

    fn emit_action_audit(&self, event: &RemediationAuditEvent) {
        self.events.emit("process_triage.action_audit", event);
    }

    fn emit_pipeline_summary(
        &self,
        request: &ProcessTriageRequest,
        response: &ProcessTriageResponse,
        start: Instant,
        aborted: bool,
        abort_reason: Option<String>,
    ) {
        let summary = PipelineRunSummary {
            correlation_id: request.correlation_id.clone(),
            worker_id: request.worker_id.clone(),
            trigger: format!("{:?}", request.trigger),
            processes_evaluated: request.candidate_processes.len() as u32,
            actions_executed: response.executed_actions.iter()
                .filter(|a| a.outcome == ProcessTriageActionOutcome::Executed).count() as u32,
            actions_skipped: response.executed_actions.iter()
                .filter(|a| a.outcome == ProcessTriageActionOutcome::Skipped).count() as u32,
            actions_escalated: response.executed_actions.iter()
                .filter(|a| a.outcome == ProcessTriageActionOutcome::Escalated).count() as u32,
            actions_failed: response.executed_actions.iter()
                .filter(|a| a.outcome == ProcessTriageActionOutcome::Failed).count() as u32,
            total_duration_ms: start.elapsed().as_millis() as u64,
            aborted,
            abort_reason,
            timestamp_unix_ms: Utc::now().timestamp_millis(),
        };
        self.events.emit("process_triage.pipeline_completed", &summary);
    }

    /// Get current remediation state for a worker (for status surfaces).
    pub async fn worker_state(&self, worker_id: &str) -> Option<WorkerRemediationState> {
        self.worker_states.read().await.get(worker_id).cloned()
    }

    /// Reset per-worker state (for testing or manual recovery).
    pub async fn reset_worker_state(&self, worker_id: &str) {
        self.worker_states.write().await.remove(worker_id);
    }

    /// Number of currently active pipeline executions.
    pub fn active_pipeline_count(&self) -> u32 {
        self.active_pipelines.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn escalation_rank(level: ProcessTriageEscalationLevel) -> u8 {
    match level {
        ProcessTriageEscalationLevel::Automatic => 0,
        ProcessTriageEscalationLevel::Supervised => 1,
        ProcessTriageEscalationLevel::ManualReview => 2,
        ProcessTriageEscalationLevel::Blocked => 3,
    }
}

/// Check if a process is alive.
fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    if cfg!(target_os = "linux") {
        return std::path::Path::new(&format!("/proc/{}", pid)).exists();
    }
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Send a signal to a process.
fn send_signal(pid: u32, signal: &str) -> Result<(), String> {
    let status = std::process::Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("Failed to spawn kill command: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "kill -{signal} {pid} failed with exit code {}",
            status.code().unwrap_or(-1)
        ))
    }
}

// ---------------------------------------------------------------------------
// Periodic triage loop (bd-vvmd.5.4)
// ---------------------------------------------------------------------------

/// Configuration for the periodic triage loop.
#[derive(Debug, Clone)]
pub struct TriageLoopConfig {
    /// Interval between triage sweeps.
    pub interval: Duration,
    /// Time budget per sweep (abort and emit partial results if exceeded).
    pub sweep_budget: Duration,
    /// Skip workers with active builds (busy slots > 0).
    pub skip_busy_workers: bool,
}

impl Default for TriageLoopConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            sweep_budget: Duration::from_secs(15),
            skip_busy_workers: true,
        }
    }
}

/// Result of a single triage sweep (periodic or on-demand).
#[derive(Debug, Clone, Serialize)]
pub struct TriageSweepResult {
    pub sweep_id: u64,
    pub workers_evaluated: u32,
    pub workers_skipped: u32,
    pub total_candidates: u32,
    pub actions_taken: u32,
    pub escalations: u32,
    pub budget_exhausted: bool,
    pub duration_ms: u64,
    pub worker_results: Vec<WorkerTriageResult>,
    pub timestamp_unix_ms: i64,
}

/// Per-worker result within a triage sweep.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerTriageResult {
    pub worker_id: String,
    pub skipped: bool,
    pub skip_reason: Option<String>,
    pub candidates_found: u32,
    pub response_status: Option<String>,
    pub escalation_level: Option<String>,
    pub actions_executed: u32,
    pub actions_escalated: u32,
}

/// Periodic triage loop that sweeps workers for stuck processes.
///
/// Shares the RemediationPipeline for deterministic decision-making,
/// ensuring loop and on-demand commands produce identical results.
pub struct TriageLoop {
    pipeline: Arc<RemediationPipeline>,
    pool: crate::workers::WorkerPool,
    events: EventBus,
    config: TriageLoopConfig,
    sweep_count: u64,
}

impl TriageLoop {
    /// Create a new periodic triage loop.
    pub fn new(
        pipeline: Arc<RemediationPipeline>,
        pool: crate::workers::WorkerPool,
        events: EventBus,
        config: TriageLoopConfig,
    ) -> Self {
        Self {
            pipeline,
            pool,
            events,
            config,
            sweep_count: 0,
        }
    }

    /// Start the periodic triage loop as a background task.
    pub fn start(mut self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.config.interval);
            loop {
                ticker.tick().await;
                let _result = self.sweep(None).await;
            }
        })
    }

    /// Execute a single triage sweep. If `worker_filter` is provided,
    /// only the specified worker is evaluated (on-demand mode).
    pub async fn sweep(
        &mut self,
        worker_filter: Option<&str>,
    ) -> TriageSweepResult {
        self.sweep_count += 1;
        let sweep_start = Instant::now();
        let sweep_id = self.sweep_count;

        let workers = self.pool.all_workers().await;
        let mut worker_results = Vec::new();
        let mut total_candidates = 0u32;
        let mut total_actions = 0u32;
        let mut total_escalations = 0u32;
        let mut workers_evaluated = 0u32;
        let mut workers_skipped = 0u32;
        let mut budget_exhausted = false;

        for worker in &workers {
            // Budget check
            if sweep_start.elapsed() > self.config.sweep_budget {
                budget_exhausted = true;
                warn!(
                    sweep_id,
                    elapsed_ms = sweep_start.elapsed().as_millis() as u64,
                    budget_ms = self.config.sweep_budget.as_millis() as u64,
                    "Triage sweep budget exhausted — partial results"
                );
                break;
            }

            let worker_config = worker.config.read().await;
            let worker_id = worker_config.id.to_string();
            drop(worker_config);

            // Filter check (on-demand mode)
            if let Some(filter) = worker_filter
                && worker_id != filter
            {
                continue;
            }

            // Skip busy workers
            if self.config.skip_busy_workers && worker.used_slots() > 0 {
                workers_skipped += 1;
                worker_results.push(WorkerTriageResult {
                    worker_id: worker_id.clone(),
                    skipped: true,
                    skip_reason: Some("active builds".to_string()),
                    candidates_found: 0,
                    response_status: None,
                    escalation_level: None,
                    actions_executed: 0,
                    actions_escalated: 0,
                });
                continue;
            }

            workers_evaluated += 1;

            // Build a synthetic triage request for this worker.
            // In a real deployment, this would come from the stuck-process detector.
            // For now, emit an observe-only sweep to exercise the pipeline.
            let request = build_sweep_request(&worker_id, sweep_id);
            if request.requested_actions.is_empty() {
                worker_results.push(WorkerTriageResult {
                    worker_id: worker_id.clone(),
                    skipped: false,
                    skip_reason: None,
                    candidates_found: 0,
                    response_status: Some("no_candidates".to_string()),
                    escalation_level: None,
                    actions_executed: 0,
                    actions_escalated: 0,
                });
                continue;
            }

            total_candidates += request.candidate_processes.len() as u32;
            let response = self.pipeline.execute(&request).await;

            let executed = response.executed_actions.iter()
                .filter(|a| a.outcome == ProcessTriageActionOutcome::Executed).count() as u32;
            let escalated = response.executed_actions.iter()
                .filter(|a| a.outcome == ProcessTriageActionOutcome::Escalated).count() as u32;

            total_actions += executed;
            total_escalations += escalated;

            worker_results.push(WorkerTriageResult {
                worker_id: worker_id.clone(),
                skipped: false,
                skip_reason: None,
                candidates_found: request.candidate_processes.len() as u32,
                response_status: Some(format!("{:?}", response.status)),
                escalation_level: Some(format!("{:?}", response.escalation_level)),
                actions_executed: executed,
                actions_escalated: escalated,
            });
        }

        let result = TriageSweepResult {
            sweep_id,
            workers_evaluated,
            workers_skipped,
            total_candidates,
            actions_taken: total_actions,
            escalations: total_escalations,
            budget_exhausted,
            duration_ms: sweep_start.elapsed().as_millis() as u64,
            worker_results,
            timestamp_unix_ms: Utc::now().timestamp_millis(),
        };

        self.events.emit("process_triage.sweep_completed", &result);

        if budget_exhausted {
            info!(
                sweep_id,
                workers_evaluated,
                workers_skipped,
                total_actions,
                "Triage sweep completed (budget exhausted, partial results)"
            );
        } else {
            debug!(
                sweep_id,
                workers_evaluated,
                workers_skipped,
                total_actions,
                "Triage sweep completed"
            );
        }

        result
    }
}

/// Build a synthetic sweep request for a worker. In production this would
/// integrate with the stuck-process detector; for now it produces an
/// observe-only probe.
fn build_sweep_request(worker_id: &str, sweep_id: u64) -> ProcessTriageRequest {
    use rch_common::e2e::process_triage::ProcessTriageTrigger;

    ProcessTriageRequest {
        schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: format!("sweep-{sweep_id}-{worker_id}"),
        worker_id: worker_id.to_string(),
        observed_at_unix_ms: Utc::now().timestamp_millis(),
        trigger: ProcessTriageTrigger::WorkerHealth,
        detector_confidence_percent: 0,
        retry_attempt: 0,
        candidate_processes: vec![],
        requested_actions: vec![],
    }
}

/// On-demand triage command that shares the same pipeline as the loop.
///
/// Returns structured results suitable for machine or human consumption.
pub struct TriageCommand {
    pipeline: Arc<RemediationPipeline>,
    pool: crate::workers::WorkerPool,
    events: EventBus,
}

impl TriageCommand {
    /// Create a new on-demand triage command.
    pub fn new(
        pipeline: Arc<RemediationPipeline>,
        pool: crate::workers::WorkerPool,
        events: EventBus,
    ) -> Self {
        Self {
            pipeline,
            pool,
            events,
        }
    }

    /// Run an on-demand triage sweep against a specific worker (or all workers).
    pub async fn run(
        &self,
        worker_filter: Option<&str>,
        budget: Duration,
    ) -> TriageSweepResult {
        let mut loop_runner = TriageLoop::new(
            self.pipeline.clone(),
            self.pool.clone(),
            self.events.clone(),
            TriageLoopConfig {
                interval: Duration::from_secs(0), // Unused for on-demand
                sweep_budget: budget,
                skip_busy_workers: false, // On-demand includes all workers
            },
        );
        loop_runner.sweep(worker_filter).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::e2e::process_triage::{
        ProcessClassification, ProcessDescriptor, ProcessTriageActionRequest,
        ProcessTriageTrigger,
    };
    use rch_common::test_guard;

    fn make_test_pipeline(config: RemediationPipelineConfig) -> RemediationPipeline {
        let contract = ProcessTriageContract::default();
        let events = EventBus::new(16);
        RemediationPipeline::new(contract, events, config)
    }

    fn make_default_pipeline() -> RemediationPipeline {
        make_test_pipeline(RemediationPipelineConfig {
            dry_run: true,
            worker_cooldown: Duration::from_millis(0),
            ..RemediationPipelineConfig::default()
        })
    }

    fn sample_process(pid: u32, command: &str, classification: ProcessClassification) -> ProcessDescriptor {
        ProcessDescriptor {
            pid,
            ppid: Some(1),
            owner: "ubuntu".to_string(),
            command: command.to_string(),
            classification,
            cpu_percent_milli: 95000,
            rss_mb: 2048,
            runtime_secs: 300,
        }
    }

    fn sample_request(processes: Vec<ProcessDescriptor>, actions: Vec<ProcessTriageActionRequest>) -> ProcessTriageRequest {
        ProcessTriageRequest {
            schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
            correlation_id: "test-corr-001".to_string(),
            worker_id: "test-worker-1".to_string(),
            observed_at_unix_ms: Utc::now().timestamp_millis(),
            trigger: ProcessTriageTrigger::BuildTimeout,
            detector_confidence_percent: 96,
            retry_attempt: 0,
            candidate_processes: processes,
            requested_actions: actions,
        }
    }

    // -----------------------------------------------------------------------
    // AC1: Bounded escalation (observe -> TERM -> KILL) with guardrails
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_observe_only_action_executes_without_signal() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let proc = sample_process(1001, "cargo test", ProcessClassification::BuildRelated);
        let req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::ObserveOnly,
                pid: 1001,
                reason_code: "stuck_observe".to_string(),
                signal: None,
            }],
        );

        let resp = pipeline.execute(&req).await;
        assert_eq!(resp.status, ProcessTriageResponseStatus::Applied);
        assert_eq!(resp.executed_actions.len(), 1);
        assert_eq!(resp.executed_actions[0].outcome, ProcessTriageActionOutcome::Executed);
        assert_eq!(resp.executed_actions[0].action_class, ProcessTriageActionClass::ObserveOnly);
    }

    #[tokio::test]
    async fn test_soft_terminate_permitted_for_managed_process() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let proc = sample_process(1001, "cargo test --workspace", ProcessClassification::BuildRelated);
        let req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 1001,
                reason_code: "stuck_compile".to_string(),
                signal: Some("TERM".to_string()),
            }],
        );

        let resp = pipeline.execute(&req).await;
        // In dry-run mode, action is "executed" (logged but not actually sent)
        assert_eq!(resp.status, ProcessTriageResponseStatus::Applied);
        assert_eq!(resp.executed_actions[0].outcome, ProcessTriageActionOutcome::Executed);
    }

    #[tokio::test]
    async fn test_hard_terminate_blocked_by_default_policy() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let proc = sample_process(1001, "cargo build", ProcessClassification::BuildRelated);
        let req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::HardTerminate,
                pid: 1001,
                reason_code: "stuck_hard".to_string(),
                signal: Some("KILL".to_string()),
            }],
        );

        let resp = pipeline.execute(&req).await;
        // Default policy denylists HardTerminate
        assert!(
            resp.status == ProcessTriageResponseStatus::EscalatedNoAction
            || resp.status == ProcessTriageResponseStatus::RejectedByPolicy
        );
        assert_eq!(resp.executed_actions[0].outcome, ProcessTriageActionOutcome::Escalated);
    }

    // -----------------------------------------------------------------------
    // AC2: Actions scoped to verified offender processes only
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_protected_process_is_never_terminated() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let proc = sample_process(1, "sshd: ubuntu@pts/0", ProcessClassification::SystemCritical);
        let req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 1,
                reason_code: "false_positive".to_string(),
                signal: Some("TERM".to_string()),
            }],
        );

        let resp = pipeline.execute(&req).await;
        assert_ne!(resp.status, ProcessTriageResponseStatus::Applied);
        assert_eq!(resp.executed_actions[0].outcome, ProcessTriageActionOutcome::Escalated);
    }

    #[tokio::test]
    async fn test_out_of_scope_process_is_blocked() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let proc = sample_process(2000, "python3 train.py", ProcessClassification::Unknown);
        let req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 2000,
                reason_code: "not_build_related".to_string(),
                signal: Some("TERM".to_string()),
            }],
        );

        let resp = pipeline.execute(&req).await;
        assert_ne!(resp.status, ProcessTriageResponseStatus::Applied);
    }

    #[tokio::test]
    async fn test_unknown_pid_in_action_rejected() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let proc = sample_process(1001, "cargo test", ProcessClassification::BuildRelated);
        let req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 9999, // not in candidate_processes
                reason_code: "bogus".to_string(),
                signal: Some("TERM".to_string()),
            }],
        );

        let resp = pipeline.execute(&req).await;
        assert_eq!(resp.status, ProcessTriageResponseStatus::Failed);
        assert!(resp.failure.is_some());
        assert_eq!(resp.failure.unwrap().kind, ProcessTriageFailureKind::InvalidRequest);
    }

    // -----------------------------------------------------------------------
    // AC3: Every action emits audit record with evidence/rationale/outcome
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_audit_record_always_present() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let proc = sample_process(1001, "cargo test", ProcessClassification::BuildRelated);
        let req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::ObserveOnly,
                pid: 1001,
                reason_code: "check".to_string(),
                signal: None,
            }],
        );

        let resp = pipeline.execute(&req).await;
        assert_eq!(resp.audit.policy_version, "v1");
        assert_eq!(resp.audit.evaluated_by, "rchd_remediation_pipeline");
        assert!(resp.audit.evaluated_at_unix_ms > 0);
        assert!(!resp.audit.decision_code.is_empty());
        assert!(resp.audit.audit_required);
    }

    #[tokio::test]
    async fn test_audit_events_emitted_for_each_action() {
        let _guard = test_guard!();
        let contract = ProcessTriageContract::default();
        let events = EventBus::new(64);
        let mut rx = events.subscribe();
        let pipeline = RemediationPipeline::new(
            contract,
            events,
            RemediationPipelineConfig {
                dry_run: true,
                worker_cooldown: Duration::from_millis(0),
                ..RemediationPipelineConfig::default()
            },
        );

        let req = sample_request(
            vec![
                sample_process(1001, "cargo test", ProcessClassification::BuildRelated),
                sample_process(1002, "rustc main.rs", ProcessClassification::BuildRelated),
            ],
            vec![
                ProcessTriageActionRequest {
                    action_class: ProcessTriageActionClass::SoftTerminate,
                    pid: 1001,
                    reason_code: "stuck_1".to_string(),
                    signal: Some("TERM".to_string()),
                },
                ProcessTriageActionRequest {
                    action_class: ProcessTriageActionClass::ObserveOnly,
                    pid: 1002,
                    reason_code: "watch_2".to_string(),
                    signal: None,
                },
            ],
        );

        let _resp = pipeline.execute(&req).await;

        // Collect all events
        let mut audit_events = vec![];
        while let Ok(msg) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            if let Ok(msg) = msg {
                let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
                if parsed["event"] == "process_triage.action_audit" {
                    audit_events.push(parsed);
                }
            }
        }

        // Should have 2 audit events (one per action)
        assert_eq!(audit_events.len(), 2);

        // Each should have evidence
        for ev in &audit_events {
            assert!(ev["data"]["evidence"]["command"].is_string());
            assert!(ev["data"]["evidence"]["detector_confidence_percent"].is_number());
            assert!(ev["data"]["decision_code"].is_string());
            assert!(ev["data"]["outcome"].is_string());
        }
    }

    // -----------------------------------------------------------------------
    // AC4: Pipeline supports abort when confidence drops or safety fails
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_low_confidence_triggers_manual_review() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let proc = sample_process(1001, "cargo test", ProcessClassification::BuildRelated);
        let mut req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 1001,
                reason_code: "uncertain".to_string(),
                signal: Some("TERM".to_string()),
            }],
        );
        req.detector_confidence_percent = 50; // Below 85% threshold

        let resp = pipeline.execute(&req).await;
        assert_eq!(resp.status, ProcessTriageResponseStatus::EscalatedNoAction);
        assert_eq!(resp.escalation_level, ProcessTriageEscalationLevel::ManualReview);
        assert!(resp.audit.requires_operator_ack);
    }

    #[tokio::test]
    async fn test_concurrent_pipeline_limit_aborts() {
        let _guard = test_guard!();
        let pipeline = make_test_pipeline(RemediationPipelineConfig {
            max_concurrent_pipelines: 0, // Immediately at limit
            dry_run: true,
            worker_cooldown: Duration::from_millis(0),
            ..RemediationPipelineConfig::default()
        });

        let proc = sample_process(1001, "cargo test", ProcessClassification::BuildRelated);
        let req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::ObserveOnly,
                pid: 1001,
                reason_code: "check".to_string(),
                signal: None,
            }],
        );

        let resp = pipeline.execute(&req).await;
        assert_eq!(resp.status, ProcessTriageResponseStatus::Failed);
        assert!(resp.failure.is_some());
        assert_eq!(resp.failure.unwrap().code, "PT_CONCURRENT_LIMIT");
    }

    #[tokio::test]
    async fn test_worker_cooldown_prevents_rapid_execution() {
        let _guard = test_guard!();
        let pipeline = make_test_pipeline(RemediationPipelineConfig {
            dry_run: true,
            worker_cooldown: Duration::from_secs(300), // Long cooldown
            ..RemediationPipelineConfig::default()
        });

        let proc = sample_process(1001, "cargo test", ProcessClassification::BuildRelated);
        let req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::ObserveOnly,
                pid: 1001,
                reason_code: "check".to_string(),
                signal: None,
            }],
        );

        // First run succeeds
        let resp1 = pipeline.execute(&req).await;
        assert_eq!(resp1.status, ProcessTriageResponseStatus::Applied);

        // Second run should be blocked by cooldown
        let resp2 = pipeline.execute(&req).await;
        assert_eq!(resp2.status, ProcessTriageResponseStatus::Failed);
        assert!(resp2.failure.is_some());
        assert_eq!(resp2.failure.unwrap().code, "PT_WORKER_COOLDOWN");
    }

    #[tokio::test]
    async fn test_retry_exhaustion_triggers_manual_review() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let proc = sample_process(1001, "cargo test", ProcessClassification::BuildRelated);
        let mut req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 1001,
                reason_code: "stuck".to_string(),
                signal: Some("TERM".to_string()),
            }],
        );
        req.retry_attempt = 2; // max_attempts=3, so attempt 2+1 >= 3

        let resp = pipeline.execute(&req).await;
        assert_eq!(resp.status, ProcessTriageResponseStatus::EscalatedNoAction);
        assert_eq!(resp.escalation_level, ProcessTriageEscalationLevel::ManualReview);
    }

    // -----------------------------------------------------------------------
    // AC5: Integration tests validate escalation, safety, and audit
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_mixed_actions_partial_apply() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let req = sample_request(
            vec![
                sample_process(1001, "cargo test", ProcessClassification::BuildRelated),
                sample_process(1002, "sshd", ProcessClassification::SystemCritical),
            ],
            vec![
                ProcessTriageActionRequest {
                    action_class: ProcessTriageActionClass::SoftTerminate,
                    pid: 1001,
                    reason_code: "stuck_build".to_string(),
                    signal: Some("TERM".to_string()),
                },
                ProcessTriageActionRequest {
                    action_class: ProcessTriageActionClass::SoftTerminate,
                    pid: 1002,
                    reason_code: "false_alarm".to_string(),
                    signal: Some("TERM".to_string()),
                },
            ],
        );

        let resp = pipeline.execute(&req).await;
        // First action should execute, second should be blocked (protected process)
        assert_eq!(resp.executed_actions.len(), 2);
        assert_eq!(resp.executed_actions[0].outcome, ProcessTriageActionOutcome::Executed);
        assert_eq!(resp.executed_actions[1].outcome, ProcessTriageActionOutcome::Escalated);
        // Partial = some executed, some escalated
        assert_eq!(resp.status, ProcessTriageResponseStatus::PartiallyApplied);
    }

    #[tokio::test]
    async fn test_pipeline_summary_event_emitted() {
        let _guard = test_guard!();
        let contract = ProcessTriageContract::default();
        let events = EventBus::new(64);
        let mut rx = events.subscribe();
        let pipeline = RemediationPipeline::new(
            contract,
            events,
            RemediationPipelineConfig {
                dry_run: true,
                worker_cooldown: Duration::from_millis(0),
                ..RemediationPipelineConfig::default()
            },
        );

        let req = sample_request(
            vec![sample_process(1001, "cargo test", ProcessClassification::BuildRelated)],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::ObserveOnly,
                pid: 1001,
                reason_code: "check".to_string(),
                signal: None,
            }],
        );

        let _resp = pipeline.execute(&req).await;

        let mut found_summary = false;
        while let Ok(msg) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            if let Ok(msg) = msg {
                let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
                if parsed["event"] == "process_triage.pipeline_completed" {
                    found_summary = true;
                    assert_eq!(parsed["data"]["correlation_id"], "test-corr-001");
                    assert!(parsed["data"]["total_duration_ms"].is_number());
                    assert_eq!(parsed["data"]["actions_executed"], 1);
                }
            }
        }
        assert!(found_summary, "Pipeline summary event not emitted");
    }

    #[tokio::test]
    async fn test_invalid_request_returns_failure() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let req = ProcessTriageRequest {
            schema_version: "0.0.0-invalid".to_string(), // Wrong version
            correlation_id: "corr-bad".to_string(),
            worker_id: "w1".to_string(),
            observed_at_unix_ms: Utc::now().timestamp_millis(),
            trigger: ProcessTriageTrigger::Manual,
            detector_confidence_percent: 90,
            retry_attempt: 0,
            candidate_processes: vec![],
            requested_actions: vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::ObserveOnly,
                pid: 1,
                reason_code: "x".to_string(),
                signal: None,
            }],
        };

        let resp = pipeline.execute(&req).await;
        assert_eq!(resp.status, ProcessTriageResponseStatus::Failed);
        assert!(resp.failure.is_some());
        assert_eq!(resp.failure.unwrap().kind, ProcessTriageFailureKind::InvalidRequest);
    }

    #[tokio::test]
    async fn test_worker_state_tracks_actions() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let proc = sample_process(1001, "cargo test", ProcessClassification::BuildRelated);
        let req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 1001,
                reason_code: "stuck".to_string(),
                signal: Some("TERM".to_string()),
            }],
        );

        assert!(pipeline.worker_state("test-worker-1").await.is_none());

        let _resp = pipeline.execute(&req).await;

        let state = pipeline.worker_state("test-worker-1").await.unwrap();
        assert_eq!(state.total_actions, 1);
        assert_eq!(state.hard_terminations, 0);
        assert_eq!(state.consecutive_failures, 0);
        assert!(state.last_pipeline_at.is_some());
    }

    #[tokio::test]
    async fn test_reset_worker_state_clears_tracking() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        let proc = sample_process(1001, "cargo test", ProcessClassification::BuildRelated);
        let req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::ObserveOnly,
                pid: 1001,
                reason_code: "check".to_string(),
                signal: None,
            }],
        );

        let _resp = pipeline.execute(&req).await;
        assert!(pipeline.worker_state("test-worker-1").await.is_some());

        pipeline.reset_worker_state("test-worker-1").await;
        assert!(pipeline.worker_state("test-worker-1").await.is_none());
    }

    #[tokio::test]
    async fn test_action_volume_downgrade_to_supervised() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();

        // Create 6 actions (exceeds max_actions_before_manual_review=5)
        let processes: Vec<ProcessDescriptor> = (0..6)
            .map(|i| sample_process(1000 + i, &format!("cargo build -p crate{i}"), ProcessClassification::BuildRelated))
            .collect();
        let actions: Vec<ProcessTriageActionRequest> = (0..6)
            .map(|i| ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 1000 + i,
                reason_code: format!("stuck_{i}"),
                signal: Some("TERM".to_string()),
            })
            .collect();

        let req = sample_request(processes, actions);
        let resp = pipeline.execute(&req).await;

        // All actions should be downgraded to ObserveOnly (supervised mode)
        for action in &resp.executed_actions {
            assert_eq!(action.action_class, ProcessTriageActionClass::ObserveOnly);
        }
        assert_eq!(resp.escalation_level, ProcessTriageEscalationLevel::Supervised);
    }

    #[tokio::test]
    async fn test_active_pipeline_count_tracking() {
        let _guard = test_guard!();
        let pipeline = make_default_pipeline();
        assert_eq!(pipeline.active_pipeline_count(), 0);

        // Run a pipeline and verify count returns to 0 after
        let proc = sample_process(1001, "cargo test", ProcessClassification::BuildRelated);
        let req = sample_request(
            vec![proc],
            vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::ObserveOnly,
                pid: 1001,
                reason_code: "check".to_string(),
                signal: None,
            }],
        );
        let _resp = pipeline.execute(&req).await;
        assert_eq!(pipeline.active_pipeline_count(), 0);
    }

    #[tokio::test]
    async fn test_config_defaults_match_constants() {
        let _guard = test_guard!();
        let config = RemediationPipelineConfig::default();
        assert_eq!(config.max_escalation_steps, MAX_ESCALATION_STEPS);
        assert_eq!(config.term_grace_period, TERM_GRACE_PERIOD);
        assert_eq!(config.pipeline_timeout, PIPELINE_TOTAL_TIMEOUT);
        assert_eq!(config.max_concurrent_pipelines, MAX_CONCURRENT_PIPELINES);
        assert_eq!(config.worker_cooldown, WORKER_PIPELINE_COOLDOWN);
        assert!(!config.dry_run);
    }

    #[tokio::test]
    async fn test_escalation_step_ladder() {
        let _guard = test_guard!();
        let step = EscalationStep::Observe;
        assert_eq!(step.next(), Some(EscalationStep::SoftTerminate));
        assert_eq!(step.signal(), None);

        let step = EscalationStep::SoftTerminate;
        assert_eq!(step.next(), Some(EscalationStep::HardTerminate));
        assert_eq!(step.signal(), Some("TERM"));

        let step = EscalationStep::HardTerminate;
        assert_eq!(step.next(), None);
        assert_eq!(step.signal(), Some("KILL"));
    }

    // -----------------------------------------------------------------------
    // TriageLoop tests (bd-vvmd.5.4)
    // -----------------------------------------------------------------------

    async fn make_test_pool() -> crate::workers::WorkerPool {
        use rch_common::WorkerConfig;
        let pool: crate::workers::WorkerPool = crate::workers::WorkerPool::new();
        pool.add_worker(WorkerConfig {
            id: rch_common::WorkerId::new("loop-w1"),
            ..WorkerConfig::default()
        }).await;
        pool.add_worker(WorkerConfig {
            id: rch_common::WorkerId::new("loop-w2"),
            ..WorkerConfig::default()
        }).await;
        pool
    }

    #[tokio::test]
    async fn test_triage_loop_sweep_empty_candidates() {
        let _guard = test_guard!();
        let pipeline = Arc::new(make_default_pipeline());
        let pool = make_test_pool().await;
        let events = EventBus::new(64);
        let mut triage = TriageLoop::new(
            pipeline,
            pool,
            events,
            TriageLoopConfig::default(),
        );

        let result = triage.sweep(None).await;
        assert_eq!(result.sweep_id, 1);
        assert_eq!(result.workers_evaluated, 2);
        assert_eq!(result.total_candidates, 0);
        assert_eq!(result.actions_taken, 0);
        assert!(!result.budget_exhausted);
    }

    #[tokio::test]
    async fn test_triage_loop_sweep_increments_id() {
        let _guard = test_guard!();
        let pipeline = Arc::new(make_default_pipeline());
        let pool = make_test_pool().await;
        let events = EventBus::new(64);
        let mut triage = TriageLoop::new(
            pipeline,
            pool,
            events,
            TriageLoopConfig::default(),
        );

        let r1 = triage.sweep(None).await;
        let r2 = triage.sweep(None).await;
        let r3 = triage.sweep(None).await;
        assert_eq!(r1.sweep_id, 1);
        assert_eq!(r2.sweep_id, 2);
        assert_eq!(r3.sweep_id, 3);
    }

    #[tokio::test]
    async fn test_triage_loop_skips_busy_workers() {
        let _guard = test_guard!();
        let pipeline = Arc::new(make_default_pipeline());
        let pool = make_test_pool().await;

        // Reserve slots on loop-w1
        // Reserve slots on loop-w1 via WorkerState
        {
            let workers = pool.all_workers().await;
            for w in &workers {
                let cfg = w.config.read().await;
                if cfg.id.as_str() == "loop-w1" {
                    w.reserve_slots(1).await;
                }
            }
        }

        let events = EventBus::new(64);
        let mut triage = TriageLoop::new(
            pipeline,
            pool.clone(),
            events,
            TriageLoopConfig {
                skip_busy_workers: true,
                ..TriageLoopConfig::default()
            },
        );

        let result = triage.sweep(None).await;
        assert_eq!(result.workers_skipped, 1);
        assert_eq!(result.workers_evaluated, 1);

        // Verify the skipped worker result
        let skipped = result.worker_results.iter()
            .find(|r| r.worker_id == "loop-w1").unwrap();
        assert!(skipped.skipped);
        assert_eq!(skipped.skip_reason.as_deref(), Some("active builds"));
    }

    #[tokio::test]
    async fn test_triage_loop_worker_filter() {
        let _guard = test_guard!();
        let pipeline = Arc::new(make_default_pipeline());
        let pool = make_test_pool().await;
        let events = EventBus::new(64);
        let mut triage = TriageLoop::new(
            pipeline,
            pool,
            events,
            TriageLoopConfig::default(),
        );

        let result = triage.sweep(Some("loop-w1")).await;
        // Only loop-w1 should be evaluated (loop-w2 filtered out)
        assert_eq!(result.worker_results.len(), 1);
        assert_eq!(result.worker_results[0].worker_id, "loop-w1");
    }

    #[tokio::test]
    async fn test_triage_loop_budget_exhaustion() {
        let _guard = test_guard!();
        let pipeline = Arc::new(make_default_pipeline());
        let pool = make_test_pool().await;
        let events = EventBus::new(64);
        let mut triage = TriageLoop::new(
            pipeline,
            pool,
            events,
            TriageLoopConfig {
                sweep_budget: Duration::from_nanos(1), // Immediate exhaustion
                ..TriageLoopConfig::default()
            },
        );

        let result = triage.sweep(None).await;
        assert!(result.budget_exhausted);
    }

    #[tokio::test]
    async fn test_triage_loop_emits_sweep_event() {
        let _guard = test_guard!();
        let pipeline = Arc::new(make_default_pipeline());
        let pool = make_test_pool().await;
        let events = EventBus::new(64);
        let mut rx = events.subscribe();
        let mut triage = TriageLoop::new(
            pipeline,
            pool,
            events,
            TriageLoopConfig::default(),
        );

        let _result = triage.sweep(None).await;

        let mut found = false;
        while let Ok(msg) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            if let Ok(msg) = msg {
                let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
                if parsed["event"] == "process_triage.sweep_completed" {
                    found = true;
                    assert_eq!(parsed["data"]["sweep_id"], 1);
                    assert!(parsed["data"]["duration_ms"].is_number());
                }
            }
        }
        assert!(found, "Sweep completed event not emitted");
    }

    #[tokio::test]
    async fn test_on_demand_triage_command() {
        let _guard = test_guard!();
        let pipeline = Arc::new(make_default_pipeline());
        let pool = make_test_pool().await;
        let events = EventBus::new(64);
        let cmd = TriageCommand::new(pipeline, pool, events);

        // Run on-demand for a specific worker
        let result = cmd.run(Some("loop-w1"), Duration::from_secs(5)).await;
        assert_eq!(result.worker_results.len(), 1);
        assert_eq!(result.worker_results[0].worker_id, "loop-w1");
        assert!(!result.worker_results[0].skipped); // On-demand doesn't skip busy
    }

    #[tokio::test]
    async fn test_on_demand_triage_all_workers() {
        let _guard = test_guard!();
        let pipeline = Arc::new(make_default_pipeline());
        let pool = make_test_pool().await;
        let events = EventBus::new(64);
        let cmd = TriageCommand::new(pipeline, pool, events);

        let result = cmd.run(None, Duration::from_secs(5)).await;
        assert_eq!(result.workers_evaluated, 2);
    }

    #[tokio::test]
    async fn test_loop_and_command_share_pipeline() {
        let _guard = test_guard!();
        let pipeline = Arc::new(make_default_pipeline());
        let pool = make_test_pool().await;
        let events = EventBus::new(64);

        // Both loop and command use the same pipeline Arc
        let mut loop_runner = TriageLoop::new(
            pipeline.clone(),
            pool.clone(),
            events.clone(),
            TriageLoopConfig::default(),
        );
        let cmd = TriageCommand::new(pipeline.clone(), pool.clone(), events.clone());

        // Both produce consistent results for same workers
        let loop_result = loop_runner.sweep(Some("loop-w1")).await;
        let cmd_result = cmd.run(Some("loop-w1"), Duration::from_secs(5)).await;

        assert_eq!(loop_result.worker_results.len(), cmd_result.worker_results.len());
        assert_eq!(
            loop_result.worker_results[0].worker_id,
            cmd_result.worker_results[0].worker_id
        );
    }

    #[tokio::test]
    async fn test_triage_loop_config_defaults() {
        let _guard = test_guard!();
        let config = TriageLoopConfig::default();
        assert_eq!(config.interval, Duration::from_secs(30));
        assert_eq!(config.sweep_budget, Duration::from_secs(15));
        assert!(config.skip_busy_workers);
    }

    #[tokio::test]
    async fn test_sweep_result_serializable() {
        let _guard = test_guard!();
        let result = TriageSweepResult {
            sweep_id: 1,
            workers_evaluated: 2,
            workers_skipped: 0,
            total_candidates: 0,
            actions_taken: 0,
            escalations: 0,
            budget_exhausted: false,
            duration_ms: 10,
            worker_results: vec![],
            timestamp_unix_ms: 1234567890,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"sweep_id\":1"));
        assert!(json.contains("\"budget_exhausted\":false"));
    }
}
