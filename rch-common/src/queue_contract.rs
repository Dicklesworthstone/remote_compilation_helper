//! Queue wait/stream/no-start CLI contract (bd-session-history-remediation-ocv9i.10.2).
//!
//! When a command hits a busy fleet it may be queued. The cardinal rule of the
//! CLI boundary is that an agent must NEVER be left with "maybe running
//! somewhere" uncertainty: every invocation resolves to a **definite**
//! [`StartState`] — it either started (and we wait/stream), returns a job id in
//! an explicit not-started state (reattachable later), or fails before
//! admission. [`resolve_queue_contract`] is the pure decision function that
//! guarantees this, honoring the CLI options (wait, follow/stream, wait
//! timeout, no-start, strict-proof). [`QueueContractResponse`] is the
//! JSON/human envelope.

use serde::{Deserialize, Serialize};

/// CLI options governing queue behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueOptions {
    /// Wait for a queued job to start (and stream), rather than returning early.
    pub wait: bool,
    /// Stream the job's output once it starts (implies `wait`).
    pub follow: bool,
    /// Maximum seconds to wait before returning a reattachable not-started job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_timeout_secs: Option<u64>,
    /// Return a job id without waiting/starting (explicit not-started).
    pub no_start: bool,
    /// Strict (proof) mode: require immediate admission — never queue.
    pub strict: bool,
}

/// What admission decided for this command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionState {
    /// Admitted immediately and running.
    AdmittedRunning,
    /// Capacity was full — the command was queued.
    Queued,
    /// Rejected before any job started (with reason).
    RejectedBeforeAdmission(String),
}

/// What happened while waiting on a queued job (a runtime input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    /// The job started during the wait.
    StartedAfterWait,
    /// The wait timed out before the job started.
    TimedOut,
    /// The job was cancelled before it started.
    CancelledBeforeStart,
}

/// The definite, unambiguous start state of a command. There is deliberately no
/// `Unknown` — eliminating "maybe running somewhere" is the whole point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartState {
    Started,
    NotStarted,
}

/// The resolved queue-contract outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum QueueContractOutcome {
    /// Admitted immediately and running.
    StartedRunning,
    /// Was queued, then started while we waited (streaming).
    WaitingStreamed,
    /// Queued and returned with an explicit not-started state (reattachable).
    QueuedNotStarted,
    /// Queued, but the wait timed out — returned reattachable not-started.
    TimedOutQueued,
    /// Cancelled before it started.
    CancelledBeforeStart,
    /// Rejected before admission — no job ever started.
    FailedBeforeAdmission { reason: String },
}

impl QueueContractOutcome {
    /// The definite start state for this outcome.
    #[must_use]
    pub const fn start_state(&self) -> StartState {
        match self {
            Self::StartedRunning | Self::WaitingStreamed => StartState::Started,
            Self::QueuedNotStarted
            | Self::TimedOutQueued
            | Self::CancelledBeforeStart
            | Self::FailedBeforeAdmission { .. } => StartState::NotStarted,
        }
    }

    /// Did the job start?
    #[must_use]
    pub const fn started(&self) -> bool {
        matches!(self.start_state(), StartState::Started)
    }

    /// Stable snake_case id.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::StartedRunning => "started_running",
            Self::WaitingStreamed => "waiting_streamed",
            Self::QueuedNotStarted => "queued_not_started",
            Self::TimedOutQueued => "timed_out_queued",
            Self::CancelledBeforeStart => "cancelled_before_start",
            Self::FailedBeforeAdmission { .. } => "failed_before_admission",
        }
    }
}

/// Resolve the queue contract — pure and total. Given admission, the CLI
/// options, and (if waited) the wait result, returns exactly one definite
/// outcome. `wait` is ignored unless the command was queued and waiting.
#[must_use]
pub fn resolve_queue_contract(
    admission: &AdmissionState,
    opts: &QueueOptions,
    wait: Option<WaitResult>,
) -> QueueContractOutcome {
    match admission {
        AdmissionState::RejectedBeforeAdmission(reason) => {
            QueueContractOutcome::FailedBeforeAdmission {
                reason: reason.clone(),
            }
        }
        AdmissionState::AdmittedRunning => QueueContractOutcome::StartedRunning,
        AdmissionState::Queued => {
            // Strict (proof) mode refuses to queue — fail fast, nothing started.
            if opts.strict {
                return QueueContractOutcome::FailedBeforeAdmission {
                    reason: "strict mode requires immediate admission; refusing to queue"
                        .to_string(),
                };
            }
            // No-start or no-wait: return a reattachable not-started job.
            if opts.no_start || !(opts.wait || opts.follow) {
                return QueueContractOutcome::QueuedNotStarted;
            }
            match wait {
                Some(WaitResult::StartedAfterWait) => QueueContractOutcome::WaitingStreamed,
                Some(WaitResult::TimedOut) => QueueContractOutcome::TimedOutQueued,
                Some(WaitResult::CancelledBeforeStart) => {
                    QueueContractOutcome::CancelledBeforeStart
                }
                None => QueueContractOutcome::QueuedNotStarted,
            }
        }
    }
}

/// The agent-facing response envelope (JSON/human).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueContractResponse {
    /// The local/remote job id, when a job exists (queued or started).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// Definite: did the job start? Never ambiguous.
    pub started: bool,
    /// The outcome id.
    pub outcome: String,
    /// Whether the agent can reattach later (a job id exists but didn't start).
    pub reattachable: bool,
    /// Operator-facing detail.
    pub detail: String,
}

impl QueueContractResponse {
    /// Build the response for an outcome and (optional) job id.
    #[must_use]
    pub fn build(outcome: &QueueContractOutcome, job_id: Option<String>) -> Self {
        let started = outcome.started();
        // A job id that didn't start is reattachable; a failed-before-admission
        // never produced a job, so it is not.
        let has_job = job_id.is_some();
        let reattachable = has_job && !started;
        let detail = match outcome {
            QueueContractOutcome::StartedRunning => "admitted and running".to_string(),
            QueueContractOutcome::WaitingStreamed => "queued, then started; streaming".to_string(),
            QueueContractOutcome::QueuedNotStarted => {
                "queued; not started — reattach with the job id".to_string()
            }
            QueueContractOutcome::TimedOutQueued => {
                "wait timed out while queued; not started — reattach with the job id".to_string()
            }
            QueueContractOutcome::CancelledBeforeStart => "cancelled before it started".to_string(),
            QueueContractOutcome::FailedBeforeAdmission { reason } => {
                format!("failed before admission: {reason}")
            }
        };
        Self {
            job_id,
            started,
            outcome: outcome.as_str().to_string(),
            reattachable,
            detail,
        }
    }

    /// Human-readable line.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "queue: {} (started={}, reattachable={}{}) — {}",
            self.outcome,
            self.started,
            self.reattachable,
            self.job_id
                .as_deref()
                .map_or_else(String::new, |j| format!(", job={j}")),
            self.detail,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_running_starts() {
        let o = resolve_queue_contract(
            &AdmissionState::AdmittedRunning,
            &QueueOptions::default(),
            None,
        );
        assert_eq!(o, QueueContractOutcome::StartedRunning);
        assert!(o.started());
        assert_eq!(o.start_state(), StartState::Started);
    }

    #[test]
    fn busy_workers_no_wait_returns_reattachable_not_started() {
        // Busy fleet, default options (no wait): explicit not-started + job id.
        let o = resolve_queue_contract(&AdmissionState::Queued, &QueueOptions::default(), None);
        assert_eq!(o, QueueContractOutcome::QueuedNotStarted);
        assert!(!o.started());
        let resp = QueueContractResponse::build(&o, Some("job-1".to_string()));
        assert!(!resp.started);
        assert!(resp.reattachable);
        assert_eq!(resp.job_id.as_deref(), Some("job-1"));
    }

    #[test]
    fn no_start_option_returns_job_id_not_started() {
        let opts = QueueOptions {
            no_start: true,
            ..QueueOptions::default()
        };
        let o = resolve_queue_contract(&AdmissionState::Queued, &opts, None);
        assert_eq!(o, QueueContractOutcome::QueuedNotStarted);
    }

    #[test]
    fn wait_then_started_streams() {
        let opts = QueueOptions {
            wait: true,
            follow: true,
            ..QueueOptions::default()
        };
        let o = resolve_queue_contract(
            &AdmissionState::Queued,
            &opts,
            Some(WaitResult::StartedAfterWait),
        );
        assert_eq!(o, QueueContractOutcome::WaitingStreamed);
        assert!(o.started());
    }

    #[test]
    fn queue_timeout_returns_reattachable_not_started() {
        let opts = QueueOptions {
            wait: true,
            wait_timeout_secs: Some(30),
            ..QueueOptions::default()
        };
        let o = resolve_queue_contract(&AdmissionState::Queued, &opts, Some(WaitResult::TimedOut));
        assert_eq!(o, QueueContractOutcome::TimedOutQueued);
        assert!(!o.started());
        let resp = QueueContractResponse::build(&o, Some("job-7".to_string()));
        assert!(resp.reattachable);
        assert!(resp.detail.contains("reattach"));
    }

    #[test]
    fn cancellation_before_start() {
        let opts = QueueOptions {
            wait: true,
            ..QueueOptions::default()
        };
        let o = resolve_queue_contract(
            &AdmissionState::Queued,
            &opts,
            Some(WaitResult::CancelledBeforeStart),
        );
        assert_eq!(o, QueueContractOutcome::CancelledBeforeStart);
        assert!(!o.started());
    }

    #[test]
    fn strict_mode_refuses_to_queue() {
        let opts = QueueOptions {
            strict: true,
            wait: true,
            ..QueueOptions::default()
        };
        let o = resolve_queue_contract(&AdmissionState::Queued, &opts, None);
        assert!(matches!(
            o,
            QueueContractOutcome::FailedBeforeAdmission { .. }
        ));
        assert!(!o.started());
    }

    #[test]
    fn rejected_before_admission_never_starts_and_has_no_job() {
        let o = resolve_queue_contract(
            &AdmissionState::RejectedBeforeAdmission("no admissible workers".to_string()),
            &QueueOptions::default(),
            None,
        );
        assert_eq!(o.as_str(), "failed_before_admission");
        let resp = QueueContractResponse::build(&o, None);
        assert!(!resp.started);
        assert!(!resp.reattachable, "no job => not reattachable");
        assert!(resp.job_id.is_none());
        assert!(resp.detail.contains("no admissible workers"));
    }

    #[test]
    fn every_outcome_has_a_definite_start_state() {
        // The contract's core guarantee: no outcome is ambiguous.
        let outcomes = [
            QueueContractOutcome::StartedRunning,
            QueueContractOutcome::WaitingStreamed,
            QueueContractOutcome::QueuedNotStarted,
            QueueContractOutcome::TimedOutQueued,
            QueueContractOutcome::CancelledBeforeStart,
            QueueContractOutcome::FailedBeforeAdmission {
                reason: "x".to_string(),
            },
        ];
        for o in &outcomes {
            // start_state() is total and returns exactly Started xor NotStarted.
            let s = o.start_state();
            assert!(s == StartState::Started || s == StartState::NotStarted);
            assert_eq!(o.started(), s == StartState::Started);
        }
    }

    #[test]
    fn response_serde_and_render() {
        let o = resolve_queue_contract(&AdmissionState::Queued, &QueueOptions::default(), None);
        let resp = QueueContractResponse::build(&o, Some("job-9".to_string()));
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["outcome"], "queued_not_started");
        assert_eq!(v["started"], false);
        assert_eq!(v["reattachable"], true);
        let back: QueueContractResponse = serde_json::from_value(v).unwrap();
        assert_eq!(resp, back);
        assert!(resp.render().contains("job=job-9"));
    }
}
