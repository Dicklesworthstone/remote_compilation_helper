//! Prometheus + OpenTelemetry instrumentation for the RCH remediation program
//! (bd-session-history-remediation-ocv9i.14.5).
//!
//! The remediation program introduced a family of durable *states* — incidents,
//! admission decisions, proof-replay intents, the capacity queue, worker
//! eligibility / temporary bypass, auto-rejoin canaries, disk pressure,
//! telemetry freshness, artifact retrieval, and daemon/hook self-healing. Those
//! states are inspectable point-in-time via the CLI, but operators also need to
//! observe *systemic* health over time. This module gives every remediation
//! state a **stable Prometheus metric name** plus an **OpenTelemetry-compatible
//! span** carrying the same stable attributes, so dashboards and traces can
//! reason about RCH the same way the validation matrix does.
//!
//! # Design
//!
//! - **Bounded cardinality.** Every metric label is drawn from a small,
//!   enumerated vocabulary (the typed `rch_common` enums, via their existing
//!   `as_str()` / `code()` accessors, or the local label enums here). Raw
//!   command text, absolute/sensitive paths, and secret-like values are *never*
//!   metric labels. High-cardinality correlation ids (command fingerprint,
//!   queue/job id, project identity) live only on **spans**, and even there are
//!   redacted ([`redact_secrets`] / [`redacted_hash`]) before they leave the
//!   process.
//! - **Typed record API.** Recording methods take `rch_common` enums, so the
//!   label vocabulary is correct by construction — there is no unbounded string
//!   to normalize on the hot path.
//! - **Off the hot path.** Recording happens at remediation *decision* points
//!   (selection fallback, the bypass-recovery loop, conveyor scans), never in
//!   the `<1ms` classification path, so the hot-path budgets (16.7) are
//!   untouched.
//! - **Process-global handle.** Mirroring the daemon's existing global metric
//!   helpers, a [`OnceLock`] holds the registered instance so daemon call sites
//!   stay terse (`remediation::record_*`) without threading an instance through
//!   every signature. Tests use the instance API against a private registry.

use std::sync::OnceLock;

use prometheus::{CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, Opts, Registry};

use rch_common::BypassFailureClass;
use rch_common::artifact_cost::RetrievalMode;
use rch_common::bypass_recovery::CanaryOutcome;
use rch_common::disk_pressure_report::{DiskRootKind, PressureLevel};
use rch_common::incident::{
    IncidentEvent, IncidentEventType, IncidentReasonCode, IncidentSource, SelectedMode,
};
use rch_common::proof_replay::{ProofState, ReplayOutcome};
use rch_common::queue_contract::QueueContractOutcome;
use rch_common::redaction::{redact_secrets, redacted_hash};
use rch_common::telemetry_freshness::FreshnessVerdict;

// ============================================================================
// Bounded label vocabularies
// ============================================================================
//
// These mirror the typed enums and are used by the [`MetricSpec`] inventory and
// the cardinality tests. They are the single source of truth for "what values
// can ever appear on this label" and are kept in lockstep with the enums by the
// `*_labels_match_enum` unit tests below.

/// Subsystem that produced an incident ([`IncidentEventType`]).
pub const INCIDENT_EVENT_TYPE_LABELS: &[&str] = &[
    "selection",
    "admission",
    "fallback",
    "proof",
    "doctor",
    "telemetry",
    "artifact_retrieval",
    "worker_lifecycle",
];

/// Emitting process/component ([`IncidentSource`]).
pub const INCIDENT_SOURCE_LABELS: &[&str] = &["hook", "daemon", "worker", "doctor", "cli"];

/// Where the build ran / was steered ([`SelectedMode`]).
pub const SELECTED_MODE_LABELS: &[&str] = &["local", "remote", "deferred"];

/// Stable `RCH-Innn` incident reason codes ([`IncidentReasonCode`]).
pub const INCIDENT_REASON_CODE_LABELS: &[&str] = &[
    "RCH-I001", "RCH-I002", "RCH-I003", "RCH-I004", "RCH-I005", "RCH-I006", "RCH-I007", "RCH-I008",
    "RCH-I009", "RCH-I010", "RCH-I011", "RCH-I012", "RCH-I013", "RCH-I014", "RCH-I015", "RCH-I016",
    "RCH-I017",
];

/// Admission decision / selected execution location ([`AdmissionDecision`]).
pub const ADMISSION_DECISION_LABELS: &[&str] =
    &["local", "remote", "deferred", "refused", "queued"];

/// Normalized local-fallback / admission reasons. Mirrors the daemon's
/// `normalize_fallback_reason_label` vocabulary so the two surfaces agree.
pub const FALLBACK_REASON_LABELS: &[&str] = &[
    "no_workers_configured",
    "all_workers_unreachable",
    "all_circuits_open",
    "all_workers_busy",
    "all_workers_failed_preflight",
    "all_workers_failed_convergence",
    "no_matching_workers",
    "no_workers_with_runtime",
    "selection_error",
    "daemon_unavailable",
    "dependency_preflight",
    "remote_pipeline_failed",
    "confidence_below_threshold",
    "force_local",
    "allowlist_blocked",
    "other",
];

/// Proof-replay intent states ([`ProofState`]).
pub const PROOF_STATE_LABELS: &[&str] = &[
    "queued",
    "blocked",
    "replaying",
    "passed",
    "failed",
    "stale",
];

/// Replay outcomes ([`ReplayOutcome`]).
pub const REPLAY_OUTCOME_LABELS: &[&str] =
    &["succeeded", "product_failed", "infrastructure_failed"];

/// Resolved queue-contract outcomes ([`QueueContractOutcome`]).
pub const QUEUE_OUTCOME_LABELS: &[&str] = &[
    "started_running",
    "waiting_streamed",
    "queued_not_started",
    "timed_out_queued",
    "cancelled_before_start",
    "failed_before_admission",
];

/// Reasons a worker is ineligible / quarantined ([`BypassFailureClass`]).
pub const WORKER_INELIGIBLE_LABELS: &[&str] = &[
    "ssh",
    "worker_binary",
    "runtime_toolchain",
    "disk_inode_pressure",
    "stale_telemetry",
    "path_sync",
    "artifact_retrieval",
    "circuit_breaker",
    "os_arch_mismatch",
];

/// Temporary-bypass lifecycle transitions ([`BypassTransition`]).
pub const BYPASS_TRANSITION_LABELS: &[&str] = &[
    "bypassed",
    "stay_bypassed",
    "keep_probing",
    "ready_for_canary",
    "rejoin",
    "relapse",
];

/// Auto-rejoin canary outcomes ([`CanaryOutcome`]).
pub const CANARY_OUTCOME_LABELS: &[&str] = &["passed", "failed"];

/// Disk roots ([`DiskRootKind`]).
pub const DISK_ROOT_KIND_LABELS: &[&str] = &[
    "target_root",
    "cargo_home",
    "sync_root",
    "log",
    "temp_root",
    "other",
];

/// Telemetry freshness verdicts ([`FreshnessVerdict`]).
pub const FRESHNESS_VERDICT_LABELS: &[&str] = &["fresh", "slow_observer", "stale", "unknown"];

/// Artifact retrieval modes ([`RetrievalMode`]).
pub const RETRIEVAL_MODE_LABELS: &[&str] = &["glob", "manifest"];

/// Self-healing actions ([`SelfHealingAction`]).
pub const SELF_HEALING_ACTION_LABELS: &[&str] = &[
    "hook_autostart_daemon",
    "daemon_install_hooks",
    "worker_rejoin",
    "bypass_recovery",
    "doctor_remediation",
];

/// Self-healing outcomes ([`SelfHealingOutcome`]).
pub const SELF_HEALING_OUTCOME_LABELS: &[&str] = &["success", "failure", "skipped", "noop"];

// ============================================================================
// Local label enums (states with no single owning rch_common enum)
// ============================================================================

/// Admission decision / selected execution location for the admission counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Ran (or fell back to) local execution.
    Local,
    /// Steered to a remote worker.
    Remote,
    /// Deferred (e.g. proof replay enqueued).
    Deferred,
    /// Refused before admission (fail-closed).
    Refused,
    /// Capacity full — queued.
    Queued,
}

impl AdmissionDecision {
    /// Every decision, in stable declaration order.
    pub const ALL: &'static [AdmissionDecision] = &[
        Self::Local,
        Self::Remote,
        Self::Deferred,
        Self::Refused,
        Self::Queued,
    ];

    /// Stable lowercase token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Deferred => "deferred",
            Self::Refused => "refused",
            Self::Queued => "queued",
        }
    }
}

/// Temporary-bypass lifecycle transition, derived from the bypass-recovery
/// decision core ([`rch_common::bypass_recovery::ProbeDecision`] /
/// [`rch_common::bypass_recovery::CanaryDecision`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassTransition {
    /// A worker was newly quarantined out of scheduling.
    Bypassed,
    /// A recovery probe failed a hard dimension — stays bypassed.
    StayBypassed,
    /// A probe passed but not yet enough consecutive passes — keep probing.
    KeepProbing,
    /// Enough consecutive passes — a canary build is scheduled.
    ReadyForCanary,
    /// The worker rejoined the pool.
    Rejoin,
    /// A canary failed — the worker relapsed into bypass.
    Relapse,
}

impl BypassTransition {
    /// Every transition, in stable declaration order.
    pub const ALL: &'static [BypassTransition] = &[
        Self::Bypassed,
        Self::StayBypassed,
        Self::KeepProbing,
        Self::ReadyForCanary,
        Self::Rejoin,
        Self::Relapse,
    ];

    /// Stable lowercase token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bypassed => "bypassed",
            Self::StayBypassed => "stay_bypassed",
            Self::KeepProbing => "keep_probing",
            Self::ReadyForCanary => "ready_for_canary",
            Self::Rejoin => "rejoin",
            Self::Relapse => "relapse",
        }
    }
}

/// A daemon/hook self-healing action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfHealingAction {
    /// The hook autostarted the daemon after a socket failure.
    HookAutostartDaemon,
    /// The daemon installed/repaired agent hooks on startup.
    DaemonInstallHooks,
    /// A bypassed worker was rejoined to the pool.
    WorkerRejoin,
    /// The bypass-recovery loop ran a probe/canary cycle.
    BypassRecovery,
    /// Doctor applied an automated remediation.
    DoctorRemediation,
}

impl SelfHealingAction {
    /// Every action, in stable declaration order.
    pub const ALL: &'static [SelfHealingAction] = &[
        Self::HookAutostartDaemon,
        Self::DaemonInstallHooks,
        Self::WorkerRejoin,
        Self::BypassRecovery,
        Self::DoctorRemediation,
    ];

    /// Stable lowercase token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HookAutostartDaemon => "hook_autostart_daemon",
            Self::DaemonInstallHooks => "daemon_install_hooks",
            Self::WorkerRejoin => "worker_rejoin",
            Self::BypassRecovery => "bypass_recovery",
            Self::DoctorRemediation => "doctor_remediation",
        }
    }
}

/// The outcome of a self-healing action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfHealingOutcome {
    /// The action repaired the condition.
    Success,
    /// The action ran but did not repair the condition.
    Failure,
    /// The action was skipped (disabled / not applicable).
    Skipped,
    /// The action ran but nothing needed doing.
    Noop,
}

impl SelfHealingOutcome {
    /// Every outcome, in stable declaration order.
    pub const ALL: &'static [SelfHealingOutcome] =
        &[Self::Success, Self::Failure, Self::Skipped, Self::Noop];

    /// Stable lowercase token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Skipped => "skipped",
            Self::Noop => "noop",
        }
    }
}

// ============================================================================
// Enum -> label mappings for rch_common enums without an `as_str` accessor
// ============================================================================

/// Label for [`IncidentEventType`] (matches the serde `snake_case` wire form).
#[must_use]
pub const fn event_type_label(t: IncidentEventType) -> &'static str {
    match t {
        IncidentEventType::Selection => "selection",
        IncidentEventType::Admission => "admission",
        IncidentEventType::Fallback => "fallback",
        IncidentEventType::Proof => "proof",
        IncidentEventType::Doctor => "doctor",
        IncidentEventType::Telemetry => "telemetry",
        IncidentEventType::ArtifactRetrieval => "artifact_retrieval",
        IncidentEventType::WorkerLifecycle => "worker_lifecycle",
    }
}

/// Label for [`IncidentSource`] (matches the serde `snake_case` wire form).
#[must_use]
pub const fn source_label(s: IncidentSource) -> &'static str {
    match s {
        IncidentSource::Hook => "hook",
        IncidentSource::Daemon => "daemon",
        IncidentSource::Worker => "worker",
        IncidentSource::Doctor => "doctor",
        IncidentSource::Cli => "cli",
    }
}

/// Label for [`SelectedMode`] (matches the serde `snake_case` wire form).
#[must_use]
pub const fn selected_mode_label(m: SelectedMode) -> &'static str {
    match m {
        SelectedMode::Local => "local",
        SelectedMode::Remote => "remote",
        SelectedMode::Deferred => "deferred",
    }
}

/// Label for [`ReplayOutcome`] (matches the serde `snake_case` wire form).
#[must_use]
pub const fn replay_outcome_label(o: ReplayOutcome) -> &'static str {
    match o {
        ReplayOutcome::Succeeded => "succeeded",
        ReplayOutcome::ProductFailed => "product_failed",
        ReplayOutcome::InfrastructureFailed => "infrastructure_failed",
    }
}

/// Label for [`CanaryOutcome`] (matches the serde `snake_case` wire form).
#[must_use]
pub const fn canary_outcome_label(o: CanaryOutcome) -> &'static str {
    match o {
        CanaryOutcome::Passed => "passed",
        CanaryOutcome::Failed => "failed",
    }
}

/// Label for [`FreshnessVerdict`] (matches the serde `snake_case` wire form).
#[must_use]
pub const fn freshness_verdict_label(v: FreshnessVerdict) -> &'static str {
    match v {
        FreshnessVerdict::Fresh => "fresh",
        FreshnessVerdict::SlowObserver => "slow_observer",
        FreshnessVerdict::Stale => "stale",
        FreshnessVerdict::Unknown => "unknown",
    }
}

/// Label for [`RetrievalMode`] (matches the serde `snake_case` wire form).
#[must_use]
pub const fn retrieval_mode_label(m: RetrievalMode) -> &'static str {
    match m {
        RetrievalMode::Glob => "glob",
        RetrievalMode::Manifest => "manifest",
    }
}

/// Severity rank for a [`PressureLevel`], used as the disk-pressure gauge value.
/// `ok=0`, `unknown=1`, `warning=2`, `critical=3` — a missing metric is more
/// concerning than a healthy one but less than a known warning/critical (mirrors
/// `PressureLevel`'s internal ranking).
#[must_use]
pub const fn pressure_rank(level: PressureLevel) -> f64 {
    match level {
        PressureLevel::Ok => 0.0,
        PressureLevel::Unknown => 1.0,
        PressureLevel::Warning => 2.0,
        PressureLevel::Critical => 3.0,
    }
}

/// Normalize a free-form fallback reason to the bounded vocabulary, routing
/// unknown values to `other` so the label can never explode.
#[must_use]
pub fn normalize_fallback_reason(reason: &str) -> &'static str {
    FALLBACK_REASON_LABELS
        .iter()
        .copied()
        .find(|candidate| *candidate == reason)
        .unwrap_or("other")
}

// ============================================================================
// Span attributes (the OpenTelemetry surface)
// ============================================================================

/// Stable, bounded, redacted attribute set for a remediation span. These are
/// the attributes bead 14.5 requires every remediation span to carry: command
/// fingerprint, worker id (when safe), reason code, selected mode, queue/job
/// ids, and a redacted project identity. The struct enforces redaction at
/// construction so no raw command text / absolute paths / secrets ever reach a
/// span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationAttributes {
    /// Subsystem that produced the event.
    pub event_type: IncidentEventType,
    /// Stable reason code.
    pub reason_code: IncidentReasonCode,
    /// Emitting component.
    pub source: IncidentSource,
    /// Where the build ran / was steered.
    pub selected_mode: SelectedMode,
    /// Redacted classified command fingerprint (never raw command text).
    pub command_fingerprint: String,
    /// Redacted project identity (`blake3:...` or an opaque key).
    pub project_id: String,
    /// Worker id where applicable (short fleet id, safe to attribute).
    pub worker_id: Option<String>,
    /// Queue id where applicable (RCH-generated correlation id).
    pub queue_id: Option<String>,
    /// Job id where applicable (RCH-generated correlation id).
    pub job_id: Option<String>,
}

impl RemediationAttributes {
    /// Build attributes from an [`IncidentEvent`], redacting the fingerprint and
    /// ensuring the project identity is opaque.
    #[must_use]
    pub fn from_incident(ev: &IncidentEvent) -> Self {
        Self {
            event_type: ev.event_type,
            reason_code: ev.reason_code,
            source: ev.source,
            selected_mode: ev.selected_mode,
            command_fingerprint: redact_secrets(&ev.command_fingerprint),
            project_id: ensure_opaque_project_id(&ev.project_id),
            worker_id: ev.worker_id.clone(),
            queue_id: None,
            job_id: None,
        }
    }

    /// Build attributes directly, redacting the fingerprint and project identity.
    #[must_use]
    pub fn new(
        event_type: IncidentEventType,
        reason_code: IncidentReasonCode,
        source: IncidentSource,
        selected_mode: SelectedMode,
        command_fingerprint: &str,
        project_id: &str,
    ) -> Self {
        Self {
            event_type,
            reason_code,
            source,
            selected_mode,
            command_fingerprint: redact_secrets(command_fingerprint),
            project_id: ensure_opaque_project_id(project_id),
            worker_id: None,
            queue_id: None,
            job_id: None,
        }
    }

    /// Attach a worker id (builder style).
    #[must_use]
    pub fn with_worker(mut self, worker_id: impl Into<String>) -> Self {
        self.worker_id = Some(worker_id.into());
        self
    }

    /// Attach a queue id (builder style).
    #[must_use]
    pub fn with_queue(mut self, queue_id: impl Into<String>) -> Self {
        self.queue_id = Some(queue_id.into());
        self
    }

    /// Attach a job id (builder style).
    #[must_use]
    pub fn with_job(mut self, job_id: impl Into<String>) -> Self {
        self.job_id = Some(job_id.into());
        self
    }

    /// Emit an OpenTelemetry-compatible span carrying these attributes. The span
    /// is created and immediately closed (the state transition is instantaneous);
    /// a `tracing-opentelemetry` layer turns it into an exported OTel span when
    /// the daemon's OTel pipeline is active. Optional ids are recorded only when
    /// present so absent attributes are omitted rather than blanked.
    pub fn emit_span(&self) {
        let span = tracing::info_span!(
            target: "rch::remediation",
            "remediation.incident",
            event_type = event_type_label(self.event_type),
            reason_code = self.reason_code.code(),
            source = source_label(self.source),
            selected_mode = selected_mode_label(self.selected_mode),
            command_fingerprint = %self.command_fingerprint,
            project_id = %self.project_id,
            worker_id = tracing::field::Empty,
            queue_id = tracing::field::Empty,
            job_id = tracing::field::Empty,
        );
        if let Some(w) = &self.worker_id {
            span.record("worker_id", w.as_str());
        }
        if let Some(q) = &self.queue_id {
            span.record("queue_id", q.as_str());
        }
        if let Some(j) = &self.job_id {
            span.record("job_id", j.as_str());
        }
        let _enter = span.enter();
    }
}

/// Ensure a project identity is opaque: pass through an existing `blake3:` hash
/// or an already-opaque key, but hash anything that looks like a filesystem path
/// so an absolute/home path never lands on a span.
#[must_use]
fn ensure_opaque_project_id(value: &str) -> String {
    if value.starts_with("blake3:") {
        value.to_string()
    } else if value.contains('/') {
        redacted_hash(value)
    } else {
        value.to_string()
    }
}

// ============================================================================
// Metric inventory
// ============================================================================

/// Static inventory metadata used by the cardinality / vocabulary tests.
#[derive(Debug, Clone, Copy)]
pub struct MetricSpec {
    /// Prometheus metric name.
    pub name: &'static str,
    /// Label names in declaration order.
    pub labels: &'static [&'static str],
    /// Bounded values accepted for each label.
    pub label_values: &'static [&'static [&'static str]],
}

const REMEDIATION_METRIC_SPECS: &[MetricSpec] = &[
    MetricSpec {
        name: "rch_remediation_incident_total",
        labels: &["event_type", "reason_code", "source"],
        label_values: &[
            INCIDENT_EVENT_TYPE_LABELS,
            INCIDENT_REASON_CODE_LABELS,
            INCIDENT_SOURCE_LABELS,
        ],
    },
    MetricSpec {
        name: "rch_remediation_admission_total",
        labels: &["decision", "reason"],
        label_values: &[ADMISSION_DECISION_LABELS, FALLBACK_REASON_LABELS],
    },
    MetricSpec {
        name: "rch_remediation_proof_state",
        labels: &["state"],
        label_values: &[PROOF_STATE_LABELS],
    },
    MetricSpec {
        name: "rch_remediation_proof_transition_total",
        labels: &["from", "to"],
        label_values: &[PROOF_STATE_LABELS, PROOF_STATE_LABELS],
    },
    MetricSpec {
        name: "rch_remediation_proof_outcome_total",
        labels: &["outcome"],
        label_values: &[REPLAY_OUTCOME_LABELS],
    },
    MetricSpec {
        name: "rch_remediation_queue_depth",
        labels: &[],
        label_values: &[],
    },
    MetricSpec {
        name: "rch_remediation_queue_wait_seconds",
        labels: &[],
        label_values: &[],
    },
    MetricSpec {
        name: "rch_remediation_queue_outcome_total",
        labels: &["outcome"],
        label_values: &[QUEUE_OUTCOME_LABELS],
    },
    MetricSpec {
        name: "rch_remediation_worker_ineligible_total",
        labels: &["reason"],
        label_values: &[WORKER_INELIGIBLE_LABELS],
    },
    MetricSpec {
        name: "rch_remediation_bypass_transition_total",
        labels: &["transition"],
        label_values: &[BYPASS_TRANSITION_LABELS],
    },
    MetricSpec {
        name: "rch_remediation_canary_total",
        labels: &["outcome"],
        label_values: &[CANARY_OUTCOME_LABELS],
    },
    MetricSpec {
        name: "rch_remediation_disk_pressure_level",
        labels: &["root_kind"],
        label_values: &[DISK_ROOT_KIND_LABELS],
    },
    MetricSpec {
        name: "rch_remediation_telemetry_freshness_total",
        labels: &["verdict"],
        label_values: &[FRESHNESS_VERDICT_LABELS],
    },
    MetricSpec {
        name: "rch_remediation_telemetry_confidence",
        labels: &[],
        label_values: &[],
    },
    MetricSpec {
        name: "rch_remediation_artifact_files_total",
        labels: &["mode"],
        label_values: &[RETRIEVAL_MODE_LABELS],
    },
    MetricSpec {
        name: "rch_remediation_artifact_bytes_total",
        labels: &["mode"],
        label_values: &[RETRIEVAL_MODE_LABELS],
    },
    MetricSpec {
        name: "rch_remediation_self_healing_total",
        labels: &["action", "outcome"],
        label_values: &[SELF_HEALING_ACTION_LABELS, SELF_HEALING_OUTCOME_LABELS],
    },
];

/// The static metric inventory, for documentation and cardinality tests.
#[must_use]
pub fn specs() -> &'static [MetricSpec] {
    REMEDIATION_METRIC_SPECS
}

// ============================================================================
// RemediationMetrics
// ============================================================================

/// Wait-time histogram buckets (seconds), from sub-second queueing to long waits.
const WAIT_BUCKETS: &[f64] = &[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0];

/// Confidence histogram buckets, covering `[0.0, 1.0]`.
const CONFIDENCE_BUCKETS: &[f64] = &[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];

/// Prometheus collectors for remediation states. Cheaply cloneable (every
/// collector is `Arc`-backed); clones share the same underlying series.
#[derive(Clone)]
pub struct RemediationMetrics {
    incident_total: CounterVec,
    admission_total: CounterVec,
    proof_state: GaugeVec,
    proof_transition_total: CounterVec,
    proof_outcome_total: CounterVec,
    queue_depth: Gauge,
    queue_wait_seconds: Histogram,
    queue_outcome_total: CounterVec,
    worker_ineligible_total: CounterVec,
    bypass_transition_total: CounterVec,
    canary_total: CounterVec,
    disk_pressure_level: GaugeVec,
    telemetry_freshness_total: CounterVec,
    telemetry_confidence: Histogram,
    artifact_files_total: CounterVec,
    artifact_bytes_total: CounterVec,
    self_healing_total: CounterVec,
}

impl RemediationMetrics {
    /// Construct the (unregistered) collector set.
    ///
    /// # Errors
    /// Returns a [`prometheus::Error`] if any metric name/label is invalid (a
    /// programming error — names here are static and valid).
    pub fn new() -> prometheus::Result<Self> {
        Ok(Self {
            incident_total: counter_vec(
                "rch_remediation_incident_total",
                "Remediation incidents by event type, reason code, and source",
                &["event_type", "reason_code", "source"],
            )?,
            admission_total: counter_vec(
                "rch_remediation_admission_total",
                "Admission decisions by selected location and reason",
                &["decision", "reason"],
            )?,
            proof_state: gauge_vec(
                "rch_remediation_proof_state",
                "Proof-replay intents currently in each state",
                &["state"],
            )?,
            proof_transition_total: counter_vec(
                "rch_remediation_proof_transition_total",
                "Proof-replay state transitions by from/to state",
                &["from", "to"],
            )?,
            proof_outcome_total: counter_vec(
                "rch_remediation_proof_outcome_total",
                "Proof-replay attempt outcomes",
                &["outcome"],
            )?,
            queue_depth: gauge(
                "rch_remediation_queue_depth",
                "Current capacity-queue depth (pending placements)",
            )?,
            queue_wait_seconds: histogram(
                "rch_remediation_queue_wait_seconds",
                "Time a placement waited in the capacity queue, in seconds",
                WAIT_BUCKETS,
            )?,
            queue_outcome_total: counter_vec(
                "rch_remediation_queue_outcome_total",
                "Resolved queue-contract outcomes",
                &["outcome"],
            )?,
            worker_ineligible_total: counter_vec(
                "rch_remediation_worker_ineligible_total",
                "Worker eligibility rejections by failure/capability reason",
                &["reason"],
            )?,
            bypass_transition_total: counter_vec(
                "rch_remediation_bypass_transition_total",
                "Temporary-bypass lifecycle transitions",
                &["transition"],
            )?,
            canary_total: counter_vec(
                "rch_remediation_canary_total",
                "Auto-rejoin canary build outcomes",
                &["outcome"],
            )?,
            disk_pressure_level: gauge_vec(
                "rch_remediation_disk_pressure_level",
                "Disk pressure severity per root (0=ok,1=unknown,2=warning,3=critical)",
                &["root_kind"],
            )?,
            telemetry_freshness_total: counter_vec(
                "rch_remediation_telemetry_freshness_total",
                "Telemetry freshness assessments by verdict",
                &["verdict"],
            )?,
            telemetry_confidence: histogram(
                "rch_remediation_telemetry_confidence",
                "Confidence that worker telemetry reflects current reality, in [0,1]",
                CONFIDENCE_BUCKETS,
            )?,
            artifact_files_total: counter_vec(
                "rch_remediation_artifact_files_total",
                "Files retrieved from workers by retrieval mode",
                &["mode"],
            )?,
            artifact_bytes_total: counter_vec(
                "rch_remediation_artifact_bytes_total",
                "Bytes retrieved from workers by retrieval mode",
                &["mode"],
            )?,
            self_healing_total: counter_vec(
                "rch_remediation_self_healing_total",
                "Daemon/hook self-healing actions by action and outcome",
                &["action", "outcome"],
            )?,
        })
    }

    /// Construct and register against a fresh default registry (test/diagnostic).
    ///
    /// # Errors
    /// Propagates construction/registration errors.
    pub fn registered_default() -> prometheus::Result<Self> {
        let metrics = Self::new()?;
        metrics.register(&Registry::new())?;
        Ok(metrics)
    }

    /// Register every collector with `registry`. Idempotent: a metric already
    /// registered (e.g. on a second daemon-reload) is silently accepted.
    ///
    /// # Errors
    /// Returns a [`prometheus::Error`] for any non-duplicate registration error.
    pub fn register(&self, registry: &Registry) -> prometheus::Result<()> {
        register_collector(registry, Box::new(self.incident_total.clone()))?;
        register_collector(registry, Box::new(self.admission_total.clone()))?;
        register_collector(registry, Box::new(self.proof_state.clone()))?;
        register_collector(registry, Box::new(self.proof_transition_total.clone()))?;
        register_collector(registry, Box::new(self.proof_outcome_total.clone()))?;
        register_collector(registry, Box::new(self.queue_depth.clone()))?;
        register_collector(registry, Box::new(self.queue_wait_seconds.clone()))?;
        register_collector(registry, Box::new(self.queue_outcome_total.clone()))?;
        register_collector(registry, Box::new(self.worker_ineligible_total.clone()))?;
        register_collector(registry, Box::new(self.bypass_transition_total.clone()))?;
        register_collector(registry, Box::new(self.canary_total.clone()))?;
        register_collector(registry, Box::new(self.disk_pressure_level.clone()))?;
        register_collector(registry, Box::new(self.telemetry_freshness_total.clone()))?;
        register_collector(registry, Box::new(self.telemetry_confidence.clone()))?;
        register_collector(registry, Box::new(self.artifact_files_total.clone()))?;
        register_collector(registry, Box::new(self.artifact_bytes_total.clone()))?;
        register_collector(registry, Box::new(self.self_healing_total.clone()))?;
        Ok(())
    }

    // ---- Recording API (typed; bounded by construction) ----

    /// Record an incident: increment the incident counter and emit a span
    /// carrying the stable, redacted attributes.
    pub fn record_incident(&self, attrs: &RemediationAttributes) {
        self.incident_total
            .with_label_values(&[
                event_type_label(attrs.event_type),
                attrs.reason_code.code(),
                source_label(attrs.source),
            ])
            .inc();
        attrs.emit_span();
    }

    /// Record an admission decision by selected location and (normalized) reason.
    pub fn record_admission(&self, decision: AdmissionDecision, reason: &str) {
        self.admission_total
            .with_label_values(&[decision.as_str(), normalize_fallback_reason(reason)])
            .inc();
    }

    /// Set the number of proof-replay intents currently in `state`.
    pub fn set_proof_state(&self, state: ProofState, count: i64) {
        self.proof_state
            .with_label_values(&[state.as_str()])
            .set(count as f64);
    }

    /// Record a proof-replay state transition.
    pub fn record_proof_transition(&self, from: ProofState, to: ProofState) {
        self.proof_transition_total
            .with_label_values(&[from.as_str(), to.as_str()])
            .inc();
    }

    /// Record a resolved proof-replay attempt outcome.
    pub fn record_proof_outcome(&self, outcome: ReplayOutcome) {
        self.proof_outcome_total
            .with_label_values(&[replay_outcome_label(outcome)])
            .inc();
    }

    /// Set the current capacity-queue depth.
    pub fn set_queue_depth(&self, depth: usize) {
        self.queue_depth.set(depth as f64);
    }

    /// Observe how long a placement waited in the queue.
    pub fn observe_queue_wait(&self, seconds: f64) {
        self.queue_wait_seconds.observe(sanitize_seconds(seconds));
    }

    /// Record a resolved queue-contract outcome.
    pub fn record_queue_outcome(&self, outcome: &QueueContractOutcome) {
        self.queue_outcome_total
            .with_label_values(&[outcome.as_str()])
            .inc();
    }

    /// Record a worker eligibility rejection by failure/capability reason.
    pub fn record_worker_ineligible(&self, class: BypassFailureClass) {
        self.worker_ineligible_total
            .with_label_values(&[class.as_str()])
            .inc();
    }

    /// Record a temporary-bypass lifecycle transition.
    pub fn record_bypass_transition(&self, transition: BypassTransition) {
        self.bypass_transition_total
            .with_label_values(&[transition.as_str()])
            .inc();
    }

    /// Record an auto-rejoin canary outcome.
    pub fn record_canary(&self, outcome: CanaryOutcome) {
        self.canary_total
            .with_label_values(&[canary_outcome_label(outcome)])
            .inc();
    }

    /// Set the disk-pressure severity for a root.
    pub fn set_disk_pressure(&self, root: DiskRootKind, level: PressureLevel) {
        self.disk_pressure_level
            .with_label_values(&[root.as_str()])
            .set(pressure_rank(level));
    }

    /// Record a telemetry freshness assessment (verdict + confidence in `[0,1]`).
    pub fn record_telemetry_freshness(&self, verdict: FreshnessVerdict, confidence: f64) {
        self.telemetry_freshness_total
            .with_label_values(&[freshness_verdict_label(verdict)])
            .inc();
        self.telemetry_confidence
            .observe(confidence.clamp(0.0, 1.0));
    }

    /// Record an artifact retrieval (file and byte counts) by retrieval mode.
    pub fn record_artifact_retrieval(&self, mode: RetrievalMode, files: u64, bytes: u64) {
        let mode = retrieval_mode_label(mode);
        self.artifact_files_total
            .with_label_values(&[mode])
            .inc_by(files as f64);
        self.artifact_bytes_total
            .with_label_values(&[mode])
            .inc_by(bytes as f64);
    }

    /// Record a daemon/hook self-healing action and its outcome.
    pub fn record_self_healing(&self, action: SelfHealingAction, outcome: SelfHealingOutcome) {
        self.self_healing_total
            .with_label_values(&[action.as_str(), outcome.as_str()])
            .inc();
    }
}

// ============================================================================
// Process-global handle
// ============================================================================

static GLOBAL: OnceLock<RemediationMetrics> = OnceLock::new();

/// Install the process-global remediation metrics handle. Idempotent: the first
/// call wins; later calls drop their argument and return the installed instance.
/// Call once at daemon startup after registering the instance with the served
/// registry.
pub fn init_global(metrics: RemediationMetrics) -> &'static RemediationMetrics {
    GLOBAL.get_or_init(|| metrics)
}

/// The process-global remediation metrics handle, if installed.
#[must_use]
pub fn global() -> Option<&'static RemediationMetrics> {
    GLOBAL.get()
}

/// Record an incident via the global handle (no-op if uninstalled).
pub fn record_incident(attrs: &RemediationAttributes) {
    if let Some(m) = global() {
        m.record_incident(attrs);
    }
}

/// Record an admission decision via the global handle (no-op if uninstalled).
pub fn record_admission(decision: AdmissionDecision, reason: &str) {
    if let Some(m) = global() {
        m.record_admission(decision, reason);
    }
}

/// Record a proof-replay transition via the global handle (no-op if uninstalled).
pub fn record_proof_transition(from: ProofState, to: ProofState) {
    if let Some(m) = global() {
        m.record_proof_transition(from, to);
    }
}

/// Record a proof-replay outcome via the global handle (no-op if uninstalled).
pub fn record_proof_outcome(outcome: ReplayOutcome) {
    if let Some(m) = global() {
        m.record_proof_outcome(outcome);
    }
}

/// Set proof-state gauge via the global handle (no-op if uninstalled).
pub fn set_proof_state(state: ProofState, count: i64) {
    if let Some(m) = global() {
        m.set_proof_state(state, count);
    }
}

/// Set queue depth via the global handle (no-op if uninstalled).
pub fn set_queue_depth(depth: usize) {
    if let Some(m) = global() {
        m.set_queue_depth(depth);
    }
}

/// Observe queue wait via the global handle (no-op if uninstalled).
pub fn observe_queue_wait(seconds: f64) {
    if let Some(m) = global() {
        m.observe_queue_wait(seconds);
    }
}

/// Record a queue-contract outcome via the global handle (no-op if uninstalled).
pub fn record_queue_outcome(outcome: &QueueContractOutcome) {
    if let Some(m) = global() {
        m.record_queue_outcome(outcome);
    }
}

/// Record a worker-ineligible reason via the global handle (no-op if uninstalled).
pub fn record_worker_ineligible(class: BypassFailureClass) {
    if let Some(m) = global() {
        m.record_worker_ineligible(class);
    }
}

/// Record a bypass transition via the global handle (no-op if uninstalled).
pub fn record_bypass_transition(transition: BypassTransition) {
    if let Some(m) = global() {
        m.record_bypass_transition(transition);
    }
}

/// Record a canary outcome via the global handle (no-op if uninstalled).
pub fn record_canary(outcome: CanaryOutcome) {
    if let Some(m) = global() {
        m.record_canary(outcome);
    }
}

/// Set disk pressure via the global handle (no-op if uninstalled).
pub fn set_disk_pressure(root: DiskRootKind, level: PressureLevel) {
    if let Some(m) = global() {
        m.set_disk_pressure(root, level);
    }
}

/// Record telemetry freshness via the global handle (no-op if uninstalled).
pub fn record_telemetry_freshness(verdict: FreshnessVerdict, confidence: f64) {
    if let Some(m) = global() {
        m.record_telemetry_freshness(verdict, confidence);
    }
}

/// Record artifact retrieval via the global handle (no-op if uninstalled).
pub fn record_artifact_retrieval(mode: RetrievalMode, files: u64, bytes: u64) {
    if let Some(m) = global() {
        m.record_artifact_retrieval(mode, files, bytes);
    }
}

/// Record a self-healing action via the global handle (no-op if uninstalled).
pub fn record_self_healing(action: SelfHealingAction, outcome: SelfHealingOutcome) {
    if let Some(m) = global() {
        m.record_self_healing(action, outcome);
    }
}

// ============================================================================
// Collector constructors / helpers
// ============================================================================

fn counter_vec(name: &str, help: &str, labels: &[&str]) -> prometheus::Result<CounterVec> {
    CounterVec::new(Opts::new(name, help), labels)
}

fn gauge_vec(name: &str, help: &str, labels: &[&str]) -> prometheus::Result<GaugeVec> {
    GaugeVec::new(Opts::new(name, help), labels)
}

fn gauge(name: &str, help: &str) -> prometheus::Result<Gauge> {
    Gauge::new(name, help)
}

fn histogram(name: &str, help: &str, buckets: &[f64]) -> prometheus::Result<Histogram> {
    Histogram::with_opts(HistogramOpts::new(name, help).buckets(buckets.to_vec()))
}

fn register_collector(
    registry: &Registry,
    collector: Box<dyn prometheus::core::Collector>,
) -> prometheus::Result<()> {
    match registry.register(collector) {
        Ok(()) | Err(prometheus::Error::AlreadyReg) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Clamp a duration to a finite, non-negative value before observing it.
fn sanitize_seconds(seconds: f64) -> f64 {
    if seconds.is_finite() && seconds >= 0.0 {
        seconds
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Encoder, TextEncoder};

    fn gather_text(registry: &Registry) -> String {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        encoder
            .encode(&registry.gather(), &mut buffer)
            .expect("encode metrics");
        String::from_utf8(buffer).expect("utf8 metrics")
    }

    /// Touch one series of every metric family so a `*Vec` collector with no
    /// children still materializes a family in `registry.gather()`.
    fn exercise_all(metrics: &RemediationMetrics) {
        metrics.record_incident(&RemediationAttributes::new(
            IncidentEventType::Admission,
            IncidentReasonCode::NoAdmissibleWorkers,
            IncidentSource::Daemon,
            SelectedMode::Local,
            "cargo build",
            "proj-1",
        ));
        metrics.record_admission(AdmissionDecision::Local, "force_local");
        metrics.set_proof_state(ProofState::Queued, 1);
        metrics.record_proof_transition(ProofState::Queued, ProofState::Replaying);
        metrics.record_proof_outcome(ReplayOutcome::Succeeded);
        metrics.set_queue_depth(0);
        metrics.observe_queue_wait(0.5);
        metrics.record_queue_outcome(&QueueContractOutcome::StartedRunning);
        metrics.record_worker_ineligible(BypassFailureClass::Ssh);
        metrics.record_bypass_transition(BypassTransition::Bypassed);
        metrics.record_canary(CanaryOutcome::Passed);
        metrics.set_disk_pressure(DiskRootKind::TargetRoot, PressureLevel::Ok);
        metrics.record_telemetry_freshness(FreshnessVerdict::Fresh, 1.0);
        metrics.record_artifact_retrieval(RetrievalMode::Glob, 1, 1);
        metrics.record_self_healing(SelfHealingAction::WorkerRejoin, SelfHealingOutcome::Success);
    }

    #[test]
    fn register_is_idempotent_and_exposes_all_specs() {
        let metrics = RemediationMetrics::new().expect("construct");
        let registry = Registry::new();
        metrics.register(&registry).expect("first register");
        metrics
            .register(&registry)
            .expect("duplicate register is ignored");

        exercise_all(&metrics);
        let names: std::collections::HashSet<String> = registry
            .gather()
            .into_iter()
            .map(|f| f.name().to_string())
            .collect();
        for spec in specs() {
            assert!(
                names.contains(spec.name),
                "metric {} missing from gathered families",
                spec.name
            );
        }
    }

    #[test]
    fn no_duplicate_metric_names_in_inventory() {
        let mut seen = std::collections::HashSet::new();
        for spec in specs() {
            assert!(
                seen.insert(spec.name),
                "duplicate metric name {}",
                spec.name
            );
            assert_eq!(
                spec.labels.len(),
                spec.label_values.len(),
                "{}: labels and label_values must align",
                spec.name
            );
        }
        assert_eq!(seen.len(), 17, "expected 17 remediation metric families");
    }

    #[test]
    fn cardinality_is_bounded_and_small() {
        for spec in specs() {
            let cardinality: usize = spec
                .label_values
                .iter()
                .map(|values| values.len())
                .product::<usize>()
                .max(1);
            // Every remediation series must stay well under any unbounded blow-up.
            // The widest is `rch_remediation_incident_total`
            // (event_type 8 x reason_code 17 x source 5 = 680), which is still a
            // small, fixed ceiling — no path/command/secret ever widens it.
            assert!(
                cardinality <= 1024,
                "{} cardinality {} too large",
                spec.name,
                cardinality
            );
        }
    }

    #[test]
    fn incident_reason_code_labels_match_enum() {
        let from_enum: Vec<&str> = IncidentReasonCode::ALL.iter().map(|c| c.code()).collect();
        assert_eq!(from_enum, INCIDENT_REASON_CODE_LABELS);
    }

    #[test]
    fn proof_state_labels_match_enum() {
        let from_enum: Vec<&str> = ProofState::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(from_enum, PROOF_STATE_LABELS);
    }

    #[test]
    fn bypass_failure_class_labels_match_enum() {
        let from_enum: Vec<&str> = BypassFailureClass::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(from_enum, WORKER_INELIGIBLE_LABELS);
    }

    #[test]
    fn local_label_enums_match_vocabularies() {
        let admission: Vec<&str> = AdmissionDecision::ALL.iter().map(|d| d.as_str()).collect();
        assert_eq!(admission, ADMISSION_DECISION_LABELS);
        let bypass: Vec<&str> = BypassTransition::ALL.iter().map(|t| t.as_str()).collect();
        assert_eq!(bypass, BYPASS_TRANSITION_LABELS);
        let actions: Vec<&str> = SelfHealingAction::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(actions, SELF_HEALING_ACTION_LABELS);
        let outcomes: Vec<&str> = SelfHealingOutcome::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(outcomes, SELF_HEALING_OUTCOME_LABELS);
    }

    #[test]
    fn unknown_fallback_reason_routes_to_other() {
        assert_eq!(normalize_fallback_reason("force_local"), "force_local");
        assert_eq!(
            normalize_fallback_reason("a-brand-new-reason-string"),
            "other"
        );
    }

    #[test]
    fn attributes_redact_fingerprint_and_project_path() {
        let attrs = RemediationAttributes::new(
            IncidentEventType::Fallback,
            IncidentReasonCode::LocalFallback,
            IncidentSource::Hook,
            SelectedMode::Local,
            "cargo build ghp_ABCDEFGHIJKLMNOPQRSTUVWX",
            "/home/alice/projects/myapp",
        );
        // Project path is hashed, never raw.
        assert!(attrs.project_id.starts_with("blake3:"));
        assert!(!attrs.project_id.contains("alice"));
        // Provider-shaped token in the fingerprint is masked.
        assert!(
            !attrs
                .command_fingerprint
                .contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWX")
        );
    }

    #[test]
    fn opaque_project_id_passthrough() {
        assert_eq!(
            ensure_opaque_project_id("blake3:deadbeef"),
            "blake3:deadbeef"
        );
        assert_eq!(ensure_opaque_project_id("proj-7f3a9c01"), "proj-7f3a9c01");
        assert!(ensure_opaque_project_id("/data/projects/x").starts_with("blake3:"));
    }

    #[test]
    fn recording_produces_scrapeable_values() {
        let metrics = RemediationMetrics::new().expect("construct");
        let registry = Registry::new();
        metrics.register(&registry).expect("register");

        metrics.record_worker_ineligible(BypassFailureClass::Ssh);
        metrics.record_bypass_transition(BypassTransition::Bypassed);
        metrics.record_canary(CanaryOutcome::Passed);
        metrics.set_disk_pressure(DiskRootKind::TargetRoot, PressureLevel::Critical);
        metrics.record_telemetry_freshness(FreshnessVerdict::SlowObserver, 0.7);
        metrics.record_artifact_retrieval(RetrievalMode::Manifest, 12, 4096);
        metrics.record_self_healing(SelfHealingAction::WorkerRejoin, SelfHealingOutcome::Success);
        metrics.record_proof_transition(ProofState::Queued, ProofState::Replaying);
        metrics.set_queue_depth(3);
        metrics.observe_queue_wait(1.5);

        // Values via the typed handles (robust against float text formatting).
        assert_eq!(
            metrics
                .worker_ineligible_total
                .with_label_values(&["ssh"])
                .get(),
            1.0
        );
        assert_eq!(
            metrics.canary_total.with_label_values(&["passed"]).get(),
            1.0
        );
        assert_eq!(
            metrics
                .disk_pressure_level
                .with_label_values(&["target_root"])
                .get(),
            3.0
        );
        assert_eq!(
            metrics
                .artifact_files_total
                .with_label_values(&["manifest"])
                .get(),
            12.0
        );
        assert_eq!(
            metrics
                .artifact_bytes_total
                .with_label_values(&["manifest"])
                .get(),
            4096.0
        );
        assert_eq!(metrics.queue_depth.get(), 3.0);
        assert_eq!(metrics.queue_wait_seconds.get_sample_count(), 1);
        assert_eq!(metrics.telemetry_confidence.get_sample_count(), 1);

        // And the text scrape surfaces the metric families with their labels.
        let text = gather_text(&registry);
        for needle in [
            "rch_remediation_worker_ineligible_total{reason=\"ssh\"}",
            "rch_remediation_bypass_transition_total{transition=\"bypassed\"}",
            "rch_remediation_canary_total{outcome=\"passed\"}",
            "rch_remediation_disk_pressure_level{root_kind=\"target_root\"}",
            "rch_remediation_artifact_files_total{mode=\"manifest\"}",
            "rch_remediation_queue_depth",
            "rch_remediation_proof_transition_total{from=\"queued\",to=\"replaying\"}",
        ] {
            assert!(text.contains(needle), "scrape missing {needle}\n{text}");
        }
    }

    #[test]
    fn confidence_and_wait_are_sanitized() {
        let metrics = RemediationMetrics::new().expect("construct");
        // Out-of-range / non-finite inputs must not panic or poison the metric.
        metrics.record_telemetry_freshness(FreshnessVerdict::Stale, 5.0);
        metrics.record_telemetry_freshness(FreshnessVerdict::Stale, f64::NAN);
        metrics.observe_queue_wait(-3.0);
        metrics.observe_queue_wait(f64::INFINITY);
    }

    #[test]
    fn global_handle_records_without_panicking() {
        // The global may already be initialized by another test in this binary;
        // get_or_init makes this safe regardless of ordering.
        let metrics = RemediationMetrics::new().expect("construct");
        let installed = init_global(metrics);
        // Recording through the free functions must not panic.
        record_worker_ineligible(BypassFailureClass::DiskInodePressure);
        record_canary(CanaryOutcome::Failed);
        assert!(global().is_some());
        // The installed handle is the same as the global one.
        assert!(std::ptr::eq(installed, global().unwrap()));
    }
}
