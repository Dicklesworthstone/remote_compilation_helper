//! Operator-facing remediation view: a compact, redacted, deterministic
//! snapshot of the remediation state the dashboards (TUI + web) render
//! (bd-session-history-remediation-ocv9i.14.4).
//!
//! README promises a terminal dashboard and a web dashboard. Agents consume the
//! status JSON, but operators need to see the *same truth* without assembling it
//! from daemon logs, status JSON, and Beads. This module is the single source of
//! truth for that view: a pure assembler that folds the already-available
//! remediation signals — fleet desired/live diff, command-admissibility, the
//! deferred-proof queue, active jobs, disk pressure, telemetry freshness, and
//! recent incidents — into a small fixed set of compact "status bands". Each
//! band is tagged with the one distinction operators care about most:
//!
//!   - [`RemediationActionClass::OperatorActionRequired`] — capacity will not
//!     return without intervention,
//!   - [`RemediationActionClass::SelfHealingInProgress`] — RCH is recovering on
//!     its own (auto-rejoin probing, proof replay, reclaim); wait, don't touch,
//!   - [`RemediationActionClass::NormalFailOpen`] — expected fail-open behavior
//!     (e.g. builds running locally because remote is unavailable),
//!   - [`RemediationActionClass::Healthy`] — nominal.
//!
//! **Safe by construction.** The view carries only counts, worker ids (config
//! aliases such as `css`, never hostnames), reason codes, and pre-redacted
//! summaries. Every free-text field is passed through
//! [`crate::redaction::redact_secrets`] at construction, and the struct
//! deliberately has *no* field for hostnames, SSH users, filesystem paths, or
//! raw command strings. The daemon assembles the view once from its live state;
//! the TUI, CLI, and web all render the identical struct, so the three surfaces
//! can never disagree on counts or posture.
//!
//! **Clock-free.** [`assemble`] takes the snapshot timestamp as a parameter, so
//! the whole view is a deterministic function of its inputs and golden-testable.

use serde::{Deserialize, Serialize};

use crate::redaction::redact_secrets;
use crate::schema_versions::{SchemaComponent, current_version};

/// The single distinction operators care about for each band and for the view
/// overall: is action needed, is the system healing itself, is this just normal
/// fail-open, or is everything nominal?
///
/// Declared in increasing severity order so the derived [`Ord`] makes "the worse
/// of two" simply `a.max(b)` — used to roll bands up into the overall posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationActionClass {
    /// Nominal: nothing to do, everything healthy.
    Healthy,
    /// Expected fail-open behavior (e.g. builds running locally because remote
    /// execution is unavailable) — not an incident, no action required.
    NormalFailOpen,
    /// RCH is recovering on its own (auto-rejoin probing, proof replay, disk
    /// reclaim); the operator should wait, not intervene.
    SelfHealingInProgress,
    /// The operator must act — capacity will not return without intervention.
    OperatorActionRequired,
}

impl RemediationActionClass {
    /// Every class, in increasing-severity declaration order.
    pub const ALL: &'static [RemediationActionClass] = &[
        Self::Healthy,
        Self::NormalFailOpen,
        Self::SelfHealingInProgress,
        Self::OperatorActionRequired,
    ];

    /// Stable lowercase token (matches the serde representation).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::NormalFailOpen => "normal_fail_open",
            Self::SelfHealingInProgress => "self_healing_in_progress",
            Self::OperatorActionRequired => "operator_action_required",
        }
    }

    /// Operator-facing label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::NormalFailOpen => "normal (fail-open local)",
            Self::SelfHealingInProgress => "self-healing in progress",
            Self::OperatorActionRequired => "operator action required",
        }
    }

    /// The worse (higher-severity) of two classes.
    #[must_use]
    pub fn max_class(self, other: Self) -> Self {
        self.max(other)
    }
}

/// Compact band severity for coloring, independent of [`RemediationActionClass`]
/// (a band can be [`BandSeverity::Warn`] while still being
/// [`RemediationActionClass::SelfHealingInProgress`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BandSeverity {
    /// Healthy/nominal.
    Ok,
    /// Informational (activity in progress, nothing wrong).
    Info,
    /// Degraded but not collapsed.
    Warn,
    /// Collapsed / urgent.
    Critical,
}

impl BandSeverity {
    /// Every severity, in increasing order.
    pub const ALL: &'static [BandSeverity] = &[Self::Ok, Self::Info, Self::Warn, Self::Critical];

    /// Stable lowercase token (matches the serde representation).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Critical => "critical",
        }
    }
}

/// Stable identifier for each band the dashboards render. A fixed, ordered set
/// so snapshot tests and web pages can address bands by id and assert the full
/// surface is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BandId {
    /// Configured/intended fleet and the dominant problem class.
    DesiredFleet,
    /// Live usable workers vs desired, with the out-of-play breakdown.
    LiveEligibility,
    /// Workers that can actually run a classified command right now.
    AdmissibleWorkers,
    /// Deferred-proof replay conveyor census.
    ProofQueue,
    /// Active and queued jobs, and stuck-wrapper detections.
    ActiveJobs,
    /// Worker disk/inode pressure.
    DiskPressure,
    /// Worker telemetry freshness.
    TelemetryFreshness,
    /// Recent incident-ledger events.
    Incidents,
}

impl BandId {
    /// Every band, in the canonical render order.
    pub const ALL: &'static [BandId] = &[
        Self::DesiredFleet,
        Self::LiveEligibility,
        Self::AdmissibleWorkers,
        Self::ProofQueue,
        Self::ActiveJobs,
        Self::DiskPressure,
        Self::TelemetryFreshness,
        Self::Incidents,
    ];

    /// Stable lowercase token (matches the serde representation).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DesiredFleet => "desired_fleet",
            Self::LiveEligibility => "live_eligibility",
            Self::AdmissibleWorkers => "admissible_workers",
            Self::ProofQueue => "proof_queue",
            Self::ActiveJobs => "active_jobs",
            Self::DiskPressure => "disk_pressure",
            Self::TelemetryFreshness => "telemetry_freshness",
            Self::Incidents => "incidents",
        }
    }

    /// Operator-facing title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::DesiredFleet => "Desired Fleet",
            Self::LiveEligibility => "Live Eligibility",
            Self::AdmissibleWorkers => "Admissible Workers",
            Self::ProofQueue => "Proof Queue",
            Self::ActiveJobs => "Active Jobs",
            Self::DiskPressure => "Disk Pressure",
            Self::TelemetryFreshness => "Telemetry Freshness",
            Self::Incidents => "Recent Incidents",
        }
    }
}

/// One compact status band in the remediation view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationBand {
    /// Stable band identifier.
    pub id: BandId,
    /// Operator-facing title (from [`BandId::title`]).
    pub title: String,
    /// Coloring severity.
    pub severity: BandSeverity,
    /// Whether this band needs operator action, is self-healing, etc.
    pub action_class: RemediationActionClass,
    /// One-line, redacted summary.
    pub headline: String,
    /// Bounded, redacted supporting lines.
    pub detail_lines: Vec<String>,
    /// Stable reason code for this band's state, when one applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

/// A compact, redacted incident line for the recent-incidents band.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationIncidentLine {
    /// Canonical `RCH-Innn` reason code.
    pub reason_code: String,
    /// Emitting subsystem token (snake_case).
    pub event_type: String,
    /// Worker id (config alias), when the incident is worker-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Age of the event in seconds at snapshot time.
    pub age_secs: u64,
    /// Short, redacted human summary.
    pub summary: String,
}

impl RemediationIncidentLine {
    /// Build a line, redacting the summary defensively.
    #[must_use]
    pub fn new(
        reason_code: impl Into<String>,
        event_type: impl Into<String>,
        worker_id: Option<String>,
        age_secs: u64,
        summary: impl AsRef<str>,
    ) -> Self {
        Self {
            reason_code: reason_code.into(),
            event_type: event_type.into(),
            worker_id,
            age_secs,
            summary: redact_secrets(summary.as_ref()),
        }
    }
}

// ===========================================================================
// Inputs — neutral, populated by the daemon (live) or by tests/fixtures.
// ===========================================================================

/// Desired/live fleet summary (mirrors [`crate::fleet_status::FleetStatusReport`]
/// counts plus the self-healing pending-canary count).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSummaryInput {
    /// Configured/intended worker count.
    pub desired: usize,
    /// Live workers usable right now.
    pub eligible: usize,
    /// Workers in transient quarantine (temporary bypass).
    pub bypassed: usize,
    /// Workers explicitly admin-disabled.
    pub disabled: usize,
    /// Workers present but unreachable.
    pub unreachable: usize,
    /// Configured workers absent from the live pool.
    pub missing: usize,
    /// Workers recovered and probing/canarying back in (self-healing).
    pub recovered_pending_canary: usize,
    /// Dominant [`crate::fleet_status::FleetProblemClass`] token.
    pub problem_class: String,
    /// One-line human summary of the dominant problem.
    pub problem_summary: String,
    /// Number of workers tripping the absence policy window.
    pub absence_warnings: usize,
}

/// Command-admissibility summary: how many live workers can actually run a
/// classified command right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissibleWorkersInput {
    /// Workers that pass capability/admission checks for some classified command.
    pub admissible: usize,
    /// Total live workers in the pool.
    pub total_live: usize,
    /// Dominant missing-capability/blocker reason, when `admissible == 0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_blocker_reason: Option<String>,
}

/// Deferred-proof replay conveyor census (mirrors
/// [`crate::proof_replay::ProofState`] groupings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProofQueueInput {
    /// Proofs waiting on a transient recovery.
    pub queued: usize,
    /// Proofs waiting on a structural condition.
    pub blocked: usize,
    /// Proofs cleared for replay this scan.
    pub replaying: usize,
    /// Recent terminal product failures.
    pub failed_recent: usize,
    /// Recent stale (no-longer-replayable) intents.
    pub stale_recent: usize,
}

/// Active/queued job summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct JobsInput {
    /// Active remote builds.
    pub active: usize,
    /// Jobs queued waiting for a worker slot.
    pub queued: usize,
    /// Jobs flagged as stuck (stale heartbeat / wrapper) needing recovery.
    pub stuck: usize,
}

/// Worker disk/inode pressure summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DiskPressureInput {
    /// Workers in warning pressure.
    pub workers_warning: usize,
    /// Workers in critical pressure.
    pub workers_critical: usize,
    /// Workers actively reclaiming space (self-healing).
    pub reclaim_in_progress: usize,
    /// Tightest observed free-disk ratio across workers, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_free_ratio: Option<f64>,
}

/// Worker telemetry-freshness summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TelemetryFreshnessInput {
    /// Workers with fresh telemetry.
    pub fresh: usize,
    /// Workers with stale telemetry (age exceeds the freshness window).
    pub stale: usize,
    /// Workers with unknown telemetry age (never reported facts).
    pub unknown: usize,
    /// Oldest observed telemetry age in seconds, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,
}

/// Worker disk/inode pressure level, derived from the normalized pressure
/// state token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskLevel {
    /// No pressure.
    Ok,
    /// Warning pressure.
    Warning,
    /// Critical pressure.
    Critical,
}

impl DiskLevel {
    /// Map the normalized pressure-state token (`healthy` / `warning` /
    /// `critical` / `telemetry_gap`) to a level. Unknown / gap tokens are `Ok`
    /// for pressure purposes — telemetry freshness is tracked separately.
    #[must_use]
    pub fn from_pressure_state(token: &str) -> Self {
        match token {
            "critical" => Self::Critical,
            "warning" => Self::Warning,
            _ => Self::Ok,
        }
    }
}

/// A neutral per-worker row that the daemon (from live state) or the CLI (from
/// the status response) maps into to build [`RemediationInputs`] via
/// [`build_inputs`]. Carries only the fields the bands need — never hostnames,
/// SSH users, or filesystem paths.
///
/// Not itself serialized — it is a build-time intermediate; only the assembled
/// [`RemediationView`] crosses the wire.
#[derive(Debug, Clone, PartialEq)]
pub struct RemediationWorkerRow {
    /// Desired/live observation (drives the fleet diff + admissibility).
    pub observation: crate::fleet_diff::WorkerObservation,
    /// Disk pressure level.
    pub disk_level: DiskLevel,
    /// Worker is actively reclaiming disk space (self-healing).
    pub reclaiming: bool,
    /// Tightest free-disk ratio observed, if known.
    pub free_ratio: Option<f64>,
    /// Used slots.
    pub slots_used: u32,
    /// Total slots.
    pub slots_total: u32,
    /// Telemetry age is known (worker reported facts at least once).
    pub telemetry_known: bool,
    /// Latest telemetry sample is fresh enough for high-confidence decisions.
    pub telemetry_fresh: bool,
    /// Age of the latest telemetry sample in seconds, if known.
    pub telemetry_age_secs: Option<u64>,
    /// Worker is in the auto-rejoin canary phase (self-healing).
    pub recovered_pending_canary: bool,
    /// Seconds absent from live eligibility, if known.
    pub absent_secs: Option<u64>,
}

/// Build [`RemediationInputs`] from neutral worker rows plus the job / proof /
/// incident summaries the caller gathers separately.
///
/// Pure and deterministic. The fleet summary is computed via the shared,
/// already-tested [`crate::fleet_status`] logic; admissibility, disk, and
/// telemetry summaries are folded directly from the rows.
#[must_use]
pub fn build_inputs(
    rows: &[RemediationWorkerRow],
    jobs: JobsInput,
    proof_queue: ProofQueueInput,
    incidents: Vec<RemediationIncidentLine>,
    absence_threshold_secs: u64,
) -> RemediationInputs {
    use crate::fleet_diff::{WorkerDiffState, derive_worker_diff};
    use crate::fleet_status::{FleetWorkerSignal, compute_fleet_status};

    let signals: Vec<FleetWorkerSignal> = rows
        .iter()
        .map(|r| FleetWorkerSignal {
            observation: r.observation.clone(),
            disk_pressure: r.disk_level != DiskLevel::Ok,
            slots_saturated: r.slots_total > 0 && r.slots_used >= r.slots_total,
            absent_secs: r.absent_secs,
        })
        .collect();
    let report = compute_fleet_status(&signals, absence_threshold_secs);

    let mut eligible = 0usize;
    let mut bypassed = 0usize;
    let mut disabled = 0usize;
    let mut unreachable = 0usize;
    let mut missing = 0usize;
    for r in rows {
        match derive_worker_diff(&r.observation) {
            WorkerDiffState::Ready => eligible += 1,
            WorkerDiffState::TemporarilyBypassed => bypassed += 1,
            WorkerDiffState::AdminDisabled => disabled += 1,
            WorkerDiffState::Unreachable => unreachable += 1,
            WorkerDiffState::MissingFromFleet
            | WorkerDiffState::RecoveredNotRejoined
            | WorkerDiffState::Unconfigured => missing += 1,
            // FactsUnknown / CommandIneligible surface in the admissibility band.
            WorkerDiffState::FactsUnknown | WorkerDiffState::CommandIneligible => {}
        }
    }
    let recovered_pending_canary = rows.iter().filter(|r| r.recovered_pending_canary).count();
    let desired = rows.iter().filter(|r| r.observation.configured).count();

    let fleet = FleetSummaryInput {
        desired,
        eligible,
        bypassed,
        disabled,
        unreachable,
        missing,
        recovered_pending_canary,
        problem_class: report.problem_class.as_str().to_string(),
        problem_summary: report.problem_summary.clone(),
        absence_warnings: report.absence_alerts.len(),
    };

    // Admissibility: how many *live* workers can run a classified command now.
    let mut total_live = 0usize;
    let mut admissible = 0usize;
    let mut blocker_counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for r in rows {
        let live = r.observation.in_daemon_pool
            && r.observation.reachable
            && !r.observation.admin_disabled;
        if !live {
            continue;
        }
        total_live += 1;
        let state = derive_worker_diff(&r.observation);
        if state == WorkerDiffState::Ready {
            admissible += 1;
        } else {
            let reason = match state {
                WorkerDiffState::FactsUnknown => "missing capability facts",
                WorkerDiffState::CommandIneligible => "not admissible for command",
                WorkerDiffState::TemporarilyBypassed => "temporarily bypassed",
                _ => "ineligible",
            };
            *blocker_counts.entry(reason).or_default() += 1;
        }
    }
    let top_blocker_reason = if admissible == 0 && total_live > 0 {
        blocker_counts
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(reason, _)| (*reason).to_string())
    } else {
        None
    };

    let mut workers_warning = 0usize;
    let mut workers_critical = 0usize;
    let mut reclaim_in_progress = 0usize;
    let mut min_free_ratio: Option<f64> = None;
    for r in rows {
        match r.disk_level {
            DiskLevel::Warning => workers_warning += 1,
            DiskLevel::Critical => workers_critical += 1,
            DiskLevel::Ok => {}
        }
        if r.reclaiming && r.disk_level != DiskLevel::Ok {
            reclaim_in_progress += 1;
        }
        if let Some(ratio) = r.free_ratio {
            min_free_ratio = Some(min_free_ratio.map_or(ratio, |m: f64| m.min(ratio)));
        }
    }

    let mut fresh = 0usize;
    let mut stale = 0usize;
    let mut unknown = 0usize;
    let mut max_age_secs: Option<u64> = None;
    for r in rows {
        let live = r.observation.in_daemon_pool && r.observation.reachable;
        if !live {
            continue;
        }
        if !r.telemetry_known {
            unknown += 1;
        } else if r.telemetry_fresh {
            fresh += 1;
        } else {
            stale += 1;
        }
        if let Some(age) = r.telemetry_age_secs {
            max_age_secs = Some(max_age_secs.map_or(age, |m| m.max(age)));
        }
    }

    RemediationInputs {
        fleet,
        admissible: AdmissibleWorkersInput {
            admissible,
            total_live,
            top_blocker_reason,
        },
        proof_queue,
        jobs,
        disk: DiskPressureInput {
            workers_warning,
            workers_critical,
            reclaim_in_progress,
            min_free_ratio,
        },
        telemetry: TelemetryFreshnessInput {
            fresh,
            stale,
            unknown,
            max_age_secs,
        },
        incidents,
    }
}

/// Everything [`assemble`] needs to build a [`RemediationView`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationInputs {
    /// Desired/live fleet summary.
    pub fleet: FleetSummaryInput,
    /// Command-admissibility summary.
    pub admissible: AdmissibleWorkersInput,
    /// Deferred-proof queue census.
    pub proof_queue: ProofQueueInput,
    /// Active/queued job summary.
    pub jobs: JobsInput,
    /// Disk pressure summary.
    pub disk: DiskPressureInput,
    /// Telemetry freshness summary.
    pub telemetry: TelemetryFreshnessInput,
    /// Recent incident lines, newest-first (caller bounds the count).
    pub incidents: Vec<RemediationIncidentLine>,
}

/// Maximum recent incidents the view retains, regardless of how many the caller
/// supplies (keeps the band compact and the payload bounded).
pub const MAX_VIEW_INCIDENTS: usize = 10;

/// The assembled operator-facing remediation view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationView {
    /// Schema version (`SchemaComponent::RemediationView`).
    pub schema_version: String,
    /// Snapshot timestamp (Unix epoch ms), caller-supplied for determinism.
    pub generated_at_unix_ms: u64,
    /// Rolled-up posture across all bands (the worst band's class).
    pub overall: RemediationActionClass,
    /// Compact status bands, in [`BandId::ALL`] order.
    pub bands: Vec<RemediationBand>,
    /// Recent incident lines (bounded by [`MAX_VIEW_INCIDENTS`]).
    pub incidents: Vec<RemediationIncidentLine>,
}

impl RemediationView {
    /// The band with this id, if present.
    #[must_use]
    pub fn band(&self, id: BandId) -> Option<&RemediationBand> {
        self.bands.iter().find(|b| b.id == id)
    }

    /// Whether any band requires operator action.
    #[must_use]
    pub fn needs_operator_action(&self) -> bool {
        self.overall == RemediationActionClass::OperatorActionRequired
    }
}

/// Assemble the operator-facing remediation view from neutral inputs.
///
/// Pure and deterministic: each band is classified by a dedicated helper, bands
/// are emitted in [`BandId::ALL`] order, and the overall posture is the worst
/// band's [`RemediationActionClass`]. All free text is redacted at construction.
#[must_use]
pub fn assemble(inputs: &RemediationInputs, generated_at_unix_ms: u64) -> RemediationView {
    let bands = vec![
        band_desired_fleet(&inputs.fleet),
        band_live_eligibility(&inputs.fleet),
        band_admissible(&inputs.admissible, &inputs.fleet),
        band_proof_queue(&inputs.proof_queue),
        band_active_jobs(&inputs.jobs),
        band_disk_pressure(&inputs.disk),
        band_telemetry(&inputs.telemetry),
        band_incidents(&inputs.incidents),
    ];

    let overall = bands.iter().map(|b| b.action_class).fold(
        RemediationActionClass::Healthy,
        RemediationActionClass::max_class,
    );

    let mut incidents = inputs.incidents.clone();
    incidents.truncate(MAX_VIEW_INCIDENTS);
    // Defensive: re-redact summaries even though callers should pre-redact.
    for line in &mut incidents {
        line.summary = redact_secrets(&line.summary);
    }

    RemediationView {
        schema_version: current_version(SchemaComponent::RemediationView).to_string(),
        generated_at_unix_ms,
        overall,
        bands,
        incidents,
    }
}

// ---------------------------------------------------------------------------
// Per-band classifiers — each a small pure function for unit testability.
// ---------------------------------------------------------------------------

fn make_band(
    id: BandId,
    severity: BandSeverity,
    action_class: RemediationActionClass,
    headline: impl AsRef<str>,
    detail_lines: Vec<String>,
    reason_code: Option<String>,
) -> RemediationBand {
    RemediationBand {
        id,
        title: id.title().to_string(),
        severity,
        action_class,
        headline: redact_secrets(headline.as_ref()),
        detail_lines: detail_lines.iter().map(|l| redact_secrets(l)).collect(),
        reason_code,
    }
}

fn band_desired_fleet(f: &FleetSummaryInput) -> RemediationBand {
    let details = vec![format!(
        "desired {} · eligible {} · bypassed {} · disabled {} · unreachable {} · missing {}",
        f.desired, f.eligible, f.bypassed, f.disabled, f.unreachable, f.missing
    )];

    // No workers configured at all is a clean, expected fail-open posture.
    if f.desired == 0 {
        return make_band(
            BandId::DesiredFleet,
            BandSeverity::Info,
            RemediationActionClass::NormalFailOpen,
            "no workers configured — builds run locally (fail-open)",
            details,
            None,
        );
    }

    if f.eligible > 0 {
        // Some capacity exists. Overload (problem_class == local_overload) is
        // normal back-pressure, not a fault.
        let (sev, class) = if f.problem_class == "local_overload" {
            (BandSeverity::Warn, RemediationActionClass::NormalFailOpen)
        } else {
            (BandSeverity::Ok, RemediationActionClass::Healthy)
        };
        return make_band(
            BandId::DesiredFleet,
            sev,
            class,
            &f.problem_summary,
            details,
            Some(f.problem_class.clone()),
        );
    }

    // Capacity collapse: classify by the dominant problem. Transient classes
    // (bypass/canary) self-heal; the rest need an operator.
    let self_healing_collapse =
        f.recovered_pending_canary > 0 || (f.bypassed > 0 && f.disabled == 0 && f.missing == 0);
    let class = if self_healing_collapse {
        RemediationActionClass::SelfHealingInProgress
    } else {
        RemediationActionClass::OperatorActionRequired
    };
    make_band(
        BandId::DesiredFleet,
        BandSeverity::Critical,
        class,
        &f.problem_summary,
        details,
        Some(f.problem_class.clone()),
    )
}

fn band_live_eligibility(f: &FleetSummaryInput) -> RemediationBand {
    let headline = format!("{} of {} desired worker(s) eligible", f.eligible, f.desired);
    let mut details = Vec::new();
    if f.bypassed > 0 {
        details.push(format!("{} temporarily bypassed (auto-rejoin)", f.bypassed));
    }
    if f.recovered_pending_canary > 0 {
        details.push(format!(
            "{} recovered, canary pending",
            f.recovered_pending_canary
        ));
    }
    if f.disabled > 0 {
        details.push(format!("{} admin-disabled", f.disabled));
    }
    if f.unreachable > 0 {
        details.push(format!("{} unreachable", f.unreachable));
    }
    if f.missing > 0 {
        details.push(format!("{} missing from pool", f.missing));
    }
    if f.absence_warnings > 0 {
        details.push(format!("{} absent past policy window", f.absence_warnings));
    }

    if f.desired == 0 {
        return make_band(
            BandId::LiveEligibility,
            BandSeverity::Info,
            RemediationActionClass::NormalFailOpen,
            "no workers configured",
            details,
            None,
        );
    }

    // Workers out only on the transient axis (bypass / pending canary) are
    // self-healing; admin-disabled / missing / unreachable need operator action.
    let operator_gaps = f.disabled + f.unreachable + f.missing;
    let transient_gaps = f.bypassed + f.recovered_pending_canary;

    let (severity, action_class) = if f.eligible == 0 {
        if operator_gaps == 0 && transient_gaps > 0 {
            (
                BandSeverity::Critical,
                RemediationActionClass::SelfHealingInProgress,
            )
        } else {
            (
                BandSeverity::Critical,
                RemediationActionClass::OperatorActionRequired,
            )
        }
    } else if operator_gaps > 0 {
        (
            BandSeverity::Warn,
            RemediationActionClass::OperatorActionRequired,
        )
    } else if transient_gaps > 0 {
        (
            BandSeverity::Warn,
            RemediationActionClass::SelfHealingInProgress,
        )
    } else {
        (BandSeverity::Ok, RemediationActionClass::Healthy)
    };

    make_band(
        BandId::LiveEligibility,
        severity,
        action_class,
        headline,
        details,
        None,
    )
}

fn band_admissible(a: &AdmissibleWorkersInput, f: &FleetSummaryInput) -> RemediationBand {
    let headline = format!(
        "{} of {} live worker(s) can run a command now",
        a.admissible, a.total_live
    );
    let mut details = Vec::new();
    if let Some(reason) = &a.top_blocker_reason {
        details.push(format!("top blocker: {reason}"));
    }

    if a.admissible > 0 {
        return make_band(
            BandId::AdmissibleWorkers,
            BandSeverity::Ok,
            RemediationActionClass::Healthy,
            headline,
            details,
            None,
        );
    }

    // Zero admissible. If there are simply no live workers, that is the fleet
    // band's story and here it is just fail-open local execution. If live
    // workers exist but none is admissible, a capability/admission gap needs an
    // operator.
    if a.total_live == 0 {
        let class = if f.recovered_pending_canary > 0 || f.bypassed > 0 {
            RemediationActionClass::SelfHealingInProgress
        } else {
            RemediationActionClass::NormalFailOpen
        };
        return make_band(
            BandId::AdmissibleWorkers,
            BandSeverity::Warn,
            class,
            "no live workers — commands run locally (fail-open)",
            details,
            a.top_blocker_reason.clone(),
        );
    }

    make_band(
        BandId::AdmissibleWorkers,
        BandSeverity::Critical,
        RemediationActionClass::OperatorActionRequired,
        "no live worker is command-admissible",
        details,
        a.top_blocker_reason.clone(),
    )
}

fn band_proof_queue(p: &ProofQueueInput) -> RemediationBand {
    let active = p.queued + p.blocked + p.replaying;
    let headline = format!(
        "{active} proof(s) pending ({} queued · {} blocked · {} replaying)",
        p.queued, p.blocked, p.replaying
    );
    let mut details = Vec::new();
    if p.failed_recent > 0 {
        details.push(format!("{} recently failed (terminal)", p.failed_recent));
    }
    if p.stale_recent > 0 {
        details.push(format!("{} recently stale", p.stale_recent));
    }

    if active == 0 {
        // Recent terminal outcomes are informational history, not action items.
        let (sev, head) = if p.failed_recent > 0 || p.stale_recent > 0 {
            (
                BandSeverity::Info,
                "no proofs pending; recent terminal outcomes".to_string(),
            )
        } else {
            (BandSeverity::Ok, "no proofs pending".to_string())
        };
        let class = if p.failed_recent > 0 || p.stale_recent > 0 {
            RemediationActionClass::NormalFailOpen
        } else {
            RemediationActionClass::Healthy
        };
        return make_band(BandId::ProofQueue, sev, class, head, details, None);
    }

    // Replaying/queued proofs are the conveyor working (self-healing). Blocked
    // proofs with nothing moving are structural — they need the underlying
    // capacity/placement gap resolved.
    let (severity, action_class) = if p.replaying > 0 || p.queued > 0 {
        (
            BandSeverity::Info,
            RemediationActionClass::SelfHealingInProgress,
        )
    } else {
        // Only blocked proofs remain.
        (
            BandSeverity::Warn,
            RemediationActionClass::OperatorActionRequired,
        )
    };

    make_band(
        BandId::ProofQueue,
        severity,
        action_class,
        headline,
        details,
        None,
    )
}

fn band_active_jobs(j: &JobsInput) -> RemediationBand {
    let headline = format!("{} active · {} queued", j.active, j.queued);
    let mut details = Vec::new();
    if j.stuck > 0 {
        details.push(format!(
            "{} job(s) stuck (stale heartbeat/wrapper)",
            j.stuck
        ));
    }

    if j.stuck > 0 {
        return make_band(
            BandId::ActiveJobs,
            BandSeverity::Warn,
            RemediationActionClass::OperatorActionRequired,
            format!("{} stuck job(s) need attention", j.stuck),
            details,
            Some("queue_ambiguity".to_string()),
        );
    }

    let (severity, action_class) = if j.active > 0 || j.queued > 0 {
        (BandSeverity::Info, RemediationActionClass::Healthy)
    } else {
        (BandSeverity::Ok, RemediationActionClass::Healthy)
    };
    make_band(
        BandId::ActiveJobs,
        severity,
        action_class,
        if j.active == 0 && j.queued == 0 {
            "idle".to_string()
        } else {
            headline
        },
        details,
        None,
    )
}

fn band_disk_pressure(d: &DiskPressureInput) -> RemediationBand {
    let mut details = Vec::new();
    if let Some(ratio) = d.min_free_ratio {
        details.push(format!("tightest free-disk ratio {ratio:.2}"));
    }
    if d.reclaim_in_progress > 0 {
        details.push(format!("{} reclaiming space", d.reclaim_in_progress));
    }

    if d.workers_critical > 0 {
        // Critical pressure is self-healing only while every critical worker is
        // actively reclaiming; otherwise an operator must free space.
        let class = if d.reclaim_in_progress >= d.workers_critical {
            RemediationActionClass::SelfHealingInProgress
        } else {
            RemediationActionClass::OperatorActionRequired
        };
        return make_band(
            BandId::DiskPressure,
            BandSeverity::Critical,
            class,
            format!("{} worker(s) at critical disk pressure", d.workers_critical),
            details,
            Some("critical_pressure".to_string()),
        );
    }

    if d.workers_warning > 0 {
        return make_band(
            BandId::DiskPressure,
            BandSeverity::Warn,
            RemediationActionClass::SelfHealingInProgress,
            format!(
                "{} worker(s) under disk-pressure warning",
                d.workers_warning
            ),
            details,
            Some("disk_full".to_string()),
        );
    }

    make_band(
        BandId::DiskPressure,
        BandSeverity::Ok,
        RemediationActionClass::Healthy,
        "no disk pressure",
        details,
        None,
    )
}

fn band_telemetry(t: &TelemetryFreshnessInput) -> RemediationBand {
    let total = t.fresh + t.stale + t.unknown;
    let mut details = Vec::new();
    if let Some(age) = t.max_age_secs {
        details.push(format!("oldest telemetry {age}s"));
    }
    if t.stale > 0 {
        details.push(format!("{} stale", t.stale));
    }
    if t.unknown > 0 {
        details.push(format!("{} unknown age", t.unknown));
    }

    if t.stale == 0 && t.unknown == 0 {
        return make_band(
            BandId::TelemetryFreshness,
            BandSeverity::Ok,
            RemediationActionClass::Healthy,
            format!("{} worker(s) reporting fresh telemetry", t.fresh),
            details,
            None,
        );
    }

    // No telemetry at all from any live worker is an operator problem (workers
    // never reported facts); otherwise staleness is expected to self-correct.
    if total > 0 && t.unknown == total {
        return make_band(
            BandId::TelemetryFreshness,
            BandSeverity::Warn,
            RemediationActionClass::OperatorActionRequired,
            "no worker telemetry available",
            details,
            Some("telemetry_stale".to_string()),
        );
    }

    make_band(
        BandId::TelemetryFreshness,
        BandSeverity::Warn,
        RemediationActionClass::SelfHealingInProgress,
        format!(
            "{} of {} worker(s) with stale/unknown telemetry",
            t.stale + t.unknown,
            total
        ),
        details,
        Some("telemetry_stale".to_string()),
    )
}

fn band_incidents(incidents: &[RemediationIncidentLine]) -> RemediationBand {
    if incidents.is_empty() {
        return make_band(
            BandId::Incidents,
            BandSeverity::Ok,
            RemediationActionClass::Healthy,
            "no recent incidents",
            Vec::new(),
            None,
        );
    }

    let worst = incidents
        .iter()
        .min_by_key(|i| i.reason_code.clone())
        .map(|i| i.reason_code.clone());
    let details: Vec<String> = incidents
        .iter()
        .take(3)
        .map(|i| {
            let who = i
                .worker_id
                .as_deref()
                .map_or_else(String::new, |w| format!(" [{w}]"));
            format!(
                "{} {}{} ({}s ago)",
                i.reason_code, i.event_type, who, i.age_secs
            )
        })
        .collect();

    // Recent incidents are a log surface: informational, not themselves an
    // action item (the live bands above carry the action posture).
    make_band(
        BandId::Incidents,
        BandSeverity::Info,
        RemediationActionClass::NormalFailOpen,
        format!("{} recent incident(s)", incidents.len()),
        details,
        worst,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_fleet() -> FleetSummaryInput {
        FleetSummaryInput {
            desired: 4,
            eligible: 4,
            bypassed: 0,
            disabled: 0,
            unreachable: 0,
            missing: 0,
            recovered_pending_canary: 0,
            problem_class: "healthy".into(),
            problem_summary: "4/4 worker(s) ready".into(),
            absence_warnings: 0,
        }
    }

    fn healthy_inputs() -> RemediationInputs {
        RemediationInputs {
            fleet: healthy_fleet(),
            admissible: AdmissibleWorkersInput {
                admissible: 4,
                total_live: 4,
                top_blocker_reason: None,
            },
            proof_queue: ProofQueueInput::default(),
            jobs: JobsInput::default(),
            disk: DiskPressureInput::default(),
            telemetry: TelemetryFreshnessInput {
                fresh: 4,
                stale: 0,
                unknown: 0,
                max_age_secs: Some(5),
            },
            incidents: Vec::new(),
        }
    }

    #[test]
    fn healthy_view_is_all_healthy() {
        let view = assemble(&healthy_inputs(), 1_000);
        assert_eq!(view.overall, RemediationActionClass::Healthy);
        assert_eq!(view.bands.len(), BandId::ALL.len());
        for band in &view.bands {
            assert_eq!(
                band.action_class,
                RemediationActionClass::Healthy,
                "band {} should be healthy",
                band.id.as_str()
            );
        }
        assert!(view.incidents.is_empty());
        assert!(!view.needs_operator_action());
    }

    #[test]
    fn bands_are_in_canonical_order_and_complete() {
        let view = assemble(&healthy_inputs(), 1);
        let ids: Vec<BandId> = view.bands.iter().map(|b| b.id).collect();
        assert_eq!(ids, BandId::ALL.to_vec());
    }

    #[test]
    fn degraded_but_eligible_is_self_healing_not_collapse() {
        let mut inputs = healthy_inputs();
        inputs.fleet = FleetSummaryInput {
            desired: 4,
            eligible: 3,
            bypassed: 1,
            problem_class: "healthy".into(),
            problem_summary: "3/4 worker(s) ready".into(),
            ..healthy_fleet()
        };
        let view = assemble(&inputs, 1);
        let live = view.band(BandId::LiveEligibility).unwrap();
        assert_eq!(
            live.action_class,
            RemediationActionClass::SelfHealingInProgress
        );
        assert_eq!(view.overall, RemediationActionClass::SelfHealingInProgress);
    }

    #[test]
    fn admin_disabled_collapse_requires_operator() {
        let mut inputs = healthy_inputs();
        inputs.fleet = FleetSummaryInput {
            desired: 2,
            eligible: 0,
            disabled: 2,
            problem_class: "admin_intent".into(),
            problem_summary: "0/2 ready — operator-disabled".into(),
            ..healthy_fleet()
        };
        inputs.admissible = AdmissibleWorkersInput {
            admissible: 0,
            total_live: 2,
            top_blocker_reason: Some("admin disabled".into()),
        };
        let view = assemble(&inputs, 1);
        assert_eq!(view.overall, RemediationActionClass::OperatorActionRequired);
        let fleet = view.band(BandId::DesiredFleet).unwrap();
        assert_eq!(
            fleet.action_class,
            RemediationActionClass::OperatorActionRequired
        );
        assert_eq!(fleet.severity, BandSeverity::Critical);
    }

    #[test]
    fn bypass_only_collapse_is_self_healing() {
        let mut inputs = healthy_inputs();
        inputs.fleet = FleetSummaryInput {
            desired: 2,
            eligible: 0,
            bypassed: 2,
            recovered_pending_canary: 0,
            problem_class: "cloud_disappearance".into(),
            problem_summary: "0/2 ready — all temporarily bypassed".into(),
            ..healthy_fleet()
        };
        inputs.admissible = AdmissibleWorkersInput {
            admissible: 0,
            total_live: 2,
            top_blocker_reason: None,
        };
        let view = assemble(&inputs, 1);
        let fleet = view.band(BandId::DesiredFleet).unwrap();
        assert_eq!(
            fleet.action_class,
            RemediationActionClass::SelfHealingInProgress
        );
    }

    #[test]
    fn no_admissible_with_live_workers_requires_operator() {
        let mut inputs = healthy_inputs();
        inputs.admissible = AdmissibleWorkersInput {
            admissible: 0,
            total_live: 3,
            top_blocker_reason: Some("missing rust target".into()),
        };
        let view = assemble(&inputs, 1);
        let band = view.band(BandId::AdmissibleWorkers).unwrap();
        assert_eq!(
            band.action_class,
            RemediationActionClass::OperatorActionRequired
        );
        assert_eq!(band.reason_code.as_deref(), Some("missing rust target"));
    }

    #[test]
    fn proof_queued_is_self_healing() {
        let mut inputs = healthy_inputs();
        inputs.proof_queue = ProofQueueInput {
            queued: 2,
            replaying: 1,
            ..ProofQueueInput::default()
        };
        let view = assemble(&inputs, 1);
        let band = view.band(BandId::ProofQueue).unwrap();
        assert_eq!(
            band.action_class,
            RemediationActionClass::SelfHealingInProgress
        );
    }

    #[test]
    fn proof_blocked_only_requires_operator() {
        let mut inputs = healthy_inputs();
        inputs.proof_queue = ProofQueueInput {
            blocked: 3,
            ..ProofQueueInput::default()
        };
        let view = assemble(&inputs, 1);
        let band = view.band(BandId::ProofQueue).unwrap();
        assert_eq!(
            band.action_class,
            RemediationActionClass::OperatorActionRequired
        );
    }

    #[test]
    fn disk_critical_without_reclaim_requires_operator() {
        let mut inputs = healthy_inputs();
        inputs.disk = DiskPressureInput {
            workers_critical: 2,
            reclaim_in_progress: 0,
            min_free_ratio: Some(0.02),
            ..DiskPressureInput::default()
        };
        let view = assemble(&inputs, 1);
        let band = view.band(BandId::DiskPressure).unwrap();
        assert_eq!(band.severity, BandSeverity::Critical);
        assert_eq!(
            band.action_class,
            RemediationActionClass::OperatorActionRequired
        );
    }

    #[test]
    fn disk_critical_with_full_reclaim_is_self_healing() {
        let mut inputs = healthy_inputs();
        inputs.disk = DiskPressureInput {
            workers_critical: 2,
            reclaim_in_progress: 2,
            ..DiskPressureInput::default()
        };
        let view = assemble(&inputs, 1);
        let band = view.band(BandId::DiskPressure).unwrap();
        assert_eq!(
            band.action_class,
            RemediationActionClass::SelfHealingInProgress
        );
    }

    #[test]
    fn stale_telemetry_is_self_healing_but_all_unknown_needs_operator() {
        let mut inputs = healthy_inputs();
        inputs.telemetry = TelemetryFreshnessInput {
            fresh: 3,
            stale: 1,
            unknown: 0,
            max_age_secs: Some(900),
        };
        let band = assemble(&inputs, 1)
            .band(BandId::TelemetryFreshness)
            .cloned()
            .unwrap();
        assert_eq!(
            band.action_class,
            RemediationActionClass::SelfHealingInProgress
        );

        inputs.telemetry = TelemetryFreshnessInput {
            fresh: 0,
            stale: 0,
            unknown: 3,
            max_age_secs: None,
        };
        let band = assemble(&inputs, 1)
            .band(BandId::TelemetryFreshness)
            .cloned()
            .unwrap();
        assert_eq!(
            band.action_class,
            RemediationActionClass::OperatorActionRequired
        );
    }

    #[test]
    fn auto_rejoin_pending_is_self_healing() {
        let mut inputs = healthy_inputs();
        inputs.fleet = FleetSummaryInput {
            desired: 4,
            eligible: 3,
            recovered_pending_canary: 1,
            problem_class: "healthy".into(),
            problem_summary: "3/4 ready — 1 canary pending".into(),
            ..healthy_fleet()
        };
        let view = assemble(&inputs, 1);
        let live = view.band(BandId::LiveEligibility).unwrap();
        assert_eq!(
            live.action_class,
            RemediationActionClass::SelfHealingInProgress
        );
        assert!(
            live.detail_lines
                .iter()
                .any(|l| l.contains("canary pending"))
        );
    }

    #[test]
    fn stuck_jobs_require_operator() {
        let mut inputs = healthy_inputs();
        inputs.jobs = JobsInput {
            active: 2,
            queued: 1,
            stuck: 1,
        };
        let band = assemble(&inputs, 1)
            .band(BandId::ActiveJobs)
            .cloned()
            .unwrap();
        assert_eq!(
            band.action_class,
            RemediationActionClass::OperatorActionRequired
        );
        assert_eq!(band.reason_code.as_deref(), Some("queue_ambiguity"));
    }

    #[test]
    fn incidents_are_informational_and_bounded() {
        let mut inputs = healthy_inputs();
        inputs.incidents = (0u64..15)
            .map(|i| {
                RemediationIncidentLine::new(
                    format!("RCH-I0{:02}", i % 9 + 1),
                    "selection",
                    Some("css".into()),
                    i * 10,
                    "no admissible workers",
                )
            })
            .collect();
        let view = assemble(&inputs, 1);
        assert_eq!(view.incidents.len(), MAX_VIEW_INCIDENTS);
        let band = view.band(BandId::Incidents).unwrap();
        assert_eq!(band.action_class, RemediationActionClass::NormalFailOpen);
        assert_eq!(band.severity, BandSeverity::Info);
    }

    #[test]
    fn no_workers_configured_is_normal_fail_open() {
        let mut inputs = healthy_inputs();
        inputs.fleet = FleetSummaryInput {
            desired: 0,
            eligible: 0,
            problem_class: "healthy".into(),
            problem_summary: "no workers configured".into(),
            ..healthy_fleet()
        };
        inputs.admissible = AdmissibleWorkersInput {
            admissible: 0,
            total_live: 0,
            top_blocker_reason: None,
        };
        inputs.telemetry = TelemetryFreshnessInput::default();
        let view = assemble(&inputs, 1);
        assert_eq!(view.overall, RemediationActionClass::NormalFailOpen);
    }

    #[test]
    fn free_text_is_redacted_at_construction() {
        let mut inputs = healthy_inputs();
        inputs.fleet.problem_summary =
            "ssh failed for ubuntu@203.0.113.20 key AKIAIOSFODNN7EXAMPLE".into();
        inputs.incidents = vec![RemediationIncidentLine::new(
            "RCH-I010",
            "hook",
            None,
            3,
            "token Bearer abcdef0123456789abcdef0123456789 at /home/ubuntu/.ssh/id_rsa",
        )];
        let view = assemble(&inputs, 1);
        let json = serde_json::to_string(&view).unwrap();
        assert!(
            !json.contains("AKIAIOSFODNN7EXAMPLE"),
            "AWS-shaped key leaked"
        );
        assert!(
            !json.contains("abcdef0123456789abcdef0123456789"),
            "bearer leaked"
        );
    }

    #[test]
    fn action_class_ordering_is_severity_ordered() {
        assert!(
            RemediationActionClass::OperatorActionRequired
                > RemediationActionClass::SelfHealingInProgress
        );
        assert!(
            RemediationActionClass::SelfHealingInProgress > RemediationActionClass::NormalFailOpen
        );
        assert!(RemediationActionClass::NormalFailOpen > RemediationActionClass::Healthy);
        assert_eq!(
            RemediationActionClass::Healthy
                .max_class(RemediationActionClass::OperatorActionRequired),
            RemediationActionClass::OperatorActionRequired
        );
    }

    #[test]
    fn view_round_trips_through_json() {
        let view = assemble(&healthy_inputs(), 42);
        let json = serde_json::to_string(&view).unwrap();
        let back: RemediationView = serde_json::from_str(&json).unwrap();
        assert_eq!(view, back);
    }

    fn ready_row(id: &str) -> RemediationWorkerRow {
        use crate::fleet_diff::WorkerObservation;
        RemediationWorkerRow {
            observation: WorkerObservation {
                worker_id: id.into(),
                configured: true,
                in_daemon_pool: true,
                reachable: true,
                admin_disabled: false,
                temporarily_bypassed: false,
                facts_known: true,
                command_admissible: true,
            },
            disk_level: DiskLevel::Ok,
            reclaiming: false,
            free_ratio: Some(0.8),
            slots_used: 0,
            slots_total: 8,
            telemetry_known: true,
            telemetry_fresh: true,
            telemetry_age_secs: Some(3),
            recovered_pending_canary: false,
            absent_secs: None,
        }
    }

    #[test]
    fn build_inputs_healthy_fleet_round_trips_to_healthy_view() {
        let rows = vec![ready_row("css"), ready_row("ovh-a"), ready_row("ovh-b")];
        let inputs = build_inputs(
            &rows,
            JobsInput::default(),
            ProofQueueInput::default(),
            Vec::new(),
            300,
        );
        assert_eq!(inputs.fleet.desired, 3);
        assert_eq!(inputs.fleet.eligible, 3);
        assert_eq!(inputs.admissible.admissible, 3);
        assert_eq!(inputs.telemetry.fresh, 3);
        let view = assemble(&inputs, 1);
        assert_eq!(view.overall, RemediationActionClass::Healthy);
    }

    #[test]
    fn build_inputs_maps_bypass_disk_and_unknown_facts() {
        let mut bypassed = ready_row("css");
        bypassed.observation.temporarily_bypassed = true;
        bypassed.recovered_pending_canary = true;

        let mut crit = ready_row("ovh-a");
        crit.disk_level = DiskLevel::Critical;
        crit.reclaiming = true;
        crit.free_ratio = Some(0.01);

        let mut no_facts = ready_row("ovh-b");
        no_facts.observation.facts_known = false;
        no_facts.telemetry_known = false;
        no_facts.telemetry_age_secs = None;

        let rows = vec![bypassed, crit, no_facts];
        let inputs = build_inputs(
            &rows,
            JobsInput {
                active: 1,
                queued: 0,
                stuck: 0,
            },
            ProofQueueInput::default(),
            Vec::new(),
            300,
        );
        assert_eq!(inputs.fleet.bypassed, 1);
        assert_eq!(inputs.fleet.recovered_pending_canary, 1);
        assert_eq!(inputs.disk.workers_critical, 1);
        assert_eq!(inputs.disk.reclaim_in_progress, 1);
        assert_eq!(inputs.disk.min_free_ratio, Some(0.01));
        // The no-facts worker is live but not admissible.
        assert_eq!(inputs.telemetry.unknown, 1);
        assert!(inputs.admissible.top_blocker_reason.is_some() || inputs.admissible.admissible > 0);
    }

    #[test]
    fn all_enum_tokens_are_stable_and_unique() {
        use std::collections::HashSet;
        let action: HashSet<_> = RemediationActionClass::ALL
            .iter()
            .map(|c| c.as_str())
            .collect();
        assert_eq!(action.len(), RemediationActionClass::ALL.len());
        let sev: HashSet<_> = BandSeverity::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(sev.len(), BandSeverity::ALL.len());
        let bands: HashSet<_> = BandId::ALL.iter().map(|b| b.as_str()).collect();
        assert_eq!(bands.len(), BandId::ALL.len());
    }
}
