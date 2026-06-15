//! Canonical placement / visibility / strict-remote controls
//! (bd-session-history-remediation-ocv9i.13.5).
//!
//! The complete session-history analysis kept turning up agents reaching for
//! folklore knobs — `RCH_WORKER`, `RCH_VISIBILITY`, `RCH_QUEUE_WHEN_BUSY`,
//! `RCH_FORCE_REMOTE`, `RCH_REQUIRE_REMOTE`, daemon wait timeouts, and
//! worker-scoped target dirs — to compensate for opaque selection and proof
//! semantics. Those controls were read in a dozen different places, some were
//! *silently ignored* (`RCH_FORCE_REMOTE` had no effect in the hook path), and
//! none of them were surfaced back to the agent so it could tell what RCH
//! actually did.
//!
//! This module is the single source of truth that makes them first-class:
//!
//! * [`placement_controls`] — the canonical registry (name, aliases, value
//!   semantics) consumed by `rch capabilities` so the knobs are discoverable.
//! * [`resolve_placement`] — a *pure* env → [`PlacementPlan`] resolver. It is
//!   deterministic (takes a getter closure rather than touching the process
//!   environment) and it never silently drops a control: an unrecognized value
//!   or a superseded alias becomes a [`ControlDiagnostic`] rather than a quiet
//!   no-op.
//! * [`StrictRemotePolicy`] — the canonical force-vs-require distinction, the
//!   single fix for the most-confused pair of knobs. `RCH_FORCE_REMOTE` means
//!   *always attempt offload but still fail open*; `RCH_REQUIRE_REMOTE` means
//!   *fail closed — refuse local fallback* (proof mode).
//! * [`evaluate_requested_worker`] — a pure admissibility evaluator. A
//!   requested worker that is unavailable, admin-disabled, bypassed,
//!   wrong-platform, missing a runtime, project-excluded, or full yields a
//!   structured refusal keyed to the stable [`IncidentReasonCode`] taxonomy
//!   plus a concrete next action — never a silent swap to a different worker.
//!
//! Everything here is clock-free and I/O-free so it is cheap on the hook hot
//! path and exhaustively unit-testable.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::incident::{ControlState, IncidentReasonCode};
use crate::schema_versions::{SchemaComponent, current_version};

// ---------------------------------------------------------------------------
// Canonical control vocabulary
// ---------------------------------------------------------------------------

/// Strict-remote / proof policy, resolved from the env precedence
/// `RCH_REQUIRE_REMOTE` > `RCH_FORCE_REMOTE`.
///
/// These two knobs were the most conflated pair in the session evidence, so the
/// distinction is encoded in the type rather than left to prose:
///
/// * [`Off`](Self::Off) — heuristics decide; local fallback is allowed.
/// * [`ForceRemote`](Self::ForceRemote) — always *attempt* offload (bypass the
///   `min_local_time` / speedup gating) but still **fail open** to local if no
///   worker can take it.
/// * [`RequireRemote`](Self::RequireRemote) — **fail closed**: refuse local
///   fallback entirely (proof mode). Implies the force-remote intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StrictRemotePolicy {
    /// Heuristics decide; local fallback allowed.
    #[default]
    Off,
    /// Always attempt offload, but fail open to local.
    ForceRemote,
    /// Fail closed: never fall back to local (proof mode).
    RequireRemote,
}

impl StrictRemotePolicy {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            StrictRemotePolicy::Off => "off",
            StrictRemotePolicy::ForceRemote => "force_remote",
            StrictRemotePolicy::RequireRemote => "require_remote",
        }
    }

    /// True when local fallback is refused (proof mode).
    #[must_use]
    pub fn fail_closed(self) -> bool {
        matches!(self, StrictRemotePolicy::RequireRemote)
    }

    /// True when offload should always be attempted (force or require),
    /// bypassing the local-runtime / speedup heuristics.
    #[must_use]
    pub fn forces_offload(self) -> bool {
        matches!(
            self,
            StrictRemotePolicy::ForceRemote | StrictRemotePolicy::RequireRemote
        )
    }
}

/// Queue-when-busy policy. Defaults to enabled (the daemon may hold a request
/// for a worker rather than immediately falling back to local).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueuePolicy {
    /// Wait for a worker to free up (default).
    #[default]
    QueueWhenBusy,
    /// Never queue; fall back to local immediately when workers are busy.
    NoQueue,
}

impl QueuePolicy {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            QueuePolicy::QueueWhenBusy => "queue_when_busy",
            QueuePolicy::NoQueue => "no_queue",
        }
    }

    /// True when the request should wait for a worker.
    #[must_use]
    pub fn waits(self) -> bool {
        matches!(self, QueuePolicy::QueueWhenBusy)
    }
}

/// Hook output visibility. `default` means "no explicit override; use config".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityMode {
    /// No explicit env override — defer to config.
    #[default]
    Default,
    /// Suppress hook output.
    None,
    /// One-line summary.
    Summary,
    /// Verbose per-step output.
    Verbose,
}

impl VisibilityMode {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            VisibilityMode::Default => "default",
            VisibilityMode::None => "none",
            VisibilityMode::Summary => "summary",
            VisibilityMode::Verbose => "verbose",
        }
    }

    /// Parse a canonical `RCH_VISIBILITY` value (`none` / `summary` /
    /// `verbose`). Returns `None` for unrecognized values so the caller can
    /// raise a diagnostic instead of silently ignoring it.
    fn parse(value: &str) -> Option<VisibilityMode> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" | "quiet" => Some(VisibilityMode::None),
            "summary" => Some(VisibilityMode::Summary),
            "verbose" => Some(VisibilityMode::Verbose),
            _ => None,
        }
    }
}

/// Worker-scoped target-dir policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetDirPolicy {
    /// Pooled, reuse-friendly remote target dir (default).
    #[default]
    Pooled,
    /// Legacy unique-per-job remote target dir (`RCH_DISABLE_TARGET_REUSE`).
    PerJob,
    /// Caller pinned a worker-scoped `CARGO_TARGET_DIR`.
    WorkerScoped,
}

impl TargetDirPolicy {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TargetDirPolicy::Pooled => "pooled",
            TargetDirPolicy::PerJob => "per_job",
            TargetDirPolicy::WorkerScoped => "worker_scoped",
        }
    }
}

// ---------------------------------------------------------------------------
// Control registry (capabilities discovery)
// ---------------------------------------------------------------------------

/// The category a control belongs to, for grouping in discovery surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    /// Worker placement / selection.
    Placement,
    /// Strict-remote / proof policy.
    StrictRemote,
    /// Queue-when-busy policy.
    Queue,
    /// Daemon wait timeout.
    WaitTimeout,
    /// Output visibility.
    Visibility,
    /// Worker-scoped target dir.
    TargetDir,
    /// Requested execution profile.
    Profile,
    /// Self-healing master switch.
    SelfHealing,
}

/// A single canonical control: its primary env var, accepted aliases, the
/// equivalent CLI flag (if any), and human/agent-facing value semantics. This
/// is the registry `rch capabilities` renders so agents stop discovering knobs
/// by folklore.
#[derive(Debug, Clone, Copy)]
pub struct PlacementControl {
    /// Canonical environment variable name.
    pub canonical_env: &'static str,
    /// Accepted aliases (documented, mapped to the canonical control).
    pub aliases: &'static [&'static str],
    /// Equivalent CLI flag, when one exists.
    pub flag: Option<&'static str>,
    /// Which family the control belongs to.
    pub kind: ControlKind,
    /// Accepted value form (e.g. `worker id`, `0|1`, `secs`).
    pub value_form: &'static str,
    /// One-line description of the effect.
    pub description: &'static str,
}

/// The canonical placement/visibility/strict/queue/wait control registry.
///
/// Adding a knob here is the *only* place it needs to be declared for discovery
/// — `rch capabilities` derives its env-var list from this slice.
#[must_use]
pub fn placement_controls() -> &'static [PlacementControl] {
    const CONTROLS: &[PlacementControl] = &[
        PlacementControl {
            canonical_env: "RCH_WORKER",
            aliases: &["RCH_WORKERS"],
            flag: None,
            kind: ControlKind::Placement,
            value_form: "worker-id[,worker-id...]",
            description: "Request specific worker(s) by id. Still passes capability/admission \
                          checks; an inadmissible requested worker is refused with a reason code.",
        },
        PlacementControl {
            canonical_env: "RCH_PRESET",
            aliases: &[],
            flag: None,
            kind: ControlKind::Profile,
            value_form: "profile-name",
            description: "Request a named execution profile (recorded as requested_profile).",
        },
        PlacementControl {
            canonical_env: "RCH_REQUIRE_REMOTE",
            aliases: &[],
            flag: None,
            kind: ControlKind::StrictRemote,
            value_form: "0|1",
            description: "Fail closed: refuse local fallback (proof mode). Takes precedence over \
                          RCH_FORCE_REMOTE.",
        },
        PlacementControl {
            canonical_env: "RCH_FORCE_REMOTE",
            aliases: &[],
            flag: None,
            kind: ControlKind::StrictRemote,
            value_form: "0|1",
            description: "Always attempt offload (bypass local-time/speedup gating) but still \
                          fail open to local. Distinct from RCH_REQUIRE_REMOTE.",
        },
        PlacementControl {
            canonical_env: "RCH_QUEUE_WHEN_BUSY",
            aliases: &[],
            flag: None,
            kind: ControlKind::Queue,
            value_form: "0|1 (default 1)",
            description: "Wait for a busy worker instead of immediately falling back to local. \
                          Set 0 to disable queueing.",
        },
        PlacementControl {
            canonical_env: "RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS",
            aliases: &["RCH_DAEMON_RESPONSE_TIMEOUT_SECS"],
            flag: None,
            kind: ControlKind::WaitTimeout,
            value_form: "secs (>0)",
            description: "Maximum time to wait for a queued worker before falling back.",
        },
        PlacementControl {
            canonical_env: "RCH_VISIBILITY",
            aliases: &["RCH_QUIET", "RCH_VERBOSE"],
            flag: None,
            kind: ControlKind::Visibility,
            value_form: "none|summary|verbose",
            description: "Hook output verbosity. RCH_QUIET=>none, RCH_VERBOSE=>verbose.",
        },
        PlacementControl {
            canonical_env: "RCH_DISABLE_TARGET_REUSE",
            aliases: &[],
            flag: None,
            kind: ControlKind::TargetDir,
            value_form: "0|1",
            description: "Use a legacy unique-per-job remote target dir instead of the pooled, \
                          reuse-friendly dir.",
        },
        PlacementControl {
            canonical_env: "RCH_NO_SELF_HEALING",
            aliases: &[],
            flag: Some("--no-self-healing"),
            kind: ControlKind::SelfHealing,
            value_form: "0|1",
            description: "Master switch disabling hook->daemon autostart and daemon hook install.",
        },
    ];
    CONTROLS
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Severity of a control diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControlDiagnosticLevel {
    /// Informational (e.g. an alias was canonicalized).
    Info,
    /// The value could not be applied as written and a fallback was used.
    Warning,
}

/// A single diagnostic explaining how a control was interpreted. The whole
/// point: a knob that cannot be applied as written is *reported*, never
/// silently dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ControlDiagnostic {
    /// Canonical control this diagnostic concerns.
    pub control: String,
    /// Severity.
    pub level: ControlDiagnosticLevel,
    /// What happened / what to do.
    pub message: String,
}

impl ControlDiagnostic {
    fn info(control: &str, message: impl Into<String>) -> Self {
        Self {
            control: control.to_string(),
            level: ControlDiagnosticLevel::Info,
            message: message.into(),
        }
    }

    fn warning(control: &str, message: impl Into<String>) -> Self {
        Self {
            control: control.to_string(),
            level: ControlDiagnosticLevel::Warning,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Requested-worker admissibility
// ---------------------------------------------------------------------------

/// Outcome class for an explicitly requested worker. Every non-`Honored`
/// variant is a *structured refusal*: the requested worker is not silently
/// swapped for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestedWorkerStatus {
    /// No worker was explicitly requested.
    NotRequested,
    /// A worker was requested but has not yet been evaluated against the fleet.
    Requested,
    /// The requested worker is admissible and was honored.
    Honored,
    /// The requested worker is unknown/unreachable/drained.
    Unavailable,
    /// The requested worker was disabled by an operator.
    AdminDisabled,
    /// The requested worker is in transient quarantine (temporary bypass).
    TemporarilyBypassed,
    /// The requested worker's OS/arch does not match the build target.
    WrongPlatform,
    /// The requested worker lacks the required runtime/toolchain/target.
    MissingRuntime,
    /// The requested worker is excluded because it already runs this project.
    ProjectExcluded,
    /// The requested worker has no free slots for this request.
    NoFreeSlots,
}

impl RequestedWorkerStatus {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RequestedWorkerStatus::NotRequested => "not_requested",
            RequestedWorkerStatus::Requested => "requested",
            RequestedWorkerStatus::Honored => "honored",
            RequestedWorkerStatus::Unavailable => "unavailable",
            RequestedWorkerStatus::AdminDisabled => "admin_disabled",
            RequestedWorkerStatus::TemporarilyBypassed => "temporarily_bypassed",
            RequestedWorkerStatus::WrongPlatform => "wrong_platform",
            RequestedWorkerStatus::MissingRuntime => "missing_runtime",
            RequestedWorkerStatus::ProjectExcluded => "project_excluded",
            RequestedWorkerStatus::NoFreeSlots => "no_free_slots",
        }
    }

    /// True when the request was refused (a worker was named but cannot be used
    /// as asked).
    #[must_use]
    pub fn is_refusal(self) -> bool {
        !matches!(
            self,
            RequestedWorkerStatus::NotRequested
                | RequestedWorkerStatus::Requested
                | RequestedWorkerStatus::Honored
        )
    }
}

/// The facts an evaluator needs about an explicitly requested worker. The hook
/// fills these from the daemon's per-worker selection diagnostics; tests fill
/// them directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedWorkerFacts {
    /// The requested worker id (empty/none means "no request").
    pub requested: Option<String>,
    /// Whether the worker is a known, configured worker.
    pub exists: bool,
    /// Operator explicitly disabled this worker.
    pub admin_disabled: bool,
    /// Worker is draining or drained (out of service by operator intent).
    pub draining_or_drained: bool,
    /// Worker is reachable / responding.
    pub reachable: bool,
    /// Worker is in transient quarantine (temporary bypass).
    pub temporarily_bypassed: bool,
    /// Worker OS/arch matches the build target.
    pub platform_matches: bool,
    /// Worker has the required runtime/toolchain/target.
    pub has_required_runtime: bool,
    /// Worker already runs this project (active-project exclusion).
    pub project_excluded: bool,
    /// Worker has enough free slots for the request.
    pub has_free_slots: bool,
}

impl RequestedWorkerFacts {
    /// Facts for "no worker requested".
    #[must_use]
    pub fn none() -> Self {
        Self {
            requested: None,
            exists: false,
            admin_disabled: false,
            draining_or_drained: false,
            reachable: true,
            temporarily_bypassed: false,
            platform_matches: true,
            has_required_runtime: true,
            project_excluded: false,
            has_free_slots: true,
        }
    }

    /// Facts for a fully admissible requested worker (test/clarity helper).
    #[must_use]
    pub fn admissible(id: impl Into<String>) -> Self {
        Self {
            requested: Some(id.into()),
            exists: true,
            ..Self::none()
        }
    }
}

/// The structured result of evaluating a requested worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestedWorkerOutcome {
    /// Outcome class.
    pub status: RequestedWorkerStatus,
    /// Stable incident reason code (`RCH-Innn`) for a refusal, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    /// Concrete next action for the agent on a refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_action: Option<String>,
}

impl RequestedWorkerOutcome {
    /// Outcome for "no worker requested".
    #[must_use]
    pub fn not_requested() -> Self {
        Self {
            status: RequestedWorkerStatus::NotRequested,
            reason_code: None,
            next_action: None,
        }
    }

    /// Outcome for "requested, pending fleet evaluation".
    #[must_use]
    pub fn requested() -> Self {
        Self {
            status: RequestedWorkerStatus::Requested,
            reason_code: None,
            next_action: None,
        }
    }

    fn honored() -> Self {
        Self {
            status: RequestedWorkerStatus::Honored,
            reason_code: None,
            next_action: None,
        }
    }

    fn refused(
        status: RequestedWorkerStatus,
        code: IncidentReasonCode,
        next_action: impl Into<String>,
    ) -> Self {
        Self {
            status,
            reason_code: Some(code.code().to_string()),
            next_action: Some(next_action.into()),
        }
    }
}

/// Evaluate an explicitly requested worker against the fleet facts.
///
/// The order is most-specific-first so the *primary* reason a worker cannot be
/// used is the one reported. Each refusal maps to a stable
/// [`IncidentReasonCode`] and carries a concrete next action — the request is
/// never silently rerouted to a different worker.
#[must_use]
pub fn evaluate_requested_worker(facts: &RequestedWorkerFacts) -> RequestedWorkerOutcome {
    let Some(id) = facts.requested.as_deref().filter(|s| !s.trim().is_empty()) else {
        return RequestedWorkerOutcome::not_requested();
    };

    if !facts.exists {
        return RequestedWorkerOutcome::refused(
            RequestedWorkerStatus::Unavailable,
            IncidentReasonCode::NoAdmissibleWorkers,
            format!("'{id}' is not a configured worker; run `rch workers list` to see valid ids"),
        );
    }
    if facts.admin_disabled {
        return RequestedWorkerOutcome::refused(
            RequestedWorkerStatus::AdminDisabled,
            IncidentReasonCode::NoAdmissibleWorkers,
            format!(
                "'{id}' is operator-disabled; re-enable with `rch workers enable {id}` or request another worker"
            ),
        );
    }
    if facts.draining_or_drained || !facts.reachable {
        return RequestedWorkerOutcome::refused(
            RequestedWorkerStatus::Unavailable,
            IncidentReasonCode::NoAdmissibleWorkers,
            format!(
                "'{id}' is draining/unreachable; wait for it to return or request another worker"
            ),
        );
    }
    if facts.temporarily_bypassed {
        return RequestedWorkerOutcome::refused(
            RequestedWorkerStatus::TemporarilyBypassed,
            IncidentReasonCode::CircuitOpen,
            format!(
                "'{id}' is in transient quarantine; wait for auto-rejoin or request another worker"
            ),
        );
    }
    if !facts.platform_matches {
        return RequestedWorkerOutcome::refused(
            RequestedWorkerStatus::WrongPlatform,
            IncidentReasonCode::OsArchMismatch,
            format!("'{id}' OS/arch does not match the build target; request a matching worker"),
        );
    }
    if !facts.has_required_runtime {
        return RequestedWorkerOutcome::refused(
            RequestedWorkerStatus::MissingRuntime,
            IncidentReasonCode::MissingRuntimeToolchainTarget,
            format!(
                "'{id}' lacks the required runtime/toolchain/target; install it or request another worker"
            ),
        );
    }
    if facts.project_excluded {
        return RequestedWorkerOutcome::refused(
            RequestedWorkerStatus::ProjectExcluded,
            IncidentReasonCode::ActiveProjectExclusion,
            format!(
                "'{id}' already runs this project (active-project exclusion); request another worker"
            ),
        );
    }
    if !facts.has_free_slots {
        return RequestedWorkerOutcome::refused(
            RequestedWorkerStatus::NoFreeSlots,
            IncidentReasonCode::InsufficientSlots,
            format!(
                "'{id}' has no free slots right now; queue with RCH_QUEUE_WHEN_BUSY=1 or request another worker"
            ),
        );
    }
    RequestedWorkerOutcome::honored()
}

// ---------------------------------------------------------------------------
// The resolved plan
// ---------------------------------------------------------------------------

/// The canonical, agent-facing resolution of all placement controls for a
/// single request. Field names are exactly the explicit-control surface the
/// session-history report asked to be made first-class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PlacementPlan {
    /// Schema version (`SchemaComponent::PlacementPlan`).
    pub schema_version: String,
    /// Worker(s) the caller explicitly requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_worker: Option<String>,
    /// Requested execution profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_profile: Option<String>,
    /// The worker actually selected (filled once selection runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_worker: Option<String>,
    /// Strict-remote / proof policy.
    pub strict_remote_policy: StrictRemotePolicy,
    /// Queue-when-busy policy.
    pub queue_policy: QueuePolicy,
    /// Output visibility mode.
    pub visibility_mode: VisibilityMode,
    /// Resolved wait timeout in milliseconds, when explicitly set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_timeout_ms: Option<u64>,
    /// Worker-scoped target-dir policy.
    pub target_dir_policy: TargetDirPolicy,
    /// Requested-worker admissibility outcome.
    pub requested_worker_outcome: RequestedWorkerOutcome,
    /// How each control was interpreted (superseded aliases, bad values, ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<ControlDiagnostic>,
}

impl PlacementPlan {
    /// The current placement-plan schema version.
    #[must_use]
    pub fn schema_version() -> &'static str {
        current_version(SchemaComponent::PlacementPlan)
    }

    /// Record the worker selection finally honored.
    #[must_use]
    pub fn with_effective_worker(mut self, worker: Option<String>) -> Self {
        self.effective_worker = worker;
        self
    }

    /// Replace the requested-worker outcome (after fleet evaluation).
    #[must_use]
    pub fn with_requested_worker_outcome(mut self, outcome: RequestedWorkerOutcome) -> Self {
        self.requested_worker_outcome = outcome;
        self
    }

    /// Bridge to the sparse [`ControlState`] embedded in incident events: only
    /// explicitly-set / non-default fields are carried, matching the
    /// incident-ledger convention of recording *why* a build was steered.
    #[must_use]
    pub fn control_state(&self) -> ControlState {
        ControlState {
            requested_worker: self.requested_worker.clone(),
            requested_profile: self.requested_profile.clone(),
            strict_remote_policy: self.strict_remote_policy != StrictRemotePolicy::Off,
            queue_policy: (self.queue_policy != QueuePolicy::default())
                .then(|| self.queue_policy.as_str().to_string()),
            visibility_mode: (self.visibility_mode != VisibilityMode::Default)
                .then(|| self.visibility_mode.as_str().to_string()),
            wait_timeout_ms: self.wait_timeout_ms,
            target_dir_policy: (self.target_dir_policy != TargetDirPolicy::default())
                .then(|| self.target_dir_policy.as_str().to_string()),
        }
    }
}

/// Repo-standard env truthiness (`1`/`true`/`yes`/`on`/`enabled`).
fn env_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | "enabled"
    )
}

/// Repo-standard env falsiness for default-enabled flags
/// (`0`/`false`/`no`/`off`/`disabled`).
fn env_falsy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off" | "disabled"
    )
}

/// Resolve every placement control from the environment into a single
/// [`PlacementPlan`].
///
/// `get` is the environment accessor — `|k| std::env::var(k).ok()` in the hook,
/// a map lookup in tests. The function is otherwise pure: no clock, no I/O, no
/// global state. It never silently drops a control; anything it cannot apply as
/// written becomes a [`ControlDiagnostic`].
///
/// The returned plan has no `effective_worker` (selection has not run yet) and a
/// `requested_worker_outcome` of `NotRequested`/`Requested`; callers refine both
/// once the daemon answers.
pub fn resolve_placement<F>(get: F) -> PlacementPlan
where
    F: Fn(&str) -> Option<String>,
{
    let mut diagnostics = Vec::new();

    // --- requested worker(s): RCH_WORKER (canonical) + RCH_WORKERS (alias) ---
    let worker_primary = get("RCH_WORKER").filter(|v| !v.trim().is_empty());
    let worker_alias = get("RCH_WORKERS").filter(|v| !v.trim().is_empty());
    let requested_worker = match (&worker_primary, &worker_alias) {
        (Some(p), Some(a)) => {
            diagnostics.push(ControlDiagnostic::info(
                "RCH_WORKER",
                "RCH_WORKER and its alias RCH_WORKERS are both set; merging both into the requested set",
            ));
            Some(merge_worker_lists(p, a))
        }
        (Some(p), None) => Some(p.trim().to_string()),
        (None, Some(a)) => {
            diagnostics.push(ControlDiagnostic::info(
                "RCH_WORKERS",
                "RCH_WORKERS is an alias for the canonical RCH_WORKER",
            ));
            Some(a.trim().to_string())
        }
        (None, None) => None,
    };

    // --- requested profile: RCH_PRESET ---
    let requested_profile = get("RCH_PRESET").filter(|v| !v.trim().is_empty());

    // --- strict remote: RCH_REQUIRE_REMOTE > RCH_FORCE_REMOTE ---
    let require_remote = get("RCH_REQUIRE_REMOTE").is_some_and(|v| env_truthy(&v));
    let force_remote = get("RCH_FORCE_REMOTE").is_some_and(|v| env_truthy(&v));
    let strict_remote_policy = if require_remote {
        if force_remote {
            diagnostics.push(ControlDiagnostic::info(
                "RCH_REQUIRE_REMOTE",
                "RCH_REQUIRE_REMOTE (fail-closed) supersedes RCH_FORCE_REMOTE (fail-open)",
            ));
        }
        StrictRemotePolicy::RequireRemote
    } else if force_remote {
        StrictRemotePolicy::ForceRemote
    } else {
        StrictRemotePolicy::Off
    };

    // --- queue-when-busy: default enabled ---
    let queue_policy = match get("RCH_QUEUE_WHEN_BUSY") {
        None => QueuePolicy::QueueWhenBusy,
        Some(v) if env_falsy(&v) => QueuePolicy::NoQueue,
        Some(v) if env_truthy(&v) || v.trim().is_empty() => QueuePolicy::QueueWhenBusy,
        Some(v) => {
            diagnostics.push(ControlDiagnostic::warning(
                "RCH_QUEUE_WHEN_BUSY",
                format!("unrecognized value {v:?}; interpreted as enabled (queue_when_busy)"),
            ));
            QueuePolicy::QueueWhenBusy
        }
    };

    // --- wait timeout: RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS (alias _RESPONSE_) ---
    let (wait_timeout_ms, wait_diag) = resolve_wait_timeout(&get);
    diagnostics.extend(wait_diag);

    // --- visibility: RCH_VISIBILITY (canonical), RCH_QUIET / RCH_VERBOSE aliases ---
    let (visibility_mode, vis_diag) = resolve_visibility(&get);
    diagnostics.extend(vis_diag);

    // --- target dir policy ---
    let target_dir_policy = if get("RCH_DISABLE_TARGET_REUSE").is_some_and(|v| env_truthy(&v)) {
        TargetDirPolicy::PerJob
    } else if get("CARGO_TARGET_DIR")
        .map(|v| v.contains(".rch-target") || v.contains("rch-worker"))
        .unwrap_or(false)
    {
        TargetDirPolicy::WorkerScoped
    } else {
        TargetDirPolicy::Pooled
    };

    let requested_worker_outcome = if requested_worker.is_some() {
        RequestedWorkerOutcome::requested()
    } else {
        RequestedWorkerOutcome::not_requested()
    };

    PlacementPlan {
        schema_version: PlacementPlan::schema_version().to_string(),
        requested_worker,
        requested_profile: requested_profile.map(|v| v.trim().to_string()),
        effective_worker: None,
        strict_remote_policy,
        queue_policy,
        visibility_mode,
        wait_timeout_ms,
        target_dir_policy,
        requested_worker_outcome,
        diagnostics,
    }
}

/// Merge two comma-separated worker lists, trimming and de-duplicating while
/// preserving first-seen order.
fn merge_worker_lists(primary: &str, alias: &str) -> String {
    let mut seen = Vec::new();
    for part in primary
        .split(',')
        .chain(alias.split(','))
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        if !seen.contains(&part) {
            seen.push(part);
        }
    }
    seen.join(",")
}

/// Resolve the wait timeout from the canonical var or its alias.
fn resolve_wait_timeout<F>(get: &F) -> (Option<u64>, Vec<ControlDiagnostic>)
where
    F: Fn(&str) -> Option<String>,
{
    const CANONICAL: &str = "RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS";
    const ALIAS: &str = "RCH_DAEMON_RESPONSE_TIMEOUT_SECS";
    let mut diags = Vec::new();

    let (name, raw) = match (get(CANONICAL), get(ALIAS)) {
        (Some(v), _) => (CANONICAL, Some(v)),
        (None, Some(v)) => {
            diags.push(ControlDiagnostic::info(
                ALIAS,
                "RCH_DAEMON_RESPONSE_TIMEOUT_SECS also applies to non-wait queries; \
                 prefer RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS for the queue wait timeout",
            ));
            (ALIAS, Some(v))
        }
        (None, None) => (CANONICAL, None),
    };

    let Some(raw) = raw else {
        return (None, diags);
    };
    match raw.trim().parse::<u64>() {
        Ok(secs) if secs > 0 => (Some(secs.saturating_mul(1000)), diags),
        _ => {
            diags.push(ControlDiagnostic::warning(
                name,
                format!("invalid timeout {raw:?}; expected a positive integer in seconds; using the default"),
            ));
            (None, diags)
        }
    }
}

/// Resolve the visibility mode from the canonical var or its quiet/verbose
/// aliases.
fn resolve_visibility<F>(get: &F) -> (VisibilityMode, Vec<ControlDiagnostic>)
where
    F: Fn(&str) -> Option<String>,
{
    let mut diags = Vec::new();

    if let Some(raw) = get("RCH_VISIBILITY") {
        match VisibilityMode::parse(&raw) {
            Some(mode) => return (mode, diags),
            None => {
                diags.push(ControlDiagnostic::warning(
                    "RCH_VISIBILITY",
                    format!("unrecognized value {raw:?}; expected none|summary|verbose; deferring to config"),
                ));
                // Fall through to the alias checks rather than silently ignoring.
            }
        }
    }
    if get("RCH_QUIET").is_some_and(|v| env_truthy(&v)) {
        return (VisibilityMode::None, diags);
    }
    if get("RCH_VERBOSE").is_some_and(|v| env_truthy(&v)) {
        return (VisibilityMode::Verbose, diags);
    }
    (VisibilityMode::Default, diags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Build an env getter over a fixed map (no process-env mutation, so tests
    /// stay deterministic and race-free).
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    // --- strict-remote precedence -----------------------------------------

    #[test]
    fn strict_remote_off_by_default() {
        let plan = resolve_placement(env(&[]));
        assert_eq!(plan.strict_remote_policy, StrictRemotePolicy::Off);
        assert!(!plan.strict_remote_policy.fail_closed());
        assert!(!plan.strict_remote_policy.forces_offload());
    }

    #[test]
    fn force_remote_is_fail_open() {
        let plan = resolve_placement(env(&[("RCH_FORCE_REMOTE", "1")]));
        assert_eq!(plan.strict_remote_policy, StrictRemotePolicy::ForceRemote);
        assert!(plan.strict_remote_policy.forces_offload());
        assert!(!plan.strict_remote_policy.fail_closed());
    }

    #[test]
    fn require_remote_is_fail_closed() {
        let plan = resolve_placement(env(&[("RCH_REQUIRE_REMOTE", "true")]));
        assert_eq!(plan.strict_remote_policy, StrictRemotePolicy::RequireRemote);
        assert!(plan.strict_remote_policy.fail_closed());
        assert!(plan.strict_remote_policy.forces_offload());
    }

    #[test]
    fn require_remote_supersedes_force_remote_with_diagnostic() {
        let plan = resolve_placement(env(&[
            ("RCH_REQUIRE_REMOTE", "1"),
            ("RCH_FORCE_REMOTE", "1"),
        ]));
        assert_eq!(plan.strict_remote_policy, StrictRemotePolicy::RequireRemote);
        assert!(
            plan.diagnostics
                .iter()
                .any(|d| d.control == "RCH_REQUIRE_REMOTE"
                    && d.level == ControlDiagnosticLevel::Info),
            "expected a precedence diagnostic, got {:?}",
            plan.diagnostics
        );
    }

    // --- queue-when-busy ---------------------------------------------------

    #[test]
    fn queue_defaults_enabled() {
        let plan = resolve_placement(env(&[]));
        assert_eq!(plan.queue_policy, QueuePolicy::QueueWhenBusy);
        assert!(plan.queue_policy.waits());
    }

    #[test]
    fn queue_disabled_by_zero() {
        let plan = resolve_placement(env(&[("RCH_QUEUE_WHEN_BUSY", "0")]));
        assert_eq!(plan.queue_policy, QueuePolicy::NoQueue);
        assert!(!plan.queue_policy.waits());
    }

    #[test]
    fn queue_unrecognized_value_warns_not_silently_ignored() {
        let plan = resolve_placement(env(&[("RCH_QUEUE_WHEN_BUSY", "maybe")]));
        assert_eq!(plan.queue_policy, QueuePolicy::QueueWhenBusy);
        assert!(
            plan.diagnostics
                .iter()
                .any(|d| d.control == "RCH_QUEUE_WHEN_BUSY"
                    && d.level == ControlDiagnosticLevel::Warning)
        );
    }

    // --- wait timeout ------------------------------------------------------

    #[test]
    fn wait_timeout_seconds_to_ms() {
        let plan = resolve_placement(env(&[("RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS", "120")]));
        assert_eq!(plan.wait_timeout_ms, Some(120_000));
    }

    #[test]
    fn wait_timeout_alias_emits_info() {
        let plan = resolve_placement(env(&[("RCH_DAEMON_RESPONSE_TIMEOUT_SECS", "45")]));
        assert_eq!(plan.wait_timeout_ms, Some(45_000));
        assert!(
            plan.diagnostics
                .iter()
                .any(|d| d.control == "RCH_DAEMON_RESPONSE_TIMEOUT_SECS"
                    && d.level == ControlDiagnosticLevel::Info)
        );
    }

    #[test]
    fn wait_timeout_invalid_warns_and_falls_back() {
        let plan = resolve_placement(env(&[("RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS", "soon")]));
        assert_eq!(plan.wait_timeout_ms, None);
        assert!(
            plan.diagnostics
                .iter()
                .any(|d| d.level == ControlDiagnosticLevel::Warning)
        );
    }

    // --- visibility --------------------------------------------------------

    #[test]
    fn visibility_canonical_values() {
        for (raw, expected) in [
            ("none", VisibilityMode::None),
            ("summary", VisibilityMode::Summary),
            ("verbose", VisibilityMode::Verbose),
        ] {
            let plan = resolve_placement(env(&[("RCH_VISIBILITY", raw)]));
            assert_eq!(plan.visibility_mode, expected);
        }
    }

    #[test]
    fn visibility_quiet_and_verbose_aliases() {
        let quiet = resolve_placement(env(&[("RCH_QUIET", "1")]));
        assert_eq!(quiet.visibility_mode, VisibilityMode::None);
        let verbose = resolve_placement(env(&[("RCH_VERBOSE", "1")]));
        assert_eq!(verbose.visibility_mode, VisibilityMode::Verbose);
    }

    #[test]
    fn visibility_invalid_warns_then_falls_back_to_alias() {
        let plan = resolve_placement(env(&[("RCH_VISIBILITY", "ultra"), ("RCH_QUIET", "1")]));
        // Invalid canonical value is reported, and the alias still applies.
        assert_eq!(plan.visibility_mode, VisibilityMode::None);
        assert!(
            plan.diagnostics.iter().any(
                |d| d.control == "RCH_VISIBILITY" && d.level == ControlDiagnosticLevel::Warning
            )
        );
    }

    // --- requested worker / profile / target dir ---------------------------

    #[test]
    fn requested_worker_and_profile_captured() {
        let plan = resolve_placement(env(&[("RCH_WORKER", "css"), ("RCH_PRESET", "fast")]));
        assert_eq!(plan.requested_worker.as_deref(), Some("css"));
        assert_eq!(plan.requested_profile.as_deref(), Some("fast"));
        assert_eq!(
            plan.requested_worker_outcome.status,
            RequestedWorkerStatus::Requested
        );
    }

    #[test]
    fn worker_alias_merges_and_dedupes() {
        let plan = resolve_placement(env(&[
            ("RCH_WORKER", "css, ovh-a"),
            ("RCH_WORKERS", "ovh-a,ovh-b"),
        ]));
        assert_eq!(plan.requested_worker.as_deref(), Some("css,ovh-a,ovh-b"));
        assert!(plan.diagnostics.iter().any(|d| d.control == "RCH_WORKER"));
    }

    #[test]
    fn target_dir_policy_variants() {
        let pooled = resolve_placement(env(&[]));
        assert_eq!(pooled.target_dir_policy, TargetDirPolicy::Pooled);
        let per_job = resolve_placement(env(&[("RCH_DISABLE_TARGET_REUSE", "1")]));
        assert_eq!(per_job.target_dir_policy, TargetDirPolicy::PerJob);
        let scoped = resolve_placement(env(&[("CARGO_TARGET_DIR", "/tmp/.rch-target/css")]));
        assert_eq!(scoped.target_dir_policy, TargetDirPolicy::WorkerScoped);
    }

    // --- requested-worker admissibility ------------------------------------

    #[test]
    fn evaluate_not_requested() {
        let out = evaluate_requested_worker(&RequestedWorkerFacts::none());
        assert_eq!(out.status, RequestedWorkerStatus::NotRequested);
        assert!(out.reason_code.is_none());
    }

    #[test]
    fn evaluate_honored() {
        let out = evaluate_requested_worker(&RequestedWorkerFacts::admissible("css"));
        assert_eq!(out.status, RequestedWorkerStatus::Honored);
        assert!(out.reason_code.is_none());
        assert!(!out.status.is_refusal());
    }

    #[test]
    fn evaluate_unknown_worker_refused() {
        let facts = RequestedWorkerFacts {
            requested: Some("ghost".into()),
            exists: false,
            ..RequestedWorkerFacts::none()
        };
        let out = evaluate_requested_worker(&facts);
        assert_eq!(out.status, RequestedWorkerStatus::Unavailable);
        assert_eq!(out.reason_code.as_deref(), Some("RCH-I001"));
        assert!(
            out.next_action
                .as_deref()
                .unwrap()
                .contains("rch workers list")
        );
        assert!(out.status.is_refusal());
    }

    #[test]
    fn evaluate_admin_disabled_refused() {
        let facts = RequestedWorkerFacts {
            admin_disabled: true,
            ..RequestedWorkerFacts::admissible("css")
        };
        let out = evaluate_requested_worker(&facts);
        assert_eq!(out.status, RequestedWorkerStatus::AdminDisabled);
        assert_eq!(out.reason_code.as_deref(), Some("RCH-I001"));
        assert!(
            out.next_action
                .as_deref()
                .unwrap()
                .contains("rch workers enable")
        );
    }

    #[test]
    fn evaluate_wrong_platform_refused() {
        let facts = RequestedWorkerFacts {
            platform_matches: false,
            ..RequestedWorkerFacts::admissible("css")
        };
        let out = evaluate_requested_worker(&facts);
        assert_eq!(out.status, RequestedWorkerStatus::WrongPlatform);
        assert_eq!(
            out.reason_code.as_deref(),
            Some(IncidentReasonCode::OsArchMismatch.code())
        );
    }

    #[test]
    fn evaluate_missing_runtime_refused() {
        let facts = RequestedWorkerFacts {
            has_required_runtime: false,
            ..RequestedWorkerFacts::admissible("css")
        };
        let out = evaluate_requested_worker(&facts);
        assert_eq!(out.status, RequestedWorkerStatus::MissingRuntime);
        assert_eq!(
            out.reason_code.as_deref(),
            Some(IncidentReasonCode::MissingRuntimeToolchainTarget.code())
        );
    }

    #[test]
    fn evaluate_project_excluded_refused() {
        let facts = RequestedWorkerFacts {
            project_excluded: true,
            ..RequestedWorkerFacts::admissible("css")
        };
        let out = evaluate_requested_worker(&facts);
        assert_eq!(out.status, RequestedWorkerStatus::ProjectExcluded);
        assert_eq!(
            out.reason_code.as_deref(),
            Some(IncidentReasonCode::ActiveProjectExclusion.code())
        );
    }

    #[test]
    fn evaluate_no_slots_refused() {
        let facts = RequestedWorkerFacts {
            has_free_slots: false,
            ..RequestedWorkerFacts::admissible("css")
        };
        let out = evaluate_requested_worker(&facts);
        assert_eq!(out.status, RequestedWorkerStatus::NoFreeSlots);
        assert_eq!(
            out.reason_code.as_deref(),
            Some(IncidentReasonCode::InsufficientSlots.code())
        );
    }

    #[test]
    fn evaluate_temporary_bypass_refused() {
        let facts = RequestedWorkerFacts {
            temporarily_bypassed: true,
            ..RequestedWorkerFacts::admissible("css")
        };
        let out = evaluate_requested_worker(&facts);
        assert_eq!(out.status, RequestedWorkerStatus::TemporarilyBypassed);
        assert_eq!(
            out.reason_code.as_deref(),
            Some(IncidentReasonCode::CircuitOpen.code())
        );
    }

    #[test]
    fn refusal_priority_is_most_specific_first() {
        // An unknown worker that is also missing a runtime reports "unavailable"
        // (existence is the primary blocker), not "missing_runtime".
        let facts = RequestedWorkerFacts {
            requested: Some("ghost".into()),
            exists: false,
            has_required_runtime: false,
            ..RequestedWorkerFacts::none()
        };
        assert_eq!(
            evaluate_requested_worker(&facts).status,
            RequestedWorkerStatus::Unavailable
        );
    }

    // --- plan -> control-state bridge & serialization ----------------------

    #[test]
    fn control_state_bridge_is_sparse() {
        // Default plan -> empty control state (nothing explicitly set).
        let plan = resolve_placement(env(&[]));
        assert!(plan.control_state().is_empty());
    }

    #[test]
    fn control_state_bridge_carries_set_fields() {
        let plan = resolve_placement(env(&[
            ("RCH_WORKER", "css"),
            ("RCH_REQUIRE_REMOTE", "1"),
            ("RCH_QUEUE_WHEN_BUSY", "0"),
        ]));
        let cs = plan.control_state();
        assert_eq!(cs.requested_worker.as_deref(), Some("css"));
        assert!(cs.strict_remote_policy);
        assert_eq!(cs.queue_policy.as_deref(), Some("no_queue"));
        assert!(!cs.is_empty());
    }

    #[test]
    fn plan_round_trips_through_json() {
        let plan = resolve_placement(env(&[("RCH_WORKER", "css"), ("RCH_FORCE_REMOTE", "1")]))
            .with_effective_worker(Some("ovh-a".to_string()))
            .with_requested_worker_outcome(evaluate_requested_worker(
                &RequestedWorkerFacts::admissible("css"),
            ));
        let v = serde_json::to_value(&plan).unwrap();
        assert_eq!(v["strict_remote_policy"], "force_remote");
        assert_eq!(v["queue_policy"], "queue_when_busy");
        assert_eq!(v["requested_worker"], "css");
        assert_eq!(v["effective_worker"], "ovh-a");
        assert_eq!(v["requested_worker_outcome"]["status"], "honored");
        let back: PlacementPlan = serde_json::from_value(v).unwrap();
        assert_eq!(back, plan);
    }

    #[test]
    fn schema_version_is_pinned() {
        let plan = resolve_placement(env(&[]));
        assert_eq!(plan.schema_version, PlacementPlan::schema_version());
    }

    // --- registry invariants ----------------------------------------------

    #[test]
    fn registry_canonical_names_unique_and_distinct_from_aliases() {
        let controls = placement_controls();
        let mut names = std::collections::HashSet::new();
        for c in controls {
            assert!(
                names.insert(c.canonical_env),
                "duplicate canonical env {}",
                c.canonical_env
            );
        }
        // No alias collides with a canonical name.
        for c in controls {
            for alias in c.aliases {
                assert!(
                    !names.contains(alias),
                    "alias {alias} collides with a canonical name"
                );
            }
        }
    }

    #[test]
    fn registry_covers_the_audited_controls() {
        let controls = placement_controls();
        let has = |n: &str| controls.iter().any(|c| c.canonical_env == n);
        for required in [
            "RCH_WORKER",
            "RCH_REQUIRE_REMOTE",
            "RCH_FORCE_REMOTE",
            "RCH_QUEUE_WHEN_BUSY",
            "RCH_VISIBILITY",
            "RCH_NO_SELF_HEALING",
        ] {
            assert!(has(required), "registry missing audited control {required}");
        }
    }
}
