//! Shared incident event schema and stable reason-code registry.
//!
//! Every RCH subsystem that can steer, reject, defer, or fall back a build —
//! selection, admission, fallback, proof, doctor, telemetry, artifact
//! retrieval, and worker lifecycle — emits a uniform [`IncidentEvent`] keyed by
//! a stable [`IncidentReasonCode`]. A single registry prevents free-form reason
//! drift across components and gives postmortems one vocabulary.
//!
//! The reason-code registry is intentionally 1:1 with the operator-facing
//! failure classes recorded in the session-history report (e.g. "no admissible
//! workers", "critical pressure", "disk full"). Each variant exposes:
//! - a stable `RCH-Innn` [`code`](IncidentReasonCode::code) (the serialized form),
//! - the exact operator-facing [`failure_class`](IncidentReasonCode::failure_class)
//!   string, and
//! - an optional mapped AGENTS-style [`ErrorCode`](IncidentReasonCode::error_code)
//!   for components that already speak the catalog.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::errors::ErrorCode;
use crate::schema_versions::{SchemaComponent, current_version};

/// Stable reason-code registry. One variant per session-history failure class.
///
/// Serializes to its canonical `RCH-Innn` string and deserializes the same way,
/// so the wire form is decoupled from the Rust variant name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IncidentReasonCode {
    /// No worker passed admission (all candidates rejected).
    NoAdmissibleWorkers,
    /// A worker (or the pool) was under critical resource pressure.
    CriticalPressure,
    /// Not enough free build slots to admit the request.
    InsufficientSlots,
    /// A hard preflight check rejected the candidate.
    HardPreflight,
    /// The active project root was excluded from offload.
    ActiveProjectExclusion,
    /// A required runtime, toolchain, or Rust target was missing.
    MissingRuntimeToolchainTarget,
    /// The worker's OS/arch did not match the artifact/target triple.
    OsArchMismatch,
    /// Telemetry was stale or its age could not be determined.
    TelemetryStale,
    /// The worker's circuit breaker was open.
    CircuitOpen,
    /// The daemon Unix socket refused the connection.
    DaemonSocketRefused,
    /// The build fell back to local execution.
    LocalFallback,
    /// Proof-mode fail-closed policy refused to proceed.
    ProofRefusal,
    /// rsync reported a source file that vanished during transfer.
    RsyncVanishedFile,
    /// An expected build artifact was missing on retrieval.
    ArtifactMiss,
    /// Ambiguous queue/job identity prevented a clean correlation.
    QueueAmbiguity,
    /// The target disk was full.
    DiskFull,
    /// A wrong-user or wrong-path/arch `rch-wkr` binary was detected.
    WrongUserPathWorkerBinary,
}

impl IncidentReasonCode {
    /// Every reason code, in stable declaration order. Used for registry
    /// coverage/uniqueness tests and reason enumeration.
    pub const ALL: &'static [IncidentReasonCode] = &[
        Self::NoAdmissibleWorkers,
        Self::CriticalPressure,
        Self::InsufficientSlots,
        Self::HardPreflight,
        Self::ActiveProjectExclusion,
        Self::MissingRuntimeToolchainTarget,
        Self::OsArchMismatch,
        Self::TelemetryStale,
        Self::CircuitOpen,
        Self::DaemonSocketRefused,
        Self::LocalFallback,
        Self::ProofRefusal,
        Self::RsyncVanishedFile,
        Self::ArtifactMiss,
        Self::QueueAmbiguity,
        Self::DiskFull,
        Self::WrongUserPathWorkerBinary,
    ];

    /// Canonical `RCH-Innn` code string. Stable across releases — never
    /// renumber an existing variant; only append.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoAdmissibleWorkers => "RCH-I001",
            Self::CriticalPressure => "RCH-I002",
            Self::InsufficientSlots => "RCH-I003",
            Self::HardPreflight => "RCH-I004",
            Self::ActiveProjectExclusion => "RCH-I005",
            Self::MissingRuntimeToolchainTarget => "RCH-I006",
            Self::OsArchMismatch => "RCH-I007",
            Self::TelemetryStale => "RCH-I008",
            Self::CircuitOpen => "RCH-I009",
            Self::DaemonSocketRefused => "RCH-I010",
            Self::LocalFallback => "RCH-I011",
            Self::ProofRefusal => "RCH-I012",
            Self::RsyncVanishedFile => "RCH-I013",
            Self::ArtifactMiss => "RCH-I014",
            Self::QueueAmbiguity => "RCH-I015",
            Self::DiskFull => "RCH-I016",
            Self::WrongUserPathWorkerBinary => "RCH-I017",
        }
    }

    /// Exact operator-facing failure-class string from the session-history
    /// report. These strings are part of the contract — dashboards and the
    /// validation matrix key off them.
    #[must_use]
    pub const fn failure_class(self) -> &'static str {
        match self {
            Self::NoAdmissibleWorkers => "no admissible workers",
            Self::CriticalPressure => "critical pressure",
            Self::InsufficientSlots => "insufficient slots",
            Self::HardPreflight => "hard preflight",
            Self::ActiveProjectExclusion => "active project exclusion",
            Self::MissingRuntimeToolchainTarget => "missing runtime/toolchain/Rust target",
            Self::OsArchMismatch => "OS/arch mismatch",
            Self::TelemetryStale => "telemetry stale/age unknown",
            Self::CircuitOpen => "circuit open",
            Self::DaemonSocketRefused => "daemon socket refused",
            Self::LocalFallback => "local fallback",
            Self::ProofRefusal => "proof refusal",
            Self::RsyncVanishedFile => "rsync vanished file",
            Self::ArtifactMiss => "artifact miss",
            Self::QueueAmbiguity => "queue ambiguity",
            Self::DiskFull => "disk full",
            Self::WrongUserPathWorkerBinary => "wrong user/path worker binary",
        }
    }

    /// Mapped AGENTS-style [`ErrorCode`] where the catalog already has a
    /// matching concept. `None` for policy/operational reasons (e.g. local
    /// fallback, proof refusal) that are incident-only by design.
    #[must_use]
    pub fn error_code(self) -> Option<ErrorCode> {
        Some(match self {
            Self::NoAdmissibleWorkers => ErrorCode::WorkerNoneAvailable,
            Self::CriticalPressure => ErrorCode::WorkerDiskPressureCritical,
            Self::InsufficientSlots => ErrorCode::WorkerAtCapacity,
            Self::MissingRuntimeToolchainTarget => ErrorCode::WorkerMissingToolchain,
            Self::TelemetryStale => ErrorCode::WorkerTelemetryGap,
            Self::CircuitOpen => ErrorCode::WorkerCircuitOpen,
            Self::DaemonSocketRefused => ErrorCode::InternalDaemonSocket,
            Self::RsyncVanishedFile => ErrorCode::TransferSourceMissing,
            Self::ArtifactMiss => ErrorCode::BuildArtifactMissing,
            Self::DiskFull => ErrorCode::TransferDiskFull,
            // Incident-only reasons with no single catalog analogue.
            Self::HardPreflight
            | Self::ActiveProjectExclusion
            | Self::OsArchMismatch
            | Self::LocalFallback
            | Self::ProofRefusal
            | Self::QueueAmbiguity
            | Self::WrongUserPathWorkerBinary => return None,
        })
    }

    /// Parse a canonical `RCH-Innn` code string back to a reason code.
    #[must_use]
    pub fn from_code_str(code: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|r| r.code() == code)
    }
}

impl fmt::Display for IncidentReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl Serialize for IncidentReasonCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.code())
    }
}

impl<'de> Deserialize<'de> for IncidentReasonCode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::from_code_str(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown incident reason code: {raw}")))
    }
}

/// The subsystem that produced an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentEventType {
    Selection,
    Admission,
    Fallback,
    Proof,
    Doctor,
    Telemetry,
    ArtifactRetrieval,
    WorkerLifecycle,
}

/// The process/component that emitted the event (for provenance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSource {
    Hook,
    Daemon,
    Worker,
    Doctor,
    Cli,
}

/// Where the build ultimately ran (or was steered).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedMode {
    Local,
    Remote,
    Deferred,
}

/// Canonical control-state snapshot (env/flag-derived) so postmortems never
/// lose *why* a build was steered, queued, or made fail-closed. Mirrors the
/// explicit-control surface: `requested_worker`, `requested_profile`,
/// `strict_remote_policy`, `queue_policy`, `visibility_mode`, `wait_timeout_ms`,
/// `target_dir_policy`. All fields optional and omitted from the wire form when
/// unset, keeping the event compact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlState {
    /// `RCH_WORKER` / `--worker` explicit worker request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_worker: Option<String>,
    /// `RCH_PRESET` / requested profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_profile: Option<String>,
    /// `RCH_REQUIRE_REMOTE` / `RCH_FORCE_REMOTE` fail-closed remote policy.
    #[serde(default, skip_serializing_if = "is_false")]
    pub strict_remote_policy: bool,
    /// `RCH_QUEUE_WHEN_BUSY` queue policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_policy: Option<String>,
    /// `RCH_VISIBILITY` visibility mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility_mode: Option<String>,
    /// Queue wait timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_timeout_ms: Option<u64>,
    /// Worker-scoped target-dir policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_dir_policy: Option<String>,
}

impl ControlState {
    /// True when no control field is set (used to omit the section entirely).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == ControlState::default()
    }
}

/// serde `skip_serializing_if` helper for `bool` fields that default to false.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

/// A single incident event. The uniform record every remediation-relevant
/// subsystem emits, keyed by a stable [`IncidentReasonCode`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentEvent {
    /// Schema version (`SchemaComponent::IncidentLedger`).
    pub schema_version: String,
    /// Emitting subsystem.
    pub event_type: IncidentEventType,
    /// Stable reason (serialized as `RCH-Innn`).
    pub reason_code: IncidentReasonCode,
    /// Project key (e.g. blake3 of the canonical project root).
    pub project_id: String,
    /// Classified command fingerprint.
    pub command_fingerprint: String,
    /// Worker id where applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Where the build ran / was steered.
    pub selected_mode: SelectedMode,
    /// Whether local fallback was permitted for this request.
    pub local_fallback_allowed: bool,
    /// Emitting process/component.
    pub source: IncidentSource,
    /// Event time as Unix epoch milliseconds. Caller-supplied so the schema is
    /// deterministic in tests and golden artifacts.
    pub occurred_at_unix_ms: u64,
    /// Canonical control-state snapshot (omitted from the wire form when empty).
    #[serde(default, skip_serializing_if = "ControlState::is_empty")]
    pub control: ControlState,
    /// Compact, ordered free-form details (small, bounded; not for secrets).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

impl IncidentEvent {
    /// Construct an event with the required core fields; optional fields
    /// (`worker_id`, `control`, `details`) default to empty and can be set
    /// afterward.
    ///
    /// These are the genuinely-required record fields — every one is a
    /// distinct, non-defaultable dimension of an incident — so a flat
    /// constructor is clearer here than a params struct.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        event_type: IncidentEventType,
        reason_code: IncidentReasonCode,
        source: IncidentSource,
        project_id: impl Into<String>,
        command_fingerprint: impl Into<String>,
        selected_mode: SelectedMode,
        local_fallback_allowed: bool,
        occurred_at_unix_ms: u64,
    ) -> Self {
        Self {
            schema_version: incident_schema_version().to_string(),
            event_type,
            reason_code,
            project_id: project_id.into(),
            command_fingerprint: command_fingerprint.into(),
            worker_id: None,
            selected_mode,
            local_fallback_allowed,
            source,
            occurred_at_unix_ms,
            control: ControlState::default(),
            details: BTreeMap::new(),
        }
    }

    /// Set the worker id (builder style).
    #[must_use]
    pub fn with_worker_id(mut self, worker_id: impl Into<String>) -> Self {
        self.worker_id = Some(worker_id.into());
        self
    }

    /// Set the control-state snapshot (builder style).
    #[must_use]
    pub fn with_control(mut self, control: ControlState) -> Self {
        self.control = control;
        self
    }

    /// Insert a compact detail key/value (builder style).
    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

/// The current incident-schema version string.
#[must_use]
pub fn incident_schema_version() -> &'static str {
    current_version(SchemaComponent::IncidentLedger)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_covers_seventeen_session_history_failure_classes() {
        // The session-history report enumerates exactly these classes; the
        // registry must stay 1:1 so the validation matrix can map each one.
        assert_eq!(IncidentReasonCode::ALL.len(), 17);
    }

    #[test]
    fn reason_codes_are_unique() {
        let mut codes: Vec<&str> = IncidentReasonCode::ALL.iter().map(|r| r.code()).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(before, codes.len(), "duplicate RCH-I codes in registry");
    }

    #[test]
    fn failure_class_strings_are_unique() {
        let mut classes: Vec<&str> = IncidentReasonCode::ALL
            .iter()
            .map(|r| r.failure_class())
            .collect();
        classes.sort_unstable();
        let before = classes.len();
        classes.dedup();
        assert_eq!(before, classes.len(), "duplicate failure-class strings");
    }

    #[test]
    fn codes_follow_rch_i_format_and_sequence() {
        for (i, reason) in IncidentReasonCode::ALL.iter().enumerate() {
            let expected = format!("RCH-I{:03}", i + 1);
            assert_eq!(reason.code(), expected, "code out of sequence at {i}");
        }
    }

    #[test]
    fn reason_code_roundtrips_through_code_str() {
        for reason in IncidentReasonCode::ALL {
            assert_eq!(
                IncidentReasonCode::from_code_str(reason.code()),
                Some(*reason)
            );
        }
        assert_eq!(IncidentReasonCode::from_code_str("RCH-I999"), None);
        assert_eq!(IncidentReasonCode::from_code_str("nonsense"), None);
    }

    #[test]
    fn reason_code_serializes_as_stable_string() {
        let json = serde_json::to_string(&IncidentReasonCode::DiskFull).unwrap();
        assert_eq!(json, "\"RCH-I016\"");
        let back: IncidentReasonCode = serde_json::from_str("\"RCH-I016\"").unwrap();
        assert_eq!(back, IncidentReasonCode::DiskFull);
    }

    #[test]
    fn unknown_reason_code_deserialization_errors() {
        let res: Result<IncidentReasonCode, _> = serde_json::from_str("\"RCH-I404\"");
        assert!(res.is_err());
    }

    #[test]
    fn error_code_mapping_is_present_where_expected() {
        // A representative sample of the catalog-mapped reasons.
        assert_eq!(
            IncidentReasonCode::CircuitOpen.error_code(),
            Some(ErrorCode::WorkerCircuitOpen)
        );
        assert_eq!(
            IncidentReasonCode::DiskFull.error_code(),
            Some(ErrorCode::TransferDiskFull)
        );
        assert_eq!(
            IncidentReasonCode::ArtifactMiss.error_code(),
            Some(ErrorCode::BuildArtifactMissing)
        );
        // Incident-only reasons have no catalog code.
        assert_eq!(IncidentReasonCode::LocalFallback.error_code(), None);
        assert_eq!(IncidentReasonCode::ProofRefusal.error_code(), None);
    }

    fn sample_event() -> IncidentEvent {
        IncidentEvent::new(
            IncidentEventType::Admission,
            IncidentReasonCode::NoAdmissibleWorkers,
            IncidentSource::Daemon,
            "proj-abc",
            "cargo build --release",
            SelectedMode::Local,
            true,
            1_700_000_000_000,
        )
    }

    #[test]
    fn incident_event_roundtrips() {
        let event = sample_event()
            .with_worker_id("css")
            .with_detail("candidates", "3")
            .with_control(ControlState {
                strict_remote_policy: true,
                requested_worker: Some("bil".to_string()),
                wait_timeout_ms: Some(5000),
                ..ControlState::default()
            });
        let json = serde_json::to_string(&event).unwrap();
        let back: IncidentEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn incident_event_serialization_is_stable_golden() {
        let event = sample_event();
        let value = serde_json::to_value(&event).unwrap();
        // Required core fields present with expected values.
        assert_eq!(value["schema_version"], "1.0.0");
        assert_eq!(value["event_type"], "admission");
        assert_eq!(value["reason_code"], "RCH-I001");
        assert_eq!(value["project_id"], "proj-abc");
        assert_eq!(value["command_fingerprint"], "cargo build --release");
        assert_eq!(value["selected_mode"], "local");
        assert_eq!(value["local_fallback_allowed"], true);
        assert_eq!(value["source"], "daemon");
        assert_eq!(value["occurred_at_unix_ms"], 1_700_000_000_000u64);
        // Empty optional sections are omitted from the wire form.
        assert!(value.get("worker_id").is_none());
        assert!(value.get("control").is_none());
        assert!(value.get("details").is_none());
    }

    #[test]
    fn control_state_fields_round_trip_and_omit_when_empty() {
        // Every canonical control field from the FIFTH AUDIT NOTE.
        let control = ControlState {
            requested_worker: Some("css".to_string()),
            requested_profile: Some("fast".to_string()),
            strict_remote_policy: true,
            queue_policy: Some("queue_when_busy".to_string()),
            visibility_mode: Some("visible".to_string()),
            wait_timeout_ms: Some(10_000),
            target_dir_policy: Some("pooled".to_string()),
        };
        assert!(!control.is_empty());
        let value = serde_json::to_value(&control).unwrap();
        for key in [
            "requested_worker",
            "requested_profile",
            "strict_remote_policy",
            "queue_policy",
            "visibility_mode",
            "wait_timeout_ms",
            "target_dir_policy",
        ] {
            assert!(value.get(key).is_some(), "missing control field {key}");
        }
        // Default control omits everything.
        assert!(ControlState::default().is_empty());
        let empty = serde_json::to_value(ControlState::default()).unwrap();
        assert_eq!(empty.as_object().unwrap().len(), 0);
    }

    #[test]
    fn incident_event_carries_current_schema_version() {
        assert_eq!(incident_schema_version(), "1.0.0");
        assert_eq!(sample_event().schema_version, incident_schema_version());
    }
}
