//! Durable local/remote job identity and lifecycle correlation
//! (bd-session-history-remediation-ocv9i.10.1).
//!
//! Session history showed agents unable to tell whether a `cargo` command they
//! launched was queued, running, already finished, abandoned, or had failed
//! before the daemon ever admitted it — because there was no stable identity
//! tying the local `rch exec` wrapper to the daemon's remote build.
//!
//! This module introduces that identity:
//! - a [`LocalWrapperId`] minted by `rch exec` the instant a command is
//!   intercepted, *before* any daemon contact, so it exists even when
//!   admission fails;
//! - the daemon's existing remote build id (`u64`), recorded once admitted;
//! - [`JobIdentity`] pairing the two;
//! - [`JobLifecycleState`] (the five operator-facing states) plus a pure
//!   [`derive_job_lifecycle_state`] correlation over observable [`JobSignals`],
//!   and [`JobRecord`] for `rch jobs --json`.
//!
//! The correlation is a pure function so the state machine is unit-tested
//! without a live daemon. Wiring the wrapper id through `rch exec`, queue
//! admission, heartbeat, and the `rch jobs` command are follow-on integration
//! beads (10.2 / 10.3); this bead establishes the shared identity contract both
//! the client and daemon correlate against.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Locally-generated wrapper id, minted by `rch exec` before any daemon
/// contact. Stable for the whole life of the command.
pub type LocalWrapperId = String;

/// Remote build id assigned by the daemon on queue admission. Mirrors the
/// existing `build_id: u64` used across the status/history surfaces.
pub type RemoteBuildId = u64;

/// Prefix of every local wrapper id, so logs and cleanup can recognise them.
pub const LOCAL_WRAPPER_ID_PREFIX: &str = "rchw-";

/// Mint a fresh, unique local wrapper id.
#[must_use]
pub fn new_local_wrapper_id() -> LocalWrapperId {
    format!("{LOCAL_WRAPPER_ID_PREFIX}{}", Uuid::new_v4())
}

/// The two-part identity of a job: the always-present local wrapper id and the
/// remote build id once admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobIdentity {
    /// Local wrapper id, always present.
    pub local_wrapper_id: LocalWrapperId,
    /// Remote build id, present iff the daemon admitted the command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_build_id: Option<RemoteBuildId>,
}

impl JobIdentity {
    /// A brand-new identity for a command just intercepted by `rch exec`
    /// (no remote build id yet).
    #[must_use]
    pub fn new_local() -> Self {
        Self {
            local_wrapper_id: new_local_wrapper_id(),
            remote_build_id: None,
        }
    }

    /// Record the daemon-assigned remote build id at admission.
    pub fn admit(&mut self, remote_build_id: RemoteBuildId) {
        self.remote_build_id = Some(remote_build_id);
    }

    /// Whether the command was admitted (has a remote build id).
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        self.remote_build_id.is_some()
    }
}

/// The five operator-/agent-facing lifecycle states a job can be correlated to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobLifecycleState {
    /// The wrapper ran but the command never received a remote build id — it
    /// was rejected/failed before admission (e.g. no admissible workers).
    FailedBeforeAdmission,
    /// Admitted and waiting for a worker slot.
    Queued,
    /// Admitted and actively executing on a worker.
    Running,
    /// Completed (success or failure) with a recorded exit.
    Finished,
    /// Admitted/started but its heartbeat went stale past the abandon
    /// threshold with no completion record — presumed dead.
    Abandoned,
}

impl JobLifecycleState {
    /// Stable lowercase token (matches the serde representation).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            JobLifecycleState::FailedBeforeAdmission => "failed_before_admission",
            JobLifecycleState::Queued => "queued",
            JobLifecycleState::Running => "running",
            JobLifecycleState::Finished => "finished",
            JobLifecycleState::Abandoned => "abandoned",
        }
    }

    /// Whether this is a terminal state (no further transitions expected).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            JobLifecycleState::Finished
                | JobLifecycleState::Abandoned
                | JobLifecycleState::FailedBeforeAdmission
        )
    }
}

/// Observable signals used to correlate a job to a lifecycle state. Plain data
/// so the derivation is pure and unit-testable.
#[derive(Debug, Clone, Copy, Default)]
pub struct JobSignals {
    /// A remote build id was assigned (the daemon admitted the command).
    pub admitted: bool,
    /// A worker began executing the build.
    pub started: bool,
    /// A terminal completion/exit was recorded.
    pub completed: bool,
    /// The last heartbeat is older than the abandon threshold.
    pub heartbeat_stale: bool,
}

/// Correlate observable signals into the single lifecycle state.
///
/// Precedence (most-terminal wins): a recorded completion is `Finished` even if
/// a late heartbeat looks stale; a command with no remote build id is
/// `FailedBeforeAdmission`; an admitted job whose heartbeat went stale without
/// completing is `Abandoned`; a started job is `Running`; otherwise `Queued`.
#[must_use]
pub fn derive_job_lifecycle_state(signals: JobSignals) -> JobLifecycleState {
    if signals.completed {
        return JobLifecycleState::Finished;
    }
    if !signals.admitted {
        return JobLifecycleState::FailedBeforeAdmission;
    }
    if signals.heartbeat_stale {
        return JobLifecycleState::Abandoned;
    }
    if signals.started {
        return JobLifecycleState::Running;
    }
    JobLifecycleState::Queued
}

/// A correlated job record for `rch jobs --json`. Bundles the identity, the
/// derived lifecycle state, and the salient human/agent fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    pub identity: JobIdentity,
    pub state: JobLifecycleState,
    /// The command line (or a fingerprint) this job ran.
    pub command: String,
    /// Worker the job was placed on, once admitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Exit code, once finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl JobRecord {
    /// Build a record, deriving the lifecycle state from the identity +
    /// signals. `admitted` is taken from the identity so callers cannot pass a
    /// state inconsistent with the presence of a remote build id.
    #[must_use]
    pub fn correlate(
        identity: JobIdentity,
        command: impl Into<String>,
        worker_id: Option<String>,
        exit_code: Option<i32>,
        mut signals: JobSignals,
    ) -> Self {
        signals.admitted = identity.is_admitted();
        if exit_code.is_some() {
            signals.completed = true;
        }
        let state = derive_job_lifecycle_state(signals);
        Self {
            identity,
            state,
            command: command.into(),
            worker_id,
            exit_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_wrapper_ids_are_prefixed_and_unique() {
        let a = new_local_wrapper_id();
        let b = new_local_wrapper_id();
        assert!(a.starts_with(LOCAL_WRAPPER_ID_PREFIX));
        assert_ne!(a, b, "wrapper ids must be unique");
    }

    #[test]
    fn identity_admit_sets_remote_build_id() {
        let mut id = JobIdentity::new_local();
        assert!(!id.is_admitted());
        assert!(id.remote_build_id.is_none());
        id.admit(42);
        assert!(id.is_admitted());
        assert_eq!(id.remote_build_id, Some(42));
    }

    #[test]
    fn lifecycle_state_matrix() {
        // Not admitted => failed before admission (regardless of other signals).
        assert_eq!(
            derive_job_lifecycle_state(JobSignals {
                admitted: false,
                started: true,
                heartbeat_stale: true,
                completed: false,
            }),
            JobLifecycleState::FailedBeforeAdmission
        );
        // Completed always wins, even over a stale heartbeat.
        assert_eq!(
            derive_job_lifecycle_state(JobSignals {
                admitted: true,
                started: true,
                heartbeat_stale: true,
                completed: true,
            }),
            JobLifecycleState::Finished
        );
        // Admitted + stale heartbeat + not completed => abandoned.
        assert_eq!(
            derive_job_lifecycle_state(JobSignals {
                admitted: true,
                started: true,
                heartbeat_stale: true,
                completed: false,
            }),
            JobLifecycleState::Abandoned
        );
        // Admitted + started + fresh => running.
        assert_eq!(
            derive_job_lifecycle_state(JobSignals {
                admitted: true,
                started: true,
                heartbeat_stale: false,
                completed: false,
            }),
            JobLifecycleState::Running
        );
        // Admitted + not started => queued.
        assert_eq!(
            derive_job_lifecycle_state(JobSignals {
                admitted: true,
                started: false,
                heartbeat_stale: false,
                completed: false,
            }),
            JobLifecycleState::Queued
        );
    }

    #[test]
    fn terminal_states_classified() {
        assert!(JobLifecycleState::Finished.is_terminal());
        assert!(JobLifecycleState::Abandoned.is_terminal());
        assert!(JobLifecycleState::FailedBeforeAdmission.is_terminal());
        assert!(!JobLifecycleState::Queued.is_terminal());
        assert!(!JobLifecycleState::Running.is_terminal());
    }

    #[test]
    fn correlate_uses_identity_admission_and_exit_code() {
        // Un-admitted identity => FailedBeforeAdmission even if caller passed
        // optimistic signals.
        let unadmitted = JobIdentity::new_local();
        let rec = JobRecord::correlate(
            unadmitted,
            "cargo build",
            None,
            None,
            JobSignals {
                admitted: true,
                started: true,
                ..JobSignals::default()
            },
        );
        assert_eq!(rec.state, JobLifecycleState::FailedBeforeAdmission);

        // Admitted + exit code => Finished, with the exit recorded.
        let mut admitted = JobIdentity::new_local();
        admitted.admit(7);
        let rec = JobRecord::correlate(
            admitted,
            "cargo test",
            Some("worker-a".to_string()),
            Some(0),
            JobSignals::default(),
        );
        assert_eq!(rec.state, JobLifecycleState::Finished);
        assert_eq!(rec.exit_code, Some(0));
        assert_eq!(rec.worker_id.as_deref(), Some("worker-a"));
    }

    #[test]
    fn identity_serde_omits_absent_remote_build_id() {
        let id = JobIdentity::new_local();
        let json = serde_json::to_string(&id).expect("serialize");
        assert!(!json.contains("remote_build_id"), "None must be omitted");
        let back: JobIdentity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, id);
    }

    #[test]
    fn job_record_serializes_state_token() {
        let mut id = JobIdentity::new_local();
        id.admit(99);
        let rec = JobRecord::correlate(
            id,
            "cargo check",
            Some("w1".to_string()),
            None,
            JobSignals {
                started: false,
                ..JobSignals::default()
            },
        );
        let json = serde_json::to_string(&rec).expect("serialize");
        assert!(json.contains("\"state\":\"queued\""));
        assert!(json.contains("rchw-"));
    }
}
