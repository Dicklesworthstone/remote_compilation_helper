//! Readiness split + diagnose incident-chain replay
//! (bd-session-history-remediation-ocv9i.4.3).
//!
//! Session history showed a `remote_ready` banner appearing while the selected
//! command actually had **zero** admissible workers — a single boolean hiding
//! four distinct questions. This module splits readiness into its real
//! dimensions — daemon reachability, desired fleet, live health, and
//! command-admissible workers — and computes a single decisive blocker, with the
//! hard invariant that **`remote_ready` is never true when zero workers are
//! admissible for the command**.
//!
//! [`assess_readiness`] is pure and total: given the split plus proof-mode and
//! recent-incident context it yields a [`ReadinessReport`] carrying the split,
//! the decisive [`DecisiveBlocker`], and a replayed incident chain — exactly
//! what `rch diagnose --json -- <command>` surfaces. The report is deterministic
//! (no clock) so the scenario JSON goldens are stable.

use serde::{Deserialize, Serialize};

use crate::admission_rejection::AdmissionRejectionCategory;
use crate::incident::{IncidentEvent, IncidentReasonCode};

/// The four real readiness dimensions, never collapsed into one boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessSplit {
    /// The daemon Unix socket answered.
    pub daemon_reachable: bool,
    /// Workers the configuration desires in the fleet.
    pub desired_fleet_workers: u32,
    /// Workers currently live and healthy.
    pub live_healthy_workers: u32,
    /// Workers admissible for the *selected command* (capability-checked).
    pub command_admissible_workers: u32,
}

/// The single decisive reason remote execution is (not) ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisiveBlocker {
    /// Ready — at least one worker is admissible and nothing blocks.
    None,
    /// The daemon socket did not answer.
    DaemonDown,
    /// Proof mode refused before execution.
    ProofRefused,
    /// No workers are configured/desired in the fleet.
    NoDesiredFleet,
    /// Workers are desired but none are live and healthy.
    NoHealthyWorkers,
    /// Healthy workers exist but none can run THIS command (capability gap).
    NoCommandCapability,
    /// Admissibility blocked by critical resource pressure.
    PressureBlocked,
    /// The most recent attempt failed at artifact retrieval.
    ArtifactMissed,
}

impl DecisiveBlocker {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DecisiveBlocker::None => "none",
            DecisiveBlocker::DaemonDown => "daemon_down",
            DecisiveBlocker::ProofRefused => "proof_refused",
            DecisiveBlocker::NoDesiredFleet => "no_desired_fleet",
            DecisiveBlocker::NoHealthyWorkers => "no_healthy_workers",
            DecisiveBlocker::NoCommandCapability => "no_command_capability",
            DecisiveBlocker::PressureBlocked => "pressure_blocked",
            DecisiveBlocker::ArtifactMissed => "artifact_missed",
        }
    }
}

/// One compact entry in the replayed incident chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentChainEntry {
    /// Stable reason code (`RCH-Innn`).
    pub reason_code: IncidentReasonCode,
    /// Event time as Unix epoch milliseconds.
    pub occurred_at_unix_ms: u64,
}

impl From<&IncidentEvent> for IncidentChainEntry {
    fn from(event: &IncidentEvent) -> Self {
        Self {
            reason_code: event.reason_code,
            occurred_at_unix_ms: event.occurred_at_unix_ms,
        }
    }
}

/// Inputs for the readiness assessment. Plain data; pure assessment.
#[derive(Debug, Clone)]
pub struct ReadinessInputs {
    pub split: ReadinessSplit,
    /// Proof mode refused execution (see [`crate::proof_policy`]).
    pub proof_refused: bool,
    /// The dominant rejection category when no worker is admissible (lets a
    /// pressure block read as `pressure_blocked` rather than a generic gap).
    pub dominant_rejection: Option<AdmissionRejectionCategory>,
    /// Recent incidents for the command/project, oldest-first.
    pub recent_incidents: Vec<IncidentChainEntry>,
}

/// The readiness report `rch diagnose --json` surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessReport {
    pub split: ReadinessSplit,
    /// True iff there is no decisive blocker. By construction this is impossible
    /// when `command_admissible_workers == 0`.
    pub remote_ready: bool,
    pub blocker: DecisiveBlocker,
    /// The replayed recent incident chain, oldest-first.
    pub incident_chain: Vec<IncidentChainEntry>,
    pub detail: String,
}

impl ReadinessReport {
    /// The invariant guard: `remote_ready` implies at least one admissible
    /// worker. Always true for a report from [`assess_readiness`]; exposed so
    /// callers/tests can assert it.
    #[must_use]
    pub fn invariant_holds(&self) -> bool {
        !self.remote_ready || self.split.command_admissible_workers > 0
    }
}

/// Assess readiness. Pure and total. Decisive-blocker precedence (most
/// fundamental first): daemon down, proof refused, no desired fleet, no healthy
/// workers, no command capability (pressure-distinguished), then a trailing
/// artifact-miss from the most recent incident. Only when none apply is it
/// `remote_ready`.
#[must_use]
pub fn assess_readiness(inputs: &ReadinessInputs) -> ReadinessReport {
    let s = &inputs.split;
    let blocker = if !s.daemon_reachable {
        DecisiveBlocker::DaemonDown
    } else if inputs.proof_refused {
        DecisiveBlocker::ProofRefused
    } else if s.desired_fleet_workers == 0 {
        DecisiveBlocker::NoDesiredFleet
    } else if s.live_healthy_workers == 0 {
        DecisiveBlocker::NoHealthyWorkers
    } else if s.command_admissible_workers == 0 {
        if inputs.dominant_rejection == Some(AdmissionRejectionCategory::CriticalPressure) {
            DecisiveBlocker::PressureBlocked
        } else {
            DecisiveBlocker::NoCommandCapability
        }
    } else if inputs
        .recent_incidents
        .last()
        .is_some_and(|e| e.reason_code == IncidentReasonCode::ArtifactMiss)
    {
        DecisiveBlocker::ArtifactMissed
    } else {
        DecisiveBlocker::None
    };

    let remote_ready = blocker == DecisiveBlocker::None;
    let detail = match blocker {
        DecisiveBlocker::None => "remote execution ready".to_string(),
        DecisiveBlocker::DaemonDown => "daemon socket unreachable".to_string(),
        DecisiveBlocker::ProofRefused => "proof mode refused before execution".to_string(),
        DecisiveBlocker::NoDesiredFleet => "no workers configured in the fleet".to_string(),
        DecisiveBlocker::NoHealthyWorkers => {
            format!(
                "{} desired worker(s) but none live/healthy",
                s.desired_fleet_workers
            )
        }
        DecisiveBlocker::NoCommandCapability => format!(
            "{} healthy worker(s) but none admissible for this command",
            s.live_healthy_workers
        ),
        DecisiveBlocker::PressureBlocked => {
            "admissibility blocked by critical resource pressure".to_string()
        }
        DecisiveBlocker::ArtifactMissed => {
            "ready, but the most recent attempt failed at artifact retrieval".to_string()
        }
    };

    ReadinessReport {
        split: *s,
        remote_ready,
        blocker,
        incident_chain: inputs.recent_incidents.clone(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(reason: IncidentReasonCode, ts: u64) -> IncidentChainEntry {
        IncidentChainEntry {
            reason_code: reason,
            occurred_at_unix_ms: ts,
        }
    }

    fn split(daemon: bool, desired: u32, healthy: u32, admissible: u32) -> ReadinessSplit {
        ReadinessSplit {
            daemon_reachable: daemon,
            desired_fleet_workers: desired,
            live_healthy_workers: healthy,
            command_admissible_workers: admissible,
        }
    }

    fn inputs(split: ReadinessSplit) -> ReadinessInputs {
        ReadinessInputs {
            split,
            proof_refused: false,
            dominant_rejection: None,
            recent_incidents: Vec::new(),
        }
    }

    // --- The hard invariant -------------------------------------------------

    #[test]
    fn remote_ready_never_appears_with_zero_admissible() {
        // Exhaustively: any split with zero admissible workers is NOT ready.
        for daemon in [false, true] {
            for desired in [0u32, 2] {
                for healthy in [0u32, 2] {
                    let report = assess_readiness(&inputs(split(daemon, desired, healthy, 0)));
                    assert!(!report.remote_ready, "ready with 0 admissible: {report:?}");
                    assert!(report.invariant_holds());
                }
            }
        }
    }

    // --- The six required golden scenarios ----------------------------------

    #[test]
    fn golden_healthy() {
        let report = assess_readiness(&inputs(split(true, 3, 3, 2)));
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["remote_ready"], true);
        assert_eq!(v["blocker"], "none");
        assert_eq!(v["split"]["command_admissible_workers"], 2);
        assert!(report.invariant_holds());
    }

    #[test]
    fn golden_daemon_down() {
        let report = assess_readiness(&inputs(split(false, 3, 0, 0)));
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["remote_ready"], false);
        assert_eq!(v["blocker"], "daemon_down");
    }

    #[test]
    fn golden_healthy_but_no_command_capability() {
        // Daemon up, healthy workers, but none admissible for the command.
        let report = assess_readiness(&inputs(split(true, 3, 3, 0)));
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["remote_ready"], false);
        assert_eq!(v["blocker"], "no_command_capability");
        assert_eq!(v["split"]["live_healthy_workers"], 3);
    }

    #[test]
    fn golden_pressure_blocked() {
        let mut i = inputs(split(true, 3, 3, 0));
        i.dominant_rejection = Some(AdmissionRejectionCategory::CriticalPressure);
        let report = assess_readiness(&i);
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["remote_ready"], false);
        assert_eq!(v["blocker"], "pressure_blocked");
    }

    #[test]
    fn golden_proof_refused() {
        let mut i = inputs(split(true, 3, 3, 2));
        i.proof_refused = true;
        let report = assess_readiness(&i);
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["remote_ready"], false);
        assert_eq!(v["blocker"], "proof_refused");
    }

    #[test]
    fn golden_artifact_missed() {
        // Ready by capacity, but the most recent incident is an artifact miss.
        let mut i = inputs(split(true, 3, 3, 2));
        i.recent_incidents = vec![
            entry(IncidentReasonCode::LocalFallback, 1_700_000_000_000),
            entry(IncidentReasonCode::ArtifactMiss, 1_700_000_001_000),
        ];
        let report = assess_readiness(&i);
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["remote_ready"], false);
        assert_eq!(v["blocker"], "artifact_missed");
        // The incident chain is replayed, oldest-first.
        assert_eq!(v["incident_chain"][0]["reason_code"], "RCH-I011");
        assert_eq!(v["incident_chain"][1]["reason_code"], "RCH-I014");
        assert_eq!(
            v["incident_chain"][1]["occurred_at_unix_ms"],
            1_700_000_001_000u64
        );
    }

    // --- Precedence + structure --------------------------------------------

    #[test]
    fn daemon_down_outranks_everything() {
        let mut i = inputs(split(false, 0, 0, 0));
        i.proof_refused = true;
        assert_eq!(assess_readiness(&i).blocker, DecisiveBlocker::DaemonDown);
    }

    #[test]
    fn no_healthy_distinct_from_no_desired_and_no_capability() {
        assert_eq!(
            assess_readiness(&inputs(split(true, 0, 0, 0))).blocker,
            DecisiveBlocker::NoDesiredFleet
        );
        assert_eq!(
            assess_readiness(&inputs(split(true, 3, 0, 0))).blocker,
            DecisiveBlocker::NoHealthyWorkers
        );
        assert_eq!(
            assess_readiness(&inputs(split(true, 3, 3, 0))).blocker,
            DecisiveBlocker::NoCommandCapability
        );
    }

    #[test]
    fn artifact_miss_only_blocks_when_it_is_the_latest_incident() {
        // An older artifact-miss followed by a clean event does NOT block.
        let mut i = inputs(split(true, 3, 3, 2));
        i.recent_incidents = vec![
            entry(IncidentReasonCode::ArtifactMiss, 1_700_000_000_000),
            entry(IncidentReasonCode::LocalFallback, 1_700_000_001_000),
        ];
        assert_eq!(assess_readiness(&i).blocker, DecisiveBlocker::None);
        assert!(assess_readiness(&i).remote_ready);
    }

    #[test]
    fn report_round_trips() {
        let report = assess_readiness(&inputs(split(true, 3, 3, 2)));
        let v = serde_json::to_value(&report).unwrap();
        let back: ReadinessReport = serde_json::from_value(v).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn incident_chain_entry_from_event() {
        use crate::incident::{IncidentEvent, IncidentEventType, IncidentSource, SelectedMode};
        let event = IncidentEvent::new(
            IncidentEventType::ArtifactRetrieval,
            IncidentReasonCode::ArtifactMiss,
            IncidentSource::Hook,
            "proj",
            "cargo build",
            SelectedMode::Remote,
            true,
            1_700_000_002_000,
        );
        let chain_entry = IncidentChainEntry::from(&event);
        assert_eq!(chain_entry.reason_code, IncidentReasonCode::ArtifactMiss);
        assert_eq!(chain_entry.occurred_at_unix_ms, 1_700_000_002_000);
    }
}
