//! Periodic full-suite verification (bead O007; plan §102; the
//! machinery that feeds the O008 zero-incorrect-pass gate).
//!
//! Caching is only trustworthy while something keeps checking it:
//!
//! - PERIODIC: every `FULL_RUN_CADENCE_WINDOWS`, CI runs a fresh
//!   COMPLETE canonical suite — nothing served, everything executed;
//! - ALWAYS-FULL LANES: high-risk and release lanes run full every
//!   time, cadence or not — a release never rides the cache;
//! - DISCREPANCY ALERTS: the fresh run is compared against what was
//!   served — a served pass that fails fresh is CACHE MASKING (fed
//!   straight to O008); a test the advisory selection skipped that
//!   fails fresh is a MISSING DEPENDENCY EDGE (the O009 graph lied
//!   by omission);
//! - agreement produces no alerts (the detector is not a scold).

use rabs_protocol::result_identity::TypedDigest;

use crate::zero_incorrect_pass::{VerificationVerdict, ZeroIncorrectPassGate};

/// Full runs at least this often (observation windows).
pub const FULL_RUN_CADENCE_WINDOWS: u32 = 24;

/// Execution lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// The agent inner loop: caching between full runs.
    AgentInnerLoop,
    /// Periodic CI verification.
    PeriodicCi,
    /// High-risk changes: always full.
    HighRisk,
    /// Release: always full.
    Release,
}

/// The scheduling decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Serve from cache where sound.
    CachedAllowed,
    /// Fresh complete canonical suite: nothing served.
    FullFresh,
}

/// Decide the run mode for a lane.
#[must_use]
pub const fn run_mode(lane: Lane, windows_since_last_full: u32) -> RunMode {
    match lane {
        // A release or high-risk change NEVER rides the cache.
        Lane::HighRisk | Lane::Release => RunMode::FullFresh,
        Lane::PeriodicCi => RunMode::FullFresh,
        Lane::AgentInnerLoop => {
            if windows_since_last_full >= FULL_RUN_CADENCE_WINDOWS {
                RunMode::FullFresh
            } else {
                RunMode::CachedAllowed
            }
        }
    }
}

/// One discrepancy between served results and the fresh full run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscrepancyAlert {
    /// A served pass failed fresh: cache masking (O008 incident).
    CacheMasking {
        /// The test key.
        key: TypedDigest,
    },
    /// A test the selection skipped failed fresh: the dependency
    /// graph missed an edge.
    MissingDependencyEdge {
        /// The test key.
        key: TypedDigest,
    },
}

/// Compare served results against the fresh full run.
///
/// `served` — (key, passed) for tests SERVED from cache this window.
/// `fresh` — (key, passed) for the COMPLETE fresh suite.
#[must_use]
pub fn compare(
    served: &[(TypedDigest, bool)],
    fresh: &[(TypedDigest, bool)],
) -> Vec<DiscrepancyAlert> {
    let mut alerts = Vec::new();
    for (key, fresh_passed) in fresh {
        if *fresh_passed {
            continue; // fresh pass masks nothing
        }
        match served.iter().find(|(k, _)| k == key) {
            Some((_, true)) => alerts.push(DiscrepancyAlert::CacheMasking { key: key.clone() }),
            Some((_, false)) => {} // both failed: agreement
            None => alerts.push(DiscrepancyAlert::MissingDependencyEdge { key: key.clone() }),
        }
    }
    alerts
}

/// Feed masking alerts into the O008 gate: every masked key is
/// verified-failed (incident + quarantine). Returns the incident
/// count.
pub fn escalate_to_gate(
    gate: &mut ZeroIncorrectPassGate,
    alerts: &[DiscrepancyAlert],
    seq: u64,
    request_id: u64,
) -> usize {
    let mut incidents = 0;
    for alert in alerts {
        if let DiscrepancyAlert::CacheMasking { key } = alert
            && matches!(
                gate.record_verification(key, false, seq, request_id),
                VerificationVerdict::IncorrectPass(_)
            )
        {
            incidents += 1;
        }
    }
    incidents
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn key(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.test-key.v1",
            bytes: [tag; 32],
        }
    }

    #[test]
    fn scheduling_wires_full_runs_where_the_bead_demands() {
        // THE scheduling acceptance: periodic cadence + always-full
        // lanes.
        assert_eq!(
            run_mode(Lane::AgentInnerLoop, 0),
            RunMode::CachedAllowed,
            "the inner loop caches between full runs"
        );
        assert_eq!(
            run_mode(Lane::AgentInnerLoop, FULL_RUN_CADENCE_WINDOWS - 1),
            RunMode::CachedAllowed
        );
        assert_eq!(
            run_mode(Lane::AgentInnerLoop, FULL_RUN_CADENCE_WINDOWS),
            RunMode::FullFresh,
            "the cadence forces a fresh complete suite"
        );
        // High-risk and release lanes ALWAYS run full — at window 0.
        assert_eq!(run_mode(Lane::HighRisk, 0), RunMode::FullFresh);
        assert_eq!(run_mode(Lane::Release, 0), RunMode::FullFresh);
        assert_eq!(run_mode(Lane::PeriodicCi, 0), RunMode::FullFresh);
    }

    #[test]
    fn discrepancy_alerts_classify_masking_and_missing_edges() {
        // THE alert acceptance: seeded discrepancies.
        let served = vec![
            (key(1), true),  // served pass — fresh FAILS: masking
            (key(2), true),  // served pass — fresh passes: fine
            (key(3), false), // served fail — fresh fails: agreement
        ];
        let fresh = vec![
            (key(1), false),
            (key(2), true),
            (key(3), false),
            (key(4), false), // never served/selected — fresh FAILS
            (key(5), true),  // never served — fresh passes: fine
        ];
        assert_eq!(
            compare(&served, &fresh),
            vec![
                DiscrepancyAlert::CacheMasking { key: key(1) },
                DiscrepancyAlert::MissingDependencyEdge { key: key(4) },
            ]
        );
        // Full agreement: no alerts (not a scold).
        let agree = vec![(key(1), true), (key(2), false)];
        assert!(compare(&agree, &agree).is_empty());
    }

    #[test]
    fn masking_alerts_escalate_to_the_o008_gate() {
        // Integration: the masked key ends up quarantined via the
        // real gate; the missing-edge alert does NOT quarantine (it
        // is a graph bug, not a wrong pass).
        let alerts = vec![
            DiscrepancyAlert::CacheMasking { key: key(1) },
            DiscrepancyAlert::MissingDependencyEdge { key: key(4) },
        ];
        let mut gate = ZeroIncorrectPassGate::default();
        let incidents = escalate_to_gate(&mut gate, &alerts, 42, 900);
        assert_eq!(incidents, 1);
        assert!(gate.is_quarantined(&key(1)));
        assert!(!gate.is_quarantined(&key(4)));
    }
}
