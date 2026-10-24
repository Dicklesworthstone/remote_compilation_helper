//! Periodic full-suite verification and mandatory uncached release-lane policy
//! (beads O007, O013; plan §§108, 110; feeds the O008 zero-incorrect-pass gate).
//!
//! Caching is only trustworthy while something keeps checking it:
//!
//! - PERIODIC: every `FULL_RUN_CADENCE_WINDOWS`, CI runs a fresh
//!   COMPLETE canonical suite — nothing served, everything executed;
//! - ALWAYS-FULL LANES: high-risk and release lanes run full every
//!   time, cadence or not — a release never rides the cache;
//! - EXECUTION-REUSE FACT vs CORRECTNESS PROOF (O013): a cached passing
//!   result is an execution-reuse fact (`ProofStanding::ExecutionReuseFact`),
//!   not proof that the program is correct (`ProofStanding::FreshCorrectnessProof`).
//!   Release and periodic uncached runs enforce cache bypass before consulting
//!   `StablePassCache` and record an append-only audit trail of every window;
//! - DISCREPANCY ALERTS: the fresh run is compared against what was
//!   served — a served pass that fails fresh is CACHE MASKING (fed
//!   straight to O008); a test the advisory selection skipped that
//!   fails fresh is a MISSING DEPENDENCY EDGE (the O009 graph lied
//!   by omission);
//! - agreement produces no alerts (the detector is not a scold).

use rabs_protocol::result_identity::TypedDigest;

use crate::test_pass_cache::{ServeDecision, SetupObligation, StablePassCache};
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

/// Epistemic standing of a test-suite execution window (plan §110; bead O013).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofStanding {
    /// One or more test results were served from cache, or the suite was not
    /// executed as a complete fresh canonical run. Useful for inner-loop speed,
    /// never admissible as release correctness proof.
    ExecutionReuseFact,
    /// Every test in the canonical suite executed fresh with zero cached hits.
    FreshCorrectnessProof,
}

/// Why test-result caching was bypassed by policy for a window (bead O013).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UncachedPolicyReason {
    /// Release lanes always bypass test-result caching.
    ReleaseLaneMandatory,
    /// High-risk lanes always bypass test-result caching.
    HighRiskLaneMandatory,
    /// Periodic CI lanes always bypass test-result caching.
    PeriodicCiMandatory,
    /// The inner loop reached the mandatory periodic full-suite cadence.
    CadenceReached {
        /// Windows elapsed since the last verified fresh full run.
        windows_since_last_full: u32,
        /// Configured cadence ceiling.
        cadence_limit: u32,
    },
}

/// Decide why a lane must bypass test-result caching, if policy requires an
/// uncached full run.
#[must_use]
pub const fn uncached_policy_reason(
    lane: Lane,
    windows_since_last_full: u32,
) -> Option<UncachedPolicyReason> {
    match lane {
        Lane::Release => Some(UncachedPolicyReason::ReleaseLaneMandatory),
        Lane::HighRisk => Some(UncachedPolicyReason::HighRiskLaneMandatory),
        Lane::PeriodicCi => Some(UncachedPolicyReason::PeriodicCiMandatory),
        Lane::AgentInnerLoop => {
            if windows_since_last_full >= FULL_RUN_CADENCE_WINDOWS {
                Some(UncachedPolicyReason::CadenceReached {
                    windows_since_last_full,
                    cadence_limit: FULL_RUN_CADENCE_WINDOWS,
                })
            } else {
                None
            }
        }
    }
}

/// Decide the run mode for a lane.
#[must_use]
pub const fn run_mode(lane: Lane, windows_since_last_full: u32) -> RunMode {
    if uncached_policy_reason(lane, windows_since_last_full).is_some() {
        RunMode::FullFresh
    } else {
        RunMode::CachedAllowed
    }
}

/// Decision when consulting `StablePassCache` under lane + cadence policy (bead O013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyServeDecision {
    /// Policy forbids serving cached test passes in this window; execute fresh.
    BypassedByPolicy(UncachedPolicyReason),
    /// Policy permits consulting the stable-pass cache.
    CacheDecision(ServeDecision),
}

/// Consult `StablePassCache` only when the lane and periodic cadence allow
/// cached test reuse; otherwise enforce a fresh execution.
#[must_use]
pub fn serve_under_policy(
    cache: &StablePassCache,
    lane: Lane,
    windows_since_last_full: u32,
    key: &TypedDigest,
    pending: &[SetupObligation],
) -> PolicyServeDecision {
    if let Some(reason) = uncached_policy_reason(lane, windows_since_last_full) {
        PolicyServeDecision::BypassedByPolicy(reason)
    } else {
        PolicyServeDecision::CacheDecision(cache.serve(key, pending))
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

/// Policy violation when evaluating a suite execution window (bead O013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleasePolicyViolation {
    /// A window required by policy to run uncached served cached test results.
    CachedReuseInUncachedRun {
        /// Why the window was required to bypass the cache.
        reason: UncachedPolicyReason,
        /// Number of cached test results improperly served.
        served_count: usize,
    },
    /// An uncached verification window executed zero fresh tests.
    EmptyFreshSuite,
    /// Fresh test executions failed or exposed discrepancies against previously
    /// served results.
    FreshVerificationFailed {
        /// Keys that failed fresh execution.
        failed_keys: Vec<TypedDigest>,
        /// Discrepancy alerts against prior served results.
        alerts: Vec<DiscrepancyAlert>,
        /// Count of keys quarantined in the O008 gate.
        quarantined_incidents: usize,
    },
}

/// Immutable audit-trail record for one suite execution window (bead O013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullSuiteAuditEntry {
    /// Monotonic audit sequence number (1-indexed).
    pub sequence: u64,
    /// Request identifier associated with the window.
    pub request_id: u64,
    /// Execution lane.
    pub lane: Lane,
    /// Windows since the last verified fresh full run before this window.
    pub windows_since_last_full_before: u32,
    /// Windows since the last verified fresh full run after this window.
    pub windows_since_last_full_after: u32,
    /// Enforced run mode for this window.
    pub enforced_mode: RunMode,
    /// Policy reason if uncached execution was mandatory.
    pub policy_reason: Option<UncachedPolicyReason>,
    /// Epistemic standing of the window (`ExecutionReuseFact` vs `FreshCorrectnessProof`).
    pub standing: ProofStanding,
    /// Count of test results served from cache during this window.
    pub served_count: usize,
    /// Count of tests executed fresh during this window.
    pub fresh_executed_count: usize,
    /// Count of fresh tests that failed.
    pub fresh_failed_count: usize,
    /// Discrepancies detected against prior served results.
    pub discrepancies: Vec<DiscrepancyAlert>,
    /// Count of keys quarantined in `ZeroIncorrectPassGate`.
    pub quarantined_incidents: usize,
    /// Policy violation, if any.
    pub violation: Option<ReleasePolicyViolation>,
    /// True only when this window is admissible to certify a release (`Lane::Release`,
    /// `ProofStanding::FreshCorrectnessProof`, zero failures, zero violations).
    pub release_certified: bool,
}

/// Stateful policy enforcer and append-only audit trail for periodic uncached
/// full-suite verification and release lanes (bead O013).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UncachedSuitePolicy {
    windows_since_last_full: u32,
    next_sequence: u64,
    audit_trail: Vec<FullSuiteAuditEntry>,
    last_served_window: Vec<(TypedDigest, bool)>,
}

impl UncachedSuitePolicy {
    /// Current count of cached inner-loop windows since the last verified
    /// fresh full-suite run.
    #[must_use]
    pub const fn windows_since_last_full(&self) -> u32 {
        self.windows_since_last_full
    }

    /// Append-only audit trail of all evaluated windows.
    #[must_use]
    pub fn audit_trail(&self) -> &[FullSuiteAuditEntry] {
        &self.audit_trail
    }

    /// Enforce policy before consulting `StablePassCache` for a test key.
    #[must_use]
    pub fn decide_serve(
        &self,
        cache: &StablePassCache,
        lane: Lane,
        key: &TypedDigest,
        pending: &[SetupObligation],
    ) -> PolicyServeDecision {
        serve_under_policy(cache, lane, self.windows_since_last_full, key, pending)
    }

    /// Record and enforce a suite execution window, escalating any cache-masking
    /// discrepancies to `ZeroIncorrectPassGate` and appending an audit entry.
    ///
    /// # Errors
    /// Returns [`ReleasePolicyViolation`] if an uncached-mandatory lane served
    /// cached results, if a required fresh suite was empty, or if fresh verification
    /// failed. The violation is still recorded in the append-only audit trail.
    pub fn record_window(
        &mut self,
        lane: Lane,
        served: &[(TypedDigest, bool)],
        fresh: &[(TypedDigest, bool)],
        gate: &mut ZeroIncorrectPassGate,
        request_id: u64,
    ) -> Result<&FullSuiteAuditEntry, ReleasePolicyViolation> {
        self.next_sequence += 1;
        let sequence = self.next_sequence;
        let before = self.windows_since_last_full;
        let policy_reason = uncached_policy_reason(lane, before);
        let enforced_mode = run_mode(lane, before);

        let failed_keys: Vec<TypedDigest> = fresh
            .iter()
            .filter(|(_, passed)| !*passed)
            .map(|(k, _)| k.clone())
            .collect();

        // Compare fresh full runs against either the same window's served slice
        // or the most recent cached window's served slice so periodic / release
        // fresh runs catch cache masking from the preceding cached window.
        let comparison_served: &[(TypedDigest, bool)] = if !served.is_empty() {
            served
        } else {
            &self.last_served_window
        };
        let discrepancies = if !fresh.is_empty() && !comparison_served.is_empty() {
            compare(comparison_served, fresh)
        } else {
            Vec::new()
        };
        let quarantined_incidents = escalate_to_gate(gate, &discrepancies, sequence, request_id);

        let violation = if let Some(reason) = policy_reason
            && !served.is_empty()
        {
            Some(ReleasePolicyViolation::CachedReuseInUncachedRun {
                reason,
                served_count: served.len(),
            })
        } else if enforced_mode == RunMode::FullFresh && fresh.is_empty() {
            Some(ReleasePolicyViolation::EmptyFreshSuite)
        } else if !failed_keys.is_empty() || !discrepancies.is_empty() {
            Some(ReleasePolicyViolation::FreshVerificationFailed {
                failed_keys: failed_keys.clone(),
                alerts: discrepancies.clone(),
                quarantined_incidents,
            })
        } else {
            None
        };

        let standing = if enforced_mode == RunMode::FullFresh
            && served.is_empty()
            && !fresh.is_empty()
            && failed_keys.is_empty()
        {
            ProofStanding::FreshCorrectnessProof
        } else {
            ProofStanding::ExecutionReuseFact
        };

        let after = if standing == ProofStanding::FreshCorrectnessProof && violation.is_none() {
            self.last_served_window.clear();
            0
        } else {
            if !served.is_empty() {
                self.last_served_window = served.to_vec();
            }
            before.saturating_add(1)
        };
        self.windows_since_last_full = after;

        let release_certified = lane == Lane::Release
            && standing == ProofStanding::FreshCorrectnessProof
            && violation.is_none();

        let entry = FullSuiteAuditEntry {
            sequence,
            request_id,
            lane,
            windows_since_last_full_before: before,
            windows_since_last_full_after: after,
            enforced_mode,
            policy_reason,
            standing,
            served_count: served.len(),
            fresh_executed_count: fresh.len(),
            fresh_failed_count: failed_keys.len(),
            discrepancies,
            quarantined_incidents,
            violation: violation.clone(),
            release_certified,
        };
        self.audit_trail.push(entry);

        if let Some(err) = violation {
            Err(err)
        } else {
            Ok(self.audit_trail.last().expect("just pushed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_config_keys::TestResultClass;
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

    #[test]
    fn o013_release_and_periodic_policy_bypass_cache_and_record_audit_trail() {
        let mut cache = StablePassCache::default();
        cache
            .admit(key(1), TestResultClass::StablePass)
            .expect("stable pass admitted");
        cache
            .admit(key(2), TestResultClass::StablePass)
            .expect("stable pass admitted");

        let mut policy = UncachedSuitePolicy::default();
        let mut gate = ZeroIncorrectPassGate::default();

        // 1. Inner-loop window 0: cache is allowed; standing is ExecutionReuseFact, NOT release proof.
        assert_eq!(
            policy.decide_serve(&cache, Lane::AgentInnerLoop, &key(1), &[]),
            PolicyServeDecision::CacheDecision(ServeDecision::ServePass)
        );
        let entry = policy
            .record_window(
                Lane::AgentInnerLoop,
                &[(key(1), true), (key(2), true)],
                &[],
                &mut gate,
                100,
            )
            .expect("cached inner-loop window allowed");
        assert_eq!(entry.standing, ProofStanding::ExecutionReuseFact);
        assert!(!entry.release_certified);
        assert_eq!(policy.windows_since_last_full(), 1);

        // 2. Release lane ALWAYS bypasses cache even at window 1.
        assert_eq!(
            policy.decide_serve(&cache, Lane::Release, &key(1), &[]),
            PolicyServeDecision::BypassedByPolicy(UncachedPolicyReason::ReleaseLaneMandatory)
        );

        // 3. Attempting to smuggle a cached pass into a release lane fails closed and is audited.
        let violation = policy
            .record_window(
                Lane::Release,
                &[(key(1), true)],
                &[(key(2), true)],
                &mut gate,
                101,
            )
            .expect_err("release lane must reject cached passes");
        assert_eq!(
            violation,
            ReleasePolicyViolation::CachedReuseInUncachedRun {
                reason: UncachedPolicyReason::ReleaseLaneMandatory,
                served_count: 1,
            }
        );
        assert!(!policy.audit_trail().last().unwrap().release_certified);
        assert_eq!(
            policy.audit_trail().last().unwrap().standing,
            ProofStanding::ExecutionReuseFact
        );
        // Violation does not reset the cadence counter!
        assert_eq!(policy.windows_since_last_full(), 2);

        // 4. Advance inner loop to FULL_RUN_CADENCE_WINDOWS; policy forces uncached run.
        while policy.windows_since_last_full() < FULL_RUN_CADENCE_WINDOWS {
            policy
                .record_window(
                    Lane::AgentInnerLoop,
                    &[(key(1), true), (key(2), true)],
                    &[],
                    &mut gate,
                    200 + u64::from(policy.windows_since_last_full()),
                )
                .expect("inner-loop window within cadence");
        }
        assert_eq!(
            policy.decide_serve(&cache, Lane::AgentInnerLoop, &key(1), &[]),
            PolicyServeDecision::BypassedByPolicy(UncachedPolicyReason::CadenceReached {
                windows_since_last_full: FULL_RUN_CADENCE_WINDOWS,
                cadence_limit: FULL_RUN_CADENCE_WINDOWS,
            })
        );

        // 5. Fresh uncached release run where key(2) fails fresh after being served-pass:
        //    escalates to O008 quarantine and refuses release certification.
        let mask_err = policy
            .record_window(
                Lane::Release,
                &[],
                &[(key(1), true), (key(2), false)],
                &mut gate,
                300,
            )
            .expect_err("fresh failure must refuse release");
        assert!(matches!(
            mask_err,
            ReleasePolicyViolation::FreshVerificationFailed {
                quarantined_incidents: 1,
                ..
            }
        ));
        assert!(gate.is_quarantined(&key(2)));
        assert!(!policy.audit_trail().last().unwrap().release_certified);

        // 6. Clean uncached release run: zero served, all fresh pass -> FreshCorrectnessProof + certified + resets cadence!
        let certified = policy
            .record_window(
                Lane::Release,
                &[],
                &[(key(1), true), (key(2), true)],
                &mut gate,
                301,
            )
            .expect("clean fresh release run succeeds");
        assert_eq!(certified.standing, ProofStanding::FreshCorrectnessProof);
        assert!(certified.release_certified);
        assert_eq!(certified.windows_since_last_full_after, 0);
        assert_eq!(policy.windows_since_last_full(), 0);
    }
}
