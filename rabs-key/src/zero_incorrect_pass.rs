//! The zero-incorrect-pass gate (bead O008; plan §102; the M12 hard
//! gate; composes the O004 cache with the R008 incident machinery).
//!
//! NO CACHED PASS MAY EVER BE WRONG. The gate sits between the
//! stable-pass cache and serving:
//!
//! - when a verification run (O007) re-executes a test whose pass
//!   was cached and the live run FAILS, that is an INCORRECT PASS:
//!   an `IncorrectResultDivergence` incident bundle is generated and
//!   the test key is QUARANTINED — serving for it stops immediately;
//! - the gate is wired IN FRONT of the cache: a quarantined key
//!   misses no matter what the cache holds;
//! - quarantine is sticky: it clears only with the R008 regression
//!   gate satisfied (a non-empty regression-test attestation), and
//!   clearing without one is a typed refusal.

use rabs_protocol::incident_bundle::{IncidentBundle, IncidentClass, generate_bundle};
use rabs_protocol::result_identity::TypedDigest;

use crate::test_pass_cache::{ServeDecision, SetupObligation, StablePassCache};

/// The verification verdict for one cached pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationVerdict {
    /// The live run passed too: the cached pass stands.
    Confirmed,
    /// The live run FAILED: the cached pass was wrong — incident
    /// opened, key quarantined.
    IncorrectPass(Box<IncidentBundle>),
}

/// Typed refusal for clearing quarantine without the R008 gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegressionGateUnsatisfied;

/// The gate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZeroIncorrectPassGate {
    quarantined: Vec<TypedDigest>,
}

impl ZeroIncorrectPassGate {
    /// Record a verification run against a cached pass.
    pub fn record_verification(
        &mut self,
        key: &TypedDigest,
        live_passed: bool,
        seq: u64,
        request_id: u64,
    ) -> VerificationVerdict {
        if live_passed {
            return VerificationVerdict::Confirmed;
        }
        if !self.quarantined.contains(key) {
            self.quarantined.push(key.clone());
        }
        VerificationVerdict::IncorrectPass(Box::new(generate_bundle(
            IncidentClass::IncorrectResultDivergence,
            seq,
            vec![request_id],
        )))
    }

    /// Whether a key is quarantined.
    #[must_use]
    pub fn is_quarantined(&self, key: &TypedDigest) -> bool {
        self.quarantined.contains(key)
    }

    /// Serving THROUGH the gate: quarantine is checked BEFORE the
    /// cache — a quarantined key misses no matter what is cached.
    #[must_use]
    pub fn serve(
        &self,
        cache: &StablePassCache,
        key: &TypedDigest,
        pending: &[SetupObligation],
    ) -> ServeDecision {
        if self.is_quarantined(key) {
            return ServeDecision::Miss;
        }
        cache.serve(key, pending)
    }

    /// Clear a quarantine — ONLY with the R008 regression gate
    /// satisfied (a non-empty attestation naming the landed test).
    ///
    /// # Errors
    /// [`RegressionGateUnsatisfied`] for an empty attestation.
    pub fn clear_quarantine(
        &mut self,
        key: &TypedDigest,
        regression_test_attestation: &str,
    ) -> Result<(), RegressionGateUnsatisfied> {
        if regression_test_attestation.trim().is_empty() {
            return Err(RegressionGateUnsatisfied);
        }
        self.quarantined.retain(|k| k != key);
        Ok(())
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

    fn cached_pass() -> StablePassCache {
        let mut cache = StablePassCache::default();
        cache
            .admit(key(1), TestResultClass::StablePass)
            .expect("admits");
        cache
    }

    #[test]
    fn a_seeded_wrong_pass_opens_the_incident_and_quarantines() {
        // THE acceptance: the cached pass is WRONG (live run fails).
        let cache = cached_pass();
        let mut gate = ZeroIncorrectPassGate::default();
        // Before: the pass serves through the gate.
        assert_eq!(gate.serve(&cache, &key(1), &[]), ServeDecision::ServePass);
        // The O007 verification run fails live — seeded wrong pass.
        let verdict = gate.record_verification(&key(1), false, 42, 900);
        let VerificationVerdict::IncorrectPass(bundle) = verdict else {
            panic!("a failed live run against a cached pass is an incident");
        };
        assert_eq!(bundle.class, IncidentClass::IncorrectResultDivergence);
        assert!(bundle.runbook_link.contains("incorrect-result-divergence"));
        assert_eq!(bundle.involved_request_ids, vec![900]);
        assert!(gate.is_quarantined(&key(1)));
    }

    #[test]
    fn the_gate_is_wired_in_front_of_serving() {
        // THE wiring acceptance: after the incident, the SAME cache
        // entry misses — quarantine overrides whatever is cached.
        let cache = cached_pass();
        let mut gate = ZeroIncorrectPassGate::default();
        gate.record_verification(&key(1), false, 42, 900);
        assert_eq!(
            gate.serve(&cache, &key(1), &[]),
            ServeDecision::Miss,
            "no cached pass may ever be wrong — the key is dead"
        );
        // Other keys are untouched.
        let mut wider = cached_pass();
        wider
            .admit(key(2), TestResultClass::StablePass)
            .expect("admits");
        assert_eq!(gate.serve(&wider, &key(2), &[]), ServeDecision::ServePass);
    }

    #[test]
    fn confirmed_verifications_change_nothing() {
        let cache = cached_pass();
        let mut gate = ZeroIncorrectPassGate::default();
        assert_eq!(
            gate.record_verification(&key(1), true, 42, 900),
            VerificationVerdict::Confirmed
        );
        assert!(!gate.is_quarantined(&key(1)));
        assert_eq!(gate.serve(&cache, &key(1), &[]), ServeDecision::ServePass);
    }

    #[test]
    fn quarantine_is_sticky_until_the_regression_gate_is_satisfied() {
        let cache = cached_pass();
        let mut gate = ZeroIncorrectPassGate::default();
        gate.record_verification(&key(1), false, 42, 900);
        // Clearing without an attestation refuses (R008's rule: an
        // incident closes only with its regression test landed).
        assert_eq!(
            gate.clear_quarantine(&key(1), "   "),
            Err(RegressionGateUnsatisfied)
        );
        assert_eq!(gate.serve(&cache, &key(1), &[]), ServeDecision::Miss);
        // With the attestation, serving resumes.
        gate.clear_quarantine(
            &key(1),
            "regression test tests/o008_wrong_pass.rs landed in a1b2c3",
        )
        .expect("clears");
        assert_eq!(gate.serve(&cache, &key(1), &[]), ServeDecision::ServePass);
    }
}
