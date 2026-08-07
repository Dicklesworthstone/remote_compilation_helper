//! Stable-pass cache for admitted tests (bead O004; plan §102;
//! serves only what O015 classified serveable).
//!
//! V1 serves stable PASSES first — the agent inner loop's repeated
//! full-suite runs are where the latency lives. Three rules:
//!
//! - only a STABLE pass admits (first-execution pass, the O015
//!   class); a flaky retry-pass or failure REFUSES to cache, typed —
//!   there is no admission path for them;
//! - a cached pass NEVER suppresses required migrations, fixture
//!   generation, or setup side effects: serving with pending
//!   obligations returns `RunObligationsFirst` carrying them — the
//!   pass is served only after the obligations run;
//! - a miss is a miss: unknown keys and changed keys run the test.

use rabs_protocol::result_identity::TypedDigest;

use crate::test_config_keys::{TestResultClass, serveable};

/// Setup obligations a cached pass must never suppress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupObligation {
    /// A pending schema/data migration.
    Migration {
        /// Which migration.
        name: String,
    },
    /// Fixture generation the suite depends on.
    FixtureGeneration {
        /// The fixture set.
        name: String,
    },
    /// A once-per-run setup side effect (O015 batch prerequisite).
    SetupSideEffect {
        /// The effect.
        name: String,
    },
}

/// Typed admission refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotServeable {
    /// The class that tried to cache.
    pub class: TestResultClass,
}

/// The serving decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeDecision {
    /// Serve the cached stable pass.
    ServePass,
    /// Obligations pend: run THEM first, then the pass may serve —
    /// the cache never suppresses setup.
    RunObligationsFirst(Vec<SetupObligation>),
    /// No cached stable pass: run the test.
    Miss,
}

/// The stable-pass cache.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StablePassCache {
    passes: Vec<TypedDigest>,
}

impl StablePassCache {
    /// Admit a result under its O002/O015 test key.
    ///
    /// # Errors
    /// [`NotServeable`] for anything but a stable pass — flaky
    /// retry-passes and failures have no admission path.
    pub fn admit(&mut self, key: TypedDigest, class: TestResultClass) -> Result<(), NotServeable> {
        if !serveable(class) {
            return Err(NotServeable { class });
        }
        if !self.passes.contains(&key) {
            self.passes.push(key);
        }
        Ok(())
    }

    /// Decide serving for a test key with the currently pending
    /// setup obligations.
    #[must_use]
    pub fn serve(&self, key: &TypedDigest, pending: &[SetupObligation]) -> ServeDecision {
        if !self.passes.contains(key) {
            return ServeDecision::Miss;
        }
        if pending.is_empty() {
            ServeDecision::ServePass
        } else {
            ServeDecision::RunObligationsFirst(pending.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_config_keys::{ExecutionHistory, classify_result};
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn key(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.test-key.v1",
            bytes: [tag; 32],
        }
    }

    #[test]
    fn only_stable_passes_admit() {
        // THE O015 coupling: classification decides admission.
        let mut cache = StablePassCache::default();
        let stable = classify_result(&ExecutionHistory {
            executions: vec![true],
        });
        assert_eq!(cache.admit(key(1), stable), Ok(()));
        // Flaky retry-pass: refused, typed.
        let flaky = classify_result(&ExecutionHistory {
            executions: vec![false, true],
        });
        assert_eq!(
            cache.admit(key(2), flaky),
            Err(NotServeable {
                class: TestResultClass::FlakyRetryPass
            })
        );
        // Failure: refused.
        let fail = classify_result(&ExecutionHistory {
            executions: vec![false],
        });
        assert!(cache.admit(key(3), fail).is_err());
        // Only the stable pass serves; the refused ones miss.
        assert_eq!(cache.serve(&key(1), &[]), ServeDecision::ServePass);
        assert_eq!(cache.serve(&key(2), &[]), ServeDecision::Miss);
        assert_eq!(cache.serve(&key(3), &[]), ServeDecision::Miss);
    }

    #[test]
    fn a_cached_pass_never_suppresses_setup() {
        // THE setup-protection fixtures: with a pending migration,
        // fixture generation, or setup side effect, the decision is
        // RunObligationsFirst carrying them — never a bare ServePass.
        let mut cache = StablePassCache::default();
        cache
            .admit(key(1), TestResultClass::StablePass)
            .expect("admits");
        let pending = vec![
            SetupObligation::Migration {
                name: "2026-08-add-users-index".into(),
            },
            SetupObligation::FixtureGeneration {
                name: "golden-corpus".into(),
            },
            SetupObligation::SetupSideEffect {
                name: "start-test-postgres".into(),
            },
        ];
        assert_eq!(
            cache.serve(&key(1), &pending),
            ServeDecision::RunObligationsFirst(pending.clone()),
            "the cache must hand the obligations back, not skip them"
        );
        // Obligations done: the pass serves.
        assert_eq!(cache.serve(&key(1), &[]), ServeDecision::ServePass);
    }

    #[test]
    fn repeated_loop_latency_savings_are_measured() {
        // THE acceptance measurement (deterministic arithmetic): a
        // 100-test suite at 200ms/test, looped 10 times by an agent.
        const TESTS: u64 = 100;
        const RUN_MS: u64 = 200;
        const SERVE_MS: u64 = 1;
        const LOOPS: u64 = 10;
        let mut cache = StablePassCache::default();
        let mut uncached_total = 0_u64;
        let mut cached_total = 0_u64;
        for _ in 0..LOOPS {
            for t in 0..TESTS {
                uncached_total += RUN_MS;
                let k = key(u8::try_from(t % 250).expect("small"));
                match cache.serve(&k, &[]) {
                    ServeDecision::ServePass => cached_total += SERVE_MS,
                    ServeDecision::Miss => {
                        cached_total += RUN_MS;
                        cache.admit(k, TestResultClass::StablePass).expect("stable");
                    }
                    ServeDecision::RunObligationsFirst(_) => unreachable!("no obligations"),
                }
            }
        }
        // Loop 1 runs everything; loops 2..10 serve everything.
        assert_eq!(uncached_total, 200_000);
        assert_eq!(cached_total, 20_000 + 9 * 100);
        let savings_factor_x10 = uncached_total * 10 / cached_total;
        assert!(
            savings_factor_x10 >= 95,
            "expected ~9.6x savings, got {savings_factor_x10}/10"
        );
    }

    #[test]
    fn changed_keys_miss() {
        // A key change (new code, new profile, new prerequisites —
        // all folded into the O002/O015 key) is a different digest:
        // the old pass cannot serve it.
        let mut cache = StablePassCache::default();
        cache
            .admit(key(1), TestResultClass::StablePass)
            .expect("admits");
        assert_eq!(cache.serve(&key(9), &[]), ServeDecision::Miss);
    }
}
