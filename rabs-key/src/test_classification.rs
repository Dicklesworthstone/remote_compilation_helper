//! Deterministic-failure and flaky evidence classifications (bead
//! O005; plan §102; extends the O015 pass/fail rule with the full
//! evidence taxonomy).
//!
//! Eight evidence classes with wire-stable tags, assigned by strict
//! precedence (the most disqualifying fact wins):
//!
//! quarantined, then side-effecting, then network-sensitive, then
//! timing-sensitive, then environment-sensitive, then flaky, and
//! only a clean history classifies as a stable pass or failure.
//!
//! Deterministic-FAILURE serving is a LATER OPT-IN: the policy
//! defaults off (typed refusal), and even opted in it serves only
//! `ObservedStableFailure`, only within a short TTL — flaky results
//! never serve under any policy.

/// The eight evidence classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum TestEvidenceClass {
    ObservedStablePass,
    ObservedStableFailure,
    FlakyOutcome,
    TimingSensitive,
    NetworkSensitive,
    EnvironmentSensitive,
    SideEffecting,
    Quarantined,
}

impl TestEvidenceClass {
    /// Wire-stable tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::ObservedStablePass => 1,
            Self::ObservedStableFailure => 2,
            Self::FlakyOutcome => 3,
            Self::TimingSensitive => 4,
            Self::NetworkSensitive => 5,
            Self::EnvironmentSensitive => 6,
            Self::SideEffecting => 7,
            Self::Quarantined => 8,
        }
    }
}

/// The evidence a supervised run gathered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassificationEvidence {
    /// Per-execution pass/fail, in order.
    pub executions: Vec<bool>,
    /// Result differed under timing perturbation (witnessed).
    pub timing_witness: bool,
    /// Network access observed (O003).
    pub network_observed: bool,
    /// Result differed under an environment change (witnessed).
    pub environment_witness: bool,
    /// O012 cache-denial (side effects) present.
    pub side_effecting: bool,
    /// Operator/incident quarantine in force.
    pub quarantined: bool,
}

/// Classify evidence by strict precedence.
#[must_use]
pub fn classify(evidence: &ClassificationEvidence) -> TestEvidenceClass {
    if evidence.quarantined {
        return TestEvidenceClass::Quarantined;
    }
    if evidence.side_effecting {
        return TestEvidenceClass::SideEffecting;
    }
    if evidence.network_observed {
        return TestEvidenceClass::NetworkSensitive;
    }
    if evidence.timing_witness {
        return TestEvidenceClass::TimingSensitive;
    }
    if evidence.environment_witness {
        return TestEvidenceClass::EnvironmentSensitive;
    }
    let passes = evidence.executions.iter().filter(|p| **p).count();
    if passes == 0 {
        TestEvidenceClass::ObservedStableFailure
    } else if passes == evidence.executions.len() {
        TestEvidenceClass::ObservedStablePass
    } else {
        TestEvidenceClass::FlakyOutcome
    }
}

/// Failure-serving policy (a LATER opt-in; default off).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FailureServingPolicy {
    /// Operator opt-in (default false).
    pub enabled: bool,
    /// TTL in observation windows.
    pub ttl_windows: u32,
}

/// Typed refusal for failure serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureServeRefusal {
    /// The opt-in has not been granted.
    NotOptedIn,
    /// The class is not a stable deterministic failure.
    NotAStableFailure(TestEvidenceClass),
    /// The cached failure aged past the TTL.
    TtlExpired {
        /// Windows since caching.
        age_windows: u32,
        /// The TTL.
        ttl_windows: u32,
    },
}

/// Decide whether a cached FAILURE may serve.
///
/// # Errors
/// [`FailureServeRefusal`] — the default posture.
pub fn serve_failure(
    class: TestEvidenceClass,
    policy: FailureServingPolicy,
    age_windows: u32,
) -> Result<(), FailureServeRefusal> {
    if !policy.enabled {
        return Err(FailureServeRefusal::NotOptedIn);
    }
    if class != TestEvidenceClass::ObservedStableFailure {
        return Err(FailureServeRefusal::NotAStableFailure(class));
    }
    if age_windows >= policy.ttl_windows {
        return Err(FailureServeRefusal::TtlExpired {
            age_windows,
            ttl_windows: policy.ttl_windows,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runs(executions: &[bool]) -> ClassificationEvidence {
        ClassificationEvidence {
            executions: executions.to_vec(),
            ..ClassificationEvidence::default()
        }
    }

    #[test]
    fn one_fixture_per_class_with_pinned_tags() {
        // THE classification fixtures: all eight classes reachable.
        let cases: [(ClassificationEvidence, TestEvidenceClass, u8); 8] = [
            (
                runs(&[true, true, true]),
                TestEvidenceClass::ObservedStablePass,
                1,
            ),
            (
                runs(&[false, false]),
                TestEvidenceClass::ObservedStableFailure,
                2,
            ),
            (
                runs(&[true, false, true]),
                TestEvidenceClass::FlakyOutcome,
                3,
            ),
            (
                ClassificationEvidence {
                    executions: vec![true],
                    timing_witness: true,
                    ..ClassificationEvidence::default()
                },
                TestEvidenceClass::TimingSensitive,
                4,
            ),
            (
                ClassificationEvidence {
                    executions: vec![true],
                    network_observed: true,
                    ..ClassificationEvidence::default()
                },
                TestEvidenceClass::NetworkSensitive,
                5,
            ),
            (
                ClassificationEvidence {
                    executions: vec![true],
                    environment_witness: true,
                    ..ClassificationEvidence::default()
                },
                TestEvidenceClass::EnvironmentSensitive,
                6,
            ),
            (
                ClassificationEvidence {
                    executions: vec![true],
                    side_effecting: true,
                    ..ClassificationEvidence::default()
                },
                TestEvidenceClass::SideEffecting,
                7,
            ),
            (
                ClassificationEvidence {
                    executions: vec![true],
                    quarantined: true,
                    ..ClassificationEvidence::default()
                },
                TestEvidenceClass::Quarantined,
                8,
            ),
        ];
        for (evidence, expected, tag) in cases {
            let class = classify(&evidence);
            assert_eq!(class, expected);
            assert_eq!(class.tag(), tag, "wire tag pinned");
        }
    }

    #[test]
    fn seeded_flaky_tests_are_detected() {
        // THE flaky-detection acceptance: a splitmix64-seeded test
        // that fails ~30% of runs over 20 executions classifies
        // FlakyOutcome; all-pass and all-fail controls do not.
        let mut state = 0x5EED_u64;
        let mut next = move || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let flaky: Vec<bool> = (0..20).map(|_| next() % 10 >= 3).collect();
        assert!(flaky.iter().any(|p| *p) && flaky.iter().any(|p| !*p));
        assert_eq!(classify(&runs(&flaky)), TestEvidenceClass::FlakyOutcome);
        assert_eq!(
            classify(&runs(&[true; 20])),
            TestEvidenceClass::ObservedStablePass
        );
        assert_eq!(
            classify(&runs(&[false; 20])),
            TestEvidenceClass::ObservedStableFailure
        );
    }

    #[test]
    fn precedence_is_strict_most_disqualifying_wins() {
        // A quarantined, side-effecting, network-touching flaky test
        // is QUARANTINED — full stack present, top wins.
        let everything = ClassificationEvidence {
            executions: vec![true, false],
            timing_witness: true,
            network_observed: true,
            environment_witness: true,
            side_effecting: true,
            quarantined: true,
        };
        assert_eq!(classify(&everything), TestEvidenceClass::Quarantined);
        // Peel layers: side-effect beats network beats timing beats
        // environment beats flaky.
        let mut e = everything;
        e.quarantined = false;
        assert_eq!(classify(&e), TestEvidenceClass::SideEffecting);
        e.side_effecting = false;
        assert_eq!(classify(&e), TestEvidenceClass::NetworkSensitive);
        e.network_observed = false;
        assert_eq!(classify(&e), TestEvidenceClass::TimingSensitive);
        e.timing_witness = false;
        assert_eq!(classify(&e), TestEvidenceClass::EnvironmentSensitive);
        e.environment_witness = false;
        assert_eq!(classify(&e), TestEvidenceClass::FlakyOutcome);
    }

    #[test]
    fn failure_serving_is_a_later_opt_in_with_short_ttl() {
        // Default posture: refused, typed.
        assert_eq!(
            serve_failure(
                TestEvidenceClass::ObservedStableFailure,
                FailureServingPolicy::default(),
                0
            ),
            Err(FailureServeRefusal::NotOptedIn)
        );
        // Opted in: serves ONLY the stable failure, within TTL.
        let policy = FailureServingPolicy {
            enabled: true,
            ttl_windows: 3,
        };
        assert_eq!(
            serve_failure(TestEvidenceClass::ObservedStableFailure, policy, 2),
            Ok(())
        );
        // Flaky NEVER serves, opt-in or not.
        assert_eq!(
            serve_failure(TestEvidenceClass::FlakyOutcome, policy, 0),
            Err(FailureServeRefusal::NotAStableFailure(
                TestEvidenceClass::FlakyOutcome
            ))
        );
        // TTL boundary: age == ttl refuses.
        assert_eq!(
            serve_failure(TestEvidenceClass::ObservedStableFailure, policy, 3),
            Err(FailureServeRefusal::TtlExpired {
                age_windows: 3,
                ttl_windows: 3,
            })
        );
    }
}
