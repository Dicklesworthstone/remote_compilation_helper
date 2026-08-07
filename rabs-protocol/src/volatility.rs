//! Volatility/effect classification (bead E013; plan §73; risk R14).
//!
//! Every observed execution gets an EFFECT CLASS describing what it
//! touched beyond its closed inputs — the shareability verdict and the
//! `rch why` explanation both hang off it. Classification is
//! evidence-driven (observation facts in, class out) and conservative:
//! the WORST observed fact decides (one ambient-network read makes the
//! whole action network-sensitive), and an observation gap classifies
//! `Unclosable`, never `Hermetic` — absence of evidence is not
//! evidence of hermeticity.
//!
//! Each class carries a stable registered reason code (F026 registry)
//! so every refusal is explainable by machine and human alike.

/// The thirteen effect classes, ordered from most to least shareable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(missing_docs)] // Plan vocabulary.
pub enum EffectClass {
    Hermetic,
    HermeticWithCapabilities,
    ObservedStable,
    PathSensitive,
    HostIdentitySensitive,
    ClockSensitive,
    RandomnessSensitive,
    GitStateSensitive,
    NetworkSensitive,
    SecretSensitive,
    SideEffecting,
    Nondeterministic,
    Unclosable,
}

impl EffectClass {
    /// All classes, for exhaustiveness checks.
    pub const ALL: [Self; 13] = [
        Self::Hermetic,
        Self::HermeticWithCapabilities,
        Self::ObservedStable,
        Self::PathSensitive,
        Self::HostIdentitySensitive,
        Self::ClockSensitive,
        Self::RandomnessSensitive,
        Self::GitStateSensitive,
        Self::NetworkSensitive,
        Self::SecretSensitive,
        Self::SideEffecting,
        Self::Nondeterministic,
        Self::Unclosable,
    ];

    /// The stable reason code for this class (SANDBOX_*/INPUT_*
    /// families; `rch why` renders these).
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Hermetic => "SANDBOX_CLASS_HERMETIC",
            Self::HermeticWithCapabilities => "SANDBOX_CLASS_HERMETIC_WITH_CAPABILITIES",
            Self::ObservedStable => "SANDBOX_CLASS_OBSERVED_STABLE",
            Self::PathSensitive => "INPUT_CLASS_PATH_SENSITIVE",
            Self::HostIdentitySensitive => "SANDBOX_CLASS_HOST_IDENTITY_SENSITIVE",
            Self::ClockSensitive => "SANDBOX_CLASS_CLOCK_SENSITIVE",
            Self::RandomnessSensitive => "SANDBOX_CLASS_RANDOMNESS_SENSITIVE",
            Self::GitStateSensitive => "INPUT_CLASS_GIT_STATE_SENSITIVE",
            Self::NetworkSensitive => "SANDBOX_CLASS_NETWORK_SENSITIVE",
            Self::SecretSensitive => "INPUT_CLASS_SECRET_SENSITIVE",
            Self::SideEffecting => "SANDBOX_CLASS_SIDE_EFFECTING",
            Self::Nondeterministic => "SANDBOX_CLASS_NONDETERMINISTIC",
            Self::Unclosable => "INPUT_CLASS_UNCLOSABLE",
        }
    }

    /// Whether results in this class may be shared fleet-wide.
    #[must_use]
    pub const fn shareable(self) -> bool {
        matches!(
            self,
            Self::Hermetic | Self::HermeticWithCapabilities | Self::ObservedStable
        )
    }
}

/// Observation facts driving classification (all default-false; the
/// observers set what they SAW — see [`classify`] for the gap rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ObservedEffects {
    /// Observation coverage was complete (no tracer gaps).
    pub observation_complete: bool,
    /// Read raw wall clock (vDSO included).
    pub read_clock: bool,
    /// Read entropy sources.
    pub read_randomness: bool,
    /// Read host identity (hostname, MAC, uname beyond presented).
    pub read_host_identity: bool,
    /// Observed real (non-canonical) paths.
    pub observed_real_paths: bool,
    /// Read live git state (HEAD, index, refs).
    pub read_git_state: bool,
    /// Touched the network beyond the deny policy.
    pub touched_network: bool,
    /// Consumed a secret value.
    pub consumed_secret: bool,
    /// Wrote outside declared outputs.
    pub wrote_outside_outputs: bool,
    /// Two identical closed runs produced different bytes.
    pub diverged_on_replay: bool,
    /// Used an approved capability grant (declared, versioned).
    pub used_approved_capability: bool,
    /// Inputs stable across repeated observation windows.
    pub inputs_observed_stable: bool,
}

/// Classify observed effects. Conservative: the worst fact wins; an
/// observation gap is `Unclosable`.
#[must_use]
pub fn classify(effects: &ObservedEffects) -> EffectClass {
    if !effects.observation_complete {
        return EffectClass::Unclosable;
    }
    // Worst-first: facts that void shareability outright.
    if effects.diverged_on_replay {
        return EffectClass::Nondeterministic;
    }
    if effects.wrote_outside_outputs {
        return EffectClass::SideEffecting;
    }
    if effects.consumed_secret {
        return EffectClass::SecretSensitive;
    }
    if effects.touched_network {
        return EffectClass::NetworkSensitive;
    }
    if effects.read_git_state {
        return EffectClass::GitStateSensitive;
    }
    if effects.read_randomness {
        return EffectClass::RandomnessSensitive;
    }
    if effects.read_clock {
        return EffectClass::ClockSensitive;
    }
    if effects.read_host_identity {
        return EffectClass::HostIdentitySensitive;
    }
    if effects.observed_real_paths {
        return EffectClass::PathSensitive;
    }
    if effects.used_approved_capability {
        return EffectClass::HermeticWithCapabilities;
    }
    if effects.inputs_observed_stable {
        return EffectClass::ObservedStable;
    }
    EffectClass::Hermetic
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closed() -> ObservedEffects {
        ObservedEffects {
            observation_complete: true,
            ..Default::default()
        }
    }

    #[test]
    fn every_class_has_a_fixture() {
        // THE acceptance: one fixture per class, exercising each arm.
        let cases: [(ObservedEffects, EffectClass); 13] = [
            (closed(), EffectClass::Hermetic),
            (
                ObservedEffects {
                    used_approved_capability: true,
                    ..closed()
                },
                EffectClass::HermeticWithCapabilities,
            ),
            (
                ObservedEffects {
                    inputs_observed_stable: true,
                    ..closed()
                },
                EffectClass::ObservedStable,
            ),
            (
                ObservedEffects {
                    observed_real_paths: true,
                    ..closed()
                },
                EffectClass::PathSensitive,
            ),
            (
                ObservedEffects {
                    read_host_identity: true,
                    ..closed()
                },
                EffectClass::HostIdentitySensitive,
            ),
            (
                ObservedEffects {
                    read_clock: true,
                    ..closed()
                },
                EffectClass::ClockSensitive,
            ),
            (
                ObservedEffects {
                    read_randomness: true,
                    ..closed()
                },
                EffectClass::RandomnessSensitive,
            ),
            (
                ObservedEffects {
                    read_git_state: true,
                    ..closed()
                },
                EffectClass::GitStateSensitive,
            ),
            (
                ObservedEffects {
                    touched_network: true,
                    ..closed()
                },
                EffectClass::NetworkSensitive,
            ),
            (
                ObservedEffects {
                    consumed_secret: true,
                    ..closed()
                },
                EffectClass::SecretSensitive,
            ),
            (
                ObservedEffects {
                    wrote_outside_outputs: true,
                    ..closed()
                },
                EffectClass::SideEffecting,
            ),
            (
                ObservedEffects {
                    diverged_on_replay: true,
                    ..closed()
                },
                EffectClass::Nondeterministic,
            ),
            (ObservedEffects::default(), EffectClass::Unclosable),
        ];
        for (effects, expected) in cases {
            assert_eq!(classify(&effects), expected);
        }
    }

    #[test]
    fn worst_fact_wins_and_gaps_never_classify_hermetic() {
        // Clock AND network: network (worse) decides.
        let both = ObservedEffects {
            read_clock: true,
            touched_network: true,
            ..closed()
        };
        assert_eq!(classify(&both), EffectClass::NetworkSensitive);
        // An observation GAP with otherwise-clean facts: Unclosable —
        // absence of evidence is not evidence of hermeticity.
        let gap = ObservedEffects {
            observation_complete: false,
            ..Default::default()
        };
        assert_eq!(classify(&gap), EffectClass::Unclosable);
    }

    #[test]
    fn reason_codes_are_stable_prefixed_and_distinct() {
        let mut codes: Vec<&str> = EffectClass::ALL.iter().map(|c| c.reason_code()).collect();
        for code in &codes {
            assert!(
                code.starts_with("SANDBOX_") || code.starts_with("INPUT_"),
                "{code}: classes explain via SANDBOX_*/INPUT_* families"
            );
        }
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(before, codes.len());
    }

    #[test]
    fn only_the_top_three_classes_share() {
        let shareable: Vec<EffectClass> = EffectClass::ALL
            .into_iter()
            .filter(|c| c.shareable())
            .collect();
        assert_eq!(
            shareable,
            [
                EffectClass::Hermetic,
                EffectClass::HermeticWithCapabilities,
                EffectClass::ObservedStable
            ]
        );
    }
}
