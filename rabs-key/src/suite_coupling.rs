//! Suite-order/shared-state coupling detection → batch or bypass
//! (bead O014; plan §102; risk R69).
//!
//! Per-test caching is only sound when tests are independent. The
//! detector folds suite-level facts into typed coupling signals, and
//! the router forces the sound execution shape:
//!
//! - once-per-suite initializers, ordering dependence, shared
//!   DB/port/temp roots, and setup/teardown side effects route to
//!   `TestBinaryBatch` — the suite runs as ONE action whose key
//!   INCLUDES the coupled state (a state change forks the batch);
//! - global EXTERNAL state routes to `Bypass` — state the key cannot
//!   close over is never cached at all;
//! - an uncoupled suite keeps per-test caching (the control);
//! - a cached per-test pass can never skip required suite
//!   initialization: `per_test_serving_allowed` is true ONLY in the
//!   per-test arm — the batch and bypass arms structurally have no
//!   per-test serving to offer.

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for the coupled-state key component.
pub const DOMAIN_SUITE_COUPLING: &str = "rabs.suite-coupling.v1";

/// One detected coupling signal (wire tags in `tag`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CouplingSignal {
    /// A once-per-suite initializer (tag 1).
    OncePerSuiteInitializer {
        /// Initializer name.
        name: String,
    },
    /// Result depends on execution order (tag 2).
    OrderingDependence {
        /// The witnessing pair: (earlier, later) whose swap diverged.
        witness: (String, String),
    },
    /// A database file shared across tests (tag 3).
    SharedDatabase {
        /// The path.
        path: String,
    },
    /// A network port shared across tests (tag 4).
    SharedPort {
        /// The port.
        port: u16,
    },
    /// A temp root shared across tests (tag 5).
    SharedTempRoot {
        /// The path.
        path: String,
    },
    /// Global EXTERNAL state (tag 6): un-keyable — bypass.
    GlobalExternalState {
        /// What.
        subject: String,
    },
    /// Setup/teardown side effects (tag 7).
    SetupTeardownSideEffect {
        /// The effect.
        name: String,
    },
}

impl CouplingSignal {
    /// Wire-stable tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::OncePerSuiteInitializer { .. } => 1,
            Self::OrderingDependence { .. } => 2,
            Self::SharedDatabase { .. } => 3,
            Self::SharedPort { .. } => 4,
            Self::SharedTempRoot { .. } => 5,
            Self::GlobalExternalState { .. } => 6,
            Self::SetupTeardownSideEffect { .. } => 7,
        }
    }

    fn encode(&self, enc: &mut CanonicalEncoder) {
        enc.u32(u32::from(self.tag()));
        match self {
            Self::OncePerSuiteInitializer { name } | Self::SetupTeardownSideEffect { name } => {
                enc.str(name);
            }
            Self::OrderingDependence { witness } => {
                enc.str(&witness.0).str(&witness.1);
            }
            Self::SharedDatabase { path } | Self::SharedTempRoot { path } => {
                enc.str(path);
            }
            Self::SharedPort { port } => {
                enc.u32(u32::from(*port));
            }
            Self::GlobalExternalState { subject } => {
                enc.str(subject);
            }
        }
    }
}

/// The routing decision for a suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteRouting {
    /// Independent tests: per-test caching stays sound.
    PerTestCaching,
    /// Coupled: the suite runs as ONE batch action whose key
    /// includes the coupled-state digest.
    TestBinaryBatch {
        /// Digest over every coupling signal (a state change forks).
        coupled_state: TypedDigest,
    },
    /// Un-keyable external state: never cached at all.
    Bypass {
        /// The offending subject.
        subject: String,
    },
}

impl SuiteRouting {
    /// Whether individual cached test passes may serve. TRUE only
    /// for the per-test arm: batch and bypass have no per-test
    /// serving to offer — a cached pass cannot skip suite init.
    #[must_use]
    pub const fn per_test_serving_allowed(&self) -> bool {
        matches!(self, Self::PerTestCaching)
    }
}

/// Route a suite from its detected signals.
#[must_use]
pub fn route(signals: &[CouplingSignal]) -> SuiteRouting {
    // External state first: it cannot be keyed, so batching would
    // still be unsound.
    if let Some(CouplingSignal::GlobalExternalState { subject }) = signals
        .iter()
        .find(|s| matches!(s, CouplingSignal::GlobalExternalState { .. }))
    {
        return SuiteRouting::Bypass {
            subject: subject.clone(),
        };
    }
    if signals.is_empty() {
        return SuiteRouting::PerTestCaching;
    }
    let mut enc = CanonicalEncoder::new();
    enc.u32(u32::try_from(signals.len()).unwrap_or(u32::MAX));
    for signal in signals {
        signal.encode(&mut enc);
    }
    SuiteRouting::TestBinaryBatch {
        coupled_state: compute(DOMAIN_SUITE_COUPLING, &enc.finish()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_coupling_fixture_routes_to_batch() {
        // THE acceptance fixtures: every batchable coupling kind
        // forces the batch shape.
        let batchable: [CouplingSignal; 6] = [
            CouplingSignal::OncePerSuiteInitializer {
                name: "init_test_db".into(),
            },
            CouplingSignal::OrderingDependence {
                witness: ("test_create_user".into(), "test_list_users".into()),
            },
            CouplingSignal::SharedDatabase {
                path: "/__rabs/state/suite.db".into(),
            },
            CouplingSignal::SharedPort { port: 5432 },
            CouplingSignal::SharedTempRoot {
                path: "/__rabs/state/tmp-shared".into(),
            },
            CouplingSignal::SetupTeardownSideEffect {
                name: "truncate_tables".into(),
            },
        ];
        for signal in batchable {
            let routing = route(std::slice::from_ref(&signal));
            assert!(
                matches!(routing, SuiteRouting::TestBinaryBatch { .. }),
                "{signal:?} must route to batch"
            );
            assert!(!routing.per_test_serving_allowed());
        }
    }

    #[test]
    fn global_external_state_bypasses_even_alongside_batchable_signals() {
        // External state cannot be keyed: bypass wins over batch.
        let signals = [
            CouplingSignal::OncePerSuiteInitializer {
                name: "init".into(),
            },
            CouplingSignal::GlobalExternalState {
                subject: "corporate-ldap".into(),
            },
        ];
        assert_eq!(
            route(&signals),
            SuiteRouting::Bypass {
                subject: "corporate-ldap".into(),
            }
        );
    }

    #[test]
    fn the_batch_key_includes_the_coupled_state() {
        // A state change forks the batch key.
        let base = route(&[CouplingSignal::SharedDatabase {
            path: "/__rabs/state/suite.db".into(),
        }]);
        let moved = route(&[CouplingSignal::SharedDatabase {
            path: "/__rabs/state/other.db".into(),
        }]);
        let extra = route(&[
            CouplingSignal::SharedDatabase {
                path: "/__rabs/state/suite.db".into(),
            },
            CouplingSignal::SharedPort { port: 6379 },
        ]);
        let (
            SuiteRouting::TestBinaryBatch { coupled_state: a },
            SuiteRouting::TestBinaryBatch { coupled_state: b },
            SuiteRouting::TestBinaryBatch { coupled_state: c },
        ) = (base, moved, extra)
        else {
            panic!("all batch");
        };
        assert_ne!(a, b, "a different shared path is different state");
        assert_ne!(a, c, "an added coupling is different state");
    }

    #[test]
    fn uncoupled_suites_keep_per_test_caching() {
        let routing = route(&[]);
        assert_eq!(routing, SuiteRouting::PerTestCaching);
        assert!(routing.per_test_serving_allowed());
    }

    #[test]
    fn cached_passes_cannot_skip_suite_initialization() {
        // Structural: per-test serving exists ONLY in the per-test
        // arm — the exhaustive match proves batch/bypass offer none.
        let routed = route(&[CouplingSignal::OncePerSuiteInitializer {
            name: "migrate".into(),
        }]);
        match &routed {
            SuiteRouting::PerTestCaching => panic!("initializer must not stay per-test"),
            SuiteRouting::TestBinaryBatch { .. } | SuiteRouting::Bypass { .. } => {
                assert!(!routed.per_test_serving_allowed());
            }
        }
    }
}
