//! Test input/side-effect observation (bead O003; plan §102).
//!
//! A test result is serveable only when every input the test read is
//! part of its key and every side effect is declared. This module is
//! the observation record: what a supervised test run captured, per
//! category, and how each category folds into the key:
//!
//! - POSITIVE inputs: fixtures/snapshots/goldens read, env/config
//!   files, dynamically loaded libraries, subprocess selection;
//! - NEGATIVE inputs: failed opens and directory listings are
//!   ABSENCE EVIDENCE — a test that probed for a file and found
//!   nothing depends on that nothing (creating the file later must
//!   miss);
//! - VOLATILE access: network, clock, entropy — any occurrence
//!   downgrades the result to observation-only (never served as an
//!   authoritative pass; couples to the E013 volatility classes);
//! - DECLARED side effects: output/state directories the test is
//!   allowed to write; they key the action and scope the capture.
//!
//! Category tags are wire-stable and pinned by test.

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for a test observation record.
pub const DOMAIN_TEST_OBSERVATION: &str = "rabs.test-observation.v1";

/// One observed input (positive or negative). Wire tags in comments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedInput {
    /// Fixture/snapshot/golden read (tag 1).
    FixtureRead {
        /// Virtual path read.
        path: String,
        /// Content identity.
        digest: TypedDigest,
    },
    /// Failed open: the test probed and found ABSENCE (tag 2).
    FailedOpen {
        /// Virtual path probed.
        path: String,
    },
    /// Directory listing: the entry set is the input (tag 3).
    DirListing {
        /// Virtual directory path.
        path: String,
        /// Digest over the sorted entry names.
        entries_digest: TypedDigest,
    },
    /// Environment variable read (tag 4).
    EnvRead {
        /// Variable name.
        name: String,
        /// Value observed (`None` = unset — absence evidence too).
        value: Option<String>,
    },
    /// Config file read (tag 5).
    ConfigRead {
        /// Virtual path.
        path: String,
        /// Content identity.
        digest: TypedDigest,
    },
    /// Dynamically loaded library (tag 6).
    DynamicLibrary {
        /// Virtual path loaded.
        path: String,
        /// Content identity.
        digest: TypedDigest,
    },
    /// Subprocess spawned: WHICH program, with what argv (tag 7).
    SubprocessSpawn {
        /// Resolved program identity (content digest of the binary).
        program: TypedDigest,
        /// Digest over the canonical argv.
        argv_digest: TypedDigest,
    },
}

impl ObservedInput {
    /// The wire-stable category tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::FixtureRead { .. } => 1,
            Self::FailedOpen { .. } => 2,
            Self::DirListing { .. } => 3,
            Self::EnvRead { .. } => 4,
            Self::ConfigRead { .. } => 5,
            Self::DynamicLibrary { .. } => 6,
            Self::SubprocessSpawn { .. } => 7,
        }
    }

    fn encode(&self, enc: &mut CanonicalEncoder) {
        enc.u32(u32::from(self.tag()));
        match self {
            Self::FixtureRead { path, digest } | Self::ConfigRead { path, digest } => {
                enc.str(path).bytes(&digest.bytes);
            }
            Self::FailedOpen { path } => {
                enc.str(path);
            }
            Self::DirListing {
                path,
                entries_digest,
            } => {
                enc.str(path).bytes(&entries_digest.bytes);
            }
            Self::EnvRead { name, value } => {
                enc.str(name);
                match value {
                    Some(v) => enc.bool(true).str(v),
                    None => enc.bool(false),
                };
            }
            Self::DynamicLibrary { path, digest } => {
                enc.str(path).bytes(&digest.bytes);
            }
            Self::SubprocessSpawn {
                program,
                argv_digest,
            } => {
                enc.bytes(&program.bytes).bytes(&argv_digest.bytes);
            }
        }
    }
}

/// A volatile access (network/clock/entropy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolatileAccess {
    /// Network access to an endpoint.
    Network {
        /// Endpoint contacted.
        endpoint: String,
    },
    /// Wall-clock read.
    Clock,
    /// Entropy source read.
    Entropy,
}

/// A declared side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclaredSideEffect {
    /// Declared output directory.
    OutputDir {
        /// Virtual path.
        path: String,
    },
    /// Declared mutable state directory.
    StateDir {
        /// Virtual path.
        path: String,
    },
}

/// The full observation record for one test action.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestObservation {
    /// Every observed input, positive and negative.
    pub inputs: Vec<ObservedInput>,
    /// Volatile accesses (any occurrence downgrades serving).
    pub volatile: Vec<VolatileAccess>,
    /// Declared side effects.
    pub side_effects: Vec<DeclaredSideEffect>,
}

/// How the observed result may be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServingClass {
    /// Every input keyed, no volatility: serveable.
    Serveable,
    /// Volatile access occurred: an observation to report, never an
    /// authoritative pass (the first offending access named).
    ObservationOnly(VolatileAccess),
}

impl TestObservation {
    /// The observation digest: every input and declared side effect,
    /// in observation order.
    #[must_use]
    pub fn digest(&self) -> TypedDigest {
        let mut enc = CanonicalEncoder::new();
        enc.u32(u32::try_from(self.inputs.len()).unwrap_or(u32::MAX));
        for input in &self.inputs {
            input.encode(&mut enc);
        }
        enc.u32(u32::try_from(self.side_effects.len()).unwrap_or(u32::MAX));
        for effect in &self.side_effects {
            match effect {
                DeclaredSideEffect::OutputDir { path } => enc.u32(1).str(path),
                DeclaredSideEffect::StateDir { path } => enc.u32(2).str(path),
            };
        }
        compute(DOMAIN_TEST_OBSERVATION, &enc.finish())
    }

    /// Serving classification: any volatile access downgrades.
    #[must_use]
    pub fn serving_class(&self) -> ServingClass {
        self.volatile.first().map_or(ServingClass::Serveable, |v| {
            ServingClass::ObservationOnly(v.clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        }
    }

    /// One observation exercising EVERY input category (the per-
    /// category acceptance fixture).
    fn full_observation() -> TestObservation {
        TestObservation {
            inputs: vec![
                ObservedInput::FixtureRead {
                    path: "/__rabs/workspace/tests/golden/out.json".into(),
                    digest: d(1),
                },
                ObservedInput::FailedOpen {
                    path: "/__rabs/workspace/.env.local".into(),
                },
                ObservedInput::DirListing {
                    path: "/__rabs/workspace/tests/cases".into(),
                    entries_digest: d(2),
                },
                ObservedInput::EnvRead {
                    name: "RUST_LOG".into(),
                    value: None, // unset is evidence too
                },
                ObservedInput::ConfigRead {
                    path: "/__rabs/workspace/config.toml".into(),
                    digest: d(3),
                },
                ObservedInput::DynamicLibrary {
                    path: "/__rabs/toolchain/lib/libssl.so.3".into(),
                    digest: d(4),
                },
                ObservedInput::SubprocessSpawn {
                    program: d(5),
                    argv_digest: d(6),
                },
            ],
            volatile: vec![],
            side_effects: vec![
                DeclaredSideEffect::OutputDir {
                    path: "/__rabs/outputs/test-artifacts".into(),
                },
                DeclaredSideEffect::StateDir {
                    path: "/__rabs/state/test-scratch".into(),
                },
            ],
        }
    }

    #[test]
    fn every_category_is_captured_and_keyed() {
        // THE acceptance: one fixture per category, and mutating ANY
        // category's observation forks the digest.
        let base = full_observation();
        let base_digest = base.digest();
        assert_eq!(base.inputs.len(), 7, "all seven input categories");
        for i in 0..base.inputs.len() {
            let mut m = base.clone();
            m.inputs.remove(i);
            assert_ne!(
                base_digest,
                m.digest(),
                "dropping input category {} must fork the key",
                base.inputs[i].tag()
            );
        }
        // Side-effect declarations are keyed too.
        let mut m = base.clone();
        m.side_effects.pop();
        assert_ne!(base_digest, m.digest());
        // And a content change inside a category forks.
        let mut m = base;
        m.inputs[0] = ObservedInput::FixtureRead {
            path: "/__rabs/workspace/tests/golden/out.json".into(),
            digest: d(9), // regenerated golden
        };
        assert_ne!(base_digest, m.digest());
    }

    #[test]
    fn absence_evidence_is_a_real_input() {
        // A failed open keys the result: creating the file later is a
        // DIFFERENT observation (the probe would succeed), so the old
        // pass cannot serve.
        let base = full_observation();
        let mut with_file = base.clone();
        with_file.inputs[1] = ObservedInput::FixtureRead {
            path: "/__rabs/workspace/.env.local".into(),
            digest: d(7), // the file now exists and was read
        };
        assert_ne!(base.digest(), with_file.digest());
        // Same for env: unset vs set are distinct observations.
        let mut env_set = base.clone();
        env_set.inputs[3] = ObservedInput::EnvRead {
            name: "RUST_LOG".into(),
            value: Some("debug".into()),
        };
        assert_ne!(base.digest(), env_set.digest());
        // And a directory listing keys its entry SET.
        let mut listed = base.clone();
        listed.inputs[2] = ObservedInput::DirListing {
            path: "/__rabs/workspace/tests/cases".into(),
            entries_digest: d(8), // a case file appeared
        };
        assert_ne!(base.digest(), listed.digest());
    }

    #[test]
    fn volatile_access_downgrades_serving() {
        // Network/clock/entropy: ANY access means observation-only.
        let clean = full_observation();
        assert_eq!(clean.serving_class(), ServingClass::Serveable);
        for access in [
            VolatileAccess::Network {
                endpoint: "api.example.com:443".into(),
            },
            VolatileAccess::Clock,
            VolatileAccess::Entropy,
        ] {
            let mut tainted = full_observation();
            tainted.volatile.push(access.clone());
            assert_eq!(
                tainted.serving_class(),
                ServingClass::ObservationOnly(access),
                "the first offending access is named"
            );
        }
    }

    #[test]
    fn category_tags_are_wire_stable() {
        // Pinned: reordering these renumbers persisted observations.
        let obs = full_observation();
        let tags: Vec<u8> = obs.inputs.iter().map(ObservedInput::tag).collect();
        assert_eq!(tags, [1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn subprocess_selection_is_keyed_by_identity_not_name() {
        // The spawned program is keyed by CONTENT digest: a different
        // binary at the same name is a different observation.
        let base = full_observation();
        let mut m = base.clone();
        m.inputs[6] = ObservedInput::SubprocessSpawn {
            program: d(9), // same $PATH name, different binary
            argv_digest: d(6),
        };
        assert_ne!(base.digest(), m.digest());
    }
}
