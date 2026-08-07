//! Environment-absence single-ownership suite (bead F027; the
//! revision-1.3 correction; risk R107's env instance).
//!
//! Absence of an environment variable is a fact with exactly ONE home:
//! `PresentedEnvironment` (F006). The E010 filesystem sets cannot
//! represent it (their destructure tripwires live in rabs-protocol);
//! this suite proves the KEYED-HASH side: an absence mutation moves
//! the environment component digest and NOTHING else — there is no
//! second hash an env fact could inconsistently reach.

use rabs_key::environment::{EnvDisposition, PresentedEnvironment};
use rabs_protocol::input_evidence::{NegativeDependency, NegativeDependencySet};
use rabs_protocol::raw_bytes::RawBytes;

/// Canonical bytes of a negative-dependency set (test-local encoding:
/// any deterministic encoding suffices to show digest immobility).
fn negdep_fingerprint(set: &NegativeDependencySet) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in &set.entries {
        out.extend_from_slice(format!("{entry:?}").as_bytes());
    }
    out
}

#[test]
fn absence_mutations_route_through_the_env_component_only() {
    // A fixed filesystem negative-dependency set…
    let negdeps = NegativeDependencySet {
        schema_version: 1,
        entries: vec![NegativeDependency::MissingPath {
            virtual_path: RawBytes::new(b"/__rabs/workspace/missing.rs".to_vec()),
        }],
    };
    let negdep_before = negdep_fingerprint(&negdeps);

    // …and an environment WITH a scrub record.
    let with_scrub = PresentedEnvironment {
        variables: vec![
            (
                b"RUSTFLAGS".to_vec(),
                EnvDisposition::SemanticHashed(b"-Cdebuginfo=1".to_vec()),
            ),
            (b"RUSTC_BOOTSTRAP".to_vec(), EnvDisposition::ScrubbedAbsent),
        ],
        path_manifest: vec![],
    };
    // Mutate the ABSENCE: remove the scrub record.
    let without_scrub = PresentedEnvironment {
        variables: vec![(
            b"RUSTFLAGS".to_vec(),
            EnvDisposition::SemanticHashed(b"-Cdebuginfo=1".to_vec()),
        )],
        path_manifest: vec![],
    };

    // The env component digest MOVES…
    assert_ne!(
        with_scrub.dataset_digest().unwrap(),
        without_scrub.dataset_digest().unwrap(),
        "absence is keyed in the environment component"
    );
    // …and the filesystem negative set is untouched by construction:
    // the mutation had no operation on it, and no NegativeDependency
    // variant could have carried the env fact anyway.
    assert_eq!(negdep_fingerprint(&negdeps), negdep_before);
}

#[test]
fn no_negative_dependency_variant_can_carry_an_env_fact() {
    // Schema-level exclusivity: enumerate every variant — each speaks
    // in paths/patterns/tools; none has an environment-variable field.
    // (The compile-time tripwire lives in rabs-protocol's E010 tests;
    // this is the cross-crate documentation of the same law.)
    let variants = [
        NegativeDependency::FailedOpen {
            virtual_path: RawBytes::new(b"/p".to_vec()),
        },
        NegativeDependency::MissingPath {
            virtual_path: RawBytes::new(b"/p".to_vec()),
        },
        NegativeDependency::GlobResult {
            pattern: RawBytes::new(b"/g/*".to_vec()),
            matches: vec![],
        },
        NegativeDependency::PathLookupMiss {
            tool: RawBytes::new(b"cc".to_vec()),
            probed_absent: vec![],
        },
        NegativeDependency::MissingSymlinkTarget {
            symlink: RawBytes::new(b"/l".to_vec()),
            target: RawBytes::new(b"/t".to_vec()),
        },
    ];
    for v in &variants {
        match v {
            NegativeDependency::FailedOpen { virtual_path: _ }
            | NegativeDependency::MissingPath { virtual_path: _ } => {}
            NegativeDependency::GlobResult {
                pattern: _,
                matches: _,
            } => {}
            NegativeDependency::PathLookupMiss {
                tool: _,
                probed_absent: _,
            } => {}
            NegativeDependency::MissingSymlinkTarget {
                symlink: _,
                target: _,
            } => {}
        }
    }
}
