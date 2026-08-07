//! Workspace dependency-artifact inputs + gated projections (bead
//! M003; plan §100; the F009/F010/F022 machinery applied at the
//! workspace level).
//!
//! Workspace crates consume upstream artifacts under the F009
//! conservative exact identity, and reduced projections exist ONLY
//! through the F010 gauntlet with the F022 runtime rollback — no
//! workspace-specific shortcut path exists. This suite proves the
//! acceptance at workspace scale, LTO configurations included.

use rabs_key::dependency_identity::{ConsumedArtifact, DependencyInputs};
use rabs_key::dependency_projection::{
    FallbackCause, ProjectionDecision, ProjectionExtractor, ShadowCorpusStatus, classify_flags,
    decide_projection, effective_inputs,
};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

fn d(tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: "rabs.dep-artifact.v1",
        bytes: [tag; 32],
    }
}

/// A workspace member's upstream consumption: two path-dep siblings'
/// rmetas plus a registry dependency's rlib.
fn member_inputs(sibling_a: u8, sibling_b: u8, registry: u8) -> DependencyInputs {
    DependencyInputs {
        compile_inputs: vec![
            ConsumedArtifact::RmetaBytes(d(sibling_a)),
            ConsumedArtifact::RmetaBytes(d(sibling_b)),
            ConsumedArtifact::RlibBytes(d(registry)),
        ],
        ..Default::default()
    }
}

#[test]
fn workspace_members_consume_upstreams_under_exact_identity() {
    // A sibling's implementation-only edit reproducing a byte-identical
    // .rmeta: the member's dependency identity is UNCHANGED (the F009
    // early cutoff at workspace scale).
    let before = member_inputs(1, 2, 3);
    let after_impl_only = member_inputs(1, 2, 3);
    assert_eq!(before.inputs_digest(), after_impl_only.inputs_digest());
    // A sibling API change (different rmeta bytes) invalidates.
    let after_api_change = member_inputs(9, 2, 3);
    assert_ne!(before.inputs_digest(), after_api_change.inputs_digest());
    // The registry dependency participates identically.
    let after_registry_bump = member_inputs(1, 2, 9);
    assert_ne!(before.inputs_digest(), after_registry_bump.inputs_digest());
}

#[test]
fn lto_configurations_stay_exact_and_refuse_projections() {
    // THE LTO acceptance: a workspace member built with -C lto=thin —
    // the projection framework auto-refuses (ambiguous flags), so the
    // member keys on the EXACT F009 identity, with the fallback being
    // byte-for-byte the exact inputs.
    let exact = member_inputs(1, 2, 3);
    let lto_flags = vec![("lto".to_owned(), Some("thin".to_owned()))];
    let decision = decide_projection(
        classify_flags(&lto_flags, &[]),
        Some(&ProjectionExtractor {
            name: "rlib-metadata-member".into(),
            version: 1,
            schema_version: 1,
        }),
        ShadowCorpusStatus::ZeroDivergence,
        &ConsumedArtifact::RmetaBytes(d(1)),
    );
    assert_eq!(
        decision,
        ProjectionDecision::ExactFallback {
            because: FallbackCause::AmbiguousFlags
        }
    );
    let (inputs, epoch) = effective_inputs(&decision, &exact);
    assert_eq!(inputs, exact, "the LTO fallback IS the exact identity");
    assert_eq!(epoch, 1, "exact namespace");
    // Under LTO, every consumed bitcode/rlib component enters
    // individually (the F009 rule at workspace scale).
    let lto_inputs = DependencyInputs {
        link_inputs: vec![
            ConsumedArtifact::LtoComponent(d(1)),
            ConsumedArtifact::LtoComponent(d(2)),
            ConsumedArtifact::LtoComponent(d(3)),
        ],
        ..Default::default()
    };
    let one_component_changed = DependencyInputs {
        link_inputs: vec![
            ConsumedArtifact::LtoComponent(d(1)),
            ConsumedArtifact::LtoComponent(d(9)),
            ConsumedArtifact::LtoComponent(d(3)),
        ],
        ..Default::default()
    };
    assert_ne!(
        lto_inputs.inputs_digest(),
        one_component_changed.inputs_digest()
    );
}

#[test]
fn projections_exist_only_through_the_gated_framework() {
    // A clean non-LTO member MAY project — but only with the full
    // F010 gauntlet held, and the projected namespace is a different
    // epoch (workspace shortcuts do not exist: this test reaches the
    // projection exclusively through decide_projection).
    let exact = member_inputs(1, 2, 3);
    let decision = decide_projection(
        classify_flags(&[("opt-level".to_owned(), Some("3".to_owned()))], &[]),
        Some(&ProjectionExtractor {
            name: "rlib-metadata-member".into(),
            version: 1,
            schema_version: 1,
        }),
        ShadowCorpusStatus::ZeroDivergence,
        &ConsumedArtifact::RmetaBytes(d(1)),
    );
    assert!(matches!(decision, ProjectionDecision::Projected { .. }));
    let (projected_inputs, projected_epoch) = effective_inputs(&decision, &exact);
    assert_ne!(projected_epoch, 1, "projected namespace is its own epoch");
    assert_ne!(projected_inputs, exact);
    // An unclean corpus refuses even for the clean flag shape.
    let unproven = decide_projection(
        classify_flags(&[], &[]),
        Some(&ProjectionExtractor {
            name: "rlib-metadata-member".into(),
            version: 1,
            schema_version: 1,
        }),
        ShadowCorpusStatus::NotClean,
        &ConsumedArtifact::RmetaBytes(d(1)),
    );
    assert_eq!(
        unproven,
        ProjectionDecision::ExactFallback {
            because: FallbackCause::CorpusNotClean
        }
    );
}
