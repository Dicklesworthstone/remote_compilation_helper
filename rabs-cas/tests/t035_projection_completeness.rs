//! T035 projection-completeness guard: every manifest field must reach
//! the result projection (bead H035; invariant I48; risk R103).
//!
//! H035 already ships the incident FIXTURE — two candidates with equal
//! semantic and observable digests but different canonical manifests
//! open a `ProjectionCompletenessIncident` and quarantine the action
//! (`publication.rs::h035_equal_digests_different_manifest_opens_...`).
//! That proves the system reacts correctly once the condition exists.
//!
//! This file attacks the condition itself. R103's scenario has two
//! possible causes: a serializer emitting different bytes for the same
//! value (the fixture's case), or **a projection that omits a field**.
//! The second one is not a bug someone writes deliberately — it is what
//! happens when a field is added to `CanonicalActionResultManifest` and
//! `semantic_result_digest_v1` is not updated to match. From that moment
//! two genuinely different results hash identically, and every
//! downstream identity, dedup and cache-hit decision is wrong in a way
//! no runtime check can see, because the digests agree.
//!
//! So: mutate each field in turn and require the digest to move. A new
//! manifest field that nobody projected fails this immediately, at the
//! commit that introduces it, instead of becoming a soundness incident
//! discovered much later by the H035 fixture.
//!
//! The codec's own canonicality is tested separately
//! (`manifest_codec::encoding_is_canonical_under_output_reordering`);
//! this is about the projection, not the encoding.

use rabs_cas::publication::{observable_result_digest_v1, semantic_result_digest_v1};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{
    CanonicalActionResultManifest, DigestAlgorithm, LogicalOutput, ObjectId, OutputRole,
    ResultKind, TypedDigest,
};

fn digest(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn object(tag: u8) -> ObjectId {
    ObjectId(digest("rabs.object.sha256.v1", tag))
}

fn output(role: OutputRole, path: &str, tag: u8) -> LogicalOutput {
    LogicalOutput {
        role,
        virtual_path: RawBytes::new(path.as_bytes().to_vec()),
        object: object(tag),
    }
}

/// A valid, fully populated success manifest. The digest fields are
/// placeholders: both projections exclude them by construction.
fn baseline() -> CanonicalActionResultManifest {
    CanonicalActionResultManifest {
        action_key: digest("rabs.action-key.sha256.v1", 1),
        canonical_descriptor_digest: digest("rabs.descriptor.sha256.v1", 2),
        key_epoch: 3,
        projection_epoch: 4,
        result_kind: ResultKind::Success,
        artifact_bundle_root: Some(object(5)),
        logical_outputs: vec![
            output(OutputRole::Materializable, "target/debug/libfoo.rlib", 6),
            output(OutputRole::DepInfo, "target/debug/foo.d", 7),
        ],
        semantic_result_digest: digest("rabs.semantic-result.sha256.v1", 0),
        observable_result_digest: digest("rabs.observable-result.sha256.v1", 0),
    }
}

/// Every mutation that must move the semantic digest, each named so a
/// failure says which field stopped being projected.
fn field_mutations() -> Vec<(&'static str, CanonicalActionResultManifest)> {
    let mut mutations = Vec::new();

    let mut m = baseline();
    m.action_key = digest("rabs.action-key.sha256.v1", 11);
    mutations.push(("action_key", m));

    let mut m = baseline();
    m.canonical_descriptor_digest = digest("rabs.descriptor.sha256.v1", 12);
    mutations.push(("canonical_descriptor_digest", m));

    let mut m = baseline();
    m.key_epoch = 99;
    mutations.push(("key_epoch", m));

    let mut m = baseline();
    m.projection_epoch = 99;
    mutations.push(("projection_epoch", m));

    // A deterministic failure must carry no outputs and no bundle root,
    // so the result_kind mutation takes its legal shape rather than an
    // invalid one — `validate` would reject the lazy version, and a
    // guard built on invalid inputs proves nothing.
    let mut m = baseline();
    m.result_kind = ResultKind::DeterministicFailure;
    m.logical_outputs = Vec::new();
    m.artifact_bundle_root = None;
    mutations.push(("result_kind", m));

    let mut m = baseline();
    m.artifact_bundle_root = Some(object(13));
    mutations.push(("artifact_bundle_root (different object)", m));

    let mut m = baseline();
    m.artifact_bundle_root = None;
    mutations.push(("artifact_bundle_root (present vs absent)", m));

    // Each component of a logical output separately: role, path and
    // object are three different ways for two results to differ, and a
    // projection that framed only one of them would still pass a test
    // that mutated the whole output at once.
    let mut m = baseline();
    m.logical_outputs[0].role = OutputRole::TestSideEffect;
    mutations.push(("logical_outputs[0].role", m));

    let mut m = baseline();
    m.logical_outputs[0].virtual_path = RawBytes::new(b"target/debug/libother.rlib".to_vec());
    mutations.push(("logical_outputs[0].virtual_path", m));

    let mut m = baseline();
    m.logical_outputs[0].object = object(14);
    mutations.push(("logical_outputs[0].object", m));

    let mut m = baseline();
    m.logical_outputs.push(output(
        OutputRole::ProvisionalMetadata,
        "target/debug/foo.rmeta",
        15,
    ));
    mutations.push(("logical_outputs (an added output)", m));

    let mut m = baseline();
    m.logical_outputs.pop();
    mutations.push(("logical_outputs (a removed output)", m));

    mutations
}

#[test]
fn t035_every_manifest_field_reaches_the_semantic_projection() {
    let base = baseline();
    base.validate()
        .expect("the baseline must be a valid manifest");
    let base_digest = semantic_result_digest_v1(&base);

    for (field, mutated) in field_mutations() {
        mutated
            .validate()
            .unwrap_or_else(|e| panic!("{field}: mutation must stay a valid manifest ({e})"));
        assert_ne!(
            semantic_result_digest_v1(&mutated),
            base_digest,
            "{field} does not reach the semantic projection: two results differing only \
             in this field would share an identity, and every dedup, cache-hit and \
             divergence decision downstream would be wrong with no way to see it (R103)"
        );
    }
}

#[test]
fn t035_the_guard_is_not_vacuous() {
    // If the projection ignored its input entirely, the test above would
    // fail; if it hashed something random, the test above would PASS for
    // the wrong reason. So: the projection is a function of the manifest
    // value, and the two placeholder digest fields are genuinely excluded
    // (they are outputs of the projection and cannot be inputs to it).
    let base = baseline();
    assert_eq!(
        semantic_result_digest_v1(&base),
        semantic_result_digest_v1(&baseline()),
        "the projection must be deterministic over equal values"
    );

    let mut restamped = baseline();
    restamped.semantic_result_digest = digest("rabs.semantic-result.sha256.v1", 77);
    restamped.observable_result_digest = digest("rabs.observable-result.sha256.v1", 88);
    assert_eq!(
        semantic_result_digest_v1(&restamped),
        semantic_result_digest_v1(&base),
        "the digest fields must be excluded from their own projection"
    );
}

#[test]
fn t035_output_order_is_not_an_identity() {
    // The projection sorts outputs, so order is not part of identity.
    // Pinning it here as a PROPERTY rather than an accident: if sorting
    // were dropped, two manifests built by different code paths from the
    // same facts would get different identities, which is the mirror
    // image of R103 — the same result published twice under two names.
    let mut reordered = baseline();
    reordered.logical_outputs.reverse();
    assert_eq!(
        semantic_result_digest_v1(&reordered),
        semantic_result_digest_v1(&baseline()),
        "output order must not change a result's identity"
    );
}

#[test]
fn t035_the_observable_projection_carries_the_semantic_one_and_its_observations() {
    // The observable digest must move when EITHER half moves, or an
    // observation-only difference would be invisible at the observable
    // layer — which is precisely the distinction T025's presentation
    // quarantine depends on.
    let observations = digest("rabs.observation-stream.sha256.v1", 20);
    let base = observable_result_digest_v1(&baseline(), &observations);

    for (field, mutated) in field_mutations() {
        assert_ne!(
            observable_result_digest_v1(&mutated, &observations),
            base,
            "{field} does not reach the observable projection"
        );
    }

    assert_ne!(
        observable_result_digest_v1(
            &baseline(),
            &digest("rabs.observation-stream.sha256.v1", 21)
        ),
        base,
        "a different observation stream must change the observable digest"
    );
}
