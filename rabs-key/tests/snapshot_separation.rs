//! ExecutionSnapshotRoot vs ActionInputManifest separation (bead F019;
//! invariants I3/I4; risk R41).
//!
//! The complete immutable command snapshot exists for materialization,
//! diagnosis, and reproduction — it lives in provenance and
//! subscription context. Only the action's ENFORCED MINIMAL CLOSURE
//! enters a fine-grained key. The hazard this kills (R41): keying leaf
//! actions on the whole snapshot makes every unrelated workspace edit
//! a fleet-wide miss.
//!
//! The exception is deliberate: a bounded WHOLE-COMMAND action's
//! declared input IS the full snapshot, so it keys on the snapshot by
//! declaration (through its `action_inputs` slot), not by leak.

use rabs_key::action_key::compute_action_key;
use rabs_protocol::descriptor::{
    ActionClass, ActionDescriptor, ActionSubscriptionContext, SubscriberKind,
};
use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};

fn d(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn leaf_descriptor(inputs_tag: u8) -> ActionDescriptor {
    ActionDescriptor {
        key_epoch: 1,
        projection_epoch: 1,
        action_class: ActionClass::RustcDependencyCompile,
        normalized_invocation: d("rabs.invocation.v1", 1),
        virtual_working_directory: d("rabs.cwd.v1", 2),
        action_inputs: d("rabs.inputs.v1", inputs_tag),
        negative_dependencies: d("rabs.negdeps.v1", 4),
        dependency_inputs: d("rabs.deps.v1", 5),
        toolchain: d("rabs.toolchain-contract.v1", 6),
        output_platform: d("rabs.output-platform.v1", 7),
        environment: d("rabs.env.v1", 8),
        sandbox_semantic_policy: d("rabs.sandbox-policy.v1", 9),
        build_path_semantic_policy: d("rabs.path-policy.v1", 10),
        execution_semantics: d("rabs.exec-semantics.v1", 11),
        output_declarations: d("rabs.outputs.v1", 12),
    }
}

fn subscription(snapshot_tag: u8) -> ActionSubscriptionContext {
    ActionSubscriptionContext {
        execution_snapshot_root: ObjectId(d("rabs.snapshot.v1", snapshot_tag)),
        requesting_edge: rabs_protocol::wire_time::PeerId("edge-1".into()),
        subscriber_kind: SubscriberKind::ForegroundInteractive,
        presentation: d("rabs.presentation.v1", 20),
        path_translation: d("rabs.path-translation.v1", 21),
        execution_requirements: rabs_protocol::descriptor::ExecutionRequirements {
            minimum_isolation_profile:
                rabs_protocol::authority_matrix::IsolationProfile::StrictHermeticLinux,
            privacy_scope: "default".into(),
            required_worker_capabilities: vec![],
        },
        queue_priority: 1,
        deadline_budget: None,
    }
}

#[test]
fn unrelated_workspace_edit_does_not_change_a_leaf_actions_key() {
    // THE acceptance case: the user edits an unrelated file — the new
    // command snapshot root differs, the leaf compile's enforced
    // closure does not. Schema separation makes the key IMMOVABLE: the
    // snapshot root lives on the subscription context, which has no
    // channel into the descriptor.
    let leaf = leaf_descriptor(3);
    let before_edit = subscription(50);
    let after_edit = subscription(51); // new snapshot, unrelated edit
    assert_ne!(
        before_edit.execution_snapshot_root,
        after_edit.execution_snapshot_root
    );
    let key_before = compute_action_key(&leaf).final_key;
    let key_after = compute_action_key(&leaf).final_key;
    assert_eq!(key_before, key_after, "leaf key must not see the snapshot");
    // And the descriptor's own components confirm: no snapshot slot.
    assert!(
        leaf.key_input_components()
            .iter()
            .all(|(name, digest)| !name.contains("snapshot")
                && !digest.domain.contains("snapshot")),
        "no descriptor slot may carry a snapshot identity"
    );
}

#[test]
fn the_enforced_closure_does_change_the_leaf_key() {
    // The counterpart: an edit INSIDE the action's minimal closure
    // (action_inputs digest moves) is exactly what must miss.
    let before = compute_action_key(&leaf_descriptor(3)).final_key;
    let after = compute_action_key(&leaf_descriptor(4)).final_key;
    assert_ne!(before, after);
}

#[test]
fn whole_command_actions_key_on_the_snapshot_by_declaration() {
    // The deliberate exception: CargoWholeCommandBounded declares the
    // full snapshot as its input — the snapshot digest enters through
    // the action_inputs SLOT (a declaration), not through a schema
    // leak. Different snapshots, different whole-command keys.
    let mut whole_a = leaf_descriptor(0);
    whole_a.action_class = ActionClass::CargoWholeCommandBounded;
    whole_a.action_inputs = d("rabs.inputs.v1", 60); // = snapshot 60's closure
    let mut whole_b = whole_a.clone();
    whole_b.action_inputs = d("rabs.inputs.v1", 61); // = snapshot 61's closure
    assert_ne!(
        compute_action_key(&whole_a).final_key,
        compute_action_key(&whole_b).final_key
    );
}
