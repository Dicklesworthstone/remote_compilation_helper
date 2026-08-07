//! Mutation matrix: EVERY semantic input changes the key (bead F015;
//! plan §67; the soundness half of the F014/F015 pair).
//!
//! F014 proves irrelevant differences DON'T move the key; this suite
//! proves every semantic descriptor component DOES. The matrix is
//! exhaustive by destructure: `ActionDescriptor` is taken apart field
//! by field, every digest slot is mutated in isolation, and each
//! mutation must produce a distinct final key. Adding a descriptor
//! field without adding it to the matrix is a compile error here — the
//! matrix cannot silently under-cover.
//!
//! The epoch/class header fields are covered too: key epoch, projection
//! epoch, and action class are deliberate invalidation/partition levers
//! and must each fork the key.

use rabs_key::action_key::compute_action_key;
use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

fn d(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn base() -> ActionDescriptor {
    ActionDescriptor {
        key_epoch: 1,
        projection_epoch: 1,
        action_class: ActionClass::RustcDependencyCompile,
        normalized_invocation: d("rabs.invocation.v1", 1),
        virtual_working_directory: d("rabs.cwd.v1", 2),
        action_inputs: d("rabs.inputs.v1", 3),
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

/// Bump one digest's bytes (simulating: a source byte changed, a dep
/// artifact byte changed, an env var changed, ... — whatever that
/// component summarizes).
fn bump(digest: &mut TypedDigest) {
    digest.bytes[0] ^= 0xFF;
}

#[test]
fn every_descriptor_component_mutated_in_isolation_forks_the_key() {
    let baseline = compute_action_key(&base()).final_key;
    // Exhaustive destructure — the compile-time completeness guarantee:
    // a new descriptor field fails this binding until added to MUTATIONS.
    let ActionDescriptor {
        key_epoch: _,
        projection_epoch: _,
        action_class: _,
        normalized_invocation: _,
        virtual_working_directory: _,
        action_inputs: _,
        negative_dependencies: _,
        dependency_inputs: _,
        toolchain: _,
        output_platform: _,
        environment: _,
        sandbox_semantic_policy: _,
        build_path_semantic_policy: _,
        execution_semantics: _,
        output_declarations: _,
    } = base();

    type Mutator = fn(&mut ActionDescriptor);
    const MUTATIONS: &[(&str, Mutator)] = &[
        ("normalized_invocation", |m| {
            bump(&mut m.normalized_invocation)
        }),
        ("virtual_working_directory", |m| {
            bump(&mut m.virtual_working_directory);
        }),
        ("action_inputs", |m| bump(&mut m.action_inputs)),
        ("negative_dependencies", |m| {
            bump(&mut m.negative_dependencies)
        }),
        ("dependency_inputs", |m| bump(&mut m.dependency_inputs)),
        ("toolchain", |m| bump(&mut m.toolchain)),
        ("output_platform", |m| bump(&mut m.output_platform)),
        ("environment", |m| bump(&mut m.environment)),
        ("sandbox_semantic_policy", |m| {
            bump(&mut m.sandbox_semantic_policy);
        }),
        ("build_path_semantic_policy", |m| {
            bump(&mut m.build_path_semantic_policy);
        }),
        ("execution_semantics", |m| bump(&mut m.execution_semantics)),
        ("output_declarations", |m| bump(&mut m.output_declarations)),
    ];
    // Matrix completeness: 12 digest slots (matches the descriptor's
    // own key_input_components list length).
    assert_eq!(MUTATIONS.len(), base().key_input_components().len());

    let mut seen = vec![baseline.clone()];
    for (name, mutate) in MUTATIONS {
        let mut mutated = base();
        mutate(&mut mutated);
        let key = compute_action_key(&mutated).final_key;
        assert_ne!(
            key, baseline,
            "mutating `{name}` in isolation must fork the key"
        );
        // Distinctness across mutations too: two different mutated
        // components must not collide with each other.
        assert!(
            !seen.contains(&key),
            "mutation of `{name}` collided with a previous mutation"
        );
        seen.push(key);
    }
}

#[test]
fn epoch_and_class_header_fields_fork_the_key() {
    let baseline = compute_action_key(&base()).final_key;
    let mut m = base();
    m.key_epoch = 2;
    assert_ne!(
        compute_action_key(&m).final_key,
        baseline,
        "key epoch is the cold-namespace invalidation lever"
    );
    let mut m = base();
    m.projection_epoch = 2;
    assert_ne!(compute_action_key(&m).final_key, baseline);
    let mut m = base();
    m.action_class = ActionClass::ClippyCompile;
    assert_ne!(
        compute_action_key(&m).final_key,
        baseline,
        "class partitions the key space (clippy vs rustc of one crate)"
    );
}

#[test]
fn single_bit_of_any_component_suffices() {
    // The finest mutation: ONE bit in one component's digest bytes.
    let baseline = compute_action_key(&base()).final_key;
    let mut m = base();
    m.action_inputs.bytes[31] ^= 0x01;
    assert_ne!(compute_action_key(&m).final_key, baseline);
}
