//! BuildPathSemanticPolicy in the descriptor/key breakdown +
//! fragmentation attribution (bead F028; invariant I41; the D030
//! policy meeting the F012/F018 machinery).
//!
//! D030 built the policy and its component digest; this suite proves
//! the two acceptance halves END TO END through the real key and
//! fragmentation machinery:
//!
//! 1. the policy is a KEYED semantic component: filling the
//!    descriptor's `build_path_semantic_policy` slot with a different
//!    policy digest forks the final ActionKey;
//! 2. `rch why` and the fragmentation analyzer can ATTRIBUTE the cost:
//!    a fleet window where otherwise-identical work ran under two
//!    path policies shows `build_path_semantic_policy` as the
//!    fragmenting component in the F018 histogram, by name.

use rabs_key::action_key::compute_action_key;
use rabs_key::fragmentation::{aggregate, top_fragmenters};
use rabs_key::path_policy::{BuildPathSemanticPolicy, policy_component_digest};
use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

fn d(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn descriptor(policy: BuildPathSemanticPolicy) -> ActionDescriptor {
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
        build_path_semantic_policy: policy_component_digest(policy),
        execution_semantics: d("rabs.exec-semantics.v1", 11),
        output_declarations: d("rabs.outputs.v1", 12),
    }
}

#[test]
fn policy_change_changes_the_key() {
    // Acceptance half 1: otherwise-identical descriptors under
    // different path policies produce different final keys — and every
    // pair of policies is pairwise distinct.
    let policies = [
        BuildPathSemanticPolicy::CanonicalPortablePath,
        BuildPathSemanticPolicy::PathOpaqueVerified,
        BuildPathSemanticPolicy::ProjectRelativeRemapped,
        BuildPathSemanticPolicy::SubscriberPathPreserving,
    ];
    let keys: Vec<_> = policies
        .iter()
        .map(|p| compute_action_key(&descriptor(*p)).final_key)
        .collect();
    for (i, a) in keys.iter().enumerate() {
        for b in &keys[i + 1..] {
            assert_ne!(a, b, "policies must key distinctly");
        }
    }
}

#[test]
fn fragmentation_report_attributes_path_policy_cost_by_name() {
    // Acceptance half 2: a fleet window — 3 compiles under canonical,
    // 2 under preserving, all else identical. The F018 histogram must
    // name `build_path_semantic_policy` as the fragmenter, and rank it
    // top (every other component has one value).
    let mut window = Vec::new();
    for _ in 0..3 {
        window.push(compute_action_key(&descriptor(
            BuildPathSemanticPolicy::CanonicalPortablePath,
        )));
    }
    for _ in 0..2 {
        window.push(compute_action_key(&descriptor(
            BuildPathSemanticPolicy::SubscriberPathPreserving,
        )));
    }
    let histograms = aggregate(&window);
    let policy_hist = histograms
        .iter()
        .find(|h| h.component == "build_path_semantic_policy")
        .expect("component present in every breakdown");
    assert_eq!(policy_hist.distinct_values(), 2);
    assert_eq!(policy_hist.total(), 5);
    assert_eq!(policy_hist.buckets[0].count, 3, "majority bucket first");
    let top = top_fragmenters(&histograms);
    assert_eq!(
        top,
        vec![("build_path_semantic_policy", 2)],
        "the report names path policy as the ONLY fragmenting component"
    );
}
