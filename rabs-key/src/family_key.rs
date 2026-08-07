//! `ActionFamilyKey`: stable, source-independent family identity for
//! discovery singleflight and recipes (bead F016; plan §18.1).
//!
//! A family identifies "the same logical unit compiled the same way" —
//! WITHOUT embedding current source content. That exclusion is the whole
//! point: if source digests entered the family, **every edit would orphan
//! the discovery recipe**, and first-run discovery would re-execute after
//! each keystroke. Instead the family carries the stable shape:
//!
//! - stable logical repository scope (bead F026/D001: package source
//!   identity or project UUID + closure role — never a mutable git remote
//!   URL, checkout path, branch, or commit);
//! - package/target/unit identity;
//! - semantic compiler invocation SHAPE (flags structure, not file
//!   contents);
//! - toolchain and projection epochs; action class; sandbox and
//!   build-path semantic policies; dependency roles; output-platform
//!   class; toolchain behavior profile + semantic-adapter epoch.
//!
//! Recipes stored under a family are optimization hints, never trust
//! anchors (E012): a recipe cannot authorize serving without the final
//! input-complete `ActionKey` and compatible trust evidence.

use rabs_protocol::result_identity::TypedDigest;

use crate::action_key::action_class_tag;
use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;
use rabs_protocol::descriptor::ActionClass;

/// Digest domain for action-family keys.
pub const DOMAIN_ACTION_FAMILY: &str = "rabs.action-family.sha256.v1";

/// The stable inputs to a family key. Every field is a digest or stable
/// identifier; there is deliberately NO field for source content or
/// snapshot identity — adding one would defeat recipe survival across
/// edits (the type is the guard).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionFamilyInputs {
    /// Stable logical repository identity (F026 scoping: recipes never
    /// leak across repos with similar unit shapes).
    pub logical_repo: TypedDigest,
    /// Package/target/unit identity within the repo.
    pub unit_identity: TypedDigest,
    /// Semantic invocation SHAPE digest (structure, not content).
    pub invocation_shape: TypedDigest,
    /// Toolchain epoch/behavior profile digest.
    pub toolchain_profile: TypedDigest,
    /// Key epoch.
    pub key_epoch: u32,
    /// Projection epoch.
    pub projection_epoch: u32,
    /// Recipe epoch (bumps when discovery semantics change).
    pub recipe_epoch: u32,
    /// Action class.
    pub action_class: ActionClass,
    /// Sandbox semantic policy digest.
    pub sandbox_semantic_policy: TypedDigest,
    /// Build-path semantic policy digest.
    pub build_path_semantic_policy: TypedDigest,
    /// Output-platform class digest.
    pub output_platform_class: TypedDigest,
}

/// Compute the family key.
#[must_use]
pub fn compute_family_key(inputs: &ActionFamilyInputs) -> TypedDigest {
    let ActionFamilyInputs {
        logical_repo,
        unit_identity,
        invocation_shape,
        toolchain_profile,
        key_epoch,
        projection_epoch,
        recipe_epoch,
        action_class,
        sandbox_semantic_policy,
        build_path_semantic_policy,
        output_platform_class,
    } = inputs;
    let mut enc = CanonicalEncoder::new();
    enc.u32(*key_epoch)
        .u32(*projection_epoch)
        .u32(*recipe_epoch)
        .u32(action_class_tag(*action_class));
    for d in [
        logical_repo,
        unit_identity,
        invocation_shape,
        toolchain_profile,
        sandbox_semantic_policy,
        build_path_semantic_policy,
        output_platform_class,
    ] {
        enc.str(d.domain);
        enc.bytes(&d.bytes);
    }
    compute(DOMAIN_ACTION_FAMILY, &enc.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn inputs() -> ActionFamilyInputs {
        ActionFamilyInputs {
            logical_repo: d("rabs.logical-repo.v1", 1),
            unit_identity: d("rabs.unit.v1", 2),
            invocation_shape: d("rabs.invocation-shape.v1", 3),
            toolchain_profile: d("rabs.toolchain-profile.v1", 4),
            key_epoch: 1,
            projection_epoch: 1,
            recipe_epoch: 1,
            action_class: ActionClass::RustcWorkspaceCompile,
            sandbox_semantic_policy: d("rabs.sandbox-policy.v1", 5),
            build_path_semantic_policy: d("rabs.path-policy.v1", 6),
            output_platform_class: d("rabs.platform-class.v1", 7),
        }
    }

    #[test]
    fn family_survives_source_edits_by_construction() {
        // The struct HAS no source/snapshot field: two computations from
        // the same stable shape are identical no matter what the sources
        // did in between. The exhaustive destructure in compute_family_key
        // makes adding such a field a compile-visible decision.
        let before_edit = compute_family_key(&inputs());
        let after_edit = compute_family_key(&inputs());
        assert_eq!(before_edit, after_edit);
        assert_eq!(before_edit.domain, DOMAIN_ACTION_FAMILY);
    }

    #[test]
    fn repo_scoping_splits_families() {
        // F026: identical unit shapes in different repos are different
        // families — recipes cannot leak across repositories.
        let a = compute_family_key(&inputs());
        let mut other_repo = inputs();
        other_repo.logical_repo = d("rabs.logical-repo.v1", 99);
        assert_ne!(a, compute_family_key(&other_repo));
    }

    #[test]
    fn shape_toolchain_policy_and_epochs_all_split_families() {
        let base = compute_family_key(&inputs());
        let mut m = inputs();
        m.invocation_shape = d("rabs.invocation-shape.v1", 99);
        assert_ne!(base, compute_family_key(&m));
        let mut t = inputs();
        t.toolchain_profile = d("rabs.toolchain-profile.v1", 99);
        assert_ne!(base, compute_family_key(&t));
        let mut r = inputs();
        r.recipe_epoch = 2;
        assert_ne!(base, compute_family_key(&r));
        let mut c = inputs();
        c.action_class = ActionClass::ClippyCompile;
        assert_ne!(base, compute_family_key(&c));
        let mut p = inputs();
        p.build_path_semantic_policy = d("rabs.path-policy.v1", 99);
        assert_ne!(base, compute_family_key(&p));
    }

    #[test]
    fn family_and_action_key_domains_are_distinct() {
        // A family key can never be mistaken for an action key: different
        // digest domains diverge in raw bytes too (F034 separation).
        use crate::typed_digest::DOMAIN_ACTION_KEY;
        let fam = compute_family_key(&inputs());
        assert_ne!(fam.domain, DOMAIN_ACTION_KEY);
    }
}
