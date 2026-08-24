//! S015: source/output namespace access-control probes
//! (rabs-root-4pidu.37.15).
//!
//! Black-box suite over [`rabs_sandbox::upload_policy`]: an unrelated
//! tenant's paths never cross the wire — denied as typed withholdings on
//! WRITES, forced LOCAL on actions that would need them, and never
//! smuggled through secret-slot references or execution trust.
//!
//! Coverage map against the acceptance ("cross-namespace probes denied
//! including existence leaks"):
//!
//! - cross-namespace WRITE probes: every probe of another tenant's tree
//!   is withheld `UPLOAD_WITHHELD_LOCAL_ONLY`, and the admitted set
//!   partitions exactly (a withheld path appears nowhere admitted);
//! - unlisted space fails CLOSED (no rule = no upload), including the
//!   `/etc/passwd` shape;
//! - SECRET slots carry references, never content: a secret-scoped path
//!   admits ONLY a `SlotReference`, so probing cannot pull bytes;
//! - READS that would need foreign bytes force `RunLocally` — remote
//!   eligibility dies before any transfer decision;
//! - EXECUTION TRUST (`trusted_for_execution`) unlocks running, NOT
//!   transferring — the separation S019 named;
//! - most-specific prefix wins in BOTH layering directions;
//! - inventory-hint side: the K010 cache-inventory engine applies the
//!   same namespace discipline with existence-hiding
//!   (`cache_inventory::namespace_policy_hides_existence_not_just_names`,
//!   rabs-cas) — this file pins the policy-layer half.
//!
//! Single-administrative-domain posture is V1 law (`trust_domain`);
//! these tests prove per-NAMESPACE containment inside it, not tenancy.

use rabs_sandbox::upload_policy::{
    NamespaceAcl, NamespaceRule, PathScope, RequiredInputDecision, UploadEntry, authorize_uploads,
    required_input_decision,
};

/// Tenant A's project ACL: workspace uploadable, ops subtree local-only,
/// credentials secret-scoped.
fn tenant_a_acl() -> NamespaceAcl {
    NamespaceAcl {
        rules: vec![
            NamespaceRule {
                prefix: "/__rabs/workspace/".into(),
                scope: PathScope::Uploadable,
            },
            NamespaceRule {
                prefix: "/__rabs/workspace/ops/".into(),
                scope: PathScope::LocalOnly,
            },
            NamespaceRule {
                prefix: "/__rabs/workspace/secrets/".into(),
                scope: PathScope::SecretScoped {
                    slot: "slot-a".into(),
                },
            },
        ],
        trusted_for_execution: true,
    }
}

fn plan_for(acl: &NamespaceAcl, candidates: &[&str]) -> rabs_sandbox::upload_policy::UploadPlan {
    let owned: Vec<String> = candidates.iter().map(|s| (*s).to_string()).collect();
    authorize_uploads(acl, &owned)
}

fn decision_for(acl: &NamespaceAcl, required: &[&str]) -> RequiredInputDecision {
    let owned: Vec<String> = required.iter().map(|s| (*s).to_string()).collect();
    required_input_decision(acl, &owned)
}

#[test]
fn cross_namespace_write_probes_are_withheld_typed() {
    let acl = tenant_a_acl();

    // A probe batch mixing tenant-A paths with foreign trees and system
    // paths. NOTHING foreign may appear in `admitted`.
    let plan = plan_for(
        &acl,
        &[
            "/__rabs/workspace/src/lib.rs",      // ours: uploadable
            "/__rabs/tenant-b/workspace/src.rs", // foreign root
            "/home/other-dev/project/main.c",    // foreign home
            "/etc/passwd",                       // system, unlisted
            "/__rabs/workspace/ops/run.sh",      // ours but local-only subtree
        ],
    );

    let admitted_paths: Vec<&str> = plan
        .admitted
        .iter()
        .map(|e| match e {
            UploadEntry::ObjectBytes { path } => path.as_str(),
            UploadEntry::SlotReference { path, .. } => path.as_str(),
        })
        .collect();
    assert_eq!(
        admitted_paths,
        ["/__rabs/workspace/src/lib.rs"],
        "exactly one path crosses the wire"
    );

    // Every withholding is TYPED with the stable reason code.
    assert_eq!(plan.withheld.len(), 4);
    for w in &plan.withheld {
        assert_eq!(w.reason_code, "UPLOAD_WITHHELD_LOCAL_ONLY");
    }
    // Partition exactness: withheld ∩ admitted = ∅.
    for w in &plan.withheld {
        assert!(!admitted_paths.contains(&w.path.as_str()));
    }
}

#[test]
fn secret_slots_carry_references_never_content() {
    let acl = tenant_a_acl();
    let plan = plan_for(&acl, &["/__rabs/workspace/secrets/token.txt"]);

    assert_eq!(
        plan.withheld.len(),
        0,
        "secret-scoped is admitted AS A SLOT"
    );
    match &plan.admitted[0] {
        UploadEntry::SlotReference { slot, .. } => {
            assert_eq!(slot, "slot-a", "only the capability slot travels");
        }
        UploadEntry::ObjectBytes { path } => {
            panic!("secret content must never become object bytes: {path}")
        }
    }
}

#[test]
fn actions_requiring_foreign_bytes_run_locally_instead_of_leaking() {
    let acl = tenant_a_acl();

    // An action whose inputs include ANOTHER TENANT'S file: remote
    // eligibility dies — the bytes stay home and the action runs local.
    assert_eq!(
        decision_for(
            &acl,
            &[
                "/__rabs/workspace/src/lib.rs",
                "/__rabs/tenant-b/generated/gen.rs",
            ]
        ),
        RequiredInputDecision::RunLocally,
        "one foreign input forces the whole action local"
    );

    // Purely-own inputs (including secret SLOTS — references travel)
    // remain remotely eligible.
    assert_eq!(
        decision_for(
            &acl,
            &[
                "/__rabs/workspace/src/lib.rs",
                "/__rabs/workspace/secrets/token.txt",
            ]
        ),
        RequiredInputDecision::RemoteEligible
    );
}

#[test]
fn execution_trust_does_not_unlock_transfer() {
    // The ACL is marked trusted-for-execution; a local-only path is STILL
    // withheld. Trust moves execution, never bytes.
    let acl = tenant_a_acl();
    assert!(acl.trusted_for_execution);
    let plan = plan_for(&acl, &["/__rabs/workspace/ops/deploy.key"]);
    assert_eq!(plan.admitted.len(), 0);
    assert_eq!(plan.withheld[0].reason_code, "UPLOAD_WITHHELD_LOCAL_ONLY");

    // And the read-side decision agrees even under trust.
    assert_eq!(
        decision_for(&acl, &["/__rabs/workspace/ops/deploy.key"]),
        RequiredInputDecision::RunLocally
    );
}

#[test]
fn most_specific_prefix_wins_in_both_layering_directions() {
    // Layering direction 1: uploadable ROOT, local-only SUBTREE.
    let acl = tenant_a_acl();
    assert_eq!(acl.scope_of("/__rabs/workspace/x"), PathScope::Uploadable);
    assert_eq!(
        acl.scope_of("/__rabs/workspace/ops/x"),
        PathScope::LocalOnly
    );

    // Layering direction 2: local-only ROOT, uploadable SUBTREE.
    let inverted = NamespaceAcl {
        rules: vec![
            NamespaceRule {
                prefix: "/proj/".into(),
                scope: PathScope::LocalOnly,
            },
            NamespaceRule {
                prefix: "/proj/public/".into(),
                scope: PathScope::Uploadable,
            },
        ],
        trusted_for_execution: false,
    };
    assert_eq!(inverted.scope_of("/proj/private/key"), PathScope::LocalOnly);
    assert_eq!(
        inverted.scope_of("/proj/public/readme"),
        PathScope::Uploadable
    );

    // Equal-length shadowing rules resolve deterministically by iteration
    // order (max_by_key keeps the LAST maximum) — pinned so any change is
    // a conscious one.
    let shadowed = NamespaceAcl {
        rules: vec![
            NamespaceRule {
                prefix: "/dup/".into(),
                scope: PathScope::LocalOnly,
            },
            NamespaceRule {
                prefix: "/dup/".into(),
                scope: PathScope::Uploadable,
            },
        ],
        trusted_for_execution: false,
    };
    assert_eq!(
        shadowed.scope_of("/dup/file"),
        PathScope::Uploadable,
        "tie behavior pinned"
    );
}

#[test]
fn unlisted_space_fails_closed_even_for_trusted_projects() {
    let mut acl = tenant_a_acl();
    acl.trusted_for_execution = true;
    // Paths OUTSIDE every rule: fail-closed LocalOnly regardless of the
    // leading-slash shape or traversal attempt.
    for hostile in [
        "/etc/passwd",
        "__rabs/workspace/relative-no-leading-slash",
        "/__rabs/workspaceX/lookalike", // separator must be part of the prefix
        "/../__rabs/workspace/escape",
    ] {
        assert_eq!(
            acl.scope_of(hostile),
            PathScope::LocalOnly,
            "{hostile} must fail closed"
        );
        let plan = plan_for(&acl, &[hostile]);
        assert!(plan.admitted.is_empty());
        assert_eq!(plan.withheld[0].reason_code, "UPLOAD_WITHHELD_LOCAL_ONLY");
    }
}
