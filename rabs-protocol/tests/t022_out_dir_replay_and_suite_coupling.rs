//! T022, the OUT_DIR replay half: ghost files and deletions (bead N012;
//! risk R66). The suite-coupling half (R69) lives in
//! `rabs-key/tests/t022_suite_coupling_serving.rs`, because
//! `rabs-protocol` is dependency-free by construction and cannot see
//! `rabs_key::suite_coupling` from here.
//!
//! N012 already ships the headline case and this does not redo it: an
//! end-to-end fixture against real cargo — clean build, ghost injected
//! into the run dir, polluted pre-state key material differs, the plan
//! names exactly the ghost for delete, and the applied tree equals the
//! clean-run manifest.
//!
//! What this adds is the drift case, and it is not a happy one.
//!
//! **`plan_swap` compares LENGTH, not content.** `OutputEntry` carries
//! a path and a `len` and nothing else — there is no digest in the
//! manifest at all — so two files that differ in content but agree in
//! size are indistinguishable to the planner. It plans neither a delete
//! nor a create for them, and the "atomic post-state replacement" hands
//! back a tree that is NOT equal to the target while reporting a clean
//! no-op. N012's own e2e cannot see this, because the ghost it injects
//! is an ADDED path, and an added path differs in the one dimension the
//! planner can observe.
//!
//! That is documented below rather than fixed, because fixing it means
//! putting a digest in `OutputEntry`, which changes
//! `pre_state_key_material` — every pre-state key — and forces the N003
//! walk to hash every output file on every build. Whether that cost is
//! worth paying, or whether the claim should be narrowed instead, is
//! the owner's call, not a test's. Filed with the evidence.
//!
//! Neither `plan_swap` nor `pre_state_key_material` has a production
//! caller today, so nothing is currently mis-replacing anything.

use rabs_protocol::output_manifest::{OutputEntry, OutputSection, OutputTreeManifest};
use rabs_protocol::post_state_replacement::{plan_swap, pre_state_key_material};

fn manifest(out: &[(&str, u64)], cache: &[(&str, u64)]) -> OutputTreeManifest {
    OutputTreeManifest::new(
        out.iter()
            .map(|(p, l)| OutputEntry::new(*p, *l))
            .collect::<Vec<_>>(),
        cache
            .iter()
            .map(|(p, l)| OutputEntry::new(*p, *l))
            .collect::<Vec<_>>(),
    )
    .expect("valid manifest")
}

/// Paths the plan would leave in place: everything the live tree has
/// that is not deleted, plus everything the plan creates.
fn resulting_paths(live: &OutputTreeManifest, plan_delete: &[Vec<u8>], created: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut paths: Vec<Vec<u8>> = live
        .section(OutputSection::OutDir)
        .iter()
        .chain(live.section(OutputSection::OutputCache).iter())
        .map(|e| e.path.clone())
        .filter(|p| !plan_delete.contains(p))
        .collect();
    for p in created {
        if !paths.contains(p) {
            paths.push(p.clone());
        }
    }
    paths.sort();
    paths
}

#[test]
fn t022_a_ghost_file_is_planned_for_deletion_and_a_clean_tree_plans_nothing() {
    // The case N012 delivers, re-stated here as the baseline the drift
    // case is measured against. A ghost from an earlier failed run is
    // an ADDED path, which the planner can see.
    let clean = manifest(&[("build/generated.rs", 120)], &[("cache/index.bin", 64)]);
    let polluted = manifest(
        &[("build/generated.rs", 120), ("build/ghost.rs", 9)],
        &[("cache/index.bin", 64)],
    );

    let plan = plan_swap(&polluted, &clean).expect("plans");
    assert_eq!(
        plan.delete,
        vec![b"build/ghost.rs".to_vec()],
        "the ghost, and only the ghost, is planned for deletion"
    );
    assert!(plan.create.is_empty());

    // Identical states plan no rows at all: silence is the no-op proof.
    let noop = plan_swap(&clean, &clean).expect("plans");
    assert!(noop.delete.is_empty() && noop.create.is_empty());
}

#[test]
fn t022_same_length_drift_is_invisible_to_the_planner() {
    // A DOCUMENTED DEFECT, not a property.
    //
    // A build script rewrites `build/generated.rs` from
    // `const N: usize = 1;` to `const N: usize = 2;`. Same path, same
    // byte length, different content. The target state wants the first;
    // the live tree holds the second.
    let live = manifest(&[("build/generated.rs", 120)], &[]);
    let target = manifest(&[("build/generated.rs", 120)], &[]);

    let plan = plan_swap(&live, &target).expect("plans");
    assert!(
        plan.delete.is_empty() && plan.create.is_empty(),
        "documented: the planner sees only (path, len), so equal-length drift \
         plans no rows and the stale bytes survive the replacement"
    );

    // And the key material cannot tell them apart either, so a drifted
    // pre-state hashes identically to a clean one — the drift is
    // invisible to the cache key as well as to the planner.
    assert_eq!(
        pre_state_key_material(&live),
        pre_state_key_material(&target),
        "documented: pre-state key material is (path, len) too"
    );
}

#[test]
fn t022_the_planner_does_see_drift_that_changes_length() {
    // The boundary of the defect above, so the report is precise rather
    // than sweeping: drift IS caught whenever it changes the size, which
    // is the common case. The gap is specifically same-size content
    // change, which is exactly what a flag flip, a version bump within
    // a fixed field, or a timestamp rewrite produces.
    let live = manifest(&[("build/generated.rs", 121)], &[]);
    let target = manifest(&[("build/generated.rs", 120)], &[]);

    let plan = plan_swap(&live, &target).expect("plans");
    assert_eq!(plan.delete, vec![b"build/generated.rs".to_vec()]);
    assert_eq!(plan.create, vec![b"build/generated.rs".to_vec()]);
    assert_ne!(pre_state_key_material(&live), pre_state_key_material(&target));
}

#[test]
fn t022_replay_equals_a_clean_run_for_every_difference_the_planner_can_see() {
    // The R66 acceptance, stated as the property rather than one
    // fixture: apply the plan and the surviving path set must equal the
    // target's. Ghosts, missing files and length drift together.
    let clean = manifest(
        &[("build/generated.rs", 120), ("build/keep.rs", 30)],
        &[("cache/index.bin", 64)],
    );
    let polluted = manifest(
        &[
            ("build/generated.rs", 999), // drifted (length visible)
            ("build/ghost.rs", 9),       // ghost from a failed run
                                         // build/keep.rs absent: must be created
        ],
        &[("cache/stale.bin", 5)],
    );

    let plan = plan_swap(&polluted, &clean).expect("plans");
    let result = resulting_paths(&polluted, &plan.delete, &plan.create);
    let mut expected: Vec<Vec<u8>> = clean
        .section(OutputSection::OutDir)
        .iter()
        .chain(clean.section(OutputSection::OutputCache).iter())
        .map(|e| e.path.clone())
        .collect();
    expected.sort();

    assert_eq!(
        result, expected,
        "after the swap the tree must hold exactly the clean-run path set"
    );
    assert!(
        plan.delete.contains(&b"build/ghost.rs".to_vec()),
        "the ghost must die in the swap"
    );
    assert!(
        plan.delete.contains(&b"cache/stale.bin".to_vec()),
        "ghosts in the output-cache section die too"
    );
    assert!(
        plan.create.contains(&b"build/keep.rs".to_vec()),
        "a target path missing from the live tree must be created"
    );
}

