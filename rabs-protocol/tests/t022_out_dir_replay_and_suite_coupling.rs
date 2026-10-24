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
//! V2 manifests bind file content explicitly. This suite covers
//! equal-length content drift, length drift and section ownership in
//! the pure planner. The N012 filesystem fixture hashes real captured
//! bytes and verifies their restoration after a same-length mutation.
//!
//! Neither `plan_swap` nor `pre_state_key_material` has a production
//! caller today, so nothing is currently mis-replacing anything.

use rabs_protocol::output_manifest::{OutputEntry, OutputSection, OutputTreeManifest};
use rabs_protocol::post_state_replacement::{OutputPath, plan_swap, pre_state_key_material};

fn manifest(out: &[(&str, u64)], cache: &[(&str, u64)]) -> OutputTreeManifest {
    OutputTreeManifest::new(
        out.iter()
            .map(|(p, l)| OutputEntry::new(*p, *l, [7; 32]))
            .collect::<Vec<_>>(),
        cache
            .iter()
            .map(|(p, l)| OutputEntry::new(*p, *l, [7; 32]))
            .collect::<Vec<_>>(),
    )
    .expect("valid manifest")
}

/// Paths the plan would leave in place: everything the live tree has
/// that is not deleted, plus everything the plan creates.
fn resulting_paths(
    live: &OutputTreeManifest,
    plan_delete: &[OutputPath],
    created: &[OutputPath],
) -> Vec<OutputPath> {
    let mut paths: Vec<OutputPath> = [OutputSection::OutDir, OutputSection::OutputCache]
        .into_iter()
        .flat_map(|section| {
            live.section(section)
                .iter()
                .map(move |e| OutputPath::new(section, e.path.clone()))
        })
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
        vec![OutputPath::new(
            OutputSection::OutDir,
            b"build/ghost.rs".to_vec()
        )],
        "the ghost, and only the ghost, is planned for deletion"
    );
    assert!(plan.create.is_empty());

    // Identical states plan no rows at all: silence is the no-op proof.
    let noop = plan_swap(&clean, &clean).expect("plans");
    assert!(noop.delete.is_empty() && noop.create.is_empty());
}

#[test]
fn t022_same_length_drift_changes_key_and_requires_replacement() {
    // Synthetic content identities exercise the schema independently
    // of its file-hashing caller. A different digest at the same
    // section/path/length must never be considered an unchanged file.
    let target = manifest(&[("build/generated.rs", 120)], &[]);
    let mut live = target.clone();
    live.out_dir_entries[0].content_sha256 = [8; 32];

    let plan = plan_swap(&live, &target).expect("plans");
    let changed = OutputPath::new(OutputSection::OutDir, b"build/generated.rs".to_vec());
    assert_eq!(plan.delete, vec![changed.clone()]);
    assert_eq!(plan.create, vec![changed]);
    assert_ne!(
        pre_state_key_material(&live),
        pre_state_key_material(&target),
        "a changed file must alter the pre-state key even when its size is unchanged"
    );
}

#[test]
fn t022_the_planner_does_see_drift_that_changes_length() {
    // Length is still part of identity, even if a corrupt or synthetic
    // fixture reuses its digest for a different length.
    let live = manifest(&[("build/generated.rs", 121)], &[]);
    let target = manifest(&[("build/generated.rs", 120)], &[]);

    let plan = plan_swap(&live, &target).expect("plans");
    let changed = OutputPath::new(OutputSection::OutDir, b"build/generated.rs".to_vec());
    assert_eq!(plan.delete, vec![changed.clone()]);
    assert_eq!(plan.create, vec![changed]);
    assert_ne!(
        pre_state_key_material(&live),
        pre_state_key_material(&target)
    );
}

#[test]
fn t022_replay_plan_preserves_clean_section_and_path_ownership() {
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
    let expected = resulting_paths(&clean, &[], &[]);

    assert_eq!(
        result, expected,
        "after the swap the tree must hold exactly the clean-run path set"
    );
    assert!(
        plan.delete.contains(&OutputPath::new(
            OutputSection::OutDir,
            b"build/ghost.rs".to_vec()
        )),
        "the ghost must die in the swap"
    );
    assert!(
        plan.delete.contains(&OutputPath::new(
            OutputSection::OutputCache,
            b"cache/stale.bin".to_vec()
        )),
        "ghosts in the output-cache section die too"
    );
    assert!(
        plan.create.contains(&OutputPath::new(
            OutputSection::OutDir,
            b"build/keep.rs".to_vec()
        )),
        "a target path missing from the live tree must be created"
    );
}
