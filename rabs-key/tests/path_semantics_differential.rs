//! Canonical-vs-original path semantic differential fixtures (bead
//! T030; risk R96; invariant I41; exercises the D030 lane machinery).
//!
//! Each fixture models a project whose observable behavior is a
//! function of the build path — `file!()` embeddings,
//! `CARGO_MANIFEST_DIR` runtime resource lookup, generated strings —
//! and runs the DIFFERENTIAL: build under the original worktree path,
//! build under the canonical `/__rabs/workspace` path, compare
//! observables. The law under test:
//!
//! - an observable difference routes the family to the PATH-
//!   PRESERVING lane — a cross-worktree canonical hit is never
//!   served;
//! - a clean differential (byte-identical observables) honors the
//!   configured shared policy;
//! - incomplete coverage is AMBIGUOUS and demotes to preserving with
//!   shadow audit — ambiguity never upgrades to a shared hit.

use rabs_key::path_policy::{
    BuildPathSemanticPolicy, DifferentialEvidence, PATH_HAZARDS, PathLaneDecision, decide_lane,
};

/// The hazard-project models: what each embeds in its observables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectKind {
    /// `file!()` / panic locations: source paths in the binary.
    FileMacroEmbedding,
    /// Runtime resource lookup via `env!("CARGO_MANIFEST_DIR")`.
    ManifestDirRuntimeLookup,
    /// No path observation anywhere.
    PathInsensitive,
    /// Generated strings observed on SOME targets; coverage partial.
    GeneratedStringsPartialCoverage,
}

/// Simulated observable output of a build at `build_path`.
fn observables(kind: ProjectKind, build_path: &str) -> Vec<String> {
    match kind {
        ProjectKind::FileMacroEmbedding => vec![
            format!("panic message: assertion failed at {build_path}/src/lib.rs:42"),
            "computation: 1337".to_owned(),
        ],
        ProjectKind::ManifestDirRuntimeLookup => vec![
            // The program OPENS this path at runtime: the observable
            // is which file it finds.
            format!("resource path: {build_path}/resources/schema.json"),
        ],
        ProjectKind::PathInsensitive => vec!["computation: 1337".to_owned()],
        ProjectKind::GeneratedStringsPartialCoverage => {
            // Only the lib target was differentially built; the bin
            // target (which embeds paths) was not covered.
            vec!["lib observable: stable".to_owned()]
        }
    }
}

/// Run the differential for one fixture project.
fn run_differential(kind: ProjectKind, original: &str, canonical: &str) -> DifferentialEvidence {
    // Partial coverage is ambiguous BEFORE comparison — an identical
    // subset proves nothing about the uncovered targets.
    if kind == ProjectKind::GeneratedStringsPartialCoverage {
        return DifferentialEvidence::Ambiguous;
    }
    if observables(kind, original) == observables(kind, canonical) {
        DifferentialEvidence::NoObservableDifference
    } else {
        DifferentialEvidence::ObservableDifference
    }
}

const WORKTREE_A: &str = "/Users/alice/checkouts/app";
const WORKTREE_B: &str = "/home/bob/src/app";
const CANONICAL: &str = "/__rabs/workspace";

#[test]
fn file_macro_projects_route_preserving_never_canonical() {
    // THE R96 fixture: file!()/panic-location embedding differs
    // between original and canonical paths.
    let evidence = run_differential(ProjectKind::FileMacroEmbedding, WORKTREE_A, CANONICAL);
    assert_eq!(evidence, DifferentialEvidence::ObservableDifference);
    // Even with a shared policy CONFIGURED, the difference demotes:
    // the decision is the preserving lane, with shadow audit.
    let decision = decide_lane(
        Some(BuildPathSemanticPolicy::CanonicalPortablePath),
        evidence,
    );
    assert_eq!(
        decision,
        PathLaneDecision::PreservingLane { shadow_audit: true }
    );
    // No arm of the decision yields a canonical hit here.
    match decision {
        PathLaneDecision::CanonicalShared(_) => panic!("R96: cross-worktree canonical hit"),
        PathLaneDecision::PreservingLane { .. } => {}
    }
}

#[test]
fn manifest_dir_runtime_lookup_differs_and_demotes() {
    // The runtime-resource fixture: the program looks up files under
    // CARGO_MANIFEST_DIR. Under the canonical path it opens a
    // DIFFERENT file than the user's worktree copy — observable.
    let evidence = run_differential(ProjectKind::ManifestDirRuntimeLookup, WORKTREE_A, CANONICAL);
    assert_eq!(evidence, DifferentialEvidence::ObservableDifference);
    assert_eq!(
        decide_lane(Some(BuildPathSemanticPolicy::PathOpaqueVerified), evidence),
        PathLaneDecision::PreservingLane { shadow_audit: true }
    );
}

#[test]
fn cross_worktree_serving_is_the_bug_the_lane_prevents() {
    // Two worktrees, one canonical spelling: the canonical builds
    // would collide on one key while the ORIGINAL-path observables
    // differ per worktree — serving A's canonical hit to B would
    // hand B alice's paths. The differential catches exactly this.
    let a = observables(ProjectKind::FileMacroEmbedding, WORKTREE_A);
    let b = observables(ProjectKind::FileMacroEmbedding, WORKTREE_B);
    let canon = observables(ProjectKind::FileMacroEmbedding, CANONICAL);
    assert_ne!(a, b, "the worktrees observably differ");
    assert_ne!(a, canon);
    assert_ne!(b, canon, "the canonical spelling matches neither");
    // And the routing therefore refuses the shared lane for both.
    for worktree in [WORKTREE_A, WORKTREE_B] {
        let evidence = run_differential(ProjectKind::FileMacroEmbedding, worktree, CANONICAL);
        assert!(matches!(
            decide_lane(
                Some(BuildPathSemanticPolicy::CanonicalPortablePath),
                evidence
            ),
            PathLaneDecision::PreservingLane { .. }
        ));
    }
}

#[test]
fn path_insensitive_projects_earn_the_shared_lane() {
    // The honest control: identical observables under both spellings
    // honor the configured shared policy.
    let evidence = run_differential(ProjectKind::PathInsensitive, WORKTREE_A, CANONICAL);
    assert_eq!(evidence, DifferentialEvidence::NoObservableDifference);
    assert_eq!(
        decide_lane(
            Some(BuildPathSemanticPolicy::CanonicalPortablePath),
            evidence
        ),
        PathLaneDecision::CanonicalShared(BuildPathSemanticPolicy::CanonicalPortablePath)
    );
}

#[test]
fn partial_coverage_is_ambiguous_and_never_upgrades() {
    // The lib target matched, but the path-embedding bin was never
    // differentially built: AMBIGUOUS — preserving with shadow
    // audit, regardless of the matching subset.
    let evidence = run_differential(
        ProjectKind::GeneratedStringsPartialCoverage,
        WORKTREE_A,
        CANONICAL,
    );
    assert_eq!(evidence, DifferentialEvidence::Ambiguous);
    assert_eq!(
        decide_lane(
            Some(BuildPathSemanticPolicy::ProjectRelativeRemapped),
            evidence
        ),
        PathLaneDecision::PreservingLane { shadow_audit: true }
    );
}

#[test]
fn the_hazard_checklist_names_the_fixture_families() {
    // The fixtures exercise hazards from the pinned D030 checklist —
    // tie them by name so a checklist edit forces fixture review.
    for hazard in [
        "file!()",
        "env!(CARGO_MANIFEST_DIR)",
        "runtime resource lookup",
    ] {
        assert!(
            PATH_HAZARDS.contains(&hazard),
            "{hazard} left the checklist"
        );
    }
}
