//! Nearest COMPATIBLE ancestor selection (bead P005; plan §103;
//! composes the P004 ancestry walk with the P001 compatibility
//! contract and a historical cost-benefit estimate).
//!
//! Selection order, with the hard rule up front:
//!
//! - NEVER across incompatible classes: a snapshot whose
//!   compatibility class (toolchain/profile/flags — the P001
//!   contract) differs from the target's is not a candidate at ANY
//!   distance — a nearer incompatible snapshot loses to a farther
//!   compatible one, and with no compatible candidate the answer is
//!   a cold build, never a cross-class warm start;
//! - exact state first (distance 0), then the nearest compatible
//!   git/source ancestor by the P004 walk;
//! - the winner still has to PAY: a warm start is selected only when
//!   the historical estimate says it beats a cold build
//!   (materialization + per-generation catch-up vs the full build);
//!   otherwise the decision is a typed cold build carrying both
//!   numbers.

use crate::ancestry_index::{CommitGraph, SourceState};

/// A compatibility class identity (the P001 contract digest, opaque
/// here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatClass(pub u64);

/// One selectable snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateSnapshot {
    /// The snapshot.
    pub snapshot_id: u64,
    /// The state it was captured at.
    pub state: SourceState,
    /// Its compatibility class.
    pub class: CompatClass,
}

/// Historical costs feeding the benefit estimate (ms; from telemetry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostHistory {
    /// A cold full build.
    pub full_build_ms: u64,
    /// Materializing a snapshot.
    pub materialize_ms: u64,
    /// Catch-up compile cost per generation of distance.
    pub per_generation_ms: u64,
}

impl CostHistory {
    /// Estimated warm-start cost at a distance.
    #[must_use]
    pub const fn warm_ms(&self, distance: u32) -> u64 {
        self.materialize_ms + (distance as u64) * self.per_generation_ms
    }
}

/// Why a cold build was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdCause {
    /// No compatible ancestor holds a snapshot.
    NoCompatibleAncestor,
    /// A compatible ancestor exists, but the estimate says the warm
    /// start loses.
    WarmNotWorthIt {
        /// Estimated warm cost.
        warm_ms: u64,
        /// Estimated full build.
        full_ms: u64,
    },
}

/// The selection decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// Warm-start from this snapshot.
    WarmStart {
        /// The chosen snapshot.
        snapshot_id: u64,
        /// Its distance (generations).
        distance: u32,
        /// Estimated saving vs a cold build (ms).
        estimated_saving_ms: u64,
    },
    /// Build cold, typed.
    ColdBuild(ColdCause),
}

/// Nearest compatible candidate by the P004-style BFS walk.
fn nearest_compatible(
    candidates: &[CandidateSnapshot],
    target: SourceState,
    target_class: CompatClass,
    graph: &CommitGraph,
) -> Option<(CandidateSnapshot, u32)> {
    // Incompatible classes are OUT before distance is even asked.
    let compatible: Vec<&CandidateSnapshot> = candidates
        .iter()
        .filter(|c| c.class == target_class)
        .collect();
    // Distance 0: exact state, then clean-at-commit.
    if let Some(exact) = compatible.iter().find(|c| c.state == target).or_else(|| {
        compatible
            .iter()
            .find(|c| c.state.commit == target.commit && c.state.dirty_digest.is_none())
    }) {
        return Some((**exact, 0));
    }
    // BFS up the commit graph.
    let mut frontier = vec![target.commit];
    let mut seen = Vec::new();
    let mut distance = 0_u32;
    while !frontier.is_empty() {
        if distance > 0 {
            for &commit in &frontier {
                if let Some(hit) = compatible
                    .iter()
                    .find(|c| c.state.commit == commit && c.state.dirty_digest.is_none())
                {
                    return Some((**hit, distance));
                }
            }
        }
        let mut next = Vec::new();
        for &commit in &frontier {
            if seen.contains(&commit) {
                continue;
            }
            seen.push(commit);
            next.extend(graph.parents_of(commit));
        }
        frontier = next;
        distance += 1;
    }
    None
}

/// Select the warm-start base (or a typed cold build).
#[must_use]
pub fn select(
    candidates: &[CandidateSnapshot],
    target: SourceState,
    target_class: CompatClass,
    graph: &CommitGraph,
    history: &CostHistory,
) -> Selection {
    let Some((candidate, distance)) = nearest_compatible(candidates, target, target_class, graph)
    else {
        return Selection::ColdBuild(ColdCause::NoCompatibleAncestor);
    };
    let warm_ms = history.warm_ms(distance);
    if warm_ms >= history.full_build_ms {
        return Selection::ColdBuild(ColdCause::WarmNotWorthIt {
            warm_ms,
            full_ms: history.full_build_ms,
        });
    }
    Selection::WarmStart {
        snapshot_id: candidate.snapshot_id,
        distance,
        estimated_saving_ms: history.full_build_ms - warm_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ancestry_index::CommitId;

    fn clean(n: u64) -> SourceState {
        SourceState {
            commit: CommitId(n),
            dirty_digest: None,
        }
    }

    /// main(1) → A1(10) → A2(11); branch B1(20) from main.
    fn graph() -> CommitGraph {
        let mut g = CommitGraph::default();
        g.insert(CommitId(1), &[]);
        g.insert(CommitId(10), &[CommitId(1)]);
        g.insert(CommitId(11), &[CommitId(10)]);
        g.insert(CommitId(20), &[CommitId(1)]);
        g
    }

    const NIGHTLY_A: CompatClass = CompatClass(0xA);
    const NIGHTLY_B: CompatClass = CompatClass(0xB);

    fn history() -> CostHistory {
        CostHistory {
            full_build_ms: 60_000,
            materialize_ms: 2_000,
            per_generation_ms: 8_000,
        }
    }

    fn candidate(snapshot_id: u64, commit: u64, class: CompatClass) -> CandidateSnapshot {
        CandidateSnapshot {
            snapshot_id,
            state: clean(commit),
            class,
        }
    }

    #[test]
    fn exact_state_and_class_wins_at_distance_zero() {
        let candidates = [candidate(100, 1, NIGHTLY_A), candidate(111, 11, NIGHTLY_A)];
        assert_eq!(
            select(&candidates, clean(11), NIGHTLY_A, &graph(), &history()),
            Selection::WarmStart {
                snapshot_id: 111,
                distance: 0,
                estimated_saving_ms: 58_000, // full 60000 - warm 2000
            }
        );
    }

    #[test]
    fn a_nearer_incompatible_snapshot_loses_to_a_farther_compatible_one() {
        // THE hard-rule fixture: at A2 there is a snapshot in the
        // WRONG class (new nightly); main holds one in the right
        // class two generations up. Selection takes main's — never
        // across classes, at any distance.
        let candidates = [
            candidate(911, 11, NIGHTLY_B), // nearer, incompatible
            candidate(100, 1, NIGHTLY_A),  // farther, compatible
        ];
        let selection = select(&candidates, clean(11), NIGHTLY_A, &graph(), &history());
        assert_eq!(
            selection,
            Selection::WarmStart {
                snapshot_id: 100,
                distance: 2,
                estimated_saving_ms: 60_000 - (2_000 + 2 * 8_000),
            }
        );
    }

    #[test]
    fn no_compatible_ancestor_is_a_cold_build_never_cross_class() {
        // Only incompatible snapshots exist — even the exact commit.
        let candidates = [candidate(911, 11, NIGHTLY_B), candidate(900, 1, NIGHTLY_B)];
        assert_eq!(
            select(&candidates, clean(11), NIGHTLY_A, &graph(), &history()),
            Selection::ColdBuild(ColdCause::NoCompatibleAncestor)
        );
    }

    #[test]
    fn the_cost_benefit_estimate_can_reject_a_far_warm_start() {
        // A compatible ancestor 8 generations up: warm = 2000 + 8 x
        // 8000 = 66000 >= full 60000 — cold build, both numbers
        // carried.
        let mut g = CommitGraph::default();
        g.insert(CommitId(0), &[]);
        for n in 1..=8_u64 {
            g.insert(CommitId(n), &[CommitId(n - 1)]);
        }
        let candidates = [candidate(50, 0, NIGHTLY_A)];
        assert_eq!(
            select(&candidates, clean(8), NIGHTLY_A, &g, &history()),
            Selection::ColdBuild(ColdCause::WarmNotWorthIt {
                warm_ms: 66_000,
                full_ms: 60_000,
            })
        );
        // Three generations: warm 26000 < 60000 — worth it.
        assert_eq!(
            select(&candidates, clean(3), NIGHTLY_A, &g, &history()),
            Selection::WarmStart {
                snapshot_id: 50,
                distance: 3,
                estimated_saving_ms: 34_000,
            }
        );
    }

    #[test]
    fn cross_branch_selection_uses_the_shared_ancestor() {
        // From B1, the A2 snapshot (same class) is NOT an ancestor:
        // selection walks to main's, never across the branch.
        let candidates = [
            candidate(111, 11, NIGHTLY_A), // other branch
            candidate(100, 1, NIGHTLY_A),  // shared ancestor
        ];
        assert_eq!(
            select(&candidates, clean(20), NIGHTLY_A, &graph(), &history()),
            Selection::WarmStart {
                snapshot_id: 100,
                distance: 1,
                estimated_saving_ms: 60_000 - 10_000,
            }
        );
    }
}
