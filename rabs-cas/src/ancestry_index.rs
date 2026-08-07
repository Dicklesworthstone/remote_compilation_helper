//! Git/source-state ancestry index for incremental snapshots (bead
//! P004; plan §103; serves the P005 nearest-ancestor query; bounded
//! alongside P008 retention).
//!
//! Every retained snapshot maps to the SOURCE-STATE identity that
//! produced it — the commit PLUS the dirty-tree digest, because a
//! dirty tree between commits is its own state, never "the commit,
//! roughly". Nearest-compatible-ancestor queries are then cheap
//! graph walks (the ≥3× branch ping-pong target needs milliseconds,
//! not content scans):
//!
//! - exact state (commit + same dirty digest) wins at distance 0;
//! - a CLEAN snapshot at the same commit serves a dirty tree at
//!   distance 0 (the warm start the ping-pong workload lives on);
//! - otherwise the walk climbs parent edges breadth-first and takes
//!   the nearest ancestor commit holding a snapshot;
//! - a rebase/amend orphans old states: they are simply unreachable
//!   from the new tip (never returned), and [`AncestryIndex::orphans`]
//!   names them for retention eviction;
//! - growth is BOUNDED: at capacity, inserting evicts the oldest
//!   entry — the index can never outgrow its budget.

use std::collections::BTreeMap;

/// A commit identity (opaque; real git plumbing arrives with the
/// P-series runtime).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CommitId(pub u64);

/// A source-state identity: the commit plus the dirty-tree digest
/// (`None` = clean tree at that commit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceState {
    /// The underlying commit.
    pub commit: CommitId,
    /// Digest of uncommitted changes; `None` for a clean tree.
    pub dirty_digest: Option<u64>,
}

/// A retained snapshot's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotId(pub u64);

/// The commit graph: child → parents (merge commits have several).
#[derive(Debug, Clone, Default)]
pub struct CommitGraph {
    parents: BTreeMap<CommitId, Vec<CommitId>>,
}

impl CommitGraph {
    /// Record a commit with its parents.
    pub fn insert(&mut self, commit: CommitId, parents: &[CommitId]) {
        self.parents.insert(commit, parents.to_vec());
    }

    /// The recorded parents of a commit (empty when unknown).
    #[must_use]
    pub fn parents_of(&self, commit: CommitId) -> Vec<CommitId> {
        self.parents.get(&commit).cloned().unwrap_or_default()
    }

    /// Whether `ancestor` is reachable from `from` (inclusive).
    #[must_use]
    pub fn reachable(&self, from: CommitId, ancestor: CommitId) -> bool {
        let mut frontier = vec![from];
        let mut seen = Vec::new();
        while let Some(c) = frontier.pop() {
            if c == ancestor {
                return true;
            }
            if seen.contains(&c) {
                continue;
            }
            seen.push(c);
            if let Some(ps) = self.parents.get(&c) {
                frontier.extend(ps.iter().copied());
            }
        }
        false
    }
}

/// A nearest-ancestor answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NearestSnapshot {
    /// The snapshot to warm-start from.
    pub snapshot: SnapshotId,
    /// The state it was captured at.
    pub state: SourceState,
    /// Generations between the query commit and the snapshot's
    /// commit (0 = same commit).
    pub distance: u32,
}

/// The bounded ancestry index.
#[derive(Debug, Clone)]
pub struct AncestryIndex {
    /// state → snapshot, in insertion order (the eviction order).
    entries: Vec<(SourceState, SnapshotId)>,
    capacity: usize,
}

impl AncestryIndex {
    /// A new index with a growth bound.
    #[must_use]
    pub const fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            capacity,
        }
    }

    /// Record a retained snapshot at its source state. At capacity,
    /// the OLDEST entry is evicted (P008 retention coupling); the
    /// bound is an invariant.
    pub fn record(&mut self, state: SourceState, snapshot: SnapshotId) {
        self.entries.retain(|(s, _)| *s != state); // re-record moves
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }
        self.entries.push((state, snapshot));
    }

    /// Entries currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Snapshots at a commit: exact dirty match first, then clean.
    fn at_commit(&self, commit: CommitId, dirty: Option<u64>) -> Option<(SourceState, SnapshotId)> {
        // Exact state match (commit + same dirty digest).
        if let Some(hit) = self
            .entries
            .iter()
            .rev()
            .find(|(s, _)| s.commit == commit && s.dirty_digest == dirty)
        {
            return Some(*hit);
        }
        // Clean snapshot at the same commit serves a dirty tree.
        self.entries
            .iter()
            .rev()
            .find(|(s, _)| s.commit == commit && s.dirty_digest.is_none())
            .copied()
    }

    /// THE P005 query: nearest compatible ancestor snapshot for a
    /// source state — a breadth-first walk up parent edges.
    #[must_use]
    pub fn nearest(&self, target: SourceState, graph: &CommitGraph) -> Option<NearestSnapshot> {
        let mut frontier = vec![target.commit];
        let mut seen: Vec<CommitId> = Vec::new();
        let mut distance = 0_u32;
        while !frontier.is_empty() {
            // Dirty digests only matter at distance 0 (the target's
            // own commit); ancestors serve as clean bases.
            let dirty = if distance == 0 {
                target.dirty_digest
            } else {
                None
            };
            for &commit in &frontier {
                if let Some((state, snapshot)) = self.at_commit(commit, dirty) {
                    return Some(NearestSnapshot {
                        snapshot,
                        state,
                        distance,
                    });
                }
            }
            let mut next = Vec::new();
            for &commit in &frontier {
                if seen.contains(&commit) {
                    continue;
                }
                seen.push(commit);
                if let Some(parents) = graph.parents.get(&commit) {
                    next.extend(parents.iter().copied());
                }
            }
            frontier = next;
            distance += 1;
        }
        None
    }

    /// Entries whose commit is unreachable from every live tip
    /// (rebase/amend orphans): retention eviction candidates.
    #[must_use]
    pub fn orphans(&self, graph: &CommitGraph, live_tips: &[CommitId]) -> Vec<SourceState> {
        self.entries
            .iter()
            .filter(|(state, _)| {
                !live_tips
                    .iter()
                    .any(|&tip| graph.reachable(tip, state.commit))
            })
            .map(|(state, _)| *state)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(n: u64) -> CommitId {
        CommitId(n)
    }

    fn clean(n: u64) -> SourceState {
        SourceState {
            commit: c(n),
            dirty_digest: None,
        }
    }

    fn dirty(n: u64, digest: u64) -> SourceState {
        SourceState {
            commit: c(n),
            dirty_digest: Some(digest),
        }
    }

    /// The branchy fixture: main(1) → {A1(10) → A2(11), B1(20)};
    /// snapshots retained at main, A2, B1.
    fn fixture() -> (CommitGraph, AncestryIndex) {
        let mut graph = CommitGraph::default();
        graph.insert(c(1), &[]);
        graph.insert(c(10), &[c(1)]);
        graph.insert(c(11), &[c(10)]);
        graph.insert(c(20), &[c(1)]);
        let mut index = AncestryIndex::new(16);
        index.record(clean(1), SnapshotId(100));
        index.record(clean(11), SnapshotId(111));
        index.record(clean(20), SnapshotId(120));
        (graph, index)
    }

    #[test]
    fn ping_pong_between_branches_hits_exactly() {
        // THE headline workload: A2 ↔ B1 switches find their own
        // snapshot at distance 0, never the other branch's.
        let (graph, index) = fixture();
        assert_eq!(
            index.nearest(clean(11), &graph),
            Some(NearestSnapshot {
                snapshot: SnapshotId(111),
                state: clean(11),
                distance: 0,
            })
        );
        assert_eq!(
            index.nearest(clean(20), &graph).expect("hit").snapshot,
            SnapshotId(120)
        );
        // A NEW branch C from main(1): nearest is main's snapshot —
        // A2/B1 are not ancestors and are never returned.
        let mut graph2 = fixture().0;
        graph2.insert(c(30), &[c(1)]);
        let hit = index.nearest(clean(30), &graph2).expect("shared ancestor");
        assert_eq!(hit.snapshot, SnapshotId(100));
        assert_eq!(hit.distance, 1);
        // A child of A2 finds A2 at one generation, not B1.
        let mut graph3 = fixture().0;
        graph3.insert(c(12), &[c(11)]);
        let hit = index.nearest(clean(12), &graph3).expect("parent hit");
        assert_eq!(hit.snapshot, SnapshotId(111));
        assert_eq!(hit.distance, 1);
    }

    #[test]
    fn dirty_trees_are_their_own_states() {
        // A dirty tree at A2: the CLEAN A2 snapshot serves at
        // distance 0 (warm base). Once a snapshot of that exact
        // dirty state exists, IT wins over the clean one.
        let (graph, mut index) = fixture();
        let dirty_state = dirty(11, 0xD1);
        let warm = index.nearest(dirty_state, &graph).expect("clean base");
        assert_eq!(warm.snapshot, SnapshotId(111));
        assert_eq!(warm.state, clean(11), "clean snapshot serves dirty tree");
        index.record(dirty_state, SnapshotId(211));
        let exact = index.nearest(dirty_state, &graph).expect("exact");
        assert_eq!(exact.snapshot, SnapshotId(211));
        assert_eq!(exact.state, dirty_state);
        // A DIFFERENT dirty digest is a different state: it gets the
        // clean base, never another dirty state's snapshot.
        let other = index.nearest(dirty(11, 0xD2), &graph).expect("clean base");
        assert_eq!(other.snapshot, SnapshotId(111));
    }

    #[test]
    fn rebase_orphans_are_unreachable_and_named_for_eviction() {
        // A2(11) is rebased into A2'(31) on top of main: the old A1/A2
        // chain is no longer reachable from any live tip.
        let (mut graph, index) = fixture();
        graph.insert(c(31), &[c(1)]); // the rebased commit
        let live_tips = [c(31), c(20)];
        // Query from the rebased tip: the orphaned A2 snapshot is
        // NEVER returned — the walk finds main's snapshot instead.
        let hit = index.nearest(clean(31), &graph).expect("main base");
        assert_eq!(hit.snapshot, SnapshotId(100));
        // And the orphan sweep names the stranded states for P008.
        assert_eq!(index.orphans(&graph, &live_tips), vec![clean(11)]);
    }

    #[test]
    fn growth_is_bounded_with_oldest_evicted() {
        let mut index = AncestryIndex::new(4);
        for n in 0..12 {
            index.record(clean(n), SnapshotId(n));
            assert!(index.len() <= 4, "the bound is an invariant");
        }
        assert_eq!(index.len(), 4);
        // The oldest entries are gone; the newest survive.
        let graph = CommitGraph::default();
        assert!(index.nearest(clean(0), &graph).is_none());
        assert_eq!(
            index.nearest(clean(11), &graph).expect("newest").snapshot,
            SnapshotId(11)
        );
        // Re-recording an existing state moves it, never duplicates.
        index.record(clean(11), SnapshotId(99));
        assert_eq!(index.len(), 4);
        assert_eq!(
            index.nearest(clean(11), &graph).expect("moved").snapshot,
            SnapshotId(99)
        );
    }
}
