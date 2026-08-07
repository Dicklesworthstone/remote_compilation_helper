//! Provenance-DAG critical-path estimator (bead I015; plan §99).
//!
//! Actions are prioritized by what their completion UNBLOCKS, not by
//! arrival order:
//!
//! - blocked dependents (how many actions wait on this one right now);
//! - historical downstream fan-out (how many actions this one's
//!   outputs have historically fed);
//! - remaining path duration (the longest downstream chain this
//!   action heads — the M009 critical-path walk, forward);
//! - foreground urgency (a human is watching this chain);
//! - metadata-ready potential (rmeta lands early and unblocks
//!   dependents before the full artifact);
//! - duration uncertainty (uncertain actions start earlier: hedging);
//! - cache/prewarm status (a likely hit shrinks the expected cost the
//!   path term is computed from — it does not get a separate bonus).
//!
//! The rule the score encodes: a slow dependency blocking many crates
//! outranks an independent leaf REGARDLESS of arrival order. Arrival
//! order is only the deterministic tie-break.
//!
//! Deterministic integer math throughout — no floats, no clocks.

/// Cache standing for an action (affects EXPECTED cost, not score).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    /// No cached result expected: full estimated duration.
    ColdMiss,
    /// A hit is likely but unverified: duration discounts to the
    /// verification cost (one quarter, floor 1ms).
    LikelyHit,
    /// Prewarmed and verified present: serving cost only (1ms).
    PrewarmedHit,
}

/// The estimator's per-action inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionEstimate {
    /// Arrival index (FIFO position; the tie-break, nothing more).
    pub arrival_index: u32,
    /// Estimated own duration (ms) before cache discounting.
    pub estimated_duration_ms: u64,
    /// Dependents blocked on this action right now.
    pub blocked_dependents: u32,
    /// Historical downstream fan-out (actions its outputs ever fed).
    pub historical_fanout: u32,
    /// Longest downstream chain cost (ms) EXCLUDING this action.
    pub downstream_path_ms: u64,
    /// A foreground request is waiting on this chain.
    pub foreground: bool,
    /// The action emits early metadata (rmeta) that unblocks
    /// dependents before full completion.
    pub metadata_ready_potential: bool,
    /// Duration uncertainty (permille of the estimate; 0 = exact).
    pub uncertainty_permille: u16,
    /// Cache standing.
    pub cache: CacheStatus,
}

impl ActionEstimate {
    /// Expected own cost after cache discounting.
    #[must_use]
    pub const fn expected_duration_ms(&self) -> u64 {
        match self.cache {
            CacheStatus::ColdMiss => self.estimated_duration_ms,
            CacheStatus::LikelyHit => {
                let quarter = self.estimated_duration_ms / 4;
                if quarter == 0 { 1 } else { quarter }
            }
            CacheStatus::PrewarmedHit => 1,
        }
    }

    /// The priority score. Higher runs first.
    #[must_use]
    pub fn score(&self) -> u64 {
        // Remaining-path term: the whole chain this action heads.
        let path = self.expected_duration_ms() + self.downstream_path_ms;
        // Unblocking terms: dependents waiting NOW dominate history.
        let blocked = u64::from(self.blocked_dependents) * 1_000;
        let fanout = u64::from(self.historical_fanout) * 100;
        // Foreground urgency: a fixed large bonus — a watched chain
        // beats an equally-shaped background chain, never a much
        // longer one into starvation.
        let urgency = if self.foreground { 5_000 } else { 0 };
        // Metadata-ready: dependents unblock early, so the effective
        // serialization this action imposes is smaller — worth
        // starting sooner to ship the rmeta.
        let metadata = if self.metadata_ready_potential && self.blocked_dependents > 0 {
            500
        } else {
            0
        };
        // Uncertainty hedge: start uncertain actions earlier so a
        // blowout surfaces while there is still schedule to absorb it.
        let hedge = self.expected_duration_ms() * u64::from(self.uncertainty_permille) / 1_000;
        path + blocked + fanout + urgency + metadata + hedge
    }
}

/// Pick the next action from the ready set: highest score, arrival
/// index as the deterministic tie-break (lower first).
#[must_use]
pub fn pick_next(ready: &[ActionEstimate]) -> Option<usize> {
    ready
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| {
            a.score()
                .cmp(&b.score())
                .then(b.arrival_index.cmp(&a.arrival_index))
        })
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(arrival: u32) -> ActionEstimate {
        ActionEstimate {
            arrival_index: arrival,
            estimated_duration_ms: 300,
            blocked_dependents: 0,
            historical_fanout: 0,
            downstream_path_ms: 0,
            foreground: false,
            metadata_ready_potential: false,
            uncertainty_permille: 0,
            cache: CacheStatus::ColdMiss,
        }
    }

    fn bottleneck(arrival: u32) -> ActionEstimate {
        ActionEstimate {
            arrival_index: arrival,
            estimated_duration_ms: 4_000,
            blocked_dependents: 20,
            historical_fanout: 20,
            downstream_path_ms: 250,
            foreground: false,
            metadata_ready_potential: true,
            uncertainty_permille: 0,
            cache: CacheStatus::ColdMiss,
        }
    }

    #[test]
    fn bottleneck_outranks_leaf_regardless_of_arrival_order() {
        // THE rule: the slow dependency blocking twenty crates wins
        // whether it arrived first or last.
        let late = [leaf(0), leaf(1), bottleneck(99)];
        assert_eq!(pick_next(&late), Some(2), "late arrival still wins");
        let early = [bottleneck(0), leaf(1), leaf(2)];
        assert_eq!(pick_next(&early), Some(0));
        assert!(bottleneck(99).score() > leaf(0).score() * 10);
    }

    #[test]
    fn every_estimator_input_moves_the_score_in_its_direction() {
        let base = leaf(0).score();
        // Blocked dependents raise.
        let mut m = leaf(0);
        m.blocked_dependents = 3;
        assert!(m.score() > base);
        // Historical fan-out raises (less than live blockers).
        let mut m = leaf(0);
        m.historical_fanout = 3;
        assert!(m.score() > base);
        let mut blocked = leaf(0);
        blocked.blocked_dependents = 3;
        let mut fanout = leaf(0);
        fanout.historical_fanout = 3;
        assert!(
            blocked.score() > fanout.score(),
            "live blockers dominate history"
        );
        // Downstream path raises.
        let mut m = leaf(0);
        m.downstream_path_ms = 2_000;
        assert!(m.score() > base);
        // Foreground raises.
        let mut m = leaf(0);
        m.foreground = true;
        assert!(m.score() > base);
        // Metadata potential raises ONLY with someone to unblock.
        let mut m = leaf(0);
        m.metadata_ready_potential = true;
        assert_eq!(m.score(), base, "no dependents: rmeta helps nobody");
        m.blocked_dependents = 1;
        let with_meta = m.score();
        m.metadata_ready_potential = false;
        assert!(with_meta > m.score());
        // Uncertainty raises (hedging).
        let mut m = leaf(0);
        m.uncertainty_permille = 500;
        assert!(m.score() > base);
        // Cache hits shrink the expected cost (and thus the path term).
        let mut m = leaf(0);
        m.cache = CacheStatus::LikelyHit;
        assert!(m.score() < base);
        m.cache = CacheStatus::PrewarmedHit;
        assert_eq!(m.expected_duration_ms(), 1);
    }

    #[test]
    fn ties_break_by_arrival_order_deterministically() {
        let ready = [leaf(7), leaf(3), leaf(5)];
        assert_eq!(pick_next(&ready), Some(1), "equal scores: FIFO order");
        assert_eq!(pick_next(&[]), None);
    }

    // ── THE ACCEPTANCE: replay-corpus storm, estimator vs FIFO ──────

    /// One corpus action: estimator inputs + real duration + deps.
    struct SimAction {
        est: ActionEstimate,
        duration_ms: u64,
        deps: Vec<usize>,
    }

    /// Deterministic greedy list scheduling over `workers` workers.
    /// `by_estimator` false = FIFO (arrival order) pick.
    /// Returns (makespan, per-action finish times).
    fn simulate(actions: &[SimAction], workers: usize, by_estimator: bool) -> (u64, Vec<u64>) {
        let mut finish: Vec<Option<u64>> = vec![None; actions.len()];
        let mut worker_free = vec![0_u64; workers];
        let mut remaining: Vec<usize> = (0..actions.len()).collect();
        while !remaining.is_empty() {
            // Ready = every dependency already scheduled.
            let ready: Vec<usize> = remaining
                .iter()
                .copied()
                .filter(|&i| actions[i].deps.iter().all(|&d| finish[d].is_some()))
                .collect();
            assert!(!ready.is_empty(), "corpus is acyclic");
            let pick = if by_estimator {
                let ests: Vec<ActionEstimate> =
                    ready.iter().map(|&i| actions[i].est.clone()).collect();
                ready[pick_next(&ests).expect("nonempty")]
            } else {
                // FIFO: lowest arrival index.
                ready
                    .iter()
                    .copied()
                    .min_by_key(|&i| actions[i].est.arrival_index)
                    .expect("nonempty")
            };
            // Earliest-free worker; start after deps complete.
            let w = (0..workers)
                .min_by_key(|&w| worker_free[w])
                .expect("workers > 0");
            let dep_done = actions[pick]
                .deps
                .iter()
                .map(|&d| finish[d].expect("scheduled"))
                .max()
                .unwrap_or(0);
            let start = worker_free[w].max(dep_done);
            let end = start + actions[pick].duration_ms;
            worker_free[w] = end;
            finish[pick] = Some(end);
            remaining.retain(|&i| i != pick);
        }
        let finishes: Vec<u64> = finish.into_iter().map(|f| f.expect("all done")).collect();
        (finishes.iter().copied().max().unwrap_or(0), finishes)
    }

    /// The storm corpus: fifteen independent leaves arrive FIRST,
    /// then the slow bottleneck lib, then its twenty dependents.
    fn storm_corpus() -> Vec<SimAction> {
        let mut actions = Vec::new();
        for i in 0..15_u32 {
            actions.push(SimAction {
                est: leaf(i),
                duration_ms: 300,
                deps: vec![],
            });
        }
        actions.push(SimAction {
            est: bottleneck(15), // arrives AFTER every leaf
            duration_ms: 4_000,
            deps: vec![],
        });
        for i in 0..20_u32 {
            actions.push(SimAction {
                est: ActionEstimate {
                    arrival_index: 16 + i,
                    estimated_duration_ms: 250,
                    blocked_dependents: 0,
                    historical_fanout: 0,
                    downstream_path_ms: 0,
                    foreground: false,
                    metadata_ready_potential: false,
                    uncertainty_permille: 0,
                    cache: CacheStatus::ColdMiss,
                },
                duration_ms: 250,
                deps: vec![15],
            });
        }
        actions
    }

    #[test]
    fn estimator_beats_fifo_on_the_storm_replay_corpus() {
        // THE acceptance: on the replay corpus, estimator ordering
        // improves storm tail latency vs FIFO on four workers.
        let corpus = storm_corpus();
        let (fifo_tail, _) = simulate(&corpus, 4, false);
        let (est_tail, est_finishes) = simulate(&corpus, 4, true);
        // FIFO burns the early workers on leaves; the bottleneck
        // waits, and its twenty dependents pay for it.
        assert_eq!(fifo_tail, 6_150);
        // The estimator starts the bottleneck immediately.
        assert_eq!(est_tail, 5_250);
        assert!(est_tail < fifo_tail, "estimator improves tail latency");
        // And the bottleneck really did start at t=0.
        assert_eq!(est_finishes[15], 4_000);
    }

    #[test]
    fn fifo_and_estimator_agree_when_there_is_no_structure() {
        // Honest control: all-independent equal leaves — ordering
        // cannot matter, and both policies produce the same makespan.
        let corpus: Vec<SimAction> = (0..8_u32)
            .map(|i| SimAction {
                est: leaf(i),
                duration_ms: 300,
                deps: vec![],
            })
            .collect();
        let (fifo, _) = simulate(&corpus, 4, false);
        let (est, _) = simulate(&corpus, 4, true);
        assert_eq!(fifo, est);
        assert_eq!(fifo, 600);
    }
}
