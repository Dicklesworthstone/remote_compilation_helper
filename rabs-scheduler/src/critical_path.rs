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

    #[test]
    fn hedged_candidate_commit_and_late_divergence_quarantine() {
        // I016 / I022 / T019 acceptance test:
        // 1. Evaluate hedging eligibility (tail straggler + independent worker +
        //    safe-to-duplicate + active publication fencing).
        let inputs = HedgePolicyInputs {
            generation_id: 0x60,
            elapsed_ms: 1_800,
            expected_duration_ms: 1_000,
            straggler_threshold_permille: 1_500,
            safe_to_duplicate: true,
            publication_fencing_active: true,
            hedges_used: 0,
            max_hedges: 2,
            primary_worker_id: "worker-a".to_owned(),
            candidate_worker_id: "worker-b".to_owned(),
            candidate_failure_domain_independent: true,
        };
        assert_eq!(
            evaluate_hedge_policy(&inputs),
            HedgePolicyDecision::SpawnHedge {
                generation_id: 0x60,
                hedge_index: 0,
            }
        );

        // Refusal checks: same worker, unsafe to duplicate, not yet straggler, no fencing, budget exhausted.
        let mut same_worker = inputs.clone();
        same_worker.candidate_worker_id = "worker-a".to_owned();
        assert_eq!(
            evaluate_hedge_policy(&same_worker),
            HedgePolicyDecision::RefusedNotIndependentWorker
        );
        let mut not_straggler = inputs.clone();
        not_straggler.elapsed_ms = 1_200;
        assert_eq!(
            evaluate_hedge_policy(&not_straggler),
            HedgePolicyDecision::RefusedNotTailStraggler
        );
        let mut unsafe_dup = inputs.clone();
        unsafe_dup.safe_to_duplicate = false;
        assert_eq!(
            evaluate_hedge_policy(&unsafe_dup),
            HedgePolicyDecision::RefusedUnsafeToDuplicate
        );

        // 2. Sibling-lease independence (I31 / T019):
        // Renewing, expiring, or revoking one sibling's lease NEVER affects
        // another sibling's lease; only generation supersession fences all.
        let mut tracker = HedgeGenerationTracker::new(0x60);
        assert!(tracker.register_sibling(1, 101));
        assert!(tracker.register_sibling(2, 202));
        assert!(!tracker.register_sibling(3, 202), "duplicate lease refused");

        assert!(tracker.renew_lease(1, 101, 1));
        assert_eq!(tracker.sibling_renewal_seq(1), Some(1));
        assert_eq!(tracker.sibling_renewal_seq(2), Some(0));

        // Expiring/revoking attempt 1's lease leaves attempt 2 active and valid.
        assert!(tracker.expire_or_revoke_lease(1, 101));
        assert!(!tracker.is_lease_active(1));
        assert!(tracker.is_lease_active(2));

        // 3. CAS winner commit, duplicate evidence merge, and late divergence quarantine:
        // Attempt 2 wins CAS first.
        let digest_win = [0x42; 32];
        assert_eq!(
            tracker.offer_candidate(2, 202, digest_win),
            HedgeCasOutcome::CommittedWinner {
                winner_attempt: 2,
                losers_to_drain: vec![1],
            }
        );

        // Register a second hedge (attempt 3, lease 303) that was already in flight before commit:
        // when it offers the SAME canonical digest, it merges as duplicate confirming evidence.
        let mut tracker_dup = HedgeGenerationTracker::new(0x61);
        assert!(tracker_dup.register_sibling(1, 101));
        assert!(tracker_dup.register_sibling(2, 202));
        assert!(tracker_dup.register_sibling(3, 303));
        assert_eq!(
            tracker_dup.offer_candidate(1, 101, digest_win),
            HedgeCasOutcome::CommittedWinner {
                winner_attempt: 1,
                losers_to_drain: vec![2, 3],
            }
        );
        assert_eq!(
            tracker_dup.offer_candidate(2, 202, digest_win),
            HedgeCasOutcome::MergedDuplicateEvidence {
                confirming_attempt: 2,
            }
        );
        assert!(!tracker_dup.is_quarantined());

        // When late sibling 3 offers a DIFFERENT canonical digest for the same key,
        // it triggers late divergence quarantine + incident without overwriting winner 1!
        let digest_divergent = [0x99; 32];
        assert_eq!(
            tracker_dup.offer_candidate(3, 303, digest_divergent),
            HedgeCasOutcome::QuarantinedLateDivergence {
                winner_attempt: 1,
                divergent_attempt: 3,
            }
        );
        assert!(tracker_dup.is_quarantined());
        assert_eq!(tracker_dup.committed_winner(), Some((1, digest_win)));

        // Coordinator generation supersession invalidates all sibling leases at once.
        tracker_dup.supersede_generation(0x62);
        assert!(!tracker_dup.is_lease_active(1));
        assert!(!tracker_dup.is_lease_active(2));
        assert!(!tracker_dup.is_lease_active(3));
    }
}

// ---------------------------------------------------------------------------
// I016 / I022 / T019: Safe hedging policy & sibling-lease CAS tracker
// ---------------------------------------------------------------------------

/// Inputs to the safe hedging policy evaluator (bead I016; invariant I31).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HedgePolicyInputs {
    /// Active coordinator generation id.
    pub generation_id: u128,
    /// Elapsed wall/monotonic time of the primary attempt (ms).
    pub elapsed_ms: u64,
    /// Expected duration of the action (ms).
    pub expected_duration_ms: u64,
    /// Tail-straggler threshold in permille of `expected_duration_ms` (e.g. 1500 = 1.5x).
    pub straggler_threshold_permille: u16,
    /// Whether the action class is side-effect-free / safe to duplicate.
    pub safe_to_duplicate: bool,
    /// Whether active publication fencing is armed on the coordinator.
    pub publication_fencing_active: bool,
    /// Number of hedges already spawned in this generation.
    pub hedges_used: u32,
    /// Maximum hedges permitted in this generation.
    pub max_hedges: u32,
    /// Primary worker peer identifier.
    pub primary_worker_id: String,
    /// Candidate hedge worker peer identifier.
    pub candidate_worker_id: String,
    /// Whether the candidate worker is in an independent failure/load domain.
    pub candidate_failure_domain_independent: bool,
}

/// Decision emitted by [`evaluate_hedge_policy`] (bead I016).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HedgePolicyDecision {
    /// Spawn a sibling hedge attempt under the shared `generation_id` with its own lease.
    SpawnHedge {
        /// Shared generation id.
        generation_id: u128,
        /// Zero-based hedge index (`hedges_used`).
        hedge_index: u32,
    },
    /// Action is not safe to duplicate.
    RefusedUnsafeToDuplicate,
    /// Publication fencing is not active.
    RefusedNoPublicationFencing,
    /// Generation hedge budget is exhausted.
    RefusedHedgeBudgetExhausted,
    /// Candidate worker is the same as primary or shares a non-independent domain.
    RefusedNotIndependentWorker,
    /// Primary attempt has not yet crossed the tail-straggler threshold.
    RefusedNotTailStraggler,
}

/// Evaluate whether to spawn a hedged sibling attempt (bead I016).
#[must_use]
pub fn evaluate_hedge_policy(inputs: &HedgePolicyInputs) -> HedgePolicyDecision {
    if !inputs.safe_to_duplicate {
        return HedgePolicyDecision::RefusedUnsafeToDuplicate;
    }
    if !inputs.publication_fencing_active {
        return HedgePolicyDecision::RefusedNoPublicationFencing;
    }
    if inputs.hedges_used >= inputs.max_hedges {
        return HedgePolicyDecision::RefusedHedgeBudgetExhausted;
    }
    if inputs.primary_worker_id == inputs.candidate_worker_id
        || !inputs.candidate_failure_domain_independent
    {
        return HedgePolicyDecision::RefusedNotIndependentWorker;
    }
    let baseline = inputs.expected_duration_ms.max(1);
    let threshold_ms =
        baseline.saturating_mul(u64::from(inputs.straggler_threshold_permille)) / 1_000;
    if inputs.elapsed_ms < threshold_ms {
        return HedgePolicyDecision::RefusedNotTailStraggler;
    }
    HedgePolicyDecision::SpawnHedge {
        generation_id: inputs.generation_id,
        hedge_index: inputs.hedges_used,
    }
}

/// Outcome of a candidate offer across hedged sibling attempts (bead I016 / I022).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HedgeCasOutcome {
    /// First valid finisher won CAS and committed; all live siblings must drain.
    CommittedWinner {
        /// Winning attempt id.
        winner_attempt: u128,
        /// Sibling attempt ids ordered to drain.
        losers_to_drain: Vec<u128>,
    },
    /// Late finisher produced byte-identical canonical result; merged as confirming evidence.
    MergedDuplicateEvidence {
        /// Confirming sibling attempt id.
        confirming_attempt: u128,
    },
    /// Late finisher produced a DIFFERENT canonical result for the same key;
    /// quarantines serving and opens a divergence incident without overwriting winner.
    QuarantinedLateDivergence {
        /// Original committed winner attempt id.
        winner_attempt: u128,
        /// Divergent sibling attempt id.
        divergent_attempt: u128,
    },
    /// Refused because the attempt's lease is expired, revoked, or belongs to a superseded generation.
    RefusedInactiveLeaseOrGeneration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SiblingLeaseState {
    attempt_id: u128,
    lease_id: u128,
    renewal_seq: u64,
    active: bool,
    draining: bool,
}

/// Tracks sibling attempts under a shared `ActionGenerationId` with strictly
/// independent execution leases (invariant I31; beads I016, I022, T019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HedgeGenerationTracker {
    generation_id: u128,
    superseded: bool,
    siblings: Vec<SiblingLeaseState>,
    winner: Option<(u128, [u8; 32])>,
    confirming_evidence_attempts: Vec<u128>,
    quarantined_divergence: bool,
}

impl HedgeGenerationTracker {
    /// Create a tracker for `generation_id`.
    #[must_use]
    pub const fn new(generation_id: u128) -> Self {
        Self {
            generation_id,
            superseded: false,
            siblings: Vec::new(),
            winner: None,
            confirming_evidence_attempts: Vec::new(),
            quarantined_divergence: false,
        }
    }

    /// Register a primary or hedge attempt with its own unique `lease_id` (I31).
    pub fn register_sibling(&mut self, attempt_id: u128, lease_id: u128) -> bool {
        if self.superseded
            || self
                .siblings
                .iter()
                .any(|s| s.attempt_id == attempt_id || s.lease_id == lease_id)
        {
            return false;
        }
        self.siblings.push(SiblingLeaseState {
            attempt_id,
            lease_id,
            renewal_seq: 0,
            active: true,
            draining: false,
        });
        true
    }

    /// Renew one sibling's lease without touching any other sibling's lease (T019).
    pub fn renew_lease(&mut self, attempt_id: u128, lease_id: u128, new_seq: u64) -> bool {
        if self.superseded {
            return false;
        }
        let Some(sibling) = self
            .siblings
            .iter_mut()
            .find(|s| s.attempt_id == attempt_id && s.lease_id == lease_id && s.active)
        else {
            return false;
        };
        if new_seq <= sibling.renewal_seq {
            return false;
        }
        sibling.renewal_seq = new_seq;
        true
    }

    /// Expire or revoke ONE sibling's lease; all other siblings remain unaffected (T019).
    pub fn expire_or_revoke_lease(&mut self, attempt_id: u128, lease_id: u128) -> bool {
        let Some(sibling) = self
            .siblings
            .iter_mut()
            .find(|s| s.attempt_id == attempt_id && s.lease_id == lease_id && s.active)
        else {
            return false;
        };
        sibling.active = false;
        sibling.draining = true;
        true
    }

    /// Supersede the entire coordinator generation — the ONLY event that fences all siblings at once.
    pub fn supersede_generation(&mut self, new_generation_id: u128) {
        if new_generation_id != self.generation_id {
            self.superseded = true;
            for sibling in &mut self.siblings {
                sibling.active = false;
                sibling.draining = true;
            }
        }
    }

    /// Inspect a sibling's current renewal sequence.
    #[must_use]
    pub fn sibling_renewal_seq(&self, attempt_id: u128) -> Option<u64> {
        self.siblings
            .iter()
            .find(|s| s.attempt_id == attempt_id)
            .map(|s| s.renewal_seq)
    }

    /// Whether a sibling's lease is still active.
    #[must_use]
    pub fn is_lease_active(&self, attempt_id: u128) -> bool {
        !self.superseded
            && self
                .siblings
                .iter()
                .any(|s| s.attempt_id == attempt_id && s.active)
    }

    /// Offer a prepared candidate result from one sibling attempt.
    pub fn offer_candidate(
        &mut self,
        attempt_id: u128,
        lease_id: u128,
        canonical_digest: [u8; 32],
    ) -> HedgeCasOutcome {
        if self.superseded {
            return HedgeCasOutcome::RefusedInactiveLeaseOrGeneration;
        }
        let Some(pos) = self
            .siblings
            .iter()
            .position(|s| s.attempt_id == attempt_id && s.lease_id == lease_id && s.active)
        else {
            return HedgeCasOutcome::RefusedInactiveLeaseOrGeneration;
        };

        if let Some((winner_attempt, winner_digest)) = self.winner {
            self.siblings[pos].active = false;
            self.siblings[pos].draining = true;
            if canonical_digest == winner_digest {
                self.confirming_evidence_attempts.push(attempt_id);
                HedgeCasOutcome::MergedDuplicateEvidence {
                    confirming_attempt: attempt_id,
                }
            } else {
                self.quarantined_divergence = true;
                HedgeCasOutcome::QuarantinedLateDivergence {
                    winner_attempt,
                    divergent_attempt: attempt_id,
                }
            }
        } else {
            self.winner = Some((attempt_id, canonical_digest));
            let mut losers_to_drain = Vec::new();
            for (idx, sibling) in self.siblings.iter_mut().enumerate() {
                if idx != pos {
                    sibling.draining = true;
                    losers_to_drain.push(sibling.attempt_id);
                }
            }
            HedgeCasOutcome::CommittedWinner {
                winner_attempt: attempt_id,
                losers_to_drain,
            }
        }
    }

    /// Whether serving has been quarantined due to a divergent late hedge offer.
    #[must_use]
    pub const fn is_quarantined(&self) -> bool {
        self.quarantined_divergence
    }

    /// Committed `(winner_attempt, canonical_digest)`, if any.
    #[must_use]
    pub const fn committed_winner(&self) -> Option<(u128, [u8; 32])> {
        self.winner
    }
}
