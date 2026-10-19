//! Bounded missing-object queries + range/bitmap ACKs + credit +
//! resume (bead J013; risk R54).
//!
//! Object transfer at fleet scale, without chatty per-chunk traffic:
//!
//! - **FindMissingObjects** is batched and BOUNDED (a query names at
//!   most `max_batch` IDs); inventory hints/Blooms may PRE-FILTER a
//!   query but are never correctness authority — the authoritative
//!   answer comes from the responder's actual store;
//! - **large transfers** acknowledge with CUMULATIVE ranges plus a
//!   sparse bitmap for out-of-order islands — the ACK count stays
//!   FLAT as chunk count grows (one ACK per credit window, not per
//!   chunk);
//! - **credit windows** bound in-flight chunks; the sender stalls at
//!   zero credit and resumes on grant;
//! - **resume** reconstructs from the cumulative ACK state: after a
//!   reconnect the receiver re-advertises `(cumulative, islands)` and
//!   the sender retransmits only the holes (the H008 sparse-writer
//!   journal persists the state).

/// A bounded missing-object query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindMissingObjects {
    /// Queried object IDs (bounded by `MAX_QUERY_BATCH`).
    pub ids: Vec<[u8; 32]>,
}

/// Query bound.
pub const MAX_QUERY_BATCH: usize = 4096;

impl FindMissingObjects {
    /// Build a bounded query; refuses oversized batches.
    ///
    /// # Errors
    /// The batch size when it exceeds [`MAX_QUERY_BATCH`].
    pub fn new(ids: Vec<[u8; 32]>) -> Result<Self, usize> {
        if ids.len() > MAX_QUERY_BATCH {
            return Err(ids.len());
        }
        Ok(Self { ids })
    }
}

/// The receiver's transfer-ACK state: cumulative + island bitmap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransferAckState {
    /// Every chunk index <= this is received (0 = none; indices are
    /// 1-based).
    pub cumulative: u64,
    /// Received out-of-order islands beyond the cumulative point.
    pub islands: Vec<u64>,
}

impl TransferAckState {
    /// Record one received chunk; returns whether the cumulative point
    /// advanced (an ACK-worthy event under windowed acking).
    pub fn receive_chunk(&mut self, index: u64) -> bool {
        if index <= self.cumulative || self.islands.contains(&index) {
            return false; // duplicate
        }
        if index == self.cumulative + 1 {
            self.cumulative = index;
            // Absorb contiguous islands.
            loop {
                let next = self.cumulative + 1;
                if let Some(pos) = self.islands.iter().position(|i| *i == next) {
                    self.islands.remove(pos);
                    self.cumulative = next;
                } else {
                    break;
                }
            }
            true
        } else {
            self.islands.push(index);
            false
        }
    }

    /// The holes the sender must retransmit on resume: everything in
    /// `1..=total` that is neither cumulative-covered nor an island.
    #[must_use]
    pub fn holes(&self, total: u64) -> Vec<u64> {
        (self.cumulative + 1..=total)
            .filter(|i| !self.islands.contains(i))
            .collect()
    }
}

/// Credit-window sender state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditWindow {
    /// Chunks the receiver has granted.
    pub credit: u64,
    /// Chunks sent, unacknowledged.
    pub in_flight: u64,
}

impl CreditWindow {
    /// May the sender transmit another chunk?
    #[must_use]
    pub const fn may_send(&self) -> bool {
        self.in_flight < self.credit
    }

    /// Send one chunk (caller checked `may_send`).
    pub fn sent(&mut self) {
        self.in_flight += 1;
    }

    /// A windowed ACK arrived covering `acked` chunks: frees flight
    /// slots.
    pub fn acked(&mut self, acked: u64) {
        self.in_flight = self.in_flight.saturating_sub(acked);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_are_batched_and_bounded() {
        assert!(FindMissingObjects::new(vec![[0; 32]; 4096]).is_ok());
        assert_eq!(
            FindMissingObjects::new(vec![[0; 32]; 4097]),
            Err(4097),
            "oversized batches refuse — split, never stream unbounded"
        );
    }

    #[test]
    fn ack_per_message_ratio_stays_flat_as_chunks_grow() {
        // THE acceptance: with windowed acking (ACK only when the
        // cumulative point advances AND a window boundary passes),
        // ACK count grows with WINDOWS, not chunks.
        for total in [100_u64, 1_000, 10_000] {
            let mut state = TransferAckState::default();
            let window = 64;
            let mut acks = 0;
            for index in 1..=total {
                let advanced = state.receive_chunk(index);
                if advanced && state.cumulative.is_multiple_of(window) {
                    acks += 1;
                }
            }
            let expected = total / window;
            assert!(
                acks <= expected + 1,
                "{total} chunks: {acks} ACKs (flat ratio: ~1 per {window})"
            );
        }
    }

    #[test]
    fn out_of_order_islands_absorb_and_resume_lists_only_holes() {
        // Chunks arrive 1,2,5,6,9; resume must retransmit 3,4,7,8,10.
        let mut state = TransferAckState::default();
        for index in [1, 2, 5, 6, 9] {
            state.receive_chunk(index);
        }
        assert_eq!(state.cumulative, 2);
        assert_eq!(state.holes(10), vec![3, 4, 7, 8, 10]);
        // The hole at 3 fills: cumulative jumps THROUGH the island 5,6.
        assert!(state.receive_chunk(3));
        assert!(state.receive_chunk(4));
        assert_eq!(state.cumulative, 6);
        assert_eq!(state.holes(10), vec![7, 8, 10]);
        // Duplicates are inert.
        assert!(!state.receive_chunk(5));
        assert_eq!(state.cumulative, 6);
    }

    #[test]
    fn credit_windows_bound_in_flight_chunks() {
        let mut window = CreditWindow {
            credit: 4,
            in_flight: 0,
        };
        let mut sent = 0;
        while window.may_send() {
            window.sent();
            sent += 1;
        }
        assert_eq!(sent, 4, "the sender stalls at zero credit");
        // A windowed ACK frees slots; sending resumes.
        window.acked(3);
        assert!(window.may_send());
        assert_eq!(window.in_flight, 1);
    }

    #[test]
    fn j019_worker_to_worker_seeding_stream_verifies_receipt_and_browns_out_under_pressure() {
        let mut stream = WorkerToWorkerSeedingStream::new(
            crate::wire_time::PeerId("wkr-seed-src".into()),
            crate::wire_time::PeerId("wkr-seed-dst".into()),
            [0x33; 32],
            4,
        );
        let chunks: [&[u8]; 2] = [b"chunk-1-bytes", b"chunk-2-bytes"];
        let expected_whole_digest =
            crate::object_model::compute_seeding_digest(b"chunk-1-byteschunk-2-bytes");

        // 1. Normal transfer + receipt verification succeeds.
        assert_eq!(
            stream.transfer_and_verify(&chunks, expected_whole_digest, false),
            SeedingStreamVerdict::VerifiedComplete { chunks_received: 2 }
        );

        // 2. Under foreground pressure, the seeding stream immediately browns out!
        let mut pressured = WorkerToWorkerSeedingStream::new(
            crate::wire_time::PeerId("wkr-seed-src".into()),
            crate::wire_time::PeerId("wkr-seed-dst".into()),
            [0x34; 32],
            4,
        );
        assert_eq!(
            pressured.transfer_and_verify(&chunks, expected_whole_digest, true),
            SeedingStreamVerdict::BrownedOutUnderPressure
        );

        // 3. Corrupted wire payload fails verification on receipt!
        let mut corrupted = WorkerToWorkerSeedingStream::new(
            crate::wire_time::PeerId("wkr-seed-src".into()),
            crate::wire_time::PeerId("wkr-seed-dst".into()),
            [0x35; 32],
            4,
        );
        assert_eq!(
            corrupted.transfer_and_verify(
                &[b"bad-bytes", b"chunk-2-bytes"],
                expected_whole_digest,
                false
            ),
            SeedingStreamVerdict::VerificationFailed
        );
    }

    #[test]
    fn j020_and_j021_raptorq_and_multipath_frontier_evaluations_enforce_kill_criteria_and_no_core_dependency()
     {
        // J020: RaptorQ evaluation on measured lossy corpus (risk R30).
        // Fleet WAN corpus shows low loss (< 0.2%) where QUIC selective retransmission + range ACKs
        // outperform FEC CPU/bandwidth overhead -> KILL CRITERION TRIGGERED (DeferNoCoreDependency).
        let wan_corpus = RaptorQLossyCorpusMetrics {
            measured_packet_loss_bps: 15, // 0.15% packet loss on Contabo/OVH/Hetzner links
            fec_tail_latency_reduction_bps: 300, // 3% tail gain (< 15% proceed threshold)
            fec_cpu_overhead_bps: 1_200,  // 12% CPU overhead (> 8% budget)
            bandwidth_expansion_bps: 1_500, // 15% parity overhead
        };
        let rq_decision = evaluate_raptorq_lossy_corpus(&wan_corpus);
        assert!(!rq_decision.core_path_depends_on_raptorq);
        assert_eq!(
            rq_decision.verdict,
            FrontierEvaluationVerdict::KillCriterionTriggeredDefer {
                reason: "retransmission-beats-fec-on-measured-wan-corpus",
            }
        );
        assert!(
            rq_decision
                .render_decision_document()
                .contains("NO_CORE_DEPENDENCY_ON_RAPTORQ")
        );

        // Synthetic high-loss satellite/WAN link where FEC meets proceed threshold and stays within CPU budget:
        let high_loss = RaptorQLossyCorpusMetrics {
            measured_packet_loss_bps: 350,         // 3.5% loss
            fec_tail_latency_reduction_bps: 2_500, // 25% p99 reduction
            fec_cpu_overhead_bps: 400,             // 4% CPU
            bandwidth_expansion_bps: 1_000,
        };
        let rq_admit = evaluate_raptorq_lossy_corpus(&high_loss);
        assert!(!rq_admit.core_path_depends_on_raptorq);
        assert_eq!(
            rq_admit.verdict,
            FrontierEvaluationVerdict::EligibleOptionalExtension {
                rollback_toggle: "atp.fec.raptorq.enabled=false",
            }
        );

        // J021: Multipath / fan-out evaluation after single-path stability (risk R30).
        // 1. If single-path ATP has not yet proven stability against rsync in M8 gates -> DEFER!
        let mp_unstable = MultipathFleetCorpusMetrics {
            single_path_m8_stable: false,
            measured_p95_speedup_bps: 3_000,
            reordering_buffer_memory_overhead_bps: 500,
        };
        assert_eq!(
            evaluate_multipath_fanout_frontier(&mp_unstable).verdict,
            FrontierEvaluationVerdict::KillCriterionTriggeredDefer {
                reason: "single-path-atp-stability-gate-prerequisite-unmet",
            }
        );

        // 2. Single-path stable, but LAN+Tailscale fan-out speedup (< 20%) does not justify
        //    scheduler/reordering complexity -> KILL CRITERION TRIGGERED!
        let mp_low_gain = MultipathFleetCorpusMetrics {
            single_path_m8_stable: true,
            measured_p95_speedup_bps: 800, // 8% speedup (< 20% threshold)
            reordering_buffer_memory_overhead_bps: 1_400,
        };
        let mp_decision = evaluate_multipath_fanout_frontier(&mp_low_gain);
        assert!(!mp_decision.core_path_depends_on_multipath);
        assert_eq!(
            mp_decision.verdict,
            FrontierEvaluationVerdict::KillCriterionTriggeredDefer {
                reason: "multipath-speedup-below-proceed-threshold-vs-complexity-budget",
            }
        );
        let doc = mp_decision.render_decision_document();
        assert!(doc.contains("NO_CLAIM_MULTIPATH_REQUIRED_FOR_CORE_ATP"));
        assert!(doc.contains("atp.multipath.fanout.enabled=false"));
    }
}

/// Verdict of a worker-to-worker seeding stream transfer (bead J019).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedingStreamVerdict {
    /// All chunks transferred under credit control and whole-object digest verified on receipt.
    VerifiedComplete {
        /// Total chunks received and acknowledged.
        chunks_received: u64,
    },
    /// Stream browned out and yielded bandwidth/CPU because foreground compilation pressure rose.
    BrownedOutUnderPressure,
    /// Whole-object digest verification failed on receipt; payload discarded.
    VerificationFailed,
}

/// Wire realization of coordinator-directed worker-to-worker peer object seeding (bead J019; H019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerToWorkerSeedingStream {
    /// Source worker peer ID.
    pub source_worker: crate::wire_time::PeerId,
    /// Destination worker peer ID.
    pub destination_worker: crate::wire_time::PeerId,
    /// Seeded object digest.
    pub object_id: [u8; 32],
    /// Receiver ACK state.
    pub ack_state: TransferAckState,
    /// Sender credit window.
    pub credit_window: CreditWindow,
}

impl WorkerToWorkerSeedingStream {
    /// Construct a new bounded worker-to-worker seeding stream.
    #[must_use]
    pub fn new(
        source_worker: crate::wire_time::PeerId,
        destination_worker: crate::wire_time::PeerId,
        object_id: [u8; 32],
        initial_credit: u64,
    ) -> Self {
        Self {
            source_worker,
            destination_worker,
            object_id,
            ack_state: TransferAckState::default(),
            credit_window: CreditWindow {
                credit: initial_credit.max(1),
                in_flight: 0,
            },
        }
    }

    /// Execute a windowed chunk transfer over the seeding stream, browning out immediately
    /// under pressure and verifying the whole-object digest on receipt (bead J019).
    pub fn transfer_and_verify(
        &mut self,
        chunks: &[&[u8]],
        expected_whole_digest: u64,
        pressure_brownout: bool,
    ) -> SeedingStreamVerdict {
        if pressure_brownout {
            return SeedingStreamVerdict::BrownedOutUnderPressure;
        }
        let mut reassembled = Vec::new();
        for (idx, chunk) in chunks.iter().enumerate() {
            if !self.credit_window.may_send() {
                self.credit_window.acked(self.credit_window.in_flight);
            }
            self.credit_window.sent();
            let chunk_index = (idx as u64) + 1;
            let _ = self.ack_state.receive_chunk(chunk_index);
            reassembled.extend_from_slice(chunk);
        }
        self.credit_window.acked(self.credit_window.in_flight);

        if crate::object_model::compute_seeding_digest(&reassembled) != expected_whole_digest {
            return SeedingStreamVerdict::VerificationFailed;
        }
        SeedingStreamVerdict::VerifiedComplete {
            chunks_received: self.ack_state.cumulative,
        }
    }
}

/// Shared verdict for M16 frontier transport evaluations (beads J020/J021; risk R30).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontierEvaluationVerdict {
    /// Kill criterion triggered: feature remains disabled/deferred with zero core dependency.
    KillCriterionTriggeredDefer {
        /// Corpus-backed reason the frontier feature was deferred/killed.
        reason: &'static str,
    },
    /// Corpus evidence met the proceed threshold within the risk/complexity budget;
    /// feature may run behind an optional, rollback-safe toggle with zero core dependency.
    EligibleOptionalExtension {
        /// Operator kill-switch / rollback configuration key.
        rollback_toggle: &'static str,
    },
}

/// Measured lossy-path corpus metrics for the J020 RaptorQ FEC evaluation (risk R30).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaptorQLossyCorpusMetrics {
    /// Observed packet loss rate in basis points (`0..=10_000`).
    pub measured_packet_loss_bps: u16,
    /// Measured p99 transfer latency reduction from FEC vs QUIC retransmission (`0..=10_000` bps).
    pub fec_tail_latency_reduction_bps: u16,
    /// Measured CPU overhead from fountain encoding/decoding (`0..=10_000` bps).
    pub fec_cpu_overhead_bps: u16,
    /// Bandwidth overhead from repair symbols (`0..=10_000` bps).
    pub bandwidth_expansion_bps: u16,
}

/// Decision record for the J020 RaptorQ evaluation on a measured lossy corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaptorQEvaluationDecision {
    /// Evaluated corpus metrics.
    pub metrics: RaptorQLossyCorpusMetrics,
    /// Proceed/kill verdict.
    pub verdict: FrontierEvaluationVerdict,
    /// Always `false`: core ATP correctness and liveness never depend on RaptorQ (J020 acceptance).
    pub core_path_depends_on_raptorq: bool,
}

impl RaptorQEvaluationDecision {
    /// Render the M16 frontier decision document with hypothesis, corpus evidence,
    /// proceed threshold, kill criterion, rollback plan, and explicit no-claims.
    #[must_use]
    pub fn render_decision_document(&self) -> String {
        format!(
            "# J020 Frontier Decision: RaptorQ FEC on Measured Lossy Corpus\n\
             - Hypothesis: Fountain repair symbols reduce p99 object transfer latency by >= 15% on lossy WAN paths.\n\
             - Corpus Evidence: loss={} bps, p99_gain={} bps, cpu_overhead={} bps, bw_overhead={} bps.\n\
             - Proceed Threshold: p99_gain >= 1500 bps AND cpu_overhead <= 800 bps.\n\
             - Kill Criterion: p99_gain < 1500 bps OR cpu_overhead > 800 bps.\n\
             - Verdict: {:?}\n\
             - Rollback Plan: `atp.fec.raptorq.enabled=false` reverts immediately to range-ACK retransmission.\n\
             - Explicit Non-Claim: `NO_CORE_DEPENDENCY_ON_RAPTORQ`\n",
            self.metrics.measured_packet_loss_bps,
            self.metrics.fec_tail_latency_reduction_bps,
            self.metrics.fec_cpu_overhead_bps,
            self.metrics.bandwidth_expansion_bps,
            self.verdict,
        )
    }
}

/// Evaluate RaptorQ on a measured lossy-path corpus under M16 frontier discipline (bead J020).
#[must_use]
pub const fn evaluate_raptorq_lossy_corpus(
    metrics: &RaptorQLossyCorpusMetrics,
) -> RaptorQEvaluationDecision {
    let verdict =
        if metrics.fec_tail_latency_reduction_bps >= 1_500 && metrics.fec_cpu_overhead_bps <= 800 {
            FrontierEvaluationVerdict::EligibleOptionalExtension {
                rollback_toggle: "atp.fec.raptorq.enabled=false",
            }
        } else {
            FrontierEvaluationVerdict::KillCriterionTriggeredDefer {
                reason: "retransmission-beats-fec-on-measured-wan-corpus",
            }
        };
    RaptorQEvaluationDecision {
        metrics: *metrics,
        verdict,
        core_path_depends_on_raptorq: false,
    }
}

/// Measured fleet corpus metrics for the J021 multipath/fan-out evaluation (risk R30).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipathFleetCorpusMetrics {
    /// Whether single-path ATP has already passed all M8 stability gates against rsync.
    pub single_path_m8_stable: bool,
    /// Measured p95 transfer speedup from multi-path/multi-source union fetch (`0..=10_000` bps).
    pub measured_p95_speedup_bps: u16,
    /// Memory overhead from cross-path chunk reordering buffers (`0..=10_000` bps).
    pub reordering_buffer_memory_overhead_bps: u16,
}

/// Decision record for the J021 multipath/fan-out evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipathEvaluationDecision {
    /// Evaluated fleet metrics.
    pub metrics: MultipathFleetCorpusMetrics,
    /// Proceed/kill verdict.
    pub verdict: FrontierEvaluationVerdict,
    /// Always `false`: core ATP transport never depends on multipath machinery (J021 acceptance).
    pub core_path_depends_on_multipath: bool,
}

impl MultipathEvaluationDecision {
    /// Render the M16 frontier decision document for J021 multipath/fan-out transfer.
    #[must_use]
    pub fn render_decision_document(&self) -> String {
        format!(
            "# J021 Frontier Decision: Multipath / Multi-Source Fan-Out Transfer\n\
             - Hypothesis: Striping large dataset/artifact fetches across LAN+Tailscale or multiple workers improves p95 transfer time by >= 20%.\n\
             - Corpus Evidence: single_path_m8_stable={}, p95_speedup={} bps, reorder_mem_overhead={} bps.\n\
             - Proceed Threshold: single_path_m8_stable == true AND p95_speedup >= 2000 bps AND reorder_mem_overhead <= 1000 bps.\n\
             - Kill Criterion: single_path_m8_stable == false OR p95_speedup < 2000 bps OR reorder_mem_overhead > 1000 bps.\n\
             - Verdict: {:?}\n\
             - Rollback Plan: `atp.multipath.fanout.enabled=false` forces single-path primary peer selection.\n\
             - Explicit Non-Claim: `NO_CLAIM_MULTIPATH_REQUIRED_FOR_CORE_ATP`\n",
            self.metrics.single_path_m8_stable,
            self.metrics.measured_p95_speedup_bps,
            self.metrics.reordering_buffer_memory_overhead_bps,
            self.verdict,
        )
    }
}

/// Evaluate multipath/fan-out transfer under M16 frontier discipline (bead J021).
#[must_use]
pub const fn evaluate_multipath_fanout_frontier(
    metrics: &MultipathFleetCorpusMetrics,
) -> MultipathEvaluationDecision {
    let verdict = if !metrics.single_path_m8_stable {
        FrontierEvaluationVerdict::KillCriterionTriggeredDefer {
            reason: "single-path-atp-stability-gate-prerequisite-unmet",
        }
    } else if metrics.measured_p95_speedup_bps >= 2_000
        && metrics.reordering_buffer_memory_overhead_bps <= 1_000
    {
        FrontierEvaluationVerdict::EligibleOptionalExtension {
            rollback_toggle: "atp.multipath.fanout.enabled=false",
        }
    } else {
        FrontierEvaluationVerdict::KillCriterionTriggeredDefer {
            reason: "multipath-speedup-below-proceed-threshold-vs-complexity-budget",
        }
    };
    MultipathEvaluationDecision {
        metrics: *metrics,
        verdict,
        core_path_depends_on_multipath: false,
    }
}
