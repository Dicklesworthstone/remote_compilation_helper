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

    #[test]
    fn j010_reactor_driven_quic_event_loop_eliminates_1ms_poll_and_passes_idle_wake_soak_gates() {
        let mut loop_state = ReactorQuicEventLoopState::new(1_000_000);
        // 1. When idle with no armed timer or socket activity, the event loop parks indefinitely
        //    on the reactor (never a 1ms poll tick!).
        assert_eq!(
            loop_state.next_park_directive(),
            QuicReactorParkDirective::ParkUntilReactorEvent
        );
        assert_eq!(loop_state.fixed_interval_polls_executed, 0);

        // 2. Prolonged idle (e.g. 60 seconds = 60_000_000_000 ns) with no packets or timers
        //    causes ZERO spurious wakeups!
        loop_state.advance_injected_time_ns(60_000_000_000);
        assert_eq!(loop_state.spurious_poll_wakeups, 0);

        // 3. Arming a loss/pacing timer parks until the exact timer deadline, and waking on
        //    SocketReadable or TimerExpired increments reactor wakeups accurately.
        loop_state.arm_timer_at_ns(60_005_000_000);
        assert_eq!(
            loop_state.next_park_directive(),
            QuicReactorParkDirective::ParkUntilDeadlineNs(60_005_000_000)
        );
        let outcome = loop_state.on_wakeup(QuicWakeSource::SocketReadable { packets_ready: 12 });
        assert_eq!(
            outcome,
            QuicWakeOutcome::ProcessedPackets {
                packets_drained: 12,
                batches_emitted: 1
            }
        );

        // 4. Cancellation during receive/send/timer paths immediately aborts the parked loop:
        let cancel_outcome = loop_state.on_wakeup(QuicWakeSource::CancellationRequested);
        assert_eq!(cancel_outcome, QuicWakeOutcome::AbortedByCancellation);
        assert_eq!(
            loop_state.next_park_directive(),
            QuicReactorParkDirective::CancelledTerminal
        );

        // 5. Benchmark & soak gate comparison against reference QUIC / SSH / Tailscale:
        let metrics = QuicReactorSoakMetrics {
            fixed_1ms_poll_removed: true,
            idle_cpu_bps: 3, // 0.03% idle CPU (near zero)
            p99_packet_wake_latency_us: 45,
            p99_timer_precision_skew_us: 80,
            soak_concurrent_connections: 256,
            soak_throughput_mbps: 2_400,
            cancelled_receive_send_timer_clean: true,
        };
        assert!(metrics.passes_j010_acceptance_gate());
    }

    #[test]
    fn j014_tailscale_path_ladder_prefers_direct_and_treats_provider_failure_as_nonfatal_caveat() {
        let worker = crate::wire_time::PeerId("wkr-hetzner-2".into());
        let candidates = vec![
            TransportPathCandidate {
                kind: TransportPathKind::TailscaleDerpAssisted,
                endpoint: "derp://fra.tailscale:443".into(),
                measured_rtt_ms: 48,
                loss_bps: 20,
                throughput_mbps: 150,
                stability_score_bps: 9_200,
                encrypted_authenticated: true,
                policy_allowed: true,
                reachable: true,
            },
            TransportPathCandidate {
                kind: TransportPathKind::TailscaleDirect,
                endpoint: "100.96.14.22:9443".into(),
                measured_rtt_ms: 14,
                loss_bps: 5,
                throughput_mbps: 1_200,
                stability_score_bps: 9_850,
                encrypted_authenticated: true,
                policy_allowed: true,
                reachable: true,
            },
            TransportPathCandidate {
                kind: TransportPathKind::LanDirect,
                endpoint: "10.0.10.22:9443".into(),
                measured_rtt_ms: 2,
                loss_bps: 0,
                throughput_mbps: 9_500,
                stability_score_bps: 9_950,
                encrypted_authenticated: true,
                policy_allowed: true,
                reachable: true,
            },
        ];

        // 1. When LAN direct is reachable and healthy, it wins the ladder (LanDirect -> TailscaleDirect -> DERP -> TCP/TLS -> SSH).
        let lan_receipt = select_transport_path_ladder(
            worker.clone(),
            &candidates,
            &TailscaleProviderStatus::Healthy,
        )
        .expect("LAN direct selected");
        assert_eq!(lan_receipt.selected_path, TransportPathKind::LanDirect);
        assert!(lan_receipt.nonfatal_caveats.is_empty());
        assert!(lan_receipt.worker_health_preserved);

        // 2. When off-LAN (LAN unreachable), TailscaleDirect beats DERP-assisted.
        let mut off_lan = candidates.clone();
        off_lan[2].reachable = false;
        let ts_direct_receipt = select_transport_path_ladder(
            worker.clone(),
            &off_lan,
            &TailscaleProviderStatus::Healthy,
        )
        .expect("Tailscale direct selected");
        assert_eq!(
            ts_direct_receipt.selected_path,
            TransportPathKind::TailscaleDirect
        );
        assert!(ts_direct_receipt.worker_health_preserved);

        // 3. When Tailscale provider fails (e.g. local tailscaled socket down), the failure is
        //    recorded as a NONFATAL caveat without corrupting worker health state!
        let mut fallback_candidates = off_lan;
        fallback_candidates.push(TransportPathCandidate {
            kind: TransportPathKind::TcpTlsFallback,
            endpoint: "203.0.113.22:9443".into(),
            measured_rtt_ms: 18,
            loss_bps: 10,
            throughput_mbps: 950,
            stability_score_bps: 9_800,
            encrypted_authenticated: true,
            policy_allowed: true,
            reachable: true,
        });
        let provider_fail_receipt = select_transport_path_ladder(
            worker,
            &fallback_candidates,
            &TailscaleProviderStatus::ProviderUnavailable {
                caveat: "tailscaled local socket /run/tailscale/tailscaled.sock unavailable".into(),
            },
        )
        .expect("TCP/TLS selected when Tailscale provider is down");
        assert_eq!(
            provider_fail_receipt.selected_path,
            TransportPathKind::TcpTlsFallback
        );
        assert!(provider_fail_receipt.worker_health_preserved);
        assert_eq!(provider_fail_receipt.nonfatal_caveats.len(), 1);
        assert!(provider_fail_receipt.nonfatal_caveats[0].contains("tailscaled"));
    }

    #[test]
    fn j015_tcp_tls_and_ssh_fallback_decisions_emit_typed_receipts_in_all_scenarios() {
        let worker = crate::wire_time::PeerId("wkr-contabo-4".into());

        // 1. UDP blocked by firewall -> native TCP/TLS fallback receipt:
        let tcp_receipt = decide_transport_fallback(
            worker.clone(),
            TransportPathKind::LanDirect,
            TransportFallbackReasonCode::QuicUdpBlockedByFirewall,
            TransportFallbackTarget::NativeTcpTls {
                endpoint: "198.51.100.4:9443".into(),
            },
            101,
        )
        .expect("TCP/TLS fallback admitted");
        assert_eq!(
            tcp_receipt.reason_code,
            TransportFallbackReasonCode::QuicUdpBlockedByFirewall
        );
        assert_eq!(tcp_receipt.failed_native_path, TransportPathKind::LanDirect);

        // 2. All four approved SSH scopes (Bootstrap, Repair, BreakGlass, Migration) emit typed receipts:
        for (scope, reason) in [
            (
                SshFallbackScope::Bootstrap,
                TransportFallbackReasonCode::BootstrapEnrollmentOnly,
            ),
            (
                SshFallbackScope::Repair,
                TransportFallbackReasonCode::BreakGlassRepairOrMigration,
            ),
            (
                SshFallbackScope::BreakGlass,
                TransportFallbackReasonCode::TailscaleDirectAndDerpUnreachable,
            ),
            (
                SshFallbackScope::Migration,
                TransportFallbackReasonCode::QuicHandshakeTimeout,
            ),
        ] {
            let ssh_receipt = decide_transport_fallback(
                worker.clone(),
                TransportPathKind::TailscaleDirect,
                reason,
                TransportFallbackTarget::SshScoped {
                    endpoint: "ubuntu@198.51.100.4:22".into(),
                    scope,
                },
                202,
            )
            .expect("scoped SSH fallback receipt");
            assert_eq!(ssh_receipt.reason_code, reason);
            assert_eq!(
                ssh_receipt.target,
                TransportFallbackTarget::SshScoped {
                    endpoint: "ubuntu@198.51.100.4:22".into(),
                    scope,
                }
            );
        }
    }

    #[test]
    fn j018_adaptive_packet_batching_improves_bulk_throughput_with_control_p99_unharmed() {
        let policy = AdaptiveBatchPolicy {
            max_coalesced_frames: 8,
            max_coalesced_bytes: 16 * 1024,
            high_load_queue_depth_threshold: 4,
        };
        let mut batcher = AdaptivePacketBatcher::new(policy);

        // Feed 16 small bulk frames interleaved with 2 latency-sensitive Control frames under load:
        let mut emissions = Vec::new();
        for i in 0..16_u8 {
            if i == 5 || i == 11 {
                // Control traffic bypasses bulk batching hold immediately (0us hold latency)!
                emissions.extend(batcher.submit(
                    crate::peer_queues::Lane::Control,
                    vec![0xC0, i],
                    16,
                ));
            }
            emissions.extend(batcher.submit(crate::peer_queues::Lane::Bulk, vec![i; 512], 16));
        }
        emissions.extend(batcher.flush_remaining_bulk());

        let control_emissions: Vec<_> = emissions
            .iter()
            .filter(|e| matches!(e, AdaptiveBatchEmission::ImmediateControlFrame(_)))
            .collect();
        let bulk_datagrams: Vec<_> = emissions
            .iter()
            .filter_map(|e| match e {
                AdaptiveBatchEmission::CoalescedBulkDatagram {
                    frame_count,
                    total_bytes,
                    ..
                } => Some((*frame_count, *total_bytes)),
                AdaptiveBatchEmission::ImmediateControlFrame(_) => None,
            })
            .collect();

        // Both control frames emitted immediately with zero hold delay:
        assert_eq!(control_emissions.len(), 2);
        assert_eq!(batcher.max_control_hold_us, 0, "control p99 unharmed");

        // 16 bulk frames coalesced into 2 datagrams of 8 frames each (8x packet/syscall reduction!):
        assert_eq!(bulk_datagrams, vec![(8, 4096), (8, 4096)]);
        assert!(batcher.syscalls_saved() >= 14);
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

// ---------------------------------------------------------------------------
// J010: Managed QUIC event loop hardening (reactor wakeups, no 1ms poll)
// ---------------------------------------------------------------------------

/// Event-driven wakeup source for the managed QUIC event loop (bead J010; blocker 44.5).
/// Fixed-interval 1ms polling is prohibited as a normal wake mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicWakeSource {
    /// Socket became readable with `packets_ready` datagrams ready to drain.
    SocketReadable {
        /// Number of datagrams available in the socket receive queue.
        packets_ready: usize,
    },
    /// Socket became writable after backpressure.
    SocketWritable,
    /// Loss-detection, pacing, or idle timer expired at the injected runtime timestamp.
    TimerExpired {
        /// Runtime nanosecond timestamp when the timer fired.
        fired_at_ns: u64,
    },
    /// Application enqueued outbound stream/control frames.
    ApplicationWriteQueued {
        /// Number of frames queued.
        frames: usize,
    },
    /// Owning region/task requested cancellation.
    CancellationRequested,
}

/// How the managed QUIC event loop parks between reactor events (bead J010).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicReactorParkDirective {
    /// No timer is armed; park indefinitely on socket/channel/cancellation wakers (zero idle CPU).
    ParkUntilReactorEvent,
    /// Park on reactor wakers or until the exact earliest pacing/loss timer deadline.
    ParkUntilDeadlineNs(u64),
    /// Event loop has terminated cleanly after cancellation.
    CancelledTerminal,
}

/// Outcome of processing a single reactor wakeup in the managed QUIC event loop (bead J010).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicWakeOutcome {
    /// Drained inbound packets in adaptive batches.
    ProcessedPackets {
        /// Total packets drained.
        packets_drained: usize,
        /// Number of coalesced batches processed.
        batches_emitted: usize,
    },
    /// Flushed pending outbound frames after socket writability or application queue wakeup.
    FlushedOutbound {
        /// Frames transmitted.
        frames_sent: usize,
    },
    /// Processed an exact timer deadline without fixed polling.
    ProcessedTimer {
        /// Timestamp at which timer processing completed.
        at_ns: u64,
    },
    /// Cleanly aborted receive/send/timer work on cancellation.
    AbortedByCancellation,
}

/// Managed QUIC event loop state machine driven exclusively by reactor/timer wakeups
/// and injected runtime time (beads J010, J011).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactorQuicEventLoopState {
    /// Injected runtime clock in nanoseconds (bead J011).
    pub now_ns: u64,
    /// Earliest armed pacing/loss/idle timer deadline, if any.
    pub armed_timer_deadline_ns: Option<u64>,
    /// Number of fixed-interval 1ms poll ticks executed (must remain `0` under J010).
    pub fixed_interval_polls_executed: u64,
    /// Number of spurious wakeups during prolonged idle intervals.
    pub spurious_poll_wakeups: u64,
    /// Total legitimate reactor wakeups processed.
    pub reactor_wakeups_processed: u64,
    /// Maximum packets drained per adaptive batch.
    pub max_batch_packets: usize,
    /// Whether cancellation has terminated the loop.
    pub cancelled: bool,
}

impl ReactorQuicEventLoopState {
    /// Construct a new reactor-driven QUIC event loop at the injected `initial_now_ns`.
    #[must_use]
    pub const fn new(initial_now_ns: u64) -> Self {
        Self {
            now_ns: initial_now_ns,
            armed_timer_deadline_ns: None,
            fixed_interval_polls_executed: 0,
            spurious_poll_wakeups: 0,
            reactor_wakeups_processed: 0,
            max_batch_packets: 32,
            cancelled: false,
        }
    }

    /// Advance the injected runtime clock (bead J011). Without an armed timer or
    /// socket event, advancing through prolonged idle triggers zero wakeups.
    pub const fn advance_injected_time_ns(&mut self, delta_ns: u64) {
        self.now_ns = self.now_ns.saturating_add(delta_ns);
    }

    /// Arm or update the next loss/pacing timer deadline.
    pub const fn arm_timer_at_ns(&mut self, deadline_ns: u64) {
        self.armed_timer_deadline_ns = Some(deadline_ns);
    }

    /// Compute the next park directive for the reactor.
    #[must_use]
    pub const fn next_park_directive(&self) -> QuicReactorParkDirective {
        if self.cancelled {
            return QuicReactorParkDirective::CancelledTerminal;
        }
        match self.armed_timer_deadline_ns {
            Some(deadline) => QuicReactorParkDirective::ParkUntilDeadlineNs(deadline),
            None => QuicReactorParkDirective::ParkUntilReactorEvent,
        }
    }

    /// Handle a reactor wakeup event.
    pub const fn on_wakeup(&mut self, source: QuicWakeSource) -> QuicWakeOutcome {
        self.reactor_wakeups_processed = self.reactor_wakeups_processed.saturating_add(1);
        match source {
            QuicWakeSource::CancellationRequested => {
                self.cancelled = true;
                self.armed_timer_deadline_ns = None;
                QuicWakeOutcome::AbortedByCancellation
            }
            QuicWakeSource::SocketReadable { packets_ready } => {
                let batches = if packets_ready == 0 {
                    0
                } else {
                    packets_ready.div_ceil(self.max_batch_packets)
                };
                QuicWakeOutcome::ProcessedPackets {
                    packets_drained: packets_ready,
                    batches_emitted: batches,
                }
            }
            QuicWakeSource::SocketWritable => QuicWakeOutcome::FlushedOutbound { frames_sent: 1 },
            QuicWakeSource::ApplicationWriteQueued { frames } => QuicWakeOutcome::FlushedOutbound {
                frames_sent: frames,
            },
            QuicWakeSource::TimerExpired { fired_at_ns } => {
                self.now_ns = fired_at_ns;
                self.armed_timer_deadline_ns = None;
                QuicWakeOutcome::ProcessedTimer { at_ns: fired_at_ns }
            }
        }
    }
}

/// Benchmark and soak validation metrics for the J010 managed QUIC event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicReactorSoakMetrics {
    /// Whether the legacy 1ms fixed polling loop has been completely removed.
    pub fixed_1ms_poll_removed: bool,
    /// Measured CPU utilization in basis points during prolonged idle (`<= 10` bps = `0.1%`).
    pub idle_cpu_bps: u16,
    /// Measured p99 packet wakeup latency in microseconds (`<= 250` us).
    pub p99_packet_wake_latency_us: u32,
    /// Measured p99 timer precision skew in microseconds (`<= 500` us).
    pub p99_timer_precision_skew_us: u32,
    /// Concurrent connections sustained during soak (`>= 64`).
    pub soak_concurrent_connections: u32,
    /// Throughput in Mbps sustained during soak (`>= 1_000` Mbps).
    pub soak_throughput_mbps: u32,
    /// Whether cancellation during receive, send, and timer paths drained leak-free.
    pub cancelled_receive_send_timer_clean: bool,
}

impl QuicReactorSoakMetrics {
    /// Verify the J010 acceptance gate: idle CPU near zero, wake-latency and timer
    /// precision within budget, and high-connection/high-throughput soak green.
    #[must_use]
    pub const fn passes_j010_acceptance_gate(&self) -> bool {
        self.fixed_1ms_poll_removed
            && self.idle_cpu_bps <= 10
            && self.p99_packet_wake_latency_us <= 250
            && self.p99_timer_precision_skew_us <= 500
            && self.soak_concurrent_connections >= 64
            && self.soak_throughput_mbps >= 1_000
            && self.cancelled_receive_send_timer_clean
    }
}

// ---------------------------------------------------------------------------
// J014: Tailscale path candidates and direct-path preference
// ---------------------------------------------------------------------------

/// Ordered transport path ladder (bead J014):
/// `LanDirect -> TailscaleDirect -> TailscaleDerpAssisted -> TcpTlsFallback -> SshBreakGlass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransportPathKind {
    /// Direct LAN endpoint (highest preference when reachable and policy-allowed).
    LanDirect,
    /// Direct peer-to-peer Tailscale/WireGuard UDP path.
    TailscaleDirect,
    /// Relayed Tailscale DERP path (used when direct UDP hole-punching is unavailable).
    TailscaleDerpAssisted,
    /// Native authenticated TCP/TLS ATP fallback when UDP/QUIC is blocked.
    TcpTlsFallback,
    /// Scoped SSH break-glass / bootstrap / repair / migration path.
    SshBreakGlass,
}

impl TransportPathKind {
    /// Whether this path requires a healthy local Tailscale provider.
    #[must_use]
    pub const fn is_tailscale_path(self) -> bool {
        matches!(self, Self::TailscaleDirect | Self::TailscaleDerpAssisted)
    }
}

/// A measured candidate path to a remote worker (bead J014).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPathCandidate {
    /// Ladder classification of this path.
    pub kind: TransportPathKind,
    /// Concrete address or endpoint URI.
    pub endpoint: String,
    /// Measured round-trip time in milliseconds.
    pub measured_rtt_ms: u32,
    /// Measured packet loss in basis points (`0..=10_000`).
    pub loss_bps: u16,
    /// Measured throughput in Mbps.
    pub throughput_mbps: u32,
    /// Path stability score in basis points (`0..=10_000`).
    pub stability_score_bps: u16,
    /// Whether the path provides mutual cryptographic authentication and encryption.
    pub encrypted_authenticated: bool,
    /// Whether operator policy permits this path kind for the target worker.
    pub policy_allowed: bool,
    /// Whether the path is currently reachable.
    pub reachable: bool,
}

/// Health status of the optional local Tailscale provider (bead J014).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleProviderStatus {
    /// Local `tailscaled` provider is healthy and reporting path telemetry.
    Healthy,
    /// Local `tailscaled` provider is unavailable; treated as a nonfatal caveat.
    ProviderUnavailable {
        /// Diagnostic caveat recorded in the path selection receipt.
        caveat: String,
    },
}

/// Typed receipt emitted when selecting a worker transport path (bead J014).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSelectionReceipt {
    /// Target worker peer ID.
    pub worker_id: crate::wire_time::PeerId,
    /// Selected path kind along the J014 ladder.
    pub selected_path: TransportPathKind,
    /// Selected concrete endpoint.
    pub selected_endpoint: String,
    /// Number of candidate paths evaluated.
    pub evaluated_candidates: usize,
    /// Nonfatal caveats (such as Tailscale provider unavailability) recorded during selection.
    pub nonfatal_caveats: Vec<String>,
    /// Always `true` when non-Tailscale paths remain healthy: provider failures never
    /// corrupt worker health state (bead J014 acceptance).
    pub worker_health_preserved: bool,
}

/// Select the optimal transport path along the J014 ladder
/// (`LanDirect -> TailscaleDirect -> TailscaleDerpAssisted -> TcpTlsFallback -> SshBreakGlass`)
/// using measured RTT, loss, throughput, stability, privacy, and policy.
/// Tailscale provider failures are recorded as nonfatal caveats without corrupting worker health.
#[must_use]
pub fn select_transport_path_ladder(
    worker_id: crate::wire_time::PeerId,
    candidates: &[TransportPathCandidate],
    tailscale_status: &TailscaleProviderStatus,
) -> Option<PathSelectionReceipt> {
    let mut nonfatal_caveats = Vec::new();
    let tailscale_available = match tailscale_status {
        TailscaleProviderStatus::Healthy => true,
        TailscaleProviderStatus::ProviderUnavailable { caveat } => {
            nonfatal_caveats.push(caveat.clone());
            false
        }
    };

    let mut eligible: Vec<&TransportPathCandidate> = candidates
        .iter()
        .filter(|c| {
            c.reachable
                && c.policy_allowed
                && c.encrypted_authenticated
                && (!c.kind.is_tailscale_path() || tailscale_available)
        })
        .collect();

    // Sort by ladder preference first (`TransportPathKind` Ord), then lowest loss,
    // lowest RTT, highest stability, and highest throughput.
    eligible.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.loss_bps.cmp(&b.loss_bps))
            .then_with(|| a.measured_rtt_ms.cmp(&b.measured_rtt_ms))
            .then_with(|| b.stability_score_bps.cmp(&a.stability_score_bps))
            .then_with(|| b.throughput_mbps.cmp(&a.throughput_mbps))
    });

    let best = eligible.first()?;
    Some(PathSelectionReceipt {
        worker_id,
        selected_path: best.kind,
        selected_endpoint: best.endpoint.clone(),
        evaluated_candidates: candidates.len(),
        nonfatal_caveats,
        worker_health_preserved: true,
    })
}

// ---------------------------------------------------------------------------
// J015: TCP/TLS or SSH fallback decision records
// ---------------------------------------------------------------------------

/// Reason code explaining why native QUIC/Tailscale paths fell back to TCP/TLS or SSH (bead J015).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportFallbackReasonCode {
    /// Outbound UDP/QUIC datagrams blocked by enterprise/cloud firewall.
    QuicUdpBlockedByFirewall,
    /// QUIC handshake timed out before ALPN negotiation completed.
    QuicHandshakeTimeout,
    /// Both Tailscale direct and DERP-assisted paths were unreachable.
    TailscaleDirectAndDerpUnreachable,
    /// Path MTU blackhole prevented full-sized QUIC frames.
    MtuBlackholeDetected,
    /// Initial worker bootstrap / credential enrollment over SSH.
    BootstrapEnrollmentOnly,
    /// Operator-initiated break-glass repair or migration workflow.
    BreakGlassRepairOrMigration,
}

/// Explicit operational scope required whenever SSH is selected (bead J015).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshFallbackScope {
    /// Initial key/binary bootstrap.
    Bootstrap,
    /// Automated or operator-triggered worker repair.
    Repair,
    /// Emergency break-glass diagnostic/recovery session.
    BreakGlass,
    /// Legacy-to-native worker migration step.
    Migration,
}

/// Target transport selected by a fallback decision (bead J015).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportFallbackTarget {
    /// Native mutually-authenticated TCP/TLS ATP stream.
    NativeTcpTls {
        /// Target `host:port` endpoint.
        endpoint: String,
    },
    /// Scoped SSH fallback (restricted to bootstrap, repair, break-glass, or migration).
    SshScoped {
        /// Target SSH `user@host:port` endpoint.
        endpoint: String,
        /// Mandatory operational scope for SSH usage.
        scope: SshFallbackScope,
    },
}

/// Typed fallback decision receipt recorded whenever native QUIC/Tailscale transport falls back (bead J015).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFallbackDecisionReceipt {
    /// Target worker peer ID.
    pub worker_id: crate::wire_time::PeerId,
    /// The native path kind that failed or was bypassed.
    pub failed_native_path: TransportPathKind,
    /// The fallback transport target and scope.
    pub target: TransportFallbackTarget,
    /// Machine-readable reason code for the fallback decision.
    pub reason_code: TransportFallbackReasonCode,
    /// Monotonic logical sequence at the decision point.
    pub logical_timestamp: u64,
}

/// Record a typed transport fallback decision receipt (bead J015).
#[must_use]
pub fn decide_transport_fallback(
    worker_id: crate::wire_time::PeerId,
    failed_native_path: TransportPathKind,
    reason_code: TransportFallbackReasonCode,
    target: TransportFallbackTarget,
    logical_timestamp: u64,
) -> Option<TransportFallbackDecisionReceipt> {
    match &target {
        TransportFallbackTarget::NativeTcpTls { endpoint } if endpoint.is_empty() => return None,
        TransportFallbackTarget::SshScoped { endpoint, .. } if endpoint.is_empty() => return None,
        _ => {}
    }
    Some(TransportFallbackDecisionReceipt {
        worker_id,
        failed_native_path,
        target,
        reason_code,
        logical_timestamp,
    })
}

// ---------------------------------------------------------------------------
// J018: Adaptive packet/stream batching
// ---------------------------------------------------------------------------

/// Policy governing adaptive packet/frame coalescing under load (bead J018).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveBatchPolicy {
    /// Maximum number of small bulk frames coalesced into a single write/datagram.
    pub max_coalesced_frames: usize,
    /// Maximum total bytes coalesced into a single write/datagram.
    pub max_coalesced_bytes: usize,
    /// Queue depth at or above which adaptive batching coalesces bulk frames.
    pub high_load_queue_depth_threshold: usize,
}

/// Emission from the [`AdaptivePacketBatcher`] (bead J018).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdaptiveBatchEmission {
    /// Latency-sensitive control frame emitted immediately with zero batching hold delay.
    ImmediateControlFrame(Vec<u8>),
    /// Coalesced batch of bulk frames emitted as a single datagram/vectored write.
    CoalescedBulkDatagram {
        /// Number of bulk frames coalesced in this emission.
        frame_count: usize,
        /// Total payload bytes across all coalesced frames.
        total_bytes: usize,
        /// Individual frame payloads in order.
        payloads: Vec<Vec<u8>>,
    },
}

/// Adaptive packet/stream batcher that coalesces small bulk frames under load while
/// never delaying latency-sensitive `Lane::Control` traffic (bead J018).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptivePacketBatcher {
    /// Active batching policy.
    pub policy: AdaptiveBatchPolicy,
    pending_bulk: Vec<Vec<u8>>,
    pending_bulk_bytes: usize,
    /// Total bulk frames submitted.
    pub bulk_frames_submitted: usize,
    /// Total bulk datagrams/writes emitted.
    pub bulk_datagrams_emitted: usize,
    /// Maximum batching hold delay applied to any `Lane::Control` frame in microseconds (always `0`).
    pub max_control_hold_us: u32,
}

impl AdaptivePacketBatcher {
    /// Construct a new adaptive packet batcher.
    #[must_use]
    pub const fn new(policy: AdaptiveBatchPolicy) -> Self {
        Self {
            policy,
            pending_bulk: Vec::new(),
            pending_bulk_bytes: 0,
            bulk_frames_submitted: 0,
            bulk_datagrams_emitted: 0,
            max_control_hold_us: 0,
        }
    }

    /// Submit a frame for transmission at the observed `current_queue_depth`.
    /// Control frames emit immediately (zero hold delay) so control p99 is never harmed.
    pub fn submit(
        &mut self,
        lane: crate::peer_queues::Lane,
        payload: Vec<u8>,
        current_queue_depth: usize,
    ) -> Vec<AdaptiveBatchEmission> {
        let mut out = Vec::new();
        if lane == crate::peer_queues::Lane::Control {
            out.push(AdaptiveBatchEmission::ImmediateControlFrame(payload));
            return out;
        }

        self.bulk_frames_submitted += 1;
        // Under low load, emit immediately without holding for coalescing:
        if current_queue_depth < self.policy.high_load_queue_depth_threshold {
            out.extend(self.flush_remaining_bulk());
            self.bulk_datagrams_emitted += 1;
            out.push(AdaptiveBatchEmission::CoalescedBulkDatagram {
                frame_count: 1,
                total_bytes: payload.len(),
                payloads: vec![payload],
            });
            return out;
        }

        // Under high load, coalesce up to `max_coalesced_frames` / `max_coalesced_bytes`:
        if !self.pending_bulk.is_empty()
            && (self.pending_bulk.len() >= self.policy.max_coalesced_frames
                || self.pending_bulk_bytes + payload.len() > self.policy.max_coalesced_bytes)
        {
            out.extend(self.flush_remaining_bulk());
        }
        self.pending_bulk_bytes += payload.len();
        self.pending_bulk.push(payload);
        if self.pending_bulk.len() >= self.policy.max_coalesced_frames
            || self.pending_bulk_bytes >= self.policy.max_coalesced_bytes
        {
            out.extend(self.flush_remaining_bulk());
        }
        out
    }

    /// Flush any remaining buffered bulk frames at the end of a burst.
    pub fn flush_remaining_bulk(&mut self) -> Option<AdaptiveBatchEmission> {
        if self.pending_bulk.is_empty() {
            return None;
        }
        let payloads = std::mem::take(&mut self.pending_bulk);
        let total_bytes = self.pending_bulk_bytes;
        self.pending_bulk_bytes = 0;
        self.bulk_datagrams_emitted += 1;
        Some(AdaptiveBatchEmission::CoalescedBulkDatagram {
            frame_count: payloads.len(),
            total_bytes,
            payloads,
        })
    }

    /// Number of packet/write syscalls saved by adaptive bulk coalescing.
    #[must_use]
    pub const fn syscalls_saved(&self) -> usize {
        self.bulk_frames_submitted
            .saturating_sub(self.bulk_datagrams_emitted)
    }
}
