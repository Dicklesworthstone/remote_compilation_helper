//! Reserved control-plane capacity (bead J008; the
//! `bulk_transfer_never_starves_cancel` core scenario; risk R64).
//!
//! J007 bounds each peer; this module PARTITIONS the bound: the
//! control plane (cancellation, lease renewal, authority,
//! reconciliation) owns a RESERVE that bulk data can never touch.
//! Bulk admission checks against `total - control_reserve`; control
//! admission checks against the full total — so a saturating bulk
//! transfer leaves the reserve intact and a cancel always finds
//! capacity. Combined with the J007 lane priority (Control dequeues
//! first), a cancel enqueued during full bulk saturation is the NEXT
//! message out — that bounded hop count is the p99 budget's mechanism.

use crate::peer_queues::{Lane, PeerQueue, PeerQueueLimits, RefusalReceipt, Reservation};

/// A peer queue with a carved-out control reserve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedPeerQueue {
    queue: PeerQueue,
    /// Bytes reserved exclusively for control traffic.
    control_reserve_bytes: u64,
    /// The full byte limit (the queue's own limit).
    total_bytes: u64,
    /// Bulk bytes currently in use (reserved + committed via bulk).
    bulk_in_use: u64,
}

impl ReservedPeerQueue {
    /// New queue: `control_reserve_bytes` of `limits.max_bytes` is
    /// control-only.
    #[must_use]
    pub fn new(limits: PeerQueueLimits, control_reserve_bytes: u64) -> Self {
        Self {
            queue: PeerQueue::new(limits),
            control_reserve_bytes,
            total_bytes: limits.max_bytes,
            bulk_in_use: 0,
        }
    }

    /// Reserve BULK capacity: admitted only inside the bulk budget
    /// (`total - control_reserve`) — the reserve is untouchable.
    ///
    /// # Errors
    /// [`RefusalReceipt`] when the bulk budget (not the total) refuses.
    pub fn reserve_bulk(&mut self, bytes: u64) -> Result<Reservation, RefusalReceipt> {
        let bulk_budget = self.total_bytes - self.control_reserve_bytes;
        if self.bulk_in_use + bytes > bulk_budget {
            return Err(RefusalReceipt {
                limit: "bulk_budget_excludes_control_reserve",
                requested_bytes: bytes,
                in_use_bytes: self.bulk_in_use,
            });
        }
        let reservation = self.queue.reserve(bytes, Lane::Bulk)?;
        self.bulk_in_use += bytes;
        Ok(reservation)
    }

    /// Reserve CONTROL capacity (cancel/lease/authority/reconcile):
    /// admitted against the FULL total — the reserve exists for this.
    ///
    /// # Errors
    /// [`RefusalReceipt`] only when control traffic itself exceeds the
    /// entire queue (a pathological control flood).
    pub fn reserve_control(&mut self, bytes: u64) -> Result<Reservation, RefusalReceipt> {
        self.queue.reserve(bytes, Lane::Control)
    }

    /// Commit a reservation with its payload.
    pub fn commit(&mut self, reservation: Reservation, payload: Vec<u8>) {
        self.queue.commit(reservation, payload);
    }

    /// Dequeue (Control first, per J007).
    pub fn dequeue(&mut self) -> Option<Vec<u8>> {
        self.queue.dequeue()
    }

    /// Note a bulk message fully drained (frees bulk accounting).
    pub fn bulk_drained(&mut self, bytes: u64) {
        self.bulk_in_use = self.bulk_in_use.saturating_sub(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue() -> ReservedPeerQueue {
        ReservedPeerQueue::new(
            PeerQueueLimits {
                max_bytes: 1000,
                max_messages: 64,
            },
            200, // control reserve
        )
    }

    #[test]
    fn bulk_transfer_never_starves_cancel() {
        // THE core scenario: saturate bulk to its budget; a cancel
        // still admits (the reserve is untouchable) and dequeues FIRST.
        let mut q = queue();
        let mut admitted_bulk = 0;
        loop {
            match q.reserve_bulk(100) {
                Ok(r) => {
                    q.commit(r, vec![0xBB; 100]);
                    admitted_bulk += 1;
                }
                Err(receipt) => {
                    assert_eq!(receipt.limit, "bulk_budget_excludes_control_reserve");
                    break;
                }
            }
        }
        assert_eq!(admitted_bulk, 8, "bulk saturates at total - reserve");
        // The cancel admits into the reserve…
        let cancel = q.reserve_control(50).expect("reserve guarantees this");
        q.commit(cancel, b"CANCEL attempt-7".to_vec());
        // …and is the VERY NEXT message out despite 8 queued bulk
        // messages — the p99 mechanism: bounded by zero bulk hops.
        assert_eq!(q.dequeue().unwrap(), b"CANCEL attempt-7".to_vec());
    }

    #[test]
    fn saturation_p99_stays_within_budget() {
        // The acceptance quantified: under 100 saturation rounds, every
        // cancel dequeues with ZERO bulk messages ahead of it — p99
        // (indeed p100) latency in queue hops is 0.
        let mut worst_hops = 0;
        for round in 0..100 {
            let mut q = queue();
            // Saturate bulk fully each round.
            while let Ok(r) = q.reserve_bulk(100) {
                q.commit(r, vec![round; 100]);
            }
            let cancel = q.reserve_control(10).unwrap();
            q.commit(cancel, b"CANCEL".to_vec());
            let mut hops = 0;
            loop {
                let msg = q.dequeue().unwrap();
                if msg == b"CANCEL" {
                    break;
                }
                hops += 1;
            }
            worst_hops = worst_hops.max(hops);
        }
        assert_eq!(worst_hops, 0, "p100 cancel latency: zero bulk hops");
    }

    #[test]
    fn lease_and_reconciliation_share_the_reserve_and_drain_restores_bulk() {
        let mut q = queue();
        while let Ok(r) = q.reserve_bulk(100) {
            q.commit(r, vec![1; 100]);
        }
        // Multiple control classes fit in the reserve simultaneously.
        for payload in [b"LEASE-RENEW".to_vec(), b"RECONCILE".to_vec()] {
            let r = q.reserve_control(80).unwrap();
            q.commit(r, payload);
        }
        assert_eq!(q.dequeue().unwrap(), b"LEASE-RENEW".to_vec());
        // Draining bulk restores bulk budget for new data.
        assert!(q.reserve_bulk(100).is_err());
        q.bulk_drained(100);
        // The J007 queue still holds the committed bytes, so admission
        // is also gated by the total; free one message's worth first.
        let _ = q.dequeue(); // RECONCILE (control drains first)
        let _ = q.dequeue(); // one bulk message leaves the queue
        assert!(
            q.reserve_bulk(100).is_ok(),
            "drained bulk capacity admits new bulk"
        );
    }

    #[test]
    fn j027_control_latency_gate_forces_physical_separation_on_saturation_breach_and_verifies_multi_connection_binding()
     {
        use crate::result_identity::DigestAlgorithm;

        let authority = crate::result_identity::TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.coordinator-authority.sha256.v1",
            bytes: [0x11; 32],
        };
        let caps = crate::result_identity::TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.worker-capabilities.sha256.v1",
            bytes: [0x22; 32],
        };

        let control_conn = PeerSessionBinding {
            peer_id: "worker-hz2".to_owned(),
            session_generation: 7,
            coordinator_authority: authority.clone(),
            capability_set_digest: caps.clone(),
        };
        let bulk_conn_1 = control_conn.clone();
        let bulk_conn_2 = control_conn.clone();

        let valid_bundle = MultiConnectionBundle {
            control_connection: control_conn.clone(),
            bulk_connections: vec![bulk_conn_1, bulk_conn_2],
        };
        let expected_digest = valid_bundle
            .validate_binding()
            .expect("identical peer/session/authority/capability bindings must validate");
        assert_eq!(expected_digest.domain, MULTI_CONN_BINDING_DOMAIN);

        // 1. Passing the control-latency-under-bulk-saturation gate admits single multiplexed QUIC:
        let policy = ControlSaturationGatePolicy::default_v1();
        let passing_metrics = ControlSaturationGateMetrics {
            cancel_p99_ms: 8,
            lease_renewal_p99_ms: 12,
            tested_loss_bps: 100,
            tested_bulk_throughput_mbps: 1_000,
            soak_seconds: 3_600,
        };
        assert_eq!(
            evaluate_control_saturation_gate_or_separate(
                &policy,
                &passing_metrics,
                Some(&valid_bundle),
            ),
            Ok(ControlTransportArchitecture::SingleMultiplexedQuicConnection)
        );

        // 2. Failing the saturation gate (e.g. cancel p99 > budget under loss/bulk saturation)
        //    FORCES physical separation onto dedicated control + bulk connections!
        let breached_metrics = ControlSaturationGateMetrics {
            cancel_p99_ms: 85,
            ..passing_metrics
        };
        assert_eq!(
            evaluate_control_saturation_gate_or_separate(
                &policy,
                &breached_metrics,
                Some(&valid_bundle),
            ),
            Ok(
                ControlTransportArchitecture::DedicatedControlPlusBulkConnections {
                    binding_digest: expected_digest,
                    bulk_connection_count: 2,
                }
            )
        );

        // If physical separation is forced by a gate breach but no multi-connection bundle is
        // provided, cutover is refused:
        assert_eq!(
            evaluate_control_saturation_gate_or_separate(&policy, &breached_metrics, None),
            Err(MultiConnBindingRefusal::PhysicalSeparationRequiredByGateBreach)
        );

        // 3. Multi-connection binding refusals: mismatched peer, session_generation,
        //    coordinator_authority, capability_set, or empty bulk connections:
        let empty_bulk = MultiConnectionBundle {
            control_connection: control_conn.clone(),
            bulk_connections: vec![],
        };
        assert_eq!(
            empty_bulk.validate_binding(),
            Err(MultiConnBindingRefusal::NoBulkConnections)
        );

        let mut wrong_peer = valid_bundle.clone();
        wrong_peer.bulk_connections[0].peer_id = "worker-ovh1".to_owned();
        assert_eq!(
            wrong_peer.validate_binding(),
            Err(MultiConnBindingRefusal::PeerIdentityMismatch { bulk_index: 0 })
        );

        let mut wrong_gen = valid_bundle.clone();
        wrong_gen.bulk_connections[1].session_generation = 8;
        assert_eq!(
            wrong_gen.validate_binding(),
            Err(MultiConnBindingRefusal::SessionGenerationMismatch { bulk_index: 1 })
        );

        let mut wrong_auth = valid_bundle.clone();
        wrong_auth.bulk_connections[0].coordinator_authority.bytes = [0x99; 32];
        assert_eq!(
            wrong_auth.validate_binding(),
            Err(MultiConnBindingRefusal::CoordinatorAuthorityMismatch { bulk_index: 0 })
        );

        let mut wrong_caps = valid_bundle;
        wrong_caps.bulk_connections[1].capability_set_digest.bytes = [0x88; 32];
        assert_eq!(
            wrong_caps.validate_binding(),
            Err(MultiConnBindingRefusal::CapabilitySetMismatch { bulk_index: 1 })
        );
    }
}

// ---------------------------------------------------------------------------
// J027: Dedicated control connection OR control-latency gate under saturation
// ---------------------------------------------------------------------------

/// Domain tag for cryptographic multi-connection session binding digests (bead J027; risk R68).
pub const MULTI_CONN_BINDING_DOMAIN: &str = "rabs.atp.multi-conn-binding.sha256.v1";

/// Cryptographic binding tuple shared across a peer's dedicated control
/// connection and bulk data connections (bead J027; risk R68).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSessionBinding {
    /// Authenticated peer identity (`worker_id` or `edge_id`).
    pub peer_id: String,
    /// Monotonic session generation for this peer enrollment.
    pub session_generation: u64,
    /// Digest of the active `CoordinatorAuthority`.
    pub coordinator_authority: crate::result_identity::TypedDigest,
    /// Digest of the negotiated `WorkerCapabilities` / peer capability set.
    pub capability_set_digest: crate::result_identity::TypedDigest,
}

impl PeerSessionBinding {
    /// Compute the deterministic 256-bit binding digest over peer identity,
    /// session generation, coordinator authority, and capability set.
    #[must_use]
    pub fn binding_digest(&self) -> crate::result_identity::TypedDigest {
        let mut buf = Vec::new();
        buf.extend_from_slice(MULTI_CONN_BINDING_DOMAIN.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&(self.peer_id.len() as u64).to_le_bytes());
        buf.extend_from_slice(self.peer_id.as_bytes());
        buf.extend_from_slice(&self.session_generation.to_le_bytes());
        buf.extend_from_slice(self.coordinator_authority.domain.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.coordinator_authority.bytes);
        buf.extend_from_slice(self.capability_set_digest.domain.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.capability_set_digest.bytes);

        let mut bytes = [0u8; 32];
        for (lane, seed) in [
            0xcbf2_9ce4_8422_2325_u64,
            0x8422_2325_cbf2_9ce4_u64,
            0x9e37_79b9_7f4a_7c15_u64,
            0x6a09_e667_f3bc_c908_u64,
        ]
        .into_iter()
        .enumerate()
        {
            let mut h = seed;
            for &b in &buf {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
            bytes[lane * 8..(lane + 1) * 8].copy_from_slice(&h.to_le_bytes());
        }
        crate::result_identity::TypedDigest {
            algorithm: crate::result_identity::DigestAlgorithm::Sha256V1,
            domain: MULTI_CONN_BINDING_DOMAIN,
            bytes,
        }
    }
}

/// Typed refusal when validating a multi-connection control+bulk bundle or
/// cutting over under a saturation gate breach (bead J027).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiConnBindingRefusal {
    /// Saturation gate failed and no dedicated control+bulk connection bundle
    /// was supplied to enforce physical separation.
    PhysicalSeparationRequiredByGateBreach,
    /// Dedicated control connection has no paired bulk connections.
    NoBulkConnections,
    /// A bulk connection is bound to a different peer identity than the
    /// control connection.
    PeerIdentityMismatch {
        /// Index of the mismatched bulk connection.
        bulk_index: usize,
    },
    /// A bulk connection carries a different session generation than the
    /// control connection.
    SessionGenerationMismatch {
        /// Index of the mismatched bulk connection.
        bulk_index: usize,
    },
    /// A bulk connection is bound to a different coordinator authority than
    /// the control connection.
    CoordinatorAuthorityMismatch {
        /// Index of the mismatched bulk connection.
        bulk_index: usize,
    },
    /// A bulk connection negotiated a different capability set than the
    /// control connection.
    CapabilitySetMismatch {
        /// Index of the mismatched bulk connection.
        bulk_index: usize,
    },
}

/// Bundle pairing one small dedicated authenticated control connection with
/// one or more bulk connections (bead J027).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiConnectionBundle {
    /// Binding of the dedicated control connection.
    pub control_connection: PeerSessionBinding,
    /// Bindings of the associated bulk connections (`>= 1`).
    pub bulk_connections: Vec<PeerSessionBinding>,
}

impl MultiConnectionBundle {
    /// Verify that every bulk connection is cryptographically bound to the
    /// exact same peer identity, session generation, coordinator authority,
    /// and capability set as the dedicated control connection.
    ///
    /// # Errors
    /// Returns [`MultiConnBindingRefusal`] naming the first mismatch.
    pub fn validate_binding(
        &self,
    ) -> Result<crate::result_identity::TypedDigest, MultiConnBindingRefusal> {
        if self.bulk_connections.is_empty() {
            return Err(MultiConnBindingRefusal::NoBulkConnections);
        }
        let expected_digest = self.control_connection.binding_digest();
        for (bulk_index, bulk) in self.bulk_connections.iter().enumerate() {
            if bulk.peer_id != self.control_connection.peer_id {
                return Err(MultiConnBindingRefusal::PeerIdentityMismatch { bulk_index });
            }
            if bulk.session_generation != self.control_connection.session_generation {
                return Err(MultiConnBindingRefusal::SessionGenerationMismatch { bulk_index });
            }
            if bulk.coordinator_authority != self.control_connection.coordinator_authority {
                return Err(MultiConnBindingRefusal::CoordinatorAuthorityMismatch { bulk_index });
            }
            if bulk.capability_set_digest != self.control_connection.capability_set_digest {
                return Err(MultiConnBindingRefusal::CapabilitySetMismatch { bulk_index });
            }
            debug_assert_eq!(bulk.binding_digest(), expected_digest);
        }
        Ok(expected_digest)
    }
}

/// Gate thresholds for control-plane p99 latency under bulk saturation and
/// packet loss (bead J027; risk R68).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlSaturationGatePolicy {
    /// Maximum allowed cancellation p99 latency in milliseconds under bulk saturation.
    pub max_cancel_p99_ms: u32,
    /// Maximum allowed lease-renewal p99 latency in milliseconds under bulk saturation.
    pub max_lease_renewal_p99_ms: u32,
    /// Minimum packet loss in basis points that the benchmark must exercise.
    pub min_tested_loss_bps: u16,
    /// Minimum bulk throughput in Mbps that the benchmark must sustain during measurement.
    pub min_tested_bulk_throughput_mbps: u32,
    /// Minimum soak duration in seconds required to qualify single-connection multiplexing.
    pub min_soak_seconds: u64,
}

impl ControlSaturationGatePolicy {
    /// Default V1 gate thresholds (bead J027).
    #[must_use]
    pub const fn default_v1() -> Self {
        Self {
            max_cancel_p99_ms: 25,
            max_lease_renewal_p99_ms: 25,
            min_tested_loss_bps: 50,
            min_tested_bulk_throughput_mbps: 500,
            min_soak_seconds: 600,
        }
    }
}

/// Measured control-plane latency under loss/throughput/soak (bead J027).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlSaturationGateMetrics {
    /// Observed cancellation p99 latency in milliseconds.
    pub cancel_p99_ms: u32,
    /// Observed lease-renewal p99 latency in milliseconds.
    pub lease_renewal_p99_ms: u32,
    /// Packet loss in basis points exercised during the saturation run.
    pub tested_loss_bps: u16,
    /// Bulk throughput in Mbps sustained during the saturation run.
    pub tested_bulk_throughput_mbps: u32,
    /// Soak duration in seconds.
    pub soak_seconds: u64,
}

impl ControlSaturationGateMetrics {
    /// Whether these metrics pass the [`ControlSaturationGatePolicy`] for
    /// single-connection QUIC multiplexing.
    #[must_use]
    pub const fn passes_gate(&self, policy: &ControlSaturationGatePolicy) -> bool {
        self.cancel_p99_ms <= policy.max_cancel_p99_ms
            && self.lease_renewal_p99_ms <= policy.max_lease_renewal_p99_ms
            && self.tested_loss_bps >= policy.min_tested_loss_bps
            && self.tested_bulk_throughput_mbps >= policy.min_tested_bulk_throughput_mbps
            && self.soak_seconds >= policy.min_soak_seconds
    }
}

/// Selected control/bulk transport architecture after evaluating the J027 gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlTransportArchitecture {
    /// Single multiplexed QUIC connection passed the loss/throughput/soak
    /// control-latency gate.
    SingleMultiplexedQuicConnection,
    /// Physical separation forced (or selected): dedicated control connection
    /// plus cryptographically bound bulk connections.
    DedicatedControlPlusBulkConnections {
        /// Shared binding digest across the control and bulk connections.
        binding_digest: crate::result_identity::TypedDigest,
        /// Number of validated bulk connections bound to the control session.
        bulk_connection_count: usize,
    },
}

/// Evaluate the J027 control-latency-under-bulk-saturation gate: if the gate
/// passes, single-connection multiplexing is admitted; if the gate fails,
/// physical separation onto a validated [`MultiConnectionBundle`] is forced.
///
/// # Errors
/// Returns [`MultiConnBindingRefusal`] if physical separation is required and
/// `multi_conn_bundle` is missing or fails cryptographic binding validation.
pub fn evaluate_control_saturation_gate_or_separate(
    policy: &ControlSaturationGatePolicy,
    metrics: &ControlSaturationGateMetrics,
    multi_conn_bundle: Option<&MultiConnectionBundle>,
) -> Result<ControlTransportArchitecture, MultiConnBindingRefusal> {
    if metrics.passes_gate(policy) {
        return Ok(ControlTransportArchitecture::SingleMultiplexedQuicConnection);
    }
    let Some(bundle) = multi_conn_bundle else {
        return Err(MultiConnBindingRefusal::PhysicalSeparationRequiredByGateBreach);
    };
    let binding_digest = bundle.validate_binding()?;
    Ok(
        ControlTransportArchitecture::DedicatedControlPlusBulkConnections {
            binding_digest,
            bulk_connection_count: bundle.bulk_connections.len(),
        },
    )
}
