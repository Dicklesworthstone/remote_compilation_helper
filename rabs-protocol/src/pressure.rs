//! Worker pressure/eligibility snapshots + staleness handling (bead
//! I006; plan §84; risks R66/R127).
//!
//! Every worker periodically reports a [`WorkerPressureSnapshot`] —
//! everything the scheduler needs to place work. Two disciplines:
//!
//! - **none of this is a key input** (I23): pressure, queue depth,
//!   cache warmth, kernel state are execution eligibility; the F008
//!   boundary tests already prove eligibility has no digest channel,
//!   and this type lives outside the descriptor entirely;
//! - **staleness is judged on the COORDINATOR'S clock** (R127): the
//!   worker's own timestamps travel as causal sequence values only;
//!   the coordinator stamps receipt with its monotonic clock and a
//!   snapshot is valid for its declared window FROM THAT STAMP. After
//!   a reconnect, validity is treated conservatively: everything
//!   received before the reconnect is stale regardless of window,
//!   because clock continuity across the gap is unprovable.

use crate::generation::{WorkerBootGeneration, WorkerIncarnationId};
use crate::result_identity::TypedDigest;
use crate::wire_time::PeerId;

/// Operator/administrative intent for a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum AdminIntent {
    Active,
    Draining,
    Maintenance,
}

/// One worker's pressure/eligibility snapshot (scheduler-only; never a
/// key input — the type lives outside the descriptor entirely).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerPressureSnapshot {
    /// Worker identity.
    pub identity: PeerId,
    /// Boot generation (F029 fencing).
    pub boot_generation: WorkerBootGeneration,
    /// Process incarnation (F029 fencing).
    pub incarnation: WorkerIncarnationId,
    /// Worker-side causal capture sequence (ordering aid only — NEVER
    /// compared with coordinator time).
    pub captured_at_causal: u64,
    /// Validity window in milliseconds FROM COORDINATOR RECEIPT.
    pub valid_for_ms: u64,
    /// Operator intent.
    pub admin_intent: AdminIntent,
    /// Hard eligibility (capability probes passed).
    pub eligible: bool,
    /// Supported platform class names.
    pub supported_platforms: Vec<String>,
    /// Enforceable isolation profile names.
    pub isolation_profiles: Vec<String>,
    /// Queue depth.
    pub queue_depth: u32,
    /// CPU utilization permille.
    pub cpu_utilization_permille: u16,
    /// Memory PSI (pressure stall) permille.
    pub memory_psi_permille: u16,
    /// IO PSI permille.
    pub io_psi_permille: u16,
    /// Free disk bytes.
    pub free_disk_bytes: u64,
    /// Cache-warmth score permille (how much of the hot set is local).
    pub cache_warmth_permille: u16,
    /// Toolchain inventory digest (which toolchains are staged).
    pub toolchain_inventory_digest: TypedDigest,
    /// Recent object-retrieval reliability permille.
    pub retrieval_reliability_permille: u16,
    /// Outstanding cancellation debt (attempts told to stop, not yet
    /// confirmed dead).
    pub cancellation_debt: u32,
    /// Network path quality permille to the coordinator.
    pub path_quality_permille: u16,
    /// Worker's own confidence in this snapshot, permille.
    pub confidence_permille: u16,
}

/// The coordinator's record of one received snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedSnapshot {
    /// The snapshot as received.
    pub snapshot: WorkerPressureSnapshot,
    /// COORDINATOR monotonic receipt stamp (ms).
    pub received_at_coordinator_ms: u64,
    /// Connection epoch at receipt (bumped on every reconnect).
    pub connection_epoch: u64,
}

/// Freshness verdict at evaluation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Inside the validity window on a continuous connection.
    Fresh,
    /// Window elapsed on the coordinator clock.
    StaleByAge,
    /// Received before the last reconnect: conservatively stale
    /// regardless of window (clock continuity unprovable).
    StaleByReconnect,
}

/// Judge a snapshot's freshness on the COORDINATOR'S clock/epoch.
#[must_use]
pub fn judge_freshness(
    received: &ReceivedSnapshot,
    now_coordinator_ms: u64,
    current_connection_epoch: u64,
) -> Freshness {
    if received.connection_epoch != current_connection_epoch {
        return Freshness::StaleByReconnect;
    }
    let age = now_coordinator_ms.saturating_sub(received.received_at_coordinator_ms);
    if age > received.snapshot.valid_for_ms {
        return Freshness::StaleByAge;
    }
    Freshness::Fresh
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::DigestAlgorithm;

    fn snapshot() -> WorkerPressureSnapshot {
        WorkerPressureSnapshot {
            identity: PeerId("wkr-1".into()),
            boot_generation: WorkerBootGeneration(3),
            incarnation: WorkerIncarnationId(11),
            captured_at_causal: 900,
            valid_for_ms: 5_000,
            admin_intent: AdminIntent::Active,
            eligible: true,
            supported_platforms: vec!["x86_64-linux-gnu".into()],
            isolation_profiles: vec!["strict-hermetic-linux".into()],
            queue_depth: 2,
            cpu_utilization_permille: 420,
            memory_psi_permille: 50,
            io_psi_permille: 10,
            free_disk_bytes: 1 << 40,
            cache_warmth_permille: 800,
            toolchain_inventory_digest: TypedDigest {
                algorithm: DigestAlgorithm::Sha256V1,
                domain: "rabs.toolchain-inventory.v1",
                bytes: [5; 32],
            },
            retrieval_reliability_permille: 990,
            cancellation_debt: 0,
            path_quality_permille: 950,
            confidence_permille: 900,
        }
    }

    fn received(at_ms: u64, epoch: u64) -> ReceivedSnapshot {
        ReceivedSnapshot {
            snapshot: snapshot(),
            received_at_coordinator_ms: at_ms,
            connection_epoch: epoch,
        }
    }

    #[test]
    fn staleness_is_judged_on_the_coordinator_clock() {
        let r = received(10_000, 1);
        // Inside the window: fresh.
        assert_eq!(judge_freshness(&r, 12_000, 1), Freshness::Fresh);
        // Window edge inclusive; one past: stale.
        assert_eq!(judge_freshness(&r, 15_000, 1), Freshness::Fresh);
        assert_eq!(judge_freshness(&r, 15_001, 1), Freshness::StaleByAge);
        // The worker's own causal value is NOT consulted: a snapshot
        // claiming captured_at_causal from "the future" changes nothing
        // (there is no code path comparing it to coordinator time).
    }

    #[test]
    fn reconnect_conservatively_invalidates_prior_snapshots() {
        // THE acceptance staleness case: a snapshot received on epoch 1
        // is stale after reconnect (epoch 2) even INSIDE its window —
        // clock continuity across the gap is unprovable.
        let r = received(10_000, 1);
        assert_eq!(judge_freshness(&r, 10_001, 2), Freshness::StaleByReconnect);
        // A new snapshot on the new epoch is fresh again.
        let renewed = received(10_002, 2);
        assert_eq!(judge_freshness(&renewed, 10_003, 2), Freshness::Fresh);
    }

    #[test]
    fn snapshot_carries_every_bead_field_and_none_reach_keys() {
        // Exhaustive destructure: the bead's field list is complete,
        // and the type contains no descriptor/digest-slot linkage —
        // eligibility facts have no key channel (the F008 boundary).
        let WorkerPressureSnapshot {
            identity: _,
            boot_generation: _,
            incarnation: _,
            captured_at_causal: _,
            valid_for_ms: _,
            admin_intent: _,
            eligible: _,
            supported_platforms: _,
            isolation_profiles: _,
            queue_depth: _,
            cpu_utilization_permille: _,
            memory_psi_permille: _,
            io_psi_permille: _,
            free_disk_bytes: _,
            cache_warmth_permille: _,
            toolchain_inventory_digest: _,
            retrieval_reliability_permille: _,
            cancellation_debt: _,
            path_quality_permille: _,
            confidence_permille: _,
        } = snapshot();
    }
}
