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
}
