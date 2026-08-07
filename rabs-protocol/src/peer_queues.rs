//! Per-peer bounded priority queues (bead J007; Asupersync blocker
//! 44.4; risk R64's backpressure arm).
//!
//! One peer must never buffer the daemon into the ground. Each peer
//! gets its OWN bounded queue with byte + message limits, priority
//! lanes, and reserve/commit admission:
//!
//! - `reserve()` claims capacity BEFORE the message is materialized;
//!   `commit()` finalizes, `abort()` returns the claim — a crashed
//!   producer cannot leak reserved bytes past its abort path;
//! - admission over limits is a NONBLOCKING typed refusal with a
//!   receipt — never unbounded buffering, never a silent drop;
//! - higher-priority lanes dequeue first; within a lane, FIFO;
//! - cancellation-aware waiting is the runtime's job — this core
//!   exposes the would-block fact synchronously so the adapter can
//!   park a permit wait on its cancellation token.

/// Priority lanes, highest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(missing_docs)]
pub enum Lane {
    Control,
    Interactive,
    Bulk,
}

/// Per-peer limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerQueueLimits {
    /// Max buffered bytes for this peer.
    pub max_bytes: u64,
    /// Max buffered messages for this peer.
    pub max_messages: usize,
}

/// Refusal receipt (emitted to telemetry + the peer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalReceipt {
    /// Which limit refused.
    pub limit: &'static str,
    /// Bytes requested.
    pub requested_bytes: u64,
    /// Bytes currently reserved+committed.
    pub in_use_bytes: u64,
}

/// A capacity reservation (must be committed or aborted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    /// Reservation id.
    pub id: u64,
    /// Reserved bytes.
    pub bytes: u64,
    /// Target lane.
    pub lane: Lane,
}

/// One committed message.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Queued {
    lane: Lane,
    bytes: u64,
    payload: Vec<u8>,
    order: u64,
}

/// The per-peer bounded queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerQueue {
    limits: PeerQueueLimits,
    reserved_bytes: u64,
    reservations: Vec<Reservation>,
    queued: Vec<Queued>,
    next_id: u64,
    next_order: u64,
}

impl PeerQueue {
    /// New queue under the given limits.
    #[must_use]
    pub fn new(limits: PeerQueueLimits) -> Self {
        Self {
            limits,
            reserved_bytes: 0,
            reservations: Vec::new(),
            queued: Vec::new(),
            next_id: 0,
            next_order: 0,
        }
    }

    /// Total bytes in use (reserved + committed).
    #[must_use]
    pub fn in_use_bytes(&self) -> u64 {
        self.reserved_bytes + self.queued.iter().map(|q| q.bytes).sum::<u64>()
    }

    /// Reserve capacity. Nonblocking: over-limit is a typed refusal
    /// with a receipt (the adapter may park a cancellation-aware
    /// permit wait and retry).
    ///
    /// # Errors
    /// [`RefusalReceipt`] naming the limit.
    pub fn reserve(&mut self, bytes: u64, lane: Lane) -> Result<Reservation, RefusalReceipt> {
        let in_use = self.in_use_bytes();
        if in_use + bytes > self.limits.max_bytes {
            return Err(RefusalReceipt {
                limit: "max_bytes",
                requested_bytes: bytes,
                in_use_bytes: in_use,
            });
        }
        if self.queued.len() + self.reservations.len() >= self.limits.max_messages {
            return Err(RefusalReceipt {
                limit: "max_messages",
                requested_bytes: bytes,
                in_use_bytes: in_use,
            });
        }
        let reservation = Reservation {
            id: self.next_id,
            bytes,
            lane,
        };
        self.next_id += 1;
        self.reserved_bytes += bytes;
        self.reservations.push(reservation);
        Ok(reservation)
    }

    /// Commit a reservation with the actual payload.
    pub fn commit(&mut self, reservation: Reservation, payload: Vec<u8>) {
        if let Some(pos) = self
            .reservations
            .iter()
            .position(|r| r.id == reservation.id)
        {
            self.reservations.remove(pos);
            self.reserved_bytes -= reservation.bytes;
            self.queued.push(Queued {
                lane: reservation.lane,
                bytes: reservation.bytes,
                payload,
                order: self.next_order,
            });
            self.next_order += 1;
        }
    }

    /// Abort a reservation (producer failed): capacity returns.
    pub fn abort(&mut self, reservation: Reservation) {
        if let Some(pos) = self
            .reservations
            .iter()
            .position(|r| r.id == reservation.id)
        {
            self.reservations.remove(pos);
            self.reserved_bytes -= reservation.bytes;
        }
    }

    /// Dequeue the next message: highest lane first, FIFO within.
    pub fn dequeue(&mut self) -> Option<Vec<u8>> {
        let best = self
            .queued
            .iter()
            .enumerate()
            .min_by_key(|(_, q)| (q.lane, q.order))
            .map(|(i, _)| i)?;
        Some(self.queued.remove(best).payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> PeerQueueLimits {
        PeerQueueLimits {
            max_bytes: 1000,
            max_messages: 4,
        }
    }

    #[test]
    fn adversarial_flood_stays_bounded_with_refusal_receipts() {
        // THE acceptance: a peer floods; buffering stays inside the
        // limits and every refusal carries a receipt.
        let mut queue = PeerQueue::new(limits());
        let mut refusals = Vec::new();
        for _ in 0..100 {
            match queue.reserve(300, Lane::Bulk) {
                Ok(reservation) => queue.commit(reservation, vec![0; 300]),
                Err(receipt) => refusals.push(receipt),
            }
        }
        assert!(queue.in_use_bytes() <= 1000, "bounded under flood");
        assert_eq!(refusals.len(), 97, "3 fit; 97 refused with receipts");
        assert_eq!(refusals[0].limit, "max_bytes");
        assert_eq!(refusals[0].requested_bytes, 300);
        assert_eq!(refusals[0].in_use_bytes, 900);
        // Message-count limit refuses too (tiny messages, many).
        let mut small = PeerQueue::new(limits());
        for _ in 0..4 {
            let r = small.reserve(1, Lane::Bulk).unwrap();
            small.commit(r, vec![0]);
        }
        assert_eq!(
            small.reserve(1, Lane::Bulk).unwrap_err().limit,
            "max_messages"
        );
    }

    #[test]
    fn reserve_commit_abort_never_leak_capacity() {
        let mut queue = PeerQueue::new(limits());
        let kept = queue.reserve(400, Lane::Interactive).unwrap();
        let crashed = queue.reserve(400, Lane::Bulk).unwrap();
        assert_eq!(queue.in_use_bytes(), 800);
        // The crashed producer aborts: its claim returns fully.
        queue.abort(crashed);
        assert_eq!(queue.in_use_bytes(), 400);
        queue.commit(kept, vec![7; 400]);
        assert_eq!(queue.in_use_bytes(), 400);
        // Freed capacity admits new work.
        assert!(queue.reserve(500, Lane::Bulk).is_ok());
    }

    #[test]
    fn priority_lanes_dequeue_first_fifo_within() {
        let mut queue = PeerQueue::new(PeerQueueLimits {
            max_bytes: 10_000,
            max_messages: 10,
        });
        for (lane, tag) in [
            (Lane::Bulk, b"bulk-1".to_vec()),
            (Lane::Interactive, b"int-1".to_vec()),
            (Lane::Control, b"ctl-1".to_vec()),
            (Lane::Bulk, b"bulk-2".to_vec()),
            (Lane::Control, b"ctl-2".to_vec()),
        ] {
            let r = queue.reserve(10, lane).unwrap();
            queue.commit(r, tag);
        }
        let order: Vec<Vec<u8>> = std::iter::from_fn(|| queue.dequeue()).collect();
        assert_eq!(
            order,
            vec![
                b"ctl-1".to_vec(),
                b"ctl-2".to_vec(),
                b"int-1".to_vec(),
                b"bulk-1".to_vec(),
                b"bulk-2".to_vec(),
            ],
            "control first, FIFO within each lane"
        );
    }
}
