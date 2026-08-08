//! Per-subscriber bounded/spillable delivery queues — slow-client
//! isolation (bead C017; the second half of risk R94).
//!
//! One action, N subscribers, and one of them is slow. The canonical
//! action stream must NEVER feel that: production backpressure on the
//! shared stream would let one stalled wrapper stall everyone (and the
//! build). The isolation discipline:
//!
//! - each subscriber owns a BOUNDED in-memory queue (byte budget);
//! - when the memory budget fills, frames SPILL — they leave the
//!   memory bound but stay queued, in order, under their own bounded
//!   spill budget (the disk region; byte accounting here, file I/O in
//!   the edge daemon);
//! - `enqueue` therefore never blocks and never refuses while budgets
//!   hold: the producer (the shared stream fan-out) always completes
//!   immediately;
//! - a subscriber that exhausts BOTH budgets is the pathological
//!   client: the outcome is a typed detach decision for THAT
//!   subscriber (its C011 interest releases; everyone else and the
//!   action are untouched) — isolation, never a shared stall and
//!   never unbounded buffering;
//! - dequeue order is global FIFO across memory and spill: a slow
//!   client that wakes up drains everything in sequence order.
//!
//! Distinct from `peer_queues` (J007): that is peer-level admission
//! with nonblocking typed refusals; this is subscriber-level delivery
//! fan-out where refusing a frame would LOSE transcript — so the
//! overflow escape is spill, and past spill, detach.

use std::collections::VecDeque;

/// One queued delivery frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedFrame {
    /// Delivery sequence.
    pub seq: u64,
    /// Frame bytes.
    pub bytes: Vec<u8>,
}

/// Byte budgets for one subscriber's queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueBudgets {
    /// In-memory byte budget (hard bound on resident bytes).
    pub memory_bytes: usize,
    /// Spill-region byte budget (hard bound on spilled bytes).
    pub spill_bytes: usize,
}

/// Where an enqueued frame landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// Within the memory budget: resident.
    InMemory,
    /// Memory budget full: spilled (in order) to the spill region.
    Spilled,
    /// BOTH budgets exhausted: the subscriber is the pathological
    /// slow client. The frame was NOT queued; the caller must detach
    /// this subscriber (C011 release) — the action and every other
    /// subscriber proceed untouched.
    DetachSlowSubscriber {
        /// Bytes the frame needed.
        needed: usize,
        /// Spill headroom that remained.
        spill_available: usize,
    },
}

/// One subscriber's bounded/spillable delivery queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriberQueue {
    budgets: QueueBudgets,
    /// Resident frames (oldest first).
    memory: VecDeque<QueuedFrame>,
    memory_used: usize,
    /// Spilled frames (oldest first) — byte accounting for the disk
    /// region; the edge daemon owns the actual file.
    spill: VecDeque<QueuedFrame>,
    spill_used: usize,
}

impl SubscriberQueue {
    /// An empty queue under the given budgets.
    #[must_use]
    pub const fn new(budgets: QueueBudgets) -> Self {
        Self {
            budgets,
            memory: VecDeque::new(),
            memory_used: 0,
            spill: VecDeque::new(),
            spill_used: 0,
        }
    }

    /// Resident bytes (the memory-bound invariant's subject).
    #[must_use]
    pub const fn memory_used(&self) -> usize {
        self.memory_used
    }

    /// Spilled bytes.
    #[must_use]
    pub const fn spill_used(&self) -> usize {
        self.spill_used
    }

    /// Queued frames across memory + spill.
    #[must_use]
    pub fn len(&self) -> usize {
        self.memory.len() + self.spill.len()
    }

    /// Whether nothing is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.memory.is_empty() && self.spill.is_empty()
    }

    /// Enqueue a frame for this subscriber. NEVER blocks the caller:
    /// the outcome is resident, spilled, or the typed detach decision
    /// — the shared action stream pays nothing either way.
    pub fn enqueue(&mut self, frame: QueuedFrame) -> EnqueueOutcome {
        let size = frame.bytes.len();
        // Order preservation: once anything is spilled, later frames
        // must spill too (a newer frame slipping into memory would
        // dequeue ahead of older spilled ones).
        if self.spill.is_empty() && self.memory_used + size <= self.budgets.memory_bytes {
            self.memory_used += size;
            self.memory.push_back(frame);
            return EnqueueOutcome::InMemory;
        }
        if self.spill_used + size <= self.budgets.spill_bytes {
            self.spill_used += size;
            self.spill.push_back(frame);
            return EnqueueOutcome::Spilled;
        }
        EnqueueOutcome::DetachSlowSubscriber {
            needed: size,
            spill_available: self.budgets.spill_bytes - self.spill_used,
        }
    }

    /// Dequeue the oldest frame (global FIFO across memory + spill).
    /// Unspilling respects the memory budget: a frame moves back to
    /// resident accounting only as it is handed out.
    pub fn dequeue(&mut self) -> Option<QueuedFrame> {
        if let Some(frame) = self.memory.pop_front() {
            self.memory_used -= frame.bytes.len();
            return Some(frame);
        }
        if let Some(frame) = self.spill.pop_front() {
            self.spill_used -= frame.bytes.len();
            return Some(frame);
        }
        None
    }

    /// Drop everything (the subscriber detached): the queue's bytes
    /// are released; nothing else in the system is touched.
    pub fn clear(&mut self) {
        self.memory.clear();
        self.spill.clear();
        self.memory_used = 0;
        self.spill_used = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(seq: u64, size: usize) -> QueuedFrame {
        QueuedFrame {
            seq,
            bytes: vec![u8::try_from(seq % 251).unwrap(); size],
        }
    }

    const BUDGETS: QueueBudgets = QueueBudgets {
        memory_bytes: 100,
        spill_bytes: 1000,
    };

    #[test]
    fn c017_slow_subscriber_never_stalls_the_action_or_other_subscribers() {
        // THE acceptance: the shared stream fans 50 frames out to a
        // fast subscriber (drains every frame immediately) and a slow
        // one (drains nothing). Every enqueue completes synchronously
        // — the production loop finishes all 50 frames regardless of
        // the slow client — the fast subscriber sees every frame with
        // no interference, and the slow queue's RESIDENT bytes never
        // exceed the memory budget.
        let mut slow = SubscriberQueue::new(BUDGETS);
        let mut fast = SubscriberQueue::new(BUDGETS);
        let mut fast_received = Vec::new();
        let mut produced = 0u64;
        for seq in 1..=50u64 {
            // Fan-out to both; the producer never observes a block or
            // a refusal from the slow client.
            let slow_outcome = slow.enqueue(frame(seq, 20));
            assert!(
                !matches!(slow_outcome, EnqueueOutcome::DetachSlowSubscriber { .. }),
                "seq {seq}: within budgets there is no detach"
            );
            assert!(matches!(
                fast.enqueue(frame(seq, 20)),
                EnqueueOutcome::InMemory
            ));
            produced = seq;
            // The fast subscriber drains immediately.
            let got = fast.dequeue().expect("fast client keeps up");
            fast_received.push(got.seq);
            // The slow queue's RESIDENT footprint stays bounded.
            assert!(
                slow.memory_used() <= BUDGETS.memory_bytes,
                "seq {seq}: memory bound violated ({} bytes)",
                slow.memory_used()
            );
        }
        assert_eq!(produced, 50, "the action finished all frames");
        assert_eq!(fast_received, (1..=50).collect::<Vec<u64>>());
        // The slow client wakes up: it receives EVERY frame in order
        // (memory first, then unspilled), nothing lost or reordered.
        let mut drained = Vec::new();
        while let Some(f) = slow.dequeue() {
            drained.push(f.seq);
        }
        assert_eq!(drained, (1..=50).collect::<Vec<u64>>());
        assert_eq!(slow.memory_used(), 0);
        assert_eq!(slow.spill_used(), 0);
    }

    #[test]
    fn c017_spill_preserves_global_fifo_order() {
        // Memory fits 5 20-byte frames; frames 6..=8 spill. A frame
        // enqueued AFTER spilling starts must spill too, even though
        // dequeues freed memory — otherwise it would jump the line.
        let mut queue = SubscriberQueue::new(BUDGETS);
        for seq in 1..=8u64 {
            queue.enqueue(frame(seq, 20));
        }
        assert_eq!(queue.memory_used(), 100);
        assert_eq!(queue.spill_used(), 60);
        // Drain two, then enqueue frame 9: memory has room now, but
        // spill is non-empty — 9 must go BEHIND 6..=8.
        assert_eq!(queue.dequeue().unwrap().seq, 1);
        assert_eq!(queue.dequeue().unwrap().seq, 2);
        assert!(matches!(
            queue.enqueue(frame(9, 20)),
            EnqueueOutcome::Spilled
        ));
        let mut order = Vec::new();
        while let Some(f) = queue.dequeue() {
            order.push(f.seq);
        }
        assert_eq!(order, vec![3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn c017_exhausting_both_budgets_is_a_typed_detach_not_a_stall() {
        let mut queue = SubscriberQueue::new(QueueBudgets {
            memory_bytes: 40,
            spill_bytes: 40,
        });
        queue.enqueue(frame(1, 40)); // fills memory
        queue.enqueue(frame(2, 40)); // fills spill
        let outcome = queue.enqueue(frame(3, 10));
        assert_eq!(
            outcome,
            EnqueueOutcome::DetachSlowSubscriber {
                needed: 10,
                spill_available: 0,
            },
            "the pathological client detaches; nothing blocks"
        );
        // The refused frame was not queued; the queue is unchanged and
        // clear() releases everything on detach.
        assert_eq!(queue.len(), 2);
        queue.clear();
        assert!(queue.is_empty());
        assert_eq!(queue.memory_used(), 0);
        assert_eq!(queue.spill_used(), 0);
    }
}
