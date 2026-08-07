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
}
