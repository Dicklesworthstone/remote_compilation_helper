//! Bounded provisional-lineage waiters + producer progress reserve
//! (bead I025; risk R112; acceptance T041).
//!
//! Provisional metadata makes a wrapper WAIT for a producer's lineage
//! to resolve. Unbounded, a wide graph of waiters starves the very
//! producers they wait for — every slot fills with someone standing
//! in line. The law, per root:
//!
//! - the root's slots are split into a PRODUCER RESERVE (at least one
//!   slot per active root — [`RootProgressBudget::new`] enforces the
//!   floor) and a bounded waiter budget on top;
//! - waiters are admitted ONLY into the waiter budget, and each
//!   carries a TRANSITIVE DEPTH bound (a waiter waiting on a waiter
//!   waiting on… is how the line grows without looking long);
//! - provisional-metadata REPLAY is admission-controlled the same
//!   way: replays stop while no non-reserved capacity remains, so
//!   replay traffic can never eat the reserve;
//! - producers are NEVER queue-refused by waiter pressure: an
//!   unresolved producer attempt (and its descendants) admits into
//!   the reserve first, always outranking waiters.
//!
//! Every refusal names the accounting that failed, so a T041 fixture
//! can pin saturation behavior exactly.

/// The per-root progress budget: total slots split by an enforced
/// producer reserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootProgressBudget {
    total_slots: u32,
    producer_reserve: u32,
}

/// Budget construction refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetRefusal {
    /// Zero total slots cannot make progress.
    Empty,
    /// The reserve must leave room for at least one waiter budget
    /// slot (`reserve == total`) — otherwise waiters are impossible
    /// and the bound is meaningless.
    ReserveLeavesNoWaiterBudget {
        /// The requested reserve.
        reserve: u32,
        /// The total slots.
        total: u32,
    },
}

impl RootProgressBudget {
    /// Split `total_slots` into `producer_reserve` (>= 1, the
    /// progress guarantee) plus the remainder as the waiter budget.
    ///
    /// # Errors
    /// [`BudgetRefusal`] naming the bad split.
    pub fn new(total_slots: u32, producer_reserve: u32) -> Result<Self, BudgetRefusal> {
        if total_slots == 0 {
            return Err(BudgetRefusal::Empty);
        }
        if producer_reserve == 0 {
            // The R112 floor: at least ONE slot belongs to producers.
            return Err(BudgetRefusal::ReserveLeavesNoWaiterBudget {
                reserve: 0,
                total: total_slots,
            });
        }
        if producer_reserve >= total_slots {
            return Err(BudgetRefusal::ReserveLeavesNoWaiterBudget {
                reserve: producer_reserve,
                total: total_slots,
            });
        }
        Ok(Self {
            total_slots,
            producer_reserve,
        })
    }

    /// Total slots.
    #[must_use]
    pub fn total_slots(&self) -> u32 {
        self.total_slots
    }

    /// Slots only producers may occupy.
    #[must_use]
    pub fn producer_reserve(&self) -> u32 {
        self.producer_reserve
    }

    /// The waiter budget: slots waiters may fill AT MOST.
    #[must_use]
    pub fn waiter_budget(&self) -> u32 {
        self.total_slots - self.producer_reserve
    }
}

/// The board tracking one root's producers and lineage waiters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageWaiterBoard {
    budget: RootProgressBudget,
    /// Admitted unresolved producer attempts.
    active_producers: u32,
    /// Admitted lineage-waiting wrappers.
    active_waiters: u32,
    /// The transitive-depth bound applied to every waiter.
    max_transitive_depth: u32,
}

/// Waiter-admission outcomes and refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaiterAdmission {
    /// The waiter parked within the budget.
    Parked,
    /// The waiter budget is full: refused BEFORE it could consume the
    /// producer reserve.
    WaiterBudgetExhausted {
        /// Active waiters at refusal time.
        active_waiters: u32,
        /// The budget they may fill.
        waiter_budget: u32,
    },
    /// The waiter's transitive depth exceeds the bound.
    DepthBeyondBound {
        /// The offered depth.
        depth: u32,
        /// The allowed maximum.
        bound: u32,
    },
}

impl LineageWaiterBoard {
    /// A board over `budget` with the transitive-depth bound applied
    /// to every waiter.
    #[must_use]
    pub fn new(budget: RootProgressBudget, max_transitive_depth: u32) -> Self {
        Self {
            budget,
            active_producers: 0,
            active_waiters: 0,
            max_transitive_depth,
        }
    }

    /// Admit an UNRESOLVED PRODUCER attempt. Producers outrank
    /// waiters by construction: admission consults only total slots —
    /// never the waiter count — so waiter pressure can never queue-
    /// refuse a producer while any slot exists.
    pub fn admit_producer(&mut self) -> Result<(), ProducerAdmissionRefusal> {
        let total = self.budget.total_slots();
        if self.active_producers + self.active_waiters >= total {
            return Err(ProducerAdmissionRefusal::AllSlotsOccupied { total });
        }
        self.active_producers += 1;
        Ok(())
    }

    /// Release a finished producer attempt.
    pub fn release_producer(&mut self) {
        self.active_producers = self.active_producers.saturating_sub(1);
    }

    /// Admit a lineage-waiting wrapper with its transitive depth.
    /// Refused when the depth bound is exceeded or when parking would
    /// consume the producer reserve.
    pub fn admit_waiter(&mut self, transitive_depth: u32) -> WaiterAdmission {
        if transitive_depth > self.max_transitive_depth {
            return WaiterAdmission::DepthBeyondBound {
                depth: transitive_depth,
                bound: self.max_transitive_depth,
            };
        }
        if self.active_waiters + 1 > self.budget.waiter_budget() {
            return WaiterAdmission::WaiterBudgetExhausted {
                active_waiters: self.active_waiters,
                waiter_budget: self.budget.waiter_budget(),
            };
        }
        self.active_waiters += 1;
        WaiterAdmission::Parked
    }

    /// Release a parked waiter.
    pub fn release_waiter(&mut self) {
        self.active_waiters = self.active_waiters.saturating_sub(1);
    }

    /// How many additional provisional-metadata REPLAYS may start right
    /// now: replay traffic occupies the same bounded lanes as waiters
    /// and STOPS at the waiter-budget edge — it can never consume the
    /// producer reserve (R112).
    #[must_use]
    pub fn remaining_replay_capacity(&self) -> u32 {
        self.budget
            .waiter_budget()
            .saturating_sub(self.active_waiters)
    }

    /// Active producers (the prioritized class).
    #[must_use]
    pub fn active_producers(&self) -> u32 {
        self.active_producers
    }

    /// Active waiters.
    #[must_use]
    pub fn active_waiters(&self) -> u32 {
        self.active_waiters
    }
}

/// Producer-admission refusals (the only way a producer fails).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProducerAdmissionRefusal {
    /// Literally every slot is occupied; even here the waiter count
    /// did not cause priority loss — the ROOT is simply full.
    AllSlotsOccupied {
        /// Total slots of the root.
        total: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn board() -> LineageWaiterBoard {
        // 6 slots: 2 reserved for producers, 4 waiter budget.
        LineageWaiterBoard::new(RootProgressBudget::new(6, 2).expect("valid split"), 3)
    }

    #[test]
    fn the_reserve_floor_and_split_are_enforced() {
        assert_eq!(
            RootProgressBudget::new(4, 0),
            Err(BudgetRefusal::ReserveLeavesNoWaiterBudget {
                reserve: 0,
                total: 4
            }),
            "zero reserve would let waiters starve producers entirely"
        );
        assert_eq!(
            RootProgressBudget::new(3, 3),
            Err(BudgetRefusal::ReserveLeavesNoWaiterBudget {
                reserve: 3,
                total: 3
            })
        );
        assert_eq!(RootProgressBudget::new(0, 1), Err(BudgetRefusal::Empty));
        let b = RootProgressBudget::new(6, 2).expect("valid");
        assert_eq!(
            (b.total_slots(), b.producer_reserve(), b.waiter_budget()),
            (6, 2, 4)
        );
    }

    #[test]
    fn waiter_saturation_keeps_producers_progressing() {
        // THE T041 scenario: fill EVERY waiter slot...
        let mut b = board();
        for i in 0..4 {
            assert_eq!(b.admit_waiter(1), WaiterAdmission::Parked, "waiter {i}");
        }
        assert_eq!(
            b.admit_waiter(1),
            WaiterAdmission::WaiterBudgetExhausted {
                active_waiters: 4,
                waiter_budget: 4
            },
            "the fifth waiter refuses BEFORE touching the reserve"
        );
        // ...and the producer walks straight in anyway.
        assert!(b.admit_producer().is_ok(), "producers outrank waiters");
        assert_eq!(b.active_producers(), 1);
        assert_eq!(b.remaining_replay_capacity(), 0);
    }

    #[test]
    fn transitive_depth_is_bounded_per_waiter() {
        let mut b = board();
        assert_eq!(b.admit_waiter(3), WaiterAdmission::Parked);
        assert_eq!(
            b.admit_waiter(4),
            WaiterAdmission::DepthBeyondBound { depth: 4, bound: 3 },
            "a waiter-of-a-waiter-of-a-... beyond the bound refuses typed"
        );
        // The refused waiter consumed nothing.
        assert_eq!(b.active_waiters(), 1);
    }

    #[test]
    fn replay_traffic_stops_at_the_waiter_edge_never_the_reserve() {
        let mut b = board();
        // Two waiters parked: two replay slots remain (budget edge).
        b.admit_waiter(1);
        b.admit_waiter(2);
        assert_eq!(b.remaining_replay_capacity(), 2);
        b.admit_waiter(3);
        b.admit_waiter(3);
        assert_eq!(b.remaining_replay_capacity(), 0);
        // At zero, further replays MUST NOT proceed — the reserve is
        // untouchable by construction (capacity is derived from the
        // waiter budget alone).
        assert_eq!(b.remaining_replay_capacity(), 0);
        // Producers still admit.
        assert!(b.admit_producer().is_ok());
    }

    #[test]
    fn releases_restore_exactly_the_released_class() {
        let mut b = board();
        b.admit_producer().expect("producer");
        assert_eq!(b.admit_waiter(1), WaiterAdmission::Parked);
        b.release_waiter();
        assert_eq!(b.active_waiters(), 0);
        assert_eq!(b.remaining_replay_capacity(), 4);
        b.release_producer();
        assert_eq!(b.active_producers(), 0);
        // Saturating releases never wrap into phantom capacity.
        b.release_waiter();
        assert_eq!(b.active_waiters(), 0);
        assert_eq!(b.remaining_replay_capacity(), 4);
    }

    #[test]
    fn producers_fill_the_whole_root_only_when_truly_free() {
        let mut b = board();
        for _ in 0..4 {
            b.admit_waiter(1);
        }
        // 4 waiter slots + 2 reserve slots: exactly TWO producers fit.
        assert!(b.admit_producer().is_ok());
        assert!(b.admit_producer().is_ok());
        assert_eq!(
            b.admit_producer(),
            Err(ProducerAdmissionRefusal::AllSlotsOccupied { total: 6 })
        );
    }
}
