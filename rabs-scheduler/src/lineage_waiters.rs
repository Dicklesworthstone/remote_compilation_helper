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
    /// Producers and waiters already occupy the whole root, even
    /// though the waiter-class budget may still have room.
    AllSlotsOccupied {
        /// Active producers at refusal time.
        active_producers: u32,
        /// Active waiters at refusal time.
        active_waiters: u32,
        /// Total slots of the root.
        total: u32,
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

    /// Slots not occupied by either class. Subtract separately so
    /// accounting never depends on an overflowing occupancy sum.
    fn remaining_slots(&self) -> u32 {
        self.budget
            .total_slots()
            .saturating_sub(self.active_producers)
            .saturating_sub(self.active_waiters)
    }

    /// Admit an UNRESOLVED PRODUCER attempt. Producers may use any
    /// unoccupied slot, including capacity beyond their reserve;
    /// unlike waiters, they have no additional class-specific cap.
    ///
    /// # Errors
    /// [`ProducerAdmissionRefusal::AllSlotsOccupied`] when the root is full.
    pub fn admit_producer(&mut self) -> Result<(), ProducerAdmissionRefusal> {
        let total = self.budget.total_slots();
        if self.remaining_slots() == 0 {
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
    /// Refused when the depth bound is exceeded, parking would consume
    /// the producer reserve, or producers and waiters fill the root.
    pub fn admit_waiter(&mut self, transitive_depth: u32) -> WaiterAdmission {
        if transitive_depth > self.max_transitive_depth {
            return WaiterAdmission::DepthBeyondBound {
                depth: transitive_depth,
                bound: self.max_transitive_depth,
            };
        }
        if self.active_waiters >= self.budget.waiter_budget() {
            return WaiterAdmission::WaiterBudgetExhausted {
                active_waiters: self.active_waiters,
                waiter_budget: self.budget.waiter_budget(),
            };
        }
        if self.remaining_slots() == 0 {
            return WaiterAdmission::AllSlotsOccupied {
                active_producers: self.active_producers,
                active_waiters: self.active_waiters,
                total: self.budget.total_slots(),
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
    /// and STOPS at either the waiter-budget edge or total occupancy.
    /// Producers may borrow non-reserved slots; that occupied capacity
    /// is unavailable for replay, even below the waiter quota (R112).
    #[must_use]
    pub fn remaining_replay_capacity(&self) -> u32 {
        self.budget
            .waiter_budget()
            .saturating_sub(self.active_waiters)
            .min(self.remaining_slots())
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
        // untouchable by construction (capacity is capped by the
        // waiter budget as well as total occupancy).
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

    #[test]
    fn producer_saturation_refuses_waiters_and_stops_replay() {
        let mut b = board();
        for _ in 0..6 {
            b.admit_producer().expect("free root slot");
        }
        assert_eq!(b.remaining_replay_capacity(), 0);
        let before = b.clone();
        assert_eq!(
            b.admit_waiter(1),
            WaiterAdmission::AllSlotsOccupied {
                active_producers: 6,
                active_waiters: 0,
                total: 6,
            }
        );
        assert_eq!(b, before, "a refused waiter consumes nothing");

        b.release_producer();
        assert_eq!(b.remaining_replay_capacity(), 1);
        assert_eq!(b.admit_waiter(1), WaiterAdmission::Parked);
        assert_eq!((b.active_producers(), b.active_waiters()), (5, 1));
        assert_eq!(b.remaining_replay_capacity(), 0);
    }

    #[test]
    fn producer_borrowing_and_releases_share_one_total_budget() {
        let mut b = board();
        for _ in 0..4 {
            b.admit_producer().expect("producers may borrow waiter lanes");
        }
        // Four nominal waiter lanes, but only two are unoccupied.
        assert_eq!(b.remaining_replay_capacity(), 2);
        assert_eq!(b.admit_waiter(1), WaiterAdmission::Parked);
        assert_eq!(b.remaining_replay_capacity(), 1);
        assert_eq!(b.admit_waiter(2), WaiterAdmission::Parked);
        assert_eq!(b.remaining_replay_capacity(), 0);
        assert_eq!(
            b.admit_waiter(3),
            WaiterAdmission::AllSlotsOccupied {
                active_producers: 4,
                active_waiters: 2,
                total: 6,
            }
        );

        b.release_waiter();
        assert_eq!(b.remaining_replay_capacity(), 1);
        b.admit_producer().expect("released slot can serve a producer");
        assert_eq!(b.remaining_replay_capacity(), 0);
        b.release_producer();
        b.release_producer();
        assert_eq!(b.remaining_replay_capacity(), 2);
        assert_eq!(b.admit_waiter(3), WaiterAdmission::Parked);
        assert_eq!((b.active_producers(), b.active_waiters()), (3, 2));
    }

    #[test]
    fn every_small_occupancy_obeys_both_limits_after_each_operation() {
        // Cover every legal occupancy and reserve split, not just the
        // waiter-first admission order. Each transition starts from the
        // same reachable state and is checked against independent counts.
        for total in 2..=12 {
            for reserve in 1..total {
                let budget = RootProgressBudget::new(total, reserve).unwrap();
                for producers in 0..=total {
                    for waiters in 0..=(total - reserve).min(total - producers) {
                        let mut b = LineageWaiterBoard::new(budget, 3);
                        for _ in 0..producers {
                            b.admit_producer().unwrap();
                        }
                        for _ in 0..waiters {
                            assert_eq!(b.admit_waiter(1), WaiterAdmission::Parked);
                        }
                        let free = total - producers - waiters;
                        let quota = total - reserve - waiters;
                        assert_eq!(b.remaining_replay_capacity(), free.min(quota));

                        let mut next = b.clone();
                        let expected = if quota == 0 {
                            WaiterAdmission::WaiterBudgetExhausted {
                                active_waiters: waiters,
                                waiter_budget: total - reserve,
                            }
                        } else if free == 0 {
                            WaiterAdmission::AllSlotsOccupied {
                                active_producers: producers,
                                active_waiters: waiters,
                                total,
                            }
                        } else {
                            WaiterAdmission::Parked
                        };
                        assert_eq!(next.admit_waiter(1), expected);
                        if expected == WaiterAdmission::Parked {
                            assert_eq!(next.active_waiters(), waiters + 1);
                            assert_eq!(next.remaining_replay_capacity(), free.min(quota) - 1);
                        } else {
                            assert_eq!(next, b, "refusals must not change accounting");
                        }

                        let mut next = b.clone();
                        assert_eq!(next.admit_producer().is_ok(), free > 0);
                        if free == 0 {
                            assert_eq!(next, b);
                        } else {
                            assert_eq!(next.active_producers(), producers + 1);
                            assert_eq!(
                                next.remaining_replay_capacity(),
                                (free - 1).min(quota)
                            );
                        }

                        let mut next = b.clone();
                        next.release_producer();
                        let released = u32::from(producers > 0);
                        assert_eq!(next.active_producers(), producers - released);
                        assert_eq!(
                            next.remaining_replay_capacity(),
                            (free + released).min(quota)
                        );

                        let mut next = b.clone();
                        next.release_waiter();
                        let released = u32::from(waiters > 0);
                        assert_eq!(next.active_waiters(), waiters - released);
                        assert_eq!(next.remaining_replay_capacity(), free.min(quota) + released);
                    }
                }
            }
        }
    }

    #[test]
    fn full_u32_capacity_cannot_wrap_into_an_available_slot() {
        // Seed a reachable boundary state without billions of admissions.
        let mut b = LineageWaiterBoard::new(RootProgressBudget::new(u32::MAX, 1).unwrap(), 3);
        b.active_producers = u32::MAX - 1;
        b.active_waiters = 1;
        assert_eq!(b.remaining_replay_capacity(), 0);
        assert_eq!(
            b.admit_waiter(1),
            WaiterAdmission::AllSlotsOccupied {
                active_producers: u32::MAX - 1,
                active_waiters: 1,
                total: u32::MAX,
            }
        );
        assert_eq!(
            b.admit_producer(),
            Err(ProducerAdmissionRefusal::AllSlotsOccupied { total: u32::MAX })
        );
        b.release_waiter();
        assert_eq!(b.remaining_replay_capacity(), 1);
        b.admit_producer().unwrap();
        assert_eq!(b.active_producers(), u32::MAX);
        assert_eq!(b.remaining_replay_capacity(), 0);
    }
}
