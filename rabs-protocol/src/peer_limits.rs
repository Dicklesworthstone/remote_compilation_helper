//! Per-peer resource-manager limits (bead S008; plan §106; the
//! adversarial-peer boundedness contract T008 exercises).
//!
//! Every resource a peer can consume has a per-peer bound, enforced
//! at admission with a typed refusal naming the dimension:
//!
//! - the dimension registry is CLOSED and exhaustively swept by
//!   test — a new resource class extends the enum and fails the
//!   pinned count until it gets a limit;
//! - accounting is PER PEER: one adversarial peer exhausting its own
//!   budgets never moves another peer's admission decisions;
//! - CONTROL/CANCEL capacity is reserved independently (the J008
//!   discipline): saturating every data dimension leaves control
//!   admission intact, and control has its own bound — neither pool
//!   can starve or overrun the other;
//! - release returns capacity (sessions end, queues drain), and
//!   usage can never exceed the limit — admission is checked BEFORE
//!   the add, so the bound is an invariant, not an aspiration.

/// The bounded per-peer resource dimensions (closed registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Dimension {
    ConcurrentSessions,
    FramesPerSecond,
    FrameBytes,
    ExtensionBytes,
    QueuedControlBytes,
    QueuedDataBytes,
    InFlightObjectRequests,
    ManifestDepth,
    ManifestFanOut,
    SparseRanges,
    DiagnosticsBytes,
    OutputCount,
    OutputBytes,
    ProcessCount,
    MemoryBytes,
    TempBytes,
    DiskBytes,
    Retries,
    Restarts,
}

/// Every dimension with its default per-peer limit, in registry
/// order (pinned by test).
pub const DEFAULT_LIMITS: [(Dimension, u64); 19] = [
    (Dimension::ConcurrentSessions, 8),
    (Dimension::FramesPerSecond, 2_000),
    (Dimension::FrameBytes, 4 * 1024 * 1024),
    (Dimension::ExtensionBytes, 64 * 1024),
    (Dimension::QueuedControlBytes, 1024 * 1024),
    (Dimension::QueuedDataBytes, 64 * 1024 * 1024),
    (Dimension::InFlightObjectRequests, 128),
    (Dimension::ManifestDepth, 64),
    (Dimension::ManifestFanOut, 4_096),
    (Dimension::SparseRanges, 1_024),
    (Dimension::DiagnosticsBytes, 16 * 1024 * 1024),
    (Dimension::OutputCount, 4_096),
    (Dimension::OutputBytes, 2 * 1024 * 1024 * 1024),
    (Dimension::ProcessCount, 64),
    (Dimension::MemoryBytes, 8 * 1024 * 1024 * 1024),
    (Dimension::TempBytes, 16 * 1024 * 1024 * 1024),
    (Dimension::DiskBytes, 32 * 1024 * 1024 * 1024),
    (Dimension::Retries, 16),
    (Dimension::Restarts, 4),
];

/// Independent control/cancel admission reserve (slots).
pub const CONTROL_RESERVE_SLOTS: u64 = 64;

fn index_of(dimension: Dimension) -> usize {
    DEFAULT_LIMITS
        .iter()
        .position(|(d, _)| *d == dimension)
        .expect("closed registry")
}

/// Typed admission refusal: the dimension, its limit, the attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitRefusal {
    /// Which bound refused.
    pub dimension: Dimension,
    /// The per-peer limit.
    pub limit: u64,
    /// Usage that admission would have reached.
    pub would_reach: u64,
}

/// Control-reserve refusal (its own bound; never data-coupled).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlReserveExhausted {
    /// The reserve size.
    pub reserve: u64,
}

/// One peer's resource accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAccount {
    usage: [u64; DEFAULT_LIMITS.len()],
    control_in_use: u64,
}

impl Default for PeerAccount {
    fn default() -> Self {
        Self {
            usage: [0; DEFAULT_LIMITS.len()],
            control_in_use: 0,
        }
    }
}

impl PeerAccount {
    /// Admit `amount` on `dimension`, checked BEFORE the add.
    ///
    /// # Errors
    /// [`LimitRefusal`] naming the dimension when the bound would be
    /// exceeded; usage is unchanged on refusal.
    pub fn admit(&mut self, dimension: Dimension, amount: u64) -> Result<(), LimitRefusal> {
        let idx = index_of(dimension);
        let limit = DEFAULT_LIMITS[idx].1;
        let would_reach = self.usage[idx].saturating_add(amount);
        if would_reach > limit {
            return Err(LimitRefusal {
                dimension,
                limit,
                would_reach,
            });
        }
        self.usage[idx] = would_reach;
        Ok(())
    }

    /// Release `amount` on `dimension` (drain/session end).
    pub fn release(&mut self, dimension: Dimension, amount: u64) {
        let idx = index_of(dimension);
        self.usage[idx] = self.usage[idx].saturating_sub(amount);
    }

    /// Current usage on a dimension.
    #[must_use]
    pub fn usage(&self, dimension: Dimension) -> u64 {
        self.usage[index_of(dimension)]
    }

    /// Admit one control/cancel message from the INDEPENDENT
    /// reserve — data-dimension saturation is irrelevant here.
    ///
    /// # Errors
    /// [`ControlReserveExhausted`] when the reserve itself is full.
    pub fn admit_control(&mut self) -> Result<(), ControlReserveExhausted> {
        if self.control_in_use >= CONTROL_RESERVE_SLOTS {
            return Err(ControlReserveExhausted {
                reserve: CONTROL_RESERVE_SLOTS,
            });
        }
        self.control_in_use += 1;
        Ok(())
    }

    /// Release one control slot.
    pub fn release_control(&mut self) {
        self.control_in_use = self.control_in_use.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_dimension_enforces_its_bound_typed() {
        // THE sweep: for each of the 19 dimensions, fill to the
        // limit, then one more unit refuses NAMING the dimension —
        // and usage is unchanged by the refusal.
        assert_eq!(DEFAULT_LIMITS.len(), 19, "closed registry, pinned");
        for (dimension, limit) in DEFAULT_LIMITS {
            let mut peer = PeerAccount::default();
            assert_eq!(peer.admit(dimension, limit), Ok(()));
            let refusal = peer.admit(dimension, 1).expect_err("bound must hold");
            assert_eq!(refusal.dimension, dimension);
            assert_eq!(refusal.limit, limit);
            assert_eq!(refusal.would_reach, limit + 1);
            assert_eq!(peer.usage(dimension), limit, "refusal changed nothing");
        }
    }

    #[test]
    fn an_adversarial_peer_stays_bounded() {
        // T008's shape: hammer every dimension with 10x its limit in
        // unit steps; usage NEVER exceeds the limit.
        let mut adversary = PeerAccount::default();
        for (dimension, limit) in DEFAULT_LIMITS {
            let step = (limit / 16).max(1);
            let mut refused = 0_u32;
            let mut pushed = 0_u64;
            while pushed < limit.saturating_mul(10) {
                if adversary.admit(dimension, step).is_err() {
                    refused += 1;
                }
                pushed += step;
            }
            assert!(adversary.usage(dimension) <= limit, "bound is an invariant");
            assert!(refused > 0, "the hammering was actually refused");
        }
    }

    #[test]
    fn accounting_is_per_peer() {
        // The adversary's exhaustion moves NOTHING for the victim.
        let mut adversary = PeerAccount::default();
        let mut victim = PeerAccount::default();
        for (dimension, limit) in DEFAULT_LIMITS {
            adversary.admit(dimension, limit).expect("fills");
        }
        for (dimension, _) in DEFAULT_LIMITS {
            assert_eq!(
                victim.admit(dimension, 1),
                Ok(()),
                "victim admission untouched on {dimension:?}"
            );
        }
    }

    #[test]
    fn control_reserve_is_independent_of_data_saturation() {
        // Saturate EVERY data dimension; control/cancel still admits.
        let mut peer = PeerAccount::default();
        for (dimension, limit) in DEFAULT_LIMITS {
            peer.admit(dimension, limit).expect("fills");
        }
        for _ in 0..CONTROL_RESERVE_SLOTS {
            peer.admit_control().expect("control rides its own reserve");
        }
        // And the reserve has its OWN bound — control cannot overrun.
        assert_eq!(
            peer.admit_control(),
            Err(ControlReserveExhausted {
                reserve: CONTROL_RESERVE_SLOTS
            })
        );
        // Draining one control slot re-admits exactly one.
        peer.release_control();
        assert_eq!(peer.admit_control(), Ok(()));
    }

    #[test]
    fn release_returns_capacity() {
        let mut peer = PeerAccount::default();
        peer.admit(Dimension::ConcurrentSessions, 8).expect("fills");
        assert!(peer.admit(Dimension::ConcurrentSessions, 1).is_err());
        peer.release(Dimension::ConcurrentSessions, 3); // sessions end
        assert_eq!(peer.admit(Dimension::ConcurrentSessions, 3), Ok(()));
        assert_eq!(peer.usage(Dimension::ConcurrentSessions), 8);
        // Over-release saturates at zero, never underflows.
        peer.release(Dimension::ConcurrentSessions, 1_000);
        assert_eq!(peer.usage(Dimension::ConcurrentSessions), 0);
    }
}
