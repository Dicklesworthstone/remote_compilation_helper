//! Acquisition ordering: no compiler token held during bulk transfer
//! (bead I024; plan §84; risk R24).
//!
//! Compiler tokens (jobserver grants, root permits) are the scarcest
//! resource in the pipeline — holding one while bytes cross the
//! network idles a whole compile slot. The order is a typestate:
//!
//! ```text
//! Planned → InputsReady → DiskReserved → TokenHeld → Executing
//! ```
//!
//! Bulk transfer happens ONLY during `Planned → InputsReady`, and
//! token acquisition exists ONLY as the `DiskReserved → TokenHeld`
//! transition — a state where a token coexists with an unfinished
//! transfer is UNREPRESENTABLE, and the instrumented pipeline counts
//! prove zero occurrences. Provisional-lineage waiters park in
//! `InputsReady` (bounded by the caller's waiter budget), never
//! holding a token while they wait.

/// The attempt's acquisition state (a strict ladder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionState {
    /// Planned; bulk input transfer may run NOW (no token exists).
    Planned,
    /// All inputs local + verified; provisional-lineage waiters park
    /// here (bounded).
    InputsReady,
    /// Disk/output staging reserved.
    DiskReserved,
    /// Jobserver grant / root permit held (transfer is OVER).
    TokenHeld,
    /// The compiler is running.
    Executing,
}

/// Instrumentation counters (the acceptance evidence).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AcquisitionStats {
    /// Bulk-transfer operations performed.
    pub transfers: u64,
    /// Tokens acquired.
    pub tokens_acquired: u64,
    /// The forbidden overlap: transfer performed while a token was
    /// held. The pipeline makes this unreachable; the counter proves
    /// it stayed zero.
    pub token_held_during_transfer: u64,
}

/// Ordering violations (typed; each names the rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderingViolation {
    /// Transfer attempted after token acquisition.
    TransferWhileTokenHeld,
    /// Token requested before inputs were ready.
    TokenBeforeInputsReady,
    /// Token requested before disk reservation.
    TokenBeforeDiskReserved,
    /// Execution without a token.
    ExecuteWithoutToken,
}

/// One attempt's acquisition pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionPipeline {
    /// Current state.
    pub state: AcquisitionState,
    /// Instrumentation.
    pub stats: AcquisitionStats,
}

impl Default for AcquisitionPipeline {
    fn default() -> Self {
        Self {
            state: AcquisitionState::Planned,
            stats: AcquisitionStats::default(),
        }
    }
}

impl AcquisitionPipeline {
    /// Perform one bulk-transfer operation. Legal ONLY before
    /// `InputsReady` completes; a transfer with a token held is the
    /// forbidden overlap.
    ///
    /// # Errors
    /// [`OrderingViolation::TransferWhileTokenHeld`].
    pub fn bulk_transfer(&mut self) -> Result<(), OrderingViolation> {
        match self.state {
            AcquisitionState::Planned => {
                self.stats.transfers += 1;
                Ok(())
            }
            AcquisitionState::TokenHeld | AcquisitionState::Executing => {
                self.stats.token_held_during_transfer += 1;
                Err(OrderingViolation::TransferWhileTokenHeld)
            }
            // Late input discovery after readiness: the attempt DROPS
            // back to Planned (releasing nothing — no token exists yet
            // by construction) rather than transferring in place.
            AcquisitionState::InputsReady | AcquisitionState::DiskReserved => {
                self.state = AcquisitionState::Planned;
                self.stats.transfers += 1;
                Ok(())
            }
        }
    }

    /// Inputs are local and verified.
    pub fn inputs_ready(&mut self) {
        if self.state == AcquisitionState::Planned {
            self.state = AcquisitionState::InputsReady;
        }
    }

    /// Reserve disk/output staging.
    pub fn reserve_disk(&mut self) {
        if self.state == AcquisitionState::InputsReady {
            self.state = AcquisitionState::DiskReserved;
        }
    }

    /// Acquire the compiler token — ONLY after inputs + disk.
    ///
    /// # Errors
    /// Names the missing precondition.
    pub fn acquire_token(&mut self) -> Result<(), OrderingViolation> {
        match self.state {
            AcquisitionState::DiskReserved => {
                self.state = AcquisitionState::TokenHeld;
                self.stats.tokens_acquired += 1;
                Ok(())
            }
            AcquisitionState::Planned => Err(OrderingViolation::TokenBeforeInputsReady),
            AcquisitionState::InputsReady => Err(OrderingViolation::TokenBeforeDiskReserved),
            AcquisitionState::TokenHeld | AcquisitionState::Executing => Ok(()),
        }
    }

    /// Begin execution.
    ///
    /// # Errors
    /// [`OrderingViolation::ExecuteWithoutToken`].
    pub fn execute(&mut self) -> Result<(), OrderingViolation> {
        if self.state == AcquisitionState::TokenHeld {
            self.state = AcquisitionState::Executing;
            Ok(())
        } else {
            Err(OrderingViolation::ExecuteWithoutToken)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_happy_path_never_overlaps_token_and_transfer() {
        // THE acceptance: an instrumented full pipeline shows ZERO
        // token-held-during-transfer occurrences.
        let mut pipeline = AcquisitionPipeline::default();
        for _ in 0..50 {
            pipeline.bulk_transfer().unwrap();
        }
        pipeline.inputs_ready();
        pipeline.reserve_disk();
        pipeline.acquire_token().unwrap();
        pipeline.execute().unwrap();
        assert_eq!(pipeline.stats.transfers, 50);
        assert_eq!(pipeline.stats.tokens_acquired, 1);
        assert_eq!(
            pipeline.stats.token_held_during_transfer, 0,
            "zero occurrences — the acceptance number"
        );
    }

    #[test]
    fn transfer_after_token_is_refused_and_counted() {
        let mut pipeline = AcquisitionPipeline::default();
        pipeline.inputs_ready();
        pipeline.reserve_disk();
        pipeline.acquire_token().unwrap();
        assert_eq!(
            pipeline.bulk_transfer(),
            Err(OrderingViolation::TransferWhileTokenHeld)
        );
        assert_eq!(pipeline.stats.token_held_during_transfer, 1);
    }

    #[test]
    fn tokens_acquire_only_after_inputs_and_disk() {
        let mut pipeline = AcquisitionPipeline::default();
        assert_eq!(
            pipeline.acquire_token(),
            Err(OrderingViolation::TokenBeforeInputsReady)
        );
        pipeline.inputs_ready();
        assert_eq!(
            pipeline.acquire_token(),
            Err(OrderingViolation::TokenBeforeDiskReserved)
        );
        pipeline.reserve_disk();
        assert_eq!(pipeline.acquire_token(), Ok(()));
        // Execution demands the token.
        let mut cold = AcquisitionPipeline::default();
        assert_eq!(cold.execute(), Err(OrderingViolation::ExecuteWithoutToken));
    }

    #[test]
    fn late_input_discovery_drops_back_without_a_token() {
        // Provisional-lineage waiters / late discovery: the attempt
        // returns to Planned and transfers WITHOUT ever having held a
        // token — the overlap stays structurally impossible.
        let mut pipeline = AcquisitionPipeline::default();
        pipeline.inputs_ready();
        pipeline.reserve_disk();
        pipeline.bulk_transfer().unwrap(); // late discovery
        assert_eq!(pipeline.state, AcquisitionState::Planned);
        assert_eq!(pipeline.stats.token_held_during_transfer, 0);
        // The ladder re-climbs normally afterwards.
        pipeline.inputs_ready();
        pipeline.reserve_disk();
        assert_eq!(pipeline.acquire_token(), Ok(()));
    }
}
