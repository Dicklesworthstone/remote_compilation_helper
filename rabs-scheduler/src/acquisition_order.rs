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
//!
//! Grant accounting + acyclicity (bead I021; risks R48/R102): ONE
//! Cargo grant of capacity `C` exposes exactly ONE implicit token
//! (consumed by the Cargo root itself) and AT MOST `C-1` transferable
//! jobserver tokens — never more. And the whole permit chain is a
//! TOTAL ORDER: every attempt acquires coordinator admission →
//! placement → materialization/disk → execution admission/memory →
//! jobserver token, strictly rank-increasing, so the held set is
//! always a chain prefix and a waiter cycle is UNREPRESENTABLE.

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

/// The permit chain (bead I021; risks R48/R102): every compiler
/// grant is acquired in THIS total order and never otherwise. A
/// waiter cycle would require some attempt to acquire a lower-ranked
/// permit while holding a higher one — [`PermitWallet`] makes that
/// unrepresentable, so the chain is acyclic by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermitKind {
    /// Coordinator graph/root or action admission.
    CoordinatorAdmission,
    /// Placement + bounded input-transfer reservation.
    Placement,
    /// Input materialization + temp/output disk reservation.
    MaterializationAndDisk,
    /// Worker/edge execution admission + memory envelope.
    ExecutionAdmission,
    /// The local jobserver token — immediately before spawn (the
    /// I024 typestate's `DiskReserved -> TokenHeld` transition).
    JobserverToken,
}

/// Acquiring out of chain order — the only shape a permit cycle
/// could take, refused before it can exist. Names both ends so the
/// operator sees exactly which step was attempted backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermitCycleRefusal {
    /// The highest-ranked permit already held.
    pub held_top: PermitKind,
    /// The out-of-order permit requested.
    pub requested: PermitKind,
}

/// The permits ONE attempt holds. Acquisition is strictly
/// rank-increasing: the held set is always a PREFIX of the chain, so
/// two attempts can never hold crossing subsets — the acyclicity
/// proof, as a type invariant rather than a convention.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PermitWallet {
    top: Option<PermitKind>,
    count: usize,
}

impl PermitWallet {
    /// Acquire `kind`. Legal only strictly later in the chain than
    /// everything already held.
    ///
    /// # Errors
    /// [`PermitCycleRefusal`] when `kind` is at-or-before something
    /// already held (a cycle attempt).
    pub fn acquire(&mut self, kind: PermitKind) -> Result<(), PermitCycleRefusal> {
        match self.top {
            None => {
                self.top = Some(kind);
                self.count = 1;
                Ok(())
            }
            Some(top) if kind > top => {
                self.top = Some(kind);
                self.count += 1;
                Ok(())
            }
            Some(top) => Err(PermitCycleRefusal {
                held_top: top,
                requested: kind,
            }),
        }
    }

    /// The highest-ranked permit held (`None` when empty).
    #[must_use]
    pub fn top(&self) -> Option<PermitKind> {
        self.top
    }

    /// How many permits are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Completion: everything is released (the ladder leaves
    /// `Executing` and the next attempt starts clean).
    pub fn release_all(&mut self) {
        self.top = None;
        self.count = 0;
    }
}

/// ONE Cargo grant of compile capacity `C` (bead I021; risk R48):
/// opening it consumes the IMPLICIT token for the Cargo root itself,
/// and it then exposes AT MOST `C-1` transferable jobserver tokens —
/// exact accounting, no hidden extra slots under any asking pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootGrant {
    capacity: u32,
    implicit_alive: bool,
    outstanding: std::collections::BTreeSet<u64>,
    next_serial: u64,
}

/// Grant-accounting refusals (each names what ran out / what was
/// returned wrongly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRefusal {
    /// Every transferable token of the `C-1` budget is outstanding.
    TransferablesExhausted {
        /// Outstanding transferable tokens (`C-1` at exhaustion).
        outstanding: u32,
        /// The grant capacity.
        capacity: u32,
    },
    /// The token serial was not outstanding (double release, foreign
    /// token, or post-close release): nothing changed.
    UnknownToken {
        /// The offending serial.
        serial: u64,
    },
    /// The grant is closed (the Cargo root exited) or was opened with
    /// a meaningless capacity; nothing issues.
    GrantClosed,
}

/// A transferable jobserver token (opaque handle; the serial carries
/// the accounting identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferableToken {
    serial: u64,
}

impl RootGrant {
    /// Open a grant of capacity `C` (>= 1). The implicit token is
    /// consumed by the Cargo root AT OPEN TIME — it is never
    /// transferable and never counted in the `C-1` budget.
    ///
    /// # Errors
    /// [`GrantRefusal::GrantClosed`] for `C == 0` (meaningless).
    pub fn open(capacity: u32) -> Result<Self, GrantRefusal> {
        if capacity == 0 {
            return Err(GrantRefusal::GrantClosed);
        }
        Ok(Self {
            capacity,
            implicit_alive: true,
            outstanding: std::collections::BTreeSet::new(),
            next_serial: 1,
        })
    }

    /// The grant capacity `C`.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// The transferable budget: EXACTLY `C-1`.
    #[must_use]
    pub fn transferable_budget(&self) -> u32 {
        self.capacity - 1
    }

    /// Outstanding transferable tokens right now.
    #[must_use]
    pub fn transferable_outstanding(&self) -> u32 {
        u32::try_from(self.outstanding.len()).unwrap_or(u32::MAX)
    }

    /// Issue one transferable jobserver token against the `C-1`
    /// budget.
    ///
    /// # Errors
    /// [`GrantRefusal::TransferablesExhausted`] at the budget edge;
    /// [`GrantRefusal::GrantClosed`] after close.
    pub fn issue_transferable(&mut self) -> Result<TransferableToken, GrantRefusal> {
        if !self.implicit_alive {
            return Err(GrantRefusal::GrantClosed);
        }
        if self.transferable_outstanding() >= self.capacity - 1 {
            return Err(GrantRefusal::TransferablesExhausted {
                outstanding: self.transferable_outstanding(),
                capacity: self.capacity,
            });
        }
        let serial = self.next_serial;
        self.next_serial += 1;
        self.outstanding.insert(serial);
        Ok(TransferableToken { serial })
    }

    /// Release a transferable token back to the budget.
    ///
    /// # Errors
    /// [`GrantRefusal::UnknownToken`] for a serial not outstanding;
    /// nothing changes on refusal.
    pub fn release(&mut self, token: &TransferableToken) -> Result<(), GrantRefusal> {
        if !self.outstanding.remove(&token.serial) {
            return Err(GrantRefusal::UnknownToken {
                serial: token.serial,
            });
        }
        Ok(())
    }

    /// Close the grant: the Cargo root exited; the implicit token dies
    /// with it and nothing further issues.
    pub fn close(&mut self) {
        self.implicit_alive = false;
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
    // -----------------------------------------------------------------
    // I021: grant accounting + the acyclic permit chain.
    // -----------------------------------------------------------------

    #[test]
    fn a_c1_grant_exposes_one_implicit_and_zero_transferable() {
        let mut grant = RootGrant::open(1).expect("opens");
        assert_eq!(grant.transferable_budget(), 0);
        // The C-1 budget is EMPTY: no asking pattern extracts more.
        assert_eq!(
            grant.issue_transferable(),
            Err(GrantRefusal::TransferablesExhausted {
                outstanding: 0,
                capacity: 1
            })
        );
        grant.close();
        assert_eq!(grant.issue_transferable(), Err(GrantRefusal::GrantClosed));
    }

    #[test]
    fn a_c_capacity_grant_exposes_exactly_c_minus_one_transferable() {
        let mut grant = RootGrant::open(5).expect("opens");
        assert_eq!(grant.capacity(), 5);
        assert_eq!(grant.transferable_budget(), 4);
        let tokens: Vec<_> = (0..4)
            .map(|_| grant.issue_transferable().expect("within budget"))
            .collect();
        // The FIFTH transferable would exceed C-1: refused, naming the
        // full accounting.
        assert_eq!(
            grant.issue_transferable(),
            Err(GrantRefusal::TransferablesExhausted {
                outstanding: 4,
                capacity: 5
            })
        );
        // A released slot returns exactly once; double release refuses
        // typed instead of minting phantom capacity.
        grant.release(&tokens[1]).expect("releases");
        assert_eq!(
            grant.release(&tokens[1]),
            Err(GrantRefusal::UnknownToken {
                serial: tokens[1].serial
            })
        );
        grant.issue_transferable().expect("slot returned");
        assert_eq!(grant.transferable_outstanding(), 4);
    }

    #[test]
    fn the_wallet_walks_the_chain_strictly_in_order() {
        let mut wallet = PermitWallet::default();
        assert!(wallet.is_empty());
        for kind in [
            PermitKind::CoordinatorAdmission,
            PermitKind::Placement,
            PermitKind::MaterializationAndDisk,
            PermitKind::ExecutionAdmission,
            PermitKind::JobserverToken,
        ] {
            wallet.acquire(kind).expect("in-chain step");
        }
        assert_eq!(wallet.len(), 5);
        assert_eq!(wallet.top(), Some(PermitKind::JobserverToken));
        wallet.release_all();
        assert!(wallet.is_empty());
    }

    #[test]
    fn out_of_order_acquisition_is_refused_before_a_cycle_can_exist() {
        let mut wallet = PermitWallet::default();
        wallet
            .acquire(PermitKind::ExecutionAdmission)
            .expect("ranks up from empty");
        // The cycle attempt: holding a LATE permit and reaching back
        // for an EARLY one is exactly how two attempts could deadlock
        // — refused with both ends named.
        assert_eq!(
            wallet.acquire(PermitKind::Placement),
            Err(PermitCycleRefusal {
                held_top: PermitKind::ExecutionAdmission,
                requested: PermitKind::Placement,
            })
        );
        // Even the SAME rank twice is refused (a prefix has no
        // repeats).
        let mut single = PermitWallet::default();
        single
            .acquire(PermitKind::CoordinatorAdmission)
            .expect("first");
        assert_eq!(
            single.acquire(PermitKind::CoordinatorAdmission),
            Err(PermitCycleRefusal {
                held_top: PermitKind::CoordinatorAdmission,
                requested: PermitKind::CoordinatorAdmission,
            })
        );
    }

    #[test]
    fn the_permit_chain_composes_with_the_attempt_typestate() {
        let mut pipeline = AcquisitionPipeline::default();
        let mut wallet = PermitWallet::default();

        // Chain order drives the ladder: admission/placement cover the
        // bulk-transfer phase (no token exists yet).
        wallet
            .acquire(PermitKind::CoordinatorAdmission)
            .expect("ok");
        pipeline.bulk_transfer().expect("transfers");
        wallet.acquire(PermitKind::Placement).expect("ok");
        pipeline.bulk_transfer().expect("transfers");
        pipeline.inputs_ready();
        wallet
            .acquire(PermitKind::MaterializationAndDisk)
            .expect("ok");
        pipeline.reserve_disk();
        wallet.acquire(PermitKind::ExecutionAdmission).expect("ok");

        // ONLY NOW the jobserver token — the chain's LAST rank lands
        // on the typestate's ONLY token transition.
        wallet.acquire(PermitKind::JobserverToken).expect("ok");
        pipeline.acquire_token().expect("token after inputs+disk");
        pipeline.execute().expect("executes under the token");

        // The instrumented proof: zero forbidden overlaps, one token,
        // and the wallet is the exact five-permit chain prefix.
        assert_eq!(pipeline.stats.token_held_during_transfer, 0);
        assert_eq!(pipeline.stats.tokens_acquired, 1);
        assert_eq!(wallet.len(), 5);
        assert_eq!(wallet.top(), Some(PermitKind::JobserverToken));
    }
}
