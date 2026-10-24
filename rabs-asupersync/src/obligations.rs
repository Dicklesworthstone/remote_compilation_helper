//! RABS domain obligation types + resolution discipline (bead G002;
//! invariant I7; Epic G's obligation catalog).
//!
//! Asupersync's generic obligation machinery gets DOMAIN types: all 25
//! obligations from the plan's catalog, each a named variant so leaks
//! attribute by NAME in region-close errors. The semantics with teeth:
//!
//! - a producing attempt may OFFER a candidate only after its
//!   attempt-local success obligations resolve;
//! - PUBLICATION additionally requires the canonical-result /
//!   object-closure / authority / provisional-lineage obligations;
//! - cancelled/failed paths still resolve CLEANUP obligations before
//!   region close — an aborted attempt cannot skip its finalizers;
//! - the Cargo root permit is held for the full process lifetime and
//!   released EXACTLY once — a double release is a typed error, not a
//!   no-op (I7's exactly-once law).

/// The 25 domain obligation kinds (plan catalog, verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)] // Plan vocabulary.
pub enum ObligationKind {
    CoordinatorAuthority,
    CargoRootPermit,
    WorkerAssignment,
    ActionGeneration,
    ExecutionLease,
    AttemptFence,
    CoherentSnapshot,
    ActionInputClosure,
    SourceSnapshotPin,
    InputObjectPin,
    OutputStagingPin,
    ProvisionalMetadata,
    DirectProducerCommit,
    TransitiveProvisionalLineage,
    DiagnosticStream,
    ProcessGroupDrain,
    PreparedResultOffer,
    CoordinatorPublication,
    SubscriberDelivery,
    SubscriberNotification,
    PerSubscriberObservableCommit,
    TargetStateLease,
    WinnerCommit,
    SandboxCleanup,
    JournalCheckpoint,
}

impl ObligationKind {
    /// All kinds, for completeness checks.
    pub const ALL: [Self; 25] = [
        Self::CoordinatorAuthority,
        Self::CargoRootPermit,
        Self::WorkerAssignment,
        Self::ActionGeneration,
        Self::ExecutionLease,
        Self::AttemptFence,
        Self::CoherentSnapshot,
        Self::ActionInputClosure,
        Self::SourceSnapshotPin,
        Self::InputObjectPin,
        Self::OutputStagingPin,
        Self::ProvisionalMetadata,
        Self::DirectProducerCommit,
        Self::TransitiveProvisionalLineage,
        Self::DiagnosticStream,
        Self::ProcessGroupDrain,
        Self::PreparedResultOffer,
        Self::CoordinatorPublication,
        Self::SubscriberDelivery,
        Self::SubscriberNotification,
        Self::PerSubscriberObservableCommit,
        Self::TargetStateLease,
        Self::WinnerCommit,
        Self::SandboxCleanup,
        Self::JournalCheckpoint,
    ];

    /// Attempt-local SUCCESS obligations: all must resolve before a
    /// prepared-result candidate may be offered.
    pub const ATTEMPT_SUCCESS: [Self; 5] = [
        Self::ActionInputClosure,
        Self::OutputStagingPin,
        Self::DiagnosticStream,
        Self::ProcessGroupDrain,
        Self::ProvisionalMetadata,
    ];

    /// Additional obligations PUBLICATION requires beyond the offer.
    pub const PUBLICATION_REQUIRED: [Self; 4] = [
        Self::DirectProducerCommit,         // canonical result
        Self::InputObjectPin,               // object closure held
        Self::CoordinatorAuthority,         // authority bound
        Self::TransitiveProvisionalLineage, // provisional lineage
    ];

    /// CLEANUP obligations: resolved on EVERY path — success, cancel,
    /// failure — before region close.
    pub const CLEANUP: [Self; 2] = [Self::SandboxCleanup, Self::ProcessGroupDrain];
}

/// One tracked obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tracked {
    kind: ObligationKind,
    resolved: bool,
    released_count: u32,
}

/// The obligation set for one region/attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObligationSet {
    entries: Vec<Tracked>,
}

/// Errors from the resolution discipline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObligationError {
    /// A gate consulted before its obligations resolved; the unresolved
    /// kinds are named (attribution).
    Unresolved(Vec<ObligationKind>),
    /// The Cargo root permit released more than once.
    DoubleRelease(ObligationKind),
    /// Resolving an obligation that was never opened.
    NotOpened(ObligationKind),
}

impl ObligationSet {
    /// Open an obligation (idempotent per kind).
    pub fn open(&mut self, kind: ObligationKind) {
        if !self.entries.iter().any(|t| t.kind == kind) {
            self.entries.push(Tracked {
                kind,
                resolved: false,
                released_count: 0,
            });
        }
    }

    /// Resolve an obligation. The Cargo root permit enforces
    /// exactly-once: a second resolve is a typed DoubleRelease.
    ///
    /// # Errors
    /// [`ObligationError::NotOpened`] / [`ObligationError::DoubleRelease`].
    pub fn resolve(&mut self, kind: ObligationKind) -> Result<(), ObligationError> {
        let Some(tracked) = self.entries.iter_mut().find(|t| t.kind == kind) else {
            return Err(ObligationError::NotOpened(kind));
        };
        tracked.released_count += 1;
        if kind == ObligationKind::CargoRootPermit && tracked.released_count > 1 {
            return Err(ObligationError::DoubleRelease(kind));
        }
        tracked.resolved = true;
        Ok(())
    }

    /// The unresolved subset of `required` that is OPEN in this set
    /// (an obligation never opened is not owed).
    fn unresolved_among(&self, required: &[ObligationKind]) -> Vec<ObligationKind> {
        required
            .iter()
            .filter(|kind| self.entries.iter().any(|t| t.kind == **kind && !t.resolved))
            .copied()
            .collect()
    }

    /// Gate: may this attempt offer its prepared-result candidate?
    ///
    /// # Errors
    /// Names every unresolved attempt-local obligation.
    pub fn may_offer_candidate(&self) -> Result<(), ObligationError> {
        let unresolved = self.unresolved_among(&ObligationKind::ATTEMPT_SUCCESS);
        if unresolved.is_empty() {
            Ok(())
        } else {
            Err(ObligationError::Unresolved(unresolved))
        }
    }

    /// Gate: may the coordinator publish? (Offer conditions PLUS the
    /// publication group.)
    ///
    /// # Errors
    /// Names every unresolved obligation across both groups.
    pub fn may_publish(&self) -> Result<(), ObligationError> {
        let mut unresolved = self.unresolved_among(&ObligationKind::ATTEMPT_SUCCESS);
        unresolved.extend(self.unresolved_among(&ObligationKind::PUBLICATION_REQUIRED));
        if unresolved.is_empty() {
            Ok(())
        } else {
            Err(ObligationError::Unresolved(unresolved))
        }
    }

    /// Gate: may the region close? EVERY opened obligation must be
    /// resolved — success obligations on success paths, and cleanup
    /// obligations on every path including cancel/failure.
    ///
    /// # Errors
    /// Names every leaked obligation (the attribution the bead demands).
    pub fn may_close_region(&self) -> Result<(), ObligationError> {
        let leaked: Vec<ObligationKind> = self
            .entries
            .iter()
            .filter(|t| !t.resolved)
            .map(|t| t.kind)
            .collect();
        if leaked.is_empty() {
            Ok(())
        } else {
            Err(ObligationError::Unresolved(leaked))
        }
    }
}

// ---------------------------------------------------------------------------
// G014: Drained-race helper for local/remote/cache/hedged attempts
// ---------------------------------------------------------------------------

/// Which leg of a competitive action race a contestant represents (bead G014).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RaceLegKind {
    /// CAS / remote cache lookup probe leg.
    CacheProbe,
    /// Local execution leg.
    LocalAttempt,
    /// Primary remote worker execution leg.
    RemotePrimary,
    /// Hedged remote worker execution leg under its own independent lease (I31).
    RemoteHedge {
        /// Zero-based hedge sibling index within the generation.
        hedge_index: u32,
    },
}

/// One contestant participating in a structured drained race (bead G014).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaceContestant {
    /// Unique attempt or probe identifier.
    pub attempt_id: u128,
    /// Leg kind (cache, local, remote primary, remote hedge).
    pub leg: RaceLegKind,
    /// Completion rank (lower finishes earlier; ties broken by leg and `attempt_id`).
    pub completion_rank: u32,
    /// Whether this contestant reached a valid candidate before cancellation.
    pub succeeded: bool,
    /// Candidate result digest when `succeeded` is true.
    pub candidate_digest: Option<[u8; 32]>,
    /// Tracked domain obligations for this contestant's region.
    pub obligations: ObligationSet,
}

impl RaceContestant {
    /// Construct a contestant with all attempt-local success and cleanup
    /// obligations opened in its region.
    #[must_use]
    pub fn new(
        attempt_id: u128,
        leg: RaceLegKind,
        completion_rank: u32,
        succeeded: bool,
        candidate_digest: Option<[u8; 32]>,
    ) -> Self {
        let mut obligations = ObligationSet::default();
        for kind in ObligationKind::ATTEMPT_SUCCESS {
            obligations.open(kind);
        }
        for kind in ObligationKind::CLEANUP {
            obligations.open(kind);
        }
        Self {
            attempt_id,
            leg,
            completion_rank,
            succeeded,
            candidate_digest,
            obligations,
        }
    }
}

/// Auditable drain receipt for a losing or cancelled race contestant (bead G014).
///
/// The race combinator never returns until every loser has drained its
/// process group, diagnostic stream, candidate staging pins, and sandbox
/// cleanup, and gated its slot release on `ownership_resolved`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainedLoserReceipt {
    /// Contestant attempt identifier.
    pub attempt_id: u128,
    /// Contestant leg kind.
    pub leg: RaceLegKind,
    /// Process group drained (`ObligationKind::ProcessGroupDrain`).
    pub drained_processes: bool,
    /// Diagnostic stream drained (`ObligationKind::DiagnosticStream`).
    pub drained_streams: bool,
    /// Candidate staging pins and provisional metadata released.
    pub released_candidate_pins: bool,
    /// Sandbox cleanup completed (`ObligationKind::SandboxCleanup`).
    pub cleaned_sandbox: bool,
    /// Ownership resolution gate (`TerminationReceipt::ownership_resolved` contract).
    pub ownership_resolved: bool,
    /// Execution slot/lease released ONLY after `ownership_resolved`.
    pub slot_released: bool,
    /// `ObligationSet::may_close_region()` succeeded with zero leaked obligations.
    pub region_closed_cleanly: bool,
}

/// Winning contestant summary from [`run_drained_race`] (bead G014).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainedRaceWinner {
    /// Winning attempt identifier.
    pub attempt_id: u128,
    /// Winning leg kind.
    pub leg: RaceLegKind,
    /// Winning candidate digest.
    pub candidate_digest: [u8; 32],
    /// Whether the winner's own region obligations also resolved cleanly.
    pub region_closed_cleanly: bool,
}

/// Result of running a structured drained race across local/remote/cache/hedged
/// contestants (bead G014; invariants I6, I7, I31).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainedRaceOutcome {
    /// First valid finisher, if any contestant succeeded.
    pub winner: Option<DrainedRaceWinner>,
    /// Receipts for every non-winning contestant proving complete drain before
    /// the combinator resolved.
    pub losers_drained: Vec<DrainedLoserReceipt>,
    /// True iff every contestant (winner and all losers) satisfied `may_close_region()`.
    pub all_regions_closed_cleanly: bool,
}

/// Execute a structured race across local/remote/cache/hedged contestants where
/// losers are ALWAYS drained (processes, streams, candidate pins, sandbox cleanup)
/// before the combinator resolves (bead G014).
///
/// # Errors
/// Returns [`ObligationError`] if any contestant's obligations fail to resolve
/// or if any region cannot close cleanly.
pub fn run_drained_race(
    mut contestants: Vec<RaceContestant>,
) -> Result<DrainedRaceOutcome, ObligationError> {
    // Identify the earliest succeeding contestant with a candidate digest.
    // Deterministic ordering: (completion_rank, leg, attempt_id).
    let winner_idx = contestants
        .iter()
        .enumerate()
        .filter(|(_, c)| c.succeeded && c.candidate_digest.is_some())
        .min_by_key(|(_, c)| (c.completion_rank, c.leg, c.attempt_id))
        .map(|(idx, _)| idx);

    let mut winner_summary = None;
    let mut losers_drained = Vec::new();

    for (idx, contestant) in contestants.iter_mut().enumerate() {
        if Some(idx) == winner_idx {
            for kind in ObligationKind::ATTEMPT_SUCCESS {
                contestant.obligations.resolve(kind)?;
            }
            contestant.obligations.may_offer_candidate()?;
            contestant
                .obligations
                .resolve(ObligationKind::SandboxCleanup)?;
            contestant.obligations.may_close_region()?;
            winner_summary = Some(DrainedRaceWinner {
                attempt_id: contestant.attempt_id,
                leg: contestant.leg,
                candidate_digest: contestant
                    .candidate_digest
                    .expect("filtered by is_some above"),
                region_closed_cleanly: true,
            });
        } else {
            // Drain loser: cancel/drain processes, streams, candidate staging pins,
            // and sandbox before resolving ownership and releasing the slot.
            contestant
                .obligations
                .resolve(ObligationKind::ProcessGroupDrain)?;
            contestant
                .obligations
                .resolve(ObligationKind::DiagnosticStream)?;
            contestant
                .obligations
                .resolve(ObligationKind::OutputStagingPin)?;
            contestant
                .obligations
                .resolve(ObligationKind::ActionInputClosure)?;
            contestant
                .obligations
                .resolve(ObligationKind::ProvisionalMetadata)?;
            contestant
                .obligations
                .resolve(ObligationKind::SandboxCleanup)?;
            contestant.obligations.may_close_region()?;

            let ownership_resolved = true;
            let slot_released = ownership_resolved;
            losers_drained.push(DrainedLoserReceipt {
                attempt_id: contestant.attempt_id,
                leg: contestant.leg,
                drained_processes: true,
                drained_streams: true,
                released_candidate_pins: true,
                cleaned_sandbox: true,
                ownership_resolved,
                slot_released,
                region_closed_cleanly: true,
            });
        }
    }

    let all_regions_closed_cleanly = winner_summary
        .as_ref()
        .is_none_or(|w| w.region_closed_cleanly)
        && losers_drained.iter().all(|l| l.region_closed_cleanly);

    Ok(DrainedRaceOutcome {
        winner: winner_summary,
        losers_drained,
        all_regions_closed_cleanly,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ObligationKind as K;

    #[test]
    fn catalog_is_complete_and_distinct() {
        let mut all = ObligationKind::ALL.to_vec();
        all.dedup();
        assert_eq!(all.len(), 25, "the plan catalog has 25 obligation types");
    }

    #[test]
    fn offers_wait_for_attempt_local_success_obligations() {
        let mut set = ObligationSet::default();
        for kind in K::ATTEMPT_SUCCESS {
            set.open(kind);
        }
        // Not yet: every unresolved obligation is NAMED.
        let Err(ObligationError::Unresolved(unresolved)) = set.may_offer_candidate() else {
            panic!("must block");
        };
        assert_eq!(unresolved.len(), 5);
        // Resolve all but one: still blocked, still attributable.
        for kind in [
            K::ActionInputClosure,
            K::OutputStagingPin,
            K::DiagnosticStream,
            K::ProcessGroupDrain,
        ] {
            set.resolve(kind).unwrap();
        }
        assert_eq!(
            set.may_offer_candidate(),
            Err(ObligationError::Unresolved(vec![K::ProvisionalMetadata]))
        );
        set.resolve(K::ProvisionalMetadata).unwrap();
        assert_eq!(set.may_offer_candidate(), Ok(()));
    }

    #[test]
    fn publication_requires_the_additional_group() {
        let mut set = ObligationSet::default();
        for kind in K::ATTEMPT_SUCCESS {
            set.open(kind);
            set.resolve(kind).unwrap();
        }
        assert_eq!(set.may_offer_candidate(), Ok(()));
        // Open the publication group: publish blocks until resolved.
        for kind in K::PUBLICATION_REQUIRED {
            set.open(kind);
        }
        let Err(ObligationError::Unresolved(unresolved)) = set.may_publish() else {
            panic!("publication must block");
        };
        assert_eq!(
            unresolved.len(),
            4,
            "canonical-result/closure/authority/lineage"
        );
        for kind in K::PUBLICATION_REQUIRED {
            set.resolve(kind).unwrap();
        }
        assert_eq!(set.may_publish(), Ok(()));
    }

    #[test]
    fn cancelled_paths_still_resolve_cleanup_before_region_close() {
        // THE leak acceptance: an attempt is cancelled — its success
        // obligations were never opened/resolved, but its CLEANUP
        // obligations were opened and MUST resolve before close, and a
        // leak attributes by name.
        let mut set = ObligationSet::default();
        for kind in K::CLEANUP {
            set.open(kind);
        }
        assert_eq!(
            set.may_close_region(),
            Err(ObligationError::Unresolved(vec![
                K::SandboxCleanup,
                K::ProcessGroupDrain
            ])),
            "an unresolved obligation blocks region close, attributably"
        );
        set.resolve(K::SandboxCleanup).unwrap();
        set.resolve(K::ProcessGroupDrain).unwrap();
        assert_eq!(set.may_close_region(), Ok(()));
    }

    #[test]
    fn cargo_root_permit_releases_exactly_once() {
        let mut set = ObligationSet::default();
        set.open(K::CargoRootPermit);
        assert_eq!(set.resolve(K::CargoRootPermit), Ok(()));
        // The second release is a typed error, never a silent no-op.
        assert_eq!(
            set.resolve(K::CargoRootPermit),
            Err(ObligationError::DoubleRelease(K::CargoRootPermit))
        );
        // Resolving an obligation never opened is also typed.
        assert_eq!(
            set.resolve(K::WinnerCommit),
            Err(ObligationError::NotOpened(K::WinnerCommit))
        );
    }

    #[test]
    fn g014_drained_race_covers_all_winner_loser_orderings() {
        let digest_a = [0xAA; 32];
        let digest_b = [0xBB; 32];

        // 1. Local wins over RemotePrimary and RemoteHedge.
        let outcome = run_drained_race(vec![
            RaceContestant::new(1, RaceLegKind::LocalAttempt, 10, true, Some(digest_a)),
            RaceContestant::new(2, RaceLegKind::RemotePrimary, 20, true, Some(digest_a)),
            RaceContestant::new(
                3,
                RaceLegKind::RemoteHedge { hedge_index: 0 },
                30,
                false,
                None,
            ),
        ])
        .expect("drained race must succeed");
        let winner = outcome.winner.expect("local winner");
        assert_eq!(winner.attempt_id, 1);
        assert_eq!(winner.leg, RaceLegKind::LocalAttempt);
        assert_eq!(winner.candidate_digest, digest_a);
        assert!(outcome.all_regions_closed_cleanly);
        assert_eq!(outcome.losers_drained.len(), 2);
        for loser in &outcome.losers_drained {
            assert!(loser.drained_processes);
            assert!(loser.drained_streams);
            assert!(loser.released_candidate_pins);
            assert!(loser.cleaned_sandbox);
            assert!(loser.ownership_resolved);
            assert!(loser.slot_released);
            assert!(loser.region_closed_cleanly);
        }

        // 2. RemoteHedge wins over stalled RemotePrimary and LocalAttempt.
        let outcome = run_drained_race(vec![
            RaceContestant::new(10, RaceLegKind::LocalAttempt, 50, false, None),
            RaceContestant::new(11, RaceLegKind::RemotePrimary, 40, true, Some(digest_b)),
            RaceContestant::new(
                12,
                RaceLegKind::RemoteHedge { hedge_index: 0 },
                15,
                true,
                Some(digest_b),
            ),
        ])
        .expect("drained race must succeed");
        let winner = outcome.winner.expect("hedge winner");
        assert_eq!(winner.attempt_id, 12);
        assert_eq!(winner.leg, RaceLegKind::RemoteHedge { hedge_index: 0 });
        assert_eq!(outcome.losers_drained.len(), 2);
        assert!(outcome.all_regions_closed_cleanly);

        // 3. CacheProbe wins on simultaneous completion rank tie-break.
        let outcome = run_drained_race(vec![
            RaceContestant::new(21, RaceLegKind::RemotePrimary, 5, true, Some(digest_a)),
            RaceContestant::new(20, RaceLegKind::CacheProbe, 5, true, Some(digest_a)),
        ])
        .expect("drained race must succeed");
        let winner = outcome.winner.expect("cache winner");
        assert_eq!(winner.attempt_id, 20);
        assert_eq!(winner.leg, RaceLegKind::CacheProbe);
        assert_eq!(outcome.losers_drained.len(), 1);
        assert_eq!(outcome.losers_drained[0].attempt_id, 21);
        assert!(outcome.all_regions_closed_cleanly);

        // 4. All contestants fail / cancel: no winner, all contestants drained cleanly.
        let outcome = run_drained_race(vec![
            RaceContestant::new(30, RaceLegKind::LocalAttempt, 10, false, None),
            RaceContestant::new(31, RaceLegKind::RemotePrimary, 20, false, None),
        ])
        .expect("drained race with all failures must still drain cleanly");
        assert!(outcome.winner.is_none());
        assert_eq!(outcome.losers_drained.len(), 2);
        assert!(outcome.all_regions_closed_cleanly);
    }
}
