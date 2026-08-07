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
}
