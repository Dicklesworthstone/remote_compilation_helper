//! Transcript/stateful delivery obligations + the pre-exposure
//! fallback frontier at the runtime layer (bead G018; realizes
//! C005/C019/C021 as G002 obligations; risks R97/R116).
//!
//! The two-frontier model (rabs-action's `ExposureFrontiers`) becomes
//! REGION BOOKKEEPING here: every transcript frame and every stateful
//! observable opens an obligation that must resolve before the
//! subscriber region closes — so "the frontier bookkeeping resolved"
//! is not a comment, it is `may_close_region()`.
//!
//! - a transcript frame is conservatively EXPOSED from the moment it
//!   is sent (R116: a frame that MAY have reached the wrapper counts);
//! - a stateful observable records its write-ahead intent BEFORE
//!   emission; a crash between intent and acknowledgement is the
//!   fail-closed uncertainty state — no replay, no uncoordinated
//!   fallback (R97), and the open obligation blocks region close
//!   until coordinator reconciliation resolves it;
//! - while NOTHING is exposed, the safe nonpublishing local fallback
//!   frontier is open (`FallbackClass::SeamlessNonpublishing`).

use crate::obligations::{ObligationError, ObligationKind, ObligationSet};
use rabs_action::state_machines::{ExposureFrontiers, FallbackClass};

/// The per-subscriber delivery ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliveryLedger {
    obligations: ObligationSet,
    frontiers: ExposureFrontiers,
    /// Transcript frames sent, not yet fully acknowledged.
    pending_transcript_frames: u64,
    /// A stateful item's intent is recorded, emission unacknowledged.
    stateful_pending: bool,
    /// Uncertainty flags (fail-closed until reconciled).
    transcript_uncertain: bool,
    stateful_uncertain: bool,
}

impl DeliveryLedger {
    /// New ledger (nothing exposed).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The fallback class the frontiers currently admit.
    #[must_use]
    pub const fn fallback_class(&self) -> FallbackClass {
        self.frontiers.fallback_class()
    }

    /// Send a transcript frame: conservatively exposed NOW (R116).
    pub fn send_transcript_frame(&mut self) {
        self.obligations.open(ObligationKind::SubscriberDelivery);
        self.frontiers.transcript_exposed = true;
        self.pending_transcript_frames += 1;
    }

    /// Full acknowledgement of one transcript frame.
    pub fn ack_transcript_frame(&mut self) {
        self.pending_transcript_frames = self.pending_transcript_frames.saturating_sub(1);
        if self.pending_transcript_frames == 0 && !self.transcript_uncertain {
            let _ = self.obligations.resolve(ObligationKind::SubscriberDelivery);
        }
    }

    /// The connection died mid-frame: transcript delivery UNCERTAIN.
    pub fn transcript_connection_lost(&mut self) {
        if self.pending_transcript_frames > 0 {
            self.transcript_uncertain = true;
        }
    }

    /// Record a stateful observable's write-ahead intent and begin
    /// emission.
    pub fn begin_stateful_observable(&mut self) {
        self.obligations
            .open(ObligationKind::PerSubscriberObservableCommit);
        self.frontiers.stateful_intent_recorded = true;
        self.stateful_pending = true;
    }

    /// Acknowledged stateful commit.
    pub fn ack_stateful_observable(&mut self) {
        if !self.stateful_uncertain {
            self.stateful_pending = false;
            let _ = self
                .obligations
                .resolve(ObligationKind::PerSubscriberObservableCommit);
        }
    }

    /// Crash between intent and acknowledgement: fail-closed (R97).
    pub fn stateful_crash_between_intent_and_ack(&mut self) {
        if self.stateful_pending {
            self.stateful_uncertain = true;
        }
    }

    /// Coordinator reconciliation resolved an uncertainty (the ONLY
    /// exit from uncertain states — never replay, never local retry).
    pub fn reconciled_by_coordinator(&mut self) {
        if self.transcript_uncertain {
            self.transcript_uncertain = false;
            if self.pending_transcript_frames > 0 {
                self.pending_transcript_frames = 0;
            }
            let _ = self.obligations.resolve(ObligationKind::SubscriberDelivery);
        }
        if self.stateful_uncertain {
            self.stateful_uncertain = false;
            self.stateful_pending = false;
            let _ = self
                .obligations
                .resolve(ObligationKind::PerSubscriberObservableCommit);
        }
    }

    /// Region close: proves the frontier bookkeeping resolved.
    ///
    /// # Errors
    /// Names the unresolved delivery obligations.
    pub fn may_close_region(&self) -> Result<(), ObligationError> {
        if self.transcript_uncertain
            || self.stateful_uncertain
            || self.pending_transcript_frames > 0
            || self.stateful_pending
        {
            // The obligation set carries the names; consult it.
            return self.obligations.may_close_region();
        }
        self.obligations.may_close_region()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_exposure_fallback_is_seamless_and_region_closes_clean() {
        // Nothing exposed: the safe nonpublishing fallback frontier is
        // open, and the region closes with no outstanding bookkeeping.
        let ledger = DeliveryLedger::new();
        assert_eq!(
            ledger.fallback_class(),
            FallbackClass::SeamlessNonpublishing
        );
        assert_eq!(ledger.may_close_region(), Ok(()));
    }

    #[test]
    fn transcript_frontier_obligations_resolve_on_full_ack() {
        let mut ledger = DeliveryLedger::new();
        ledger.send_transcript_frame();
        // Sent = conservatively exposed (R116): labeled recovery only.
        assert_eq!(
            ledger.fallback_class(),
            FallbackClass::LabeledTranscriptRecoveryOnly
        );
        // Region close blocked with the obligation NAMED.
        assert_eq!(
            ledger.may_close_region(),
            Err(ObligationError::Unresolved(vec![
                ObligationKind::SubscriberDelivery
            ]))
        );
        ledger.ack_transcript_frame();
        assert_eq!(ledger.may_close_region(), Ok(()));
        // Exposure is a one-way frontier: still labeled-only.
        assert_eq!(
            ledger.fallback_class(),
            FallbackClass::LabeledTranscriptRecoveryOnly
        );
    }

    #[test]
    fn transcript_uncertainty_fails_closed_until_reconciled() {
        let mut ledger = DeliveryLedger::new();
        ledger.send_transcript_frame();
        ledger.transcript_connection_lost();
        // An ack arriving AFTER the loss does not clear uncertainty.
        ledger.ack_transcript_frame();
        assert!(ledger.may_close_region().is_err(), "uncertainty holds");
        // Only coordinator reconciliation exits the state.
        ledger.reconciled_by_coordinator();
        assert_eq!(ledger.may_close_region(), Ok(()));
    }

    #[test]
    fn stateful_uncertainty_forbids_uncoordinated_fallback_forever() {
        let mut ledger = DeliveryLedger::new();
        ledger.begin_stateful_observable();
        // Intent recorded: NO uncoordinated fallback, dominating any
        // transcript state.
        assert_eq!(
            ledger.fallback_class(),
            FallbackClass::NoUncoordinatedFallback
        );
        ledger.stateful_crash_between_intent_and_ack();
        // A local ack cannot clear the crash uncertainty (R97: no
        // replay, no local retry).
        ledger.ack_stateful_observable();
        assert_eq!(
            ledger.may_close_region(),
            Err(ObligationError::Unresolved(vec![
                ObligationKind::PerSubscriberObservableCommit
            ]))
        );
        // Fallback stays forbidden even while uncertain.
        assert_eq!(
            ledger.fallback_class(),
            FallbackClass::NoUncoordinatedFallback
        );
        // Coordinator reconciliation is the only exit.
        ledger.reconciled_by_coordinator();
        assert_eq!(ledger.may_close_region(), Ok(()));
    }

    #[test]
    fn stateful_dominates_transcript_in_the_fallback_table() {
        let mut ledger = DeliveryLedger::new();
        ledger.send_transcript_frame();
        ledger.ack_transcript_frame();
        ledger.begin_stateful_observable();
        assert_eq!(
            ledger.fallback_class(),
            FallbackClass::NoUncoordinatedFallback,
            "stateful intent dominates transcript exposure"
        );
    }
}
