//! The four separate RABS state machines (bead A017; invariants I29/I30;
//! risk R61 forbids collapsing them into one lifecycle enum).
//!
//! One Cargo build operation may subscribe to many actions; one action may
//! serve many operations across hosts; each attempt has its own lease; each
//! subscriber has its own delivery frontiers. Because these are FOUR
//! machines, a cache hit does not "commit" an action again, one
//! subscriber's observable commit does not commit another's, and a
//! transition model can be replayed/audited per machine.
//!
//! Each machine exposes `may_transition(from, to)`; anything not explicitly
//! allowed is rejected (denial-default, same posture as the authority
//! matrix). Terminal states have no successors.

// ---------------------------------------------------------------------------
// 1. Build operation
// ---------------------------------------------------------------------------

/// One user/agent/IDE/CI Cargo command (owns snapshot lineage, root permit,
/// wrapper connections, subscriptions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildOperationState {
    /// Created, nothing captured yet.
    Created,
    /// Capturing the coherent requested snapshot (I2).
    Snapshotting,
    /// Canonical Cargo driver starting (root permit being acquired).
    CargoStarting,
    /// Cargo running; subscriptions active.
    CargoRunning,
    /// Cargo exiting; draining subscriptions/permits.
    CargoDraining,
    /// Terminal: completed normally.
    Completed,
    /// Terminal: cancelled.
    Cancelled,
    /// Terminal: failed before any observable exposure.
    FailedBeforeStart,
    /// Terminal: failed after some subscriber crossed observable commit.
    FailedAfterObservableCommit,
    /// Terminal: finished via nonpublishing local fallback.
    LocalFallbackCompleted,
    /// Terminal: client vanished.
    AbandonedClient,
    /// Terminal: internal defect (crashpack produced).
    InternalFailure,
}

impl BuildOperationState {
    /// Whether this state is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(
            self,
            Self::Created
                | Self::Snapshotting
                | Self::CargoStarting
                | Self::CargoRunning
                | Self::CargoDraining
        )
    }

    /// Whether `from → to` is a legal transition.
    #[must_use]
    pub const fn may_transition(from: Self, to: Self) -> bool {
        use BuildOperationState as S;
        if from.is_terminal() {
            return false;
        }
        match (from, to) {
            // The forward spine.
            (S::Created, S::Snapshotting)
            | (S::Snapshotting, S::CargoStarting)
            | (S::CargoStarting, S::CargoRunning)
            | (S::CargoRunning, S::CargoDraining)
            | (S::CargoDraining, S::Completed) => true,
            // Terminal alternates reachable from any live state...
            (_, S::Cancelled | S::AbandonedClient | S::InternalFailure) => true,
            // ...with exposure-sensitive failure split (I30): before Cargo
            // runs nothing was exposed; after, the stricter terminal.
            (S::Created | S::Snapshotting | S::CargoStarting, S::FailedBeforeStart) => true,
            (S::CargoRunning | S::CargoDraining, S::FailedAfterObservableCommit) => true,
            // Local fallback is only reachable while live (pre-frontier
            // checks are per-subscriber; the operation-level terminal
            // records that the whole command finished locally).
            (
                S::Created | S::Snapshotting | S::CargoStarting | S::CargoRunning,
                S::LocalFallbackCompleted,
            ) => true,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Logical action publication slot
// ---------------------------------------------------------------------------

/// The authority-bearing publication slot for one action key — deliberately
/// tiny. Serving/trust disposition is a SEPARATE versioned record (I50) and
/// is not represented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationSlotState {
    /// No active generation, no committed result.
    Absent,
    /// One active generation is executing (its never-reused ID lives in the
    /// generation record, not this enum).
    Executing,
    /// A canonical result is committed. Immutable history: there is no
    /// transition out — correction means quarantine (serving-side) or a new
    /// key epoch, never un-committing.
    Committed,
}

impl PublicationSlotState {
    /// Whether `from → to` is legal.
    ///
    /// `Executing → Absent` is the close-generation path (all attempts
    /// terminated without an eligible candidate; the generation tombstone
    /// persists in its own record). A CACHE HIT is expressed as *no
    /// transition at all* on `Committed` — re-committing is not
    /// representable (I29: "a cache hit does not commit an action again").
    #[must_use]
    pub const fn may_transition(from: Self, to: Self) -> bool {
        matches!(
            (from, to),
            (Self::Absent, Self::Executing)
                | (Self::Executing, Self::Committed)
                | (Self::Executing, Self::Absent)
        )
    }
}

// ---------------------------------------------------------------------------
// 3. Execution attempt
// ---------------------------------------------------------------------------

/// One concrete attempt under one execution lease (hedges are sibling
/// attempts with independent leases — I31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptState {
    /// Created by the coordinator.
    Created,
    /// Lease offered to a worker.
    LeaseOffered,
    /// Worker accepted the lease.
    LeaseAccepted,
    /// Waiting for input objects.
    AwaitingInputs,
    /// Materializing the sandbox/execroot.
    Materializing,
    /// Compiler/tool process running (MetadataReady and diagnostics are
    /// EVENTS during this state, not states).
    Running,
    /// Process exited; outcome being classified.
    ProcessExited,
    /// Success path: harvesting declared outputs.
    HarvestingOutputs,
    /// Success path: uploading under candidate pins.
    UploadingOutputs,
    /// Success path: verifying digests/closures.
    VerifyingOutputs,
    /// Eligible deterministic failure: harvesting canonical observations.
    HarvestingCanonicalObservations,
    /// Eligible deterministic failure: verifying the failure record.
    VerifyingFailure,
    /// Candidate offered to the coordinator (success OR eligible
    /// deterministic failure).
    PreparedResultOffered,
    /// Coordinator compare-and-set chose this attempt.
    AcceptedAsWinner,
    /// Another attempt already committed the same canonical result.
    RejectedAsDuplicate,
    /// Attempt authority/lease was stale at offer time.
    RejectedAsStale,
    /// Same key, different canonical result: divergence incident (I34).
    RejectedAsDivergent,
    /// Draining processes/streams/pins (always passed through).
    Draining,
    /// Terminal.
    Finished,
}

impl AttemptState {
    /// Whether `from → to` is legal.
    #[must_use]
    pub const fn may_transition(from: Self, to: Self) -> bool {
        use AttemptState as S;
        match (from, to) {
            // Spine to process exit.
            (S::Created, S::LeaseOffered)
            | (S::LeaseOffered, S::LeaseAccepted)
            | (S::LeaseAccepted, S::AwaitingInputs)
            | (S::AwaitingInputs, S::Materializing)
            | (S::Materializing, S::Running)
            | (S::Running, S::ProcessExited) => true,
            // Outcome classification fans out (I16: only classified
            // deterministic outcomes reach a publishable path; abnormal
            // outcomes go straight to Draining).
            (S::ProcessExited, S::HarvestingOutputs | S::HarvestingCanonicalObservations) => true,
            // Success pipeline.
            (S::HarvestingOutputs, S::UploadingOutputs)
            | (S::UploadingOutputs, S::VerifyingOutputs)
            | (S::VerifyingOutputs, S::PreparedResultOffered) => true,
            // Deterministic-failure pipeline.
            (S::HarvestingCanonicalObservations, S::VerifyingFailure)
            | (S::VerifyingFailure, S::PreparedResultOffered) => true,
            // Coordinator decision.
            (
                S::PreparedResultOffered,
                S::AcceptedAsWinner
                | S::RejectedAsDuplicate
                | S::RejectedAsStale
                | S::RejectedAsDivergent,
            ) => true,
            // Everything funnels through Draining to Finished; any live or
            // decided state may begin draining (cancellation, abnormal
            // outcome, lease expiry, rejection, acceptance cleanup).
            (S::Draining, S::Finished) => true,
            (s, S::Draining) if !matches!(s, S::Draining | S::Finished) => true,
            _ => false,
        }
    }

    /// A worker-side offer is legal only from `PreparedResultOffered`; in
    /// particular an attempt that never verified outputs cannot offer.
    #[must_use]
    pub const fn may_offer(self) -> bool {
        matches!(self, Self::PreparedResultOffered)
    }
}

// ---------------------------------------------------------------------------
// 4. Subscriber delivery (two exposure frontiers)
// ---------------------------------------------------------------------------

/// Per-subscriber delivery state: one ordered stream, two frontiers
/// (transcript vs stateful), uncertainty fails closed (I43/I46).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriberDeliveryState {
    /// Subscribed, nothing in flight.
    Subscribed,
    /// Waiting for a result or attempt progress.
    Waiting,
    /// Staging private outputs (not yet visible).
    StagingPrivateOutputs,
    /// A transcript frame is being written to the wrapper.
    EmittingTranscript,
    /// A transcript frame MAY have reached the wrapper without full
    /// acknowledgement — conservatively treated as exposed (R116).
    TranscriptDeliveryUncertain,
    /// A stateful item's write-ahead intent is recorded; emission underway.
    EmittingStatefulObservable,
    /// Crash between stateful intent and acknowledgement: no replay, no
    /// uncoordinated fallback (R97).
    StatefulDeliveryUncertain,
    /// Terminal item + all owned outputs acknowledged.
    DeliveryComplete,
    /// Subscription detached (cancel/fallback); materialization rights
    /// revoked.
    Detached,
}

/// The two exposure frontiers, tracked independently per subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExposureFrontiers {
    /// Any transcript frame fully exposed (or conservatively assumed so).
    pub transcript_exposed: bool,
    /// Any stateful commit intent recorded (rename/readiness/terminal).
    pub stateful_intent_recorded: bool,
}

/// What kind of fallback, if any, this subscriber may still take
/// (plan §85's three-band table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackClass {
    /// Nothing exposed: seamless nonpublishing local fallback is safe.
    SeamlessNonpublishing,
    /// Transcript-only exposure: reconnect or fail coherently by default;
    /// explicitly configured LABELED transcript recovery only.
    LabeledTranscriptRecoveryOnly,
    /// Stateful intent/commit exists: no uncoordinated fallback, ever.
    NoUncoordinatedFallback,
}

impl ExposureFrontiers {
    /// The fallback class these frontiers admit. The stateful frontier
    /// dominates: once intent is recorded, transcript state is irrelevant.
    #[must_use]
    pub const fn fallback_class(self) -> FallbackClass {
        if self.stateful_intent_recorded {
            FallbackClass::NoUncoordinatedFallback
        } else if self.transcript_exposed {
            FallbackClass::LabeledTranscriptRecoveryOnly
        } else {
            FallbackClass::SeamlessNonpublishing
        }
    }
}

impl SubscriberDeliveryState {
    /// Whether `from → to` is legal.
    #[must_use]
    pub const fn may_transition(from: Self, to: Self) -> bool {
        use SubscriberDeliveryState as S;
        match (from, to) {
            (S::Subscribed, S::Waiting)
            | (S::Waiting, S::StagingPrivateOutputs | S::EmittingTranscript | S::EmittingStatefulObservable)
            | (S::StagingPrivateOutputs, S::Waiting | S::EmittingTranscript | S::EmittingStatefulObservable)
            // Transcript loop: emit → back to waiting on full ack, or into
            // uncertainty on connection death mid-frame.
            | (S::EmittingTranscript, S::Waiting | S::TranscriptDeliveryUncertain)
            | (S::TranscriptDeliveryUncertain, S::Waiting | S::Detached)
            // Stateful loop: emit → back to waiting on full ack, or into
            // fail-closed uncertainty.
            | (S::EmittingStatefulObservable, S::Waiting | S::StatefulDeliveryUncertain)
            | (S::StatefulDeliveryUncertain, S::Waiting)
            // Terminal completion only from the quiescent loop position.
            | (S::Waiting, S::DeliveryComplete)
            // Detach (cancel / pre-frontier fallback) from live states.
            | (S::Subscribed | S::Waiting | S::StagingPrivateOutputs, S::Detached) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_operation_spine_and_exposure_split() {
        use BuildOperationState as S;
        for (a, b) in [
            (S::Created, S::Snapshotting),
            (S::Snapshotting, S::CargoStarting),
            (S::CargoStarting, S::CargoRunning),
            (S::CargoRunning, S::CargoDraining),
            (S::CargoDraining, S::Completed),
        ] {
            assert!(S::may_transition(a, b), "{a:?}->{b:?} must be legal");
        }
        // Exposure split: pre-run failure vs post-exposure failure.
        assert!(S::may_transition(S::Snapshotting, S::FailedBeforeStart));
        assert!(!S::may_transition(S::CargoRunning, S::FailedBeforeStart));
        assert!(S::may_transition(
            S::CargoRunning,
            S::FailedAfterObservableCommit
        ));
        assert!(!S::may_transition(
            S::Created,
            S::FailedAfterObservableCommit
        ));
        // Terminals are terminal.
        assert!(!S::may_transition(S::Completed, S::CargoRunning));
        assert!(!S::may_transition(S::Cancelled, S::Snapshotting));
    }

    #[test]
    fn publication_slot_cannot_recommit_and_cache_hit_is_no_transition() {
        use PublicationSlotState as S;
        assert!(S::may_transition(S::Absent, S::Executing));
        assert!(S::may_transition(S::Executing, S::Committed));
        // Failed generation closes back to Absent (tombstone elsewhere).
        assert!(S::may_transition(S::Executing, S::Absent));
        // Committed is immutable history: NOTHING leaves it — a cache hit
        // is not a transition, and re-commit is unrepresentable (I29).
        assert!(!S::may_transition(S::Committed, S::Committed));
        assert!(!S::may_transition(S::Committed, S::Executing));
        assert!(!S::may_transition(S::Committed, S::Absent));
        // And commitment cannot appear from thin air.
        assert!(!S::may_transition(S::Absent, S::Committed));
    }

    #[test]
    fn attempt_success_and_failure_pipelines() {
        use AttemptState as S;
        // Success spine.
        for (a, b) in [
            (S::Created, S::LeaseOffered),
            (S::LeaseOffered, S::LeaseAccepted),
            (S::LeaseAccepted, S::AwaitingInputs),
            (S::AwaitingInputs, S::Materializing),
            (S::Materializing, S::Running),
            (S::Running, S::ProcessExited),
            (S::ProcessExited, S::HarvestingOutputs),
            (S::HarvestingOutputs, S::UploadingOutputs),
            (S::UploadingOutputs, S::VerifyingOutputs),
            (S::VerifyingOutputs, S::PreparedResultOffered),
            (S::PreparedResultOffered, S::AcceptedAsWinner),
            (S::AcceptedAsWinner, S::Draining),
            (S::Draining, S::Finished),
        ] {
            assert!(S::may_transition(a, b), "{a:?}->{b:?} must be legal");
        }
        // Deterministic-failure pipeline exists and reaches the offer.
        assert!(S::may_transition(
            S::ProcessExited,
            S::HarvestingCanonicalObservations
        ));
        assert!(S::may_transition(
            S::HarvestingCanonicalObservations,
            S::VerifyingFailure
        ));
        assert!(S::may_transition(
            S::VerifyingFailure,
            S::PreparedResultOffered
        ));
        // Abnormal outcomes skip publication: ProcessExited may drain
        // directly, and an offer from an unverified state is illegal.
        assert!(S::may_transition(S::ProcessExited, S::Draining));
        assert!(!S::may_transition(S::Running, S::PreparedResultOffered));
        assert!(!S::may_transition(
            S::HarvestingOutputs,
            S::PreparedResultOffered
        ));
        // Only the offered state may offer.
        assert!(S::PreparedResultOffered.may_offer());
        assert!(!S::VerifyingOutputs.may_offer());
        // Rejections drain too.
        assert!(S::may_transition(S::RejectedAsDivergent, S::Draining));
        assert!(!S::may_transition(S::Finished, S::Draining));
    }

    #[test]
    fn subscriber_delivery_loops_and_uncertainty_fails_closed() {
        use SubscriberDeliveryState as S;
        assert!(S::may_transition(S::Subscribed, S::Waiting));
        // Transcript loop with ack.
        assert!(S::may_transition(S::Waiting, S::EmittingTranscript));
        assert!(S::may_transition(S::EmittingTranscript, S::Waiting));
        // Mid-frame death: uncertainty, which may NOT slide straight to
        // DeliveryComplete or re-emit.
        assert!(S::may_transition(
            S::EmittingTranscript,
            S::TranscriptDeliveryUncertain
        ));
        assert!(!S::may_transition(
            S::TranscriptDeliveryUncertain,
            S::DeliveryComplete
        ));
        assert!(!S::may_transition(
            S::TranscriptDeliveryUncertain,
            S::EmittingTranscript
        ));
        // Stateful uncertainty: no detach-and-fallback either (fail closed).
        assert!(S::may_transition(
            S::EmittingStatefulObservable,
            S::StatefulDeliveryUncertain
        ));
        assert!(!S::may_transition(
            S::StatefulDeliveryUncertain,
            S::Detached
        ));
        // Completion only from the quiescent loop position.
        assert!(S::may_transition(S::Waiting, S::DeliveryComplete));
        assert!(!S::may_transition(
            S::EmittingStatefulObservable,
            S::DeliveryComplete
        ));
    }

    #[test]
    fn fallback_classes_follow_the_two_frontiers() {
        let clean = ExposureFrontiers::default();
        assert_eq!(clean.fallback_class(), FallbackClass::SeamlessNonpublishing);
        let transcript = ExposureFrontiers {
            transcript_exposed: true,
            stateful_intent_recorded: false,
        };
        assert_eq!(
            transcript.fallback_class(),
            FallbackClass::LabeledTranscriptRecoveryOnly
        );
        // Stateful dominates regardless of transcript state.
        for t in [false, true] {
            let stateful = ExposureFrontiers {
                transcript_exposed: t,
                stateful_intent_recorded: true,
            };
            assert_eq!(
                stateful.fallback_class(),
                FallbackClass::NoUncoordinatedFallback
            );
        }
    }
}
