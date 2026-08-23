//! Write-ahead stateful delivery intent, full-write acknowledgement,
//! iterative sequence replay, and DeliveryUncertain fail-closed
//! resolution (bead C019; invariant I43; risk R97; plan §85).
//!
//! The delivery loop for one subscriber walks a validated item plan in
//! sequence order. For every STATEFUL item (a visible rename/write or
//! any other state-advancing event) the edge durably records a commit
//! intent BEFORE the first visible effect; the wrapper acknowledges an
//! item only after its COMPLETE exposure; the frontier advances one
//! item at a time (ack after each — many-item builds replay
//! iteratively, never in one uncheckable batch).
//!
//! A crash between intent and acknowledgement leaves exactly one item
//! in the **uncertain interval**: the effect may or may not have become
//! visible. That state is [`RecoveryClass::DeliveryUncertain`] and it
//! FAILS CLOSED:
//!
//! - no uncoordinated local fallback (the frontier report shows a
//!   sticky stateful signal, so C005's `decide_fallback` refuses a
//!   local rerun under every configuration);
//! - no blind replay: re-exposing the uncertain item without a
//!   destination inspection is a typed refusal — a blind rerun could
//!   double-apply a visible rename (R97);
//! - resolution consults the DESTINATION (did the effect land?): an
//!   effect that landed completes the item without re-exposure (the
//!   lost message was only the ack); an effect that did not land
//!   re-exposes under the already-recorded intent. Either way each
//!   visible effect happens exactly once.
//!
//! `DeliveryComplete` exists only after the TERMINAL item — which the
//! plan requires to be last, behind every owned output — is
//! acknowledged. This module is the pure protocol core: ledgers here
//! are values; fsync, sockets, and real renames live in the edge and
//! wrapper. The crash-at-every-boundary fixture below is the
//! T031/T036 seed.

use crate::local_protocol::SubscriberFrontierReport;

/// What kind of delivery item a sequence position carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryItemKind {
    /// Pure transcript output: visible, but replay-safe under the C006
    /// labeled-recovery rules (its uncertainty is tracked by the
    /// transcript frontier, not the stateful one).
    Transcript,
    /// A state-advancing visible effect (rename/write into the user's
    /// world). Requires a durably recorded intent BEFORE exposure.
    StatefulWrite,
    /// The terminal item: acknowledging it is `DeliveryComplete`.
    Terminal,
}

/// Plan validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    /// No terminal item: the stream could never complete.
    MissingTerminal,
    /// A terminal item somewhere other than the last position — owned
    /// outputs after "complete" would be unreachable.
    TerminalNotLast,
    /// An empty plan is meaningless.
    Empty,
}

/// A validated delivery plan: items at sequences `1..=len`, terminal
/// last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryPlan {
    items: Vec<DeliveryItemKind>,
}

impl DeliveryPlan {
    /// Validate: non-empty, exactly one terminal, and it is last.
    ///
    /// # Errors
    /// A typed [`PlanError`].
    pub fn new(items: Vec<DeliveryItemKind>) -> Result<Self, PlanError> {
        if items.is_empty() {
            return Err(PlanError::Empty);
        }
        let terminals = items
            .iter()
            .filter(|i| **i == DeliveryItemKind::Terminal)
            .count();
        if terminals == 0 {
            return Err(PlanError::MissingTerminal);
        }
        if terminals > 1 || *items.last().expect("non-empty") != DeliveryItemKind::Terminal {
            return Err(PlanError::TerminalNotLast);
        }
        Ok(Self { items })
    }

    /// Number of items (the terminal sequence).
    #[must_use]
    pub fn len(&self) -> u64 {
        self.items.len() as u64
    }

    /// Whether the plan is empty (never true for a validated plan).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Item kind at a 1-based sequence.
    #[must_use]
    pub fn kind(&self, seq: u64) -> Option<DeliveryItemKind> {
        usize::try_from(seq.checked_sub(1)?)
            .ok()
            .and_then(|i| self.items.get(i))
            .copied()
    }
}

/// The DURABLE slice of delivery state — exactly what survives a crash
/// (the edge fsyncs this before acting on it; here it is a value).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DurableDeliveryState {
    /// Sequences whose stateful commit intent is durably recorded
    /// (write-ahead: recorded BEFORE any visible effect).
    pub intents: std::collections::BTreeSet<u64>,
    /// Items `1..=frontier` are fully exposed AND acknowledged.
    pub acked_frontier: u64,
}

/// The user-visible world (destinations): which items' effects actually
/// became visible. Survives crashes by definition — it IS the outside
/// world. Fixtures use it as the destination-inspection oracle.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VisibleWorld {
    /// Exposure events in the order they became visible.
    pub exposed: Vec<u64>,
}

impl VisibleWorld {
    /// Destination inspection: did `seq`'s effect land?
    #[must_use]
    pub fn inspect(&self, seq: u64) -> DestinationInspection {
        if self.exposed.contains(&seq) {
            DestinationInspection::EffectLanded
        } else {
            DestinationInspection::EffectAbsent
        }
    }
}

/// The outcome of inspecting the uncertain item's destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationInspection {
    /// The visible effect is present and complete: only the ack was
    /// lost. The item completes WITHOUT re-exposure.
    EffectLanded,
    /// The visible effect never landed: re-exposure under the recorded
    /// intent is safe and required.
    EffectAbsent,
}

/// Recovery classification after a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryClass {
    /// The next item never entered the uncertain interval: resume the
    /// loop cleanly at `next_seq`.
    CleanResume {
        /// First sequence still to deliver.
        next_seq: u64,
    },
    /// A stateful item has a recorded intent but no acknowledgement:
    /// its effect may or may not be visible. Fail closed — no
    /// uncoordinated fallback, no blind replay — until a destination
    /// inspection resolves it.
    DeliveryUncertain {
        /// The uncertain sequence.
        seq: u64,
    },
    /// Everything (including the terminal item) is acknowledged.
    Complete,
}

/// Typed refusals from the delivery engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryError {
    /// Sequence is not the next undelivered item (delivery is strictly
    /// iterative: ack after each item).
    NotNextItem {
        /// The sequence the loop expects next.
        expected: u64,
    },
    /// A stateful item's exposure was attempted before its intent was
    /// durably recorded (the I43 write-ahead violation).
    IntentNotRecorded {
        /// The offending sequence.
        seq: u64,
    },
    /// Intent recording is only meaningful for stateful items.
    NotAStatefulItem {
        /// The offending sequence.
        seq: u64,
    },
    /// An exposure is already in flight; ack it (or crash) first.
    AlreadyExposing {
        /// The in-flight sequence.
        exposing: u64,
    },
    /// Acknowledgement for an item that is not the one being exposed.
    NotExposing {
        /// The offending sequence.
        seq: u64,
    },
    /// The engine is in the DeliveryUncertain state: exposing or acking
    /// ANYTHING before resolution would be a blind replay (R97).
    UncertainUnresolved {
        /// The uncertain sequence.
        seq: u64,
    },
    /// Resolution was attempted but nothing is uncertain.
    NothingUncertain,
    /// Sequence beyond the plan.
    UnknownSequence {
        /// The offending sequence.
        seq: u64,
    },
}

/// The per-subscriber delivery engine. Volatile fields die with a
/// crash; [`DurableDeliveryState`] survives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryEngine {
    plan: DeliveryPlan,
    durable: DurableDeliveryState,
    /// The item currently exposing (volatile).
    exposing: Option<u64>,
    /// Set when recovery classified DeliveryUncertain and no resolution
    /// has been applied yet (volatile but re-derivable from durable
    /// state at every recovery).
    unresolved_uncertain: Option<u64>,
}

impl DeliveryEngine {
    /// A fresh engine at the start of delivery.
    #[must_use]
    pub fn new(plan: DeliveryPlan) -> Self {
        Self {
            plan,
            durable: DurableDeliveryState::default(),
            exposing: None,
            unresolved_uncertain: None,
        }
    }

    fn next_seq(&self) -> u64 {
        self.durable.acked_frontier + 1
    }

    fn guard_uncertain(&self) -> Result<(), DeliveryError> {
        match self.unresolved_uncertain {
            Some(seq) => Err(DeliveryError::UncertainUnresolved { seq }),
            None => Ok(()),
        }
    }

    /// Durably record the stateful commit intent for the NEXT item —
    /// the write-ahead step that must precede its first visible effect.
    ///
    /// # Errors
    /// Typed [`DeliveryError`]; nothing is recorded on refusal.
    pub fn record_intent(&mut self, seq: u64) -> Result<(), DeliveryError> {
        self.guard_uncertain()?;
        if seq != self.next_seq() {
            return Err(DeliveryError::NotNextItem {
                expected: self.next_seq(),
            });
        }
        match self.plan.kind(seq) {
            None => return Err(DeliveryError::UnknownSequence { seq }),
            Some(DeliveryItemKind::StatefulWrite) => {}
            Some(_) => return Err(DeliveryError::NotAStatefulItem { seq }),
        }
        self.durable.intents.insert(seq);
        Ok(())
    }

    /// Expose the next item: the visible effect lands in `world`. For
    /// stateful items the intent must already be durably recorded.
    ///
    /// # Errors
    /// Typed [`DeliveryError`]; no effect lands on refusal.
    pub fn begin_expose(
        &mut self,
        seq: u64,
        world: &mut VisibleWorld,
    ) -> Result<(), DeliveryError> {
        self.guard_uncertain()?;
        if let Some(exposing) = self.exposing {
            return Err(DeliveryError::AlreadyExposing { exposing });
        }
        if seq != self.next_seq() {
            return Err(DeliveryError::NotNextItem {
                expected: self.next_seq(),
            });
        }
        let kind = self
            .plan
            .kind(seq)
            .ok_or(DeliveryError::UnknownSequence { seq })?;
        if kind == DeliveryItemKind::StatefulWrite && !self.durable.intents.contains(&seq) {
            // The I43 order violation: a visible effect before the
            // durable intent would make a crash unclassifiable.
            return Err(DeliveryError::IntentNotRecorded { seq });
        }
        self.exposing = Some(seq);
        world.exposed.push(seq);
        Ok(())
    }

    /// Full-write acknowledgement: the wrapper confirms COMPLETE
    /// exposure; the frontier advances exactly one item.
    ///
    /// # Errors
    /// Typed [`DeliveryError`].
    pub fn ack(&mut self, seq: u64) -> Result<(), DeliveryError> {
        self.guard_uncertain()?;
        if self.exposing != Some(seq) {
            return Err(DeliveryError::NotExposing { seq });
        }
        self.exposing = None;
        self.durable.acked_frontier = seq;
        Ok(())
    }

    /// Crash: volatile state dies; the durable slice is all that
    /// remains. Returns the recovered engine (a restarted edge).
    #[must_use]
    pub fn crash(&self) -> Self {
        let mut recovered = Self {
            plan: self.plan.clone(),
            durable: self.durable.clone(),
            exposing: None,
            unresolved_uncertain: None,
        };
        if let RecoveryClass::DeliveryUncertain { seq } = recovered.classify() {
            recovered.unresolved_uncertain = Some(seq);
        }
        recovered
    }

    /// Classify recovery state from durable truth alone.
    #[must_use]
    pub fn classify(&self) -> RecoveryClass {
        if self.durable.acked_frontier >= self.plan.len() {
            return RecoveryClass::Complete;
        }
        let next = self.next_seq();
        if self.durable.intents.contains(&next) {
            // Intent durably recorded, no ack: the uncertain interval.
            RecoveryClass::DeliveryUncertain { seq: next }
        } else {
            RecoveryClass::CleanResume { next_seq: next }
        }
    }

    /// Resolve the DeliveryUncertain state with a destination
    /// inspection. An effect that landed completes the item WITHOUT
    /// re-exposure; an absent effect clears the block so the item can
    /// re-expose under its already-recorded intent.
    ///
    /// # Errors
    /// [`DeliveryError::NothingUncertain`] when no resolution is due.
    pub fn resolve_uncertain(
        &mut self,
        inspection: DestinationInspection,
    ) -> Result<(), DeliveryError> {
        let seq = self
            .unresolved_uncertain
            .take()
            .ok_or(DeliveryError::NothingUncertain)?;
        match inspection {
            DestinationInspection::EffectLanded => {
                // The write completed; only the acknowledgement was
                // lost. Advance without touching the destination again
                // (re-exposing would double-apply, R97).
                self.durable.acked_frontier = seq;
            }
            DestinationInspection::EffectAbsent => {
                // Intent stands; the loop may expose it now.
            }
        }
        Ok(())
    }

    /// `DeliveryComplete`: terminal item acknowledged — which, because
    /// the plan puts the terminal last and acks are strictly
    /// sequential, implies every owned output was delivered first.
    #[must_use]
    pub fn delivery_complete(&self) -> bool {
        self.durable.acked_frontier >= self.plan.len()
    }

    /// The C005 frontier report for this subscriber's stateful lane.
    /// Sticky by construction: any recorded intent keeps the stateful
    /// signal raised until delivery completes, and an unresolved
    /// uncertain interval raises the uncertainty flag — driving
    /// `decide_fallback` to refuse uncoordinated local fallback under
    /// EVERY configuration (I43/R97).
    #[must_use]
    pub fn frontier_report(&self) -> SubscriberFrontierReport {
        SubscriberFrontierReport {
            transcript_exposed: self.durable.acked_frontier > 0,
            transcript_uncertain: false,
            stateful_intent_recorded: !self.durable.intents.is_empty(),
            stateful_uncertain: self.unresolved_uncertain.is_some(),
            last_fully_delivered_seq: self.durable.acked_frontier,
        }
    }
    /// The acknowledged frontier: items `1..=n` are fully exposed AND
    /// acknowledged (read view for the wire layer).
    #[must_use]
    pub fn acked_frontier(&self) -> u64 {
        self.durable.acked_frontier
    }

    /// The terminal (last) sequence of the validated plan.
    #[must_use]
    pub fn terminal_seq(&self) -> u64 {
        self.plan.len()
    }
}

/// Local-protocol messages for the stateful lane (bead J031; risk
/// R124): the concrete wire mirror of the C019 engine's intent /
/// acknowledgement / uncertainty / completion states. The four are
/// DELIBERATELY distinct message shapes — no message conflates intent,
/// acknowledgement, uncertainty, or completion — so a reconnect
/// fixture (T046) interprets each by its constructor alone:
///
/// - [`StatefulLaneMessage::SubscriberStatefulCommitIntent`] rides
///   BEFORE any visible effect (the I43 write-ahead order, on the
///   wire);
/// - [`StatefulLaneMessage::SubscriberStatefulAcknowledged`] is a
///   full-write acknowledgement of COMPLETE exposure only;
/// - [`StatefulLaneMessage::SubscriberStatefulDeliveryUncertain`] is
///   the reconnect carrier of the uncertain interval — it asserts a
///   frontier and names at most ONE possibly-landed item;
/// - [`StatefulLaneMessage::SubscriberDeliveryComplete`] exists only
///   after the terminal item is acknowledged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatefulLaneMessage {
    /// Edge → wrapper: the write-ahead commit-intent header for the
    /// next stateful item. Its arrival precedes every visible effect
    /// for that sequence (I43).
    SubscriberStatefulCommitIntent {
        /// The sequence whose commit is intended.
        seq: u64,
    },
    /// Wrapper → edge: full-write acknowledgement — the item's effect
    /// is COMPLETE and visible; nothing partial is ever acknowledged.
    SubscriberStatefulAcknowledged {
        /// The fully delivered sequence.
        seq: u64,
    },
    /// Wrapper → edge on reconnect: last fully acknowledged frontier
    /// plus the one item that may have landed without its ack landing
    /// (the C019 uncertain interval). Resolution is the edge's job via
    /// destination inspection — never a blind replay (R97).
    SubscriberStatefulDeliveryUncertain {
        /// Last fully acknowledged sequence.
        last_acked_seq: u64,
        /// The item in the uncertain interval, if any.
        uncertain_seq: Option<u64>,
    },
    /// Edge → wrapper: the delivery is COMPLETE — terminal item
    /// acknowledged, therefore (plan order) every owned output
    /// delivered. No other message implies completion.
    SubscriberDeliveryComplete {
        /// The terminal (last) sequence of the plan.
        last_seq: u64,
    },
}

/// Edge-side outcome of applying a wrapper stateful acknowledgement —
/// the J012 idempotency doctrine mirrored onto this lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatefulAckOutcome {
    /// The exposing item was acknowledged; the frontier advanced one.
    Acknowledged,
    /// A duplicate ack for an already-acknowledged item: no-op.
    AlreadyAcknowledged,
    /// An ack for an item the lane is not currently exposing (never
    /// sent, already resolved otherwise, or skipping ahead): refused,
    /// nothing changes.
    RefusedNotExposing {
        /// The sequence the loop expects next.
        expected: u64,
    },
}

/// Apply a wrapper `SubscriberStatefulAcknowledged` to the edge
/// engine: duplicates are harmless no-ops, anything the lane is not
/// mid-exposing refuses typed with the expected sequence.
///
/// # Errors
/// Never returns `Err`; refusals are values in
/// [`StatefulAckOutcome`] (the caller reports them on the wire).
pub fn edge_apply_stateful_ack(
    engine: &mut DeliveryEngine,
    seq: u64,
) -> Result<StatefulAckOutcome, std::convert::Infallible> {
    if seq <= engine.acked_frontier() {
        return Ok(StatefulAckOutcome::AlreadyAcknowledged);
    }
    match engine.ack(seq) {
        Ok(()) => Ok(StatefulAckOutcome::Acknowledged),
        Err(DeliveryError::NotExposing { .. }) => Ok(StatefulAckOutcome::RefusedNotExposing {
            expected: engine.acked_frontier() + 1,
        }),
        // Unreachable for a non-uncertain engine above the frontier:
        // `ack` refuses only NotExposing here. Kept total anyway.
        Err(_) => Ok(StatefulAckOutcome::RefusedNotExposing {
            expected: engine.acked_frontier() + 1,
        }),
    }
}

/// Build the wrapper's reconnect message from the durable truth (the
/// wire form of [`DeliveryEngine::classify`]): the acknowledged
/// frontier plus at most one uncertain item.
#[must_use]
pub fn wrapper_uncertainty_message(engine: &DeliveryEngine) -> StatefulLaneMessage {
    let last_acked_seq = engine.acked_frontier();
    let uncertain_seq = match engine.classify() {
        RecoveryClass::DeliveryUncertain { seq } => Some(seq),
        _ => None,
    };
    StatefulLaneMessage::SubscriberStatefulDeliveryUncertain {
        last_acked_seq,
        uncertain_seq,
    }
}

/// The completion message, exactly when the terminal item is
/// acknowledged — `None` before, so completion can never be implied
/// early.
#[must_use]
pub fn edge_complete_message(engine: &DeliveryEngine) -> Option<StatefulLaneMessage> {
    let last_seq = engine.terminal_seq();
    engine
        .delivery_complete()
        .then_some(StatefulLaneMessage::SubscriberDeliveryComplete { last_seq })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_protocol::{FallbackAction, FallbackConfig, decide_fallback};

    fn mixed_plan() -> DeliveryPlan {
        DeliveryPlan::new(vec![
            DeliveryItemKind::Transcript,
            DeliveryItemKind::StatefulWrite,
            DeliveryItemKind::Transcript,
            DeliveryItemKind::StatefulWrite,
            DeliveryItemKind::Terminal,
        ])
        .unwrap()
    }

    /// One primitive delivery event in the scripted happy path.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Event {
        Intent(u64),
        Expose(u64),
        Ack(u64),
    }

    fn script(plan: &DeliveryPlan) -> Vec<Event> {
        let mut events = Vec::new();
        for seq in 1..=plan.len() {
            if plan.kind(seq) == Some(DeliveryItemKind::StatefulWrite) {
                events.push(Event::Intent(seq));
            }
            events.push(Event::Expose(seq));
            events.push(Event::Ack(seq));
        }
        events
    }

    fn apply(engine: &mut DeliveryEngine, world: &mut VisibleWorld, event: Event) {
        match event {
            Event::Intent(seq) => engine.record_intent(seq).unwrap(),
            Event::Expose(seq) => engine.begin_expose(seq, world).unwrap(),
            Event::Ack(seq) => engine.ack(seq).unwrap(),
        }
    }

    /// Drive a recovered engine to completion, resolving uncertainty
    /// truthfully from the world. Returns re-exposure count.
    fn finish(engine: &mut DeliveryEngine, world: &mut VisibleWorld) {
        if let Some(seq) = engine.unresolved_uncertain {
            // Fail-closed first: blind replay and acks refuse.
            assert_eq!(
                engine.begin_expose(seq, world),
                Err(DeliveryError::UncertainUnresolved { seq }),
                "blind replay must refuse before resolution"
            );
            assert_eq!(
                engine.ack(seq),
                Err(DeliveryError::UncertainUnresolved { seq }),
                "blind ack must refuse before resolution"
            );
            // And the fallback decision is reconnect-or-fail under
            // every configuration while uncertain (R97).
            for config in [
                FallbackConfig::default(),
                FallbackConfig {
                    labeled_transcript_recovery: true,
                },
            ] {
                assert!(matches!(
                    decide_fallback(&engine.frontier_report(), &config, 1),
                    FallbackAction::ReconnectOrFailCoherently { .. }
                ));
            }
            engine.resolve_uncertain(world.inspect(seq)).unwrap();
        }
        // Iterative replay: intent (if missing), expose, ack, item by
        // item, exactly as the first pass would.
        while !engine.delivery_complete() {
            let (RecoveryClass::CleanResume { next_seq }
            | RecoveryClass::DeliveryUncertain { seq: next_seq }) = engine.classify()
            else {
                break;
            };
            if engine.plan.kind(next_seq) == Some(DeliveryItemKind::StatefulWrite)
                && !engine.durable.intents.contains(&next_seq)
            {
                engine.record_intent(next_seq).unwrap();
            }
            engine.begin_expose(next_seq, world).unwrap();
            engine.ack(next_seq).unwrap();
        }
    }

    #[test]
    fn c019_crash_at_every_delivery_boundary_is_exactly_once() {
        // THE acceptance fixture (feeds T031/T036): run the scripted
        // delivery, crash after every prefix of primitive events,
        // recover, resolve truthfully, finish — every visible effect
        // must land EXACTLY once, and completion must always be
        // reachable.
        let plan = mixed_plan();
        let events = script(&plan);
        for kill_at in 0..=events.len() {
            let mut engine = DeliveryEngine::new(plan.clone());
            let mut world = VisibleWorld::default();
            for event in &events[..kill_at] {
                apply(&mut engine, &mut world, *event);
            }
            let mut recovered = engine.crash();
            // The uncertain classification appears EXACTLY when the
            // killed prefix left a stateful item intent-recorded,
            // possibly-exposed, but unacked.
            let next = recovered.durable.acked_frontier + 1;
            let expect_uncertain = recovered.durable.intents.contains(&next) && next <= plan.len();
            assert_eq!(
                matches!(
                    recovered.classify(),
                    RecoveryClass::DeliveryUncertain { .. }
                ),
                expect_uncertain,
                "kill_at={kill_at}"
            );
            finish(&mut recovered, &mut world);
            assert!(recovered.delivery_complete(), "kill_at={kill_at}");
            // STATEFUL effects land EXACTLY once at every kill point —
            // that is the C019 guarantee (R97). An unacked transcript
            // frame may be re-sent on resume (the wrapper's C014
            // framing discipline dedups it; a partial frame was never
            // exposed), so transcripts assert at-least-once + coverage.
            for seq in 1..=plan.len() {
                let count = world.exposed.iter().filter(|s| **s == seq).count();
                match plan.kind(seq).unwrap() {
                    DeliveryItemKind::StatefulWrite => assert_eq!(
                        count, 1,
                        "kill_at={kill_at}: stateful effect {seq} must land exactly once"
                    ),
                    DeliveryItemKind::Transcript | DeliveryItemKind::Terminal => {
                        assert!(count >= 1, "kill_at={kill_at}: item {seq} lost")
                    }
                }
            }
            // Exposure order is nondecreasing: a resume never reaches
            // back before the frontier.
            assert!(
                world.exposed.windows(2).all(|w| w[0] <= w[1]),
                "kill_at={kill_at}: out-of-order exposure {:?}",
                world.exposed
            );
        }
    }

    #[test]
    fn write_ahead_order_is_enforced() {
        let mut engine = DeliveryEngine::new(mixed_plan());
        let mut world = VisibleWorld::default();
        // Item 1 (transcript) needs no intent.
        engine.begin_expose(1, &mut world).unwrap();
        engine.ack(1).unwrap();
        // Item 2 is stateful: exposure BEFORE intent is the I43
        // violation and refuses without any visible effect.
        assert_eq!(
            engine.begin_expose(2, &mut world),
            Err(DeliveryError::IntentNotRecorded { seq: 2 })
        );
        assert_eq!(world.exposed, vec![1], "refusal must not expose");
        engine.record_intent(2).unwrap();
        engine.begin_expose(2, &mut world).unwrap();
        engine.ack(2).unwrap();
        assert_eq!(world.exposed, vec![1, 2]);
    }

    #[test]
    fn delivery_is_strictly_iterative_with_ack_after_each() {
        let mut engine = DeliveryEngine::new(mixed_plan());
        let mut world = VisibleWorld::default();
        // Skipping ahead refuses.
        assert_eq!(
            engine.begin_expose(3, &mut world),
            Err(DeliveryError::NotNextItem { expected: 1 })
        );
        engine.begin_expose(1, &mut world).unwrap();
        // A second exposure while one is unacked refuses.
        assert_eq!(
            engine.begin_expose(1, &mut world),
            Err(DeliveryError::AlreadyExposing { exposing: 1 })
        );
        // Acking something else refuses.
        assert_eq!(engine.ack(2), Err(DeliveryError::NotExposing { seq: 2 }));
        engine.ack(1).unwrap();
    }

    #[test]
    fn landed_effect_completes_without_reexposure() {
        // Crash after the stateful effect landed but before the ack:
        // inspection says landed; the item completes with NO second
        // visible effect.
        let mut engine = DeliveryEngine::new(mixed_plan());
        let mut world = VisibleWorld::default();
        engine.begin_expose(1, &mut world).unwrap();
        engine.ack(1).unwrap();
        engine.record_intent(2).unwrap();
        engine.begin_expose(2, &mut world).unwrap();
        // ...ack lost in the crash.
        let mut recovered = engine.crash();
        assert_eq!(
            recovered.classify(),
            RecoveryClass::DeliveryUncertain { seq: 2 }
        );
        recovered.resolve_uncertain(world.inspect(2)).unwrap();
        assert_eq!(recovered.durable.acked_frontier, 2, "landed = acked");
        assert_eq!(
            world.exposed.iter().filter(|s| **s == 2).count(),
            1,
            "no re-exposure of a landed effect"
        );
    }

    #[test]
    fn delivery_complete_requires_terminal_and_all_outputs() {
        let plan = mixed_plan();
        let mut engine = DeliveryEngine::new(plan.clone());
        let mut world = VisibleWorld::default();
        for seq in 1..plan.len() {
            if plan.kind(seq) == Some(DeliveryItemKind::StatefulWrite) {
                engine.record_intent(seq).unwrap();
            }
            engine.begin_expose(seq, &mut world).unwrap();
            engine.ack(seq).unwrap();
            assert!(
                !engine.delivery_complete(),
                "complete before the terminal item is a lie"
            );
        }
        engine.begin_expose(plan.len(), &mut world).unwrap();
        engine.ack(plan.len()).unwrap();
        assert!(engine.delivery_complete());
        assert_eq!(engine.classify(), RecoveryClass::Complete);
    }

    #[test]
    fn plans_require_exactly_one_terminal_last() {
        assert_eq!(DeliveryPlan::new(vec![]), Err(PlanError::Empty));
        assert_eq!(
            DeliveryPlan::new(vec![DeliveryItemKind::Transcript]),
            Err(PlanError::MissingTerminal)
        );
        assert_eq!(
            DeliveryPlan::new(vec![
                DeliveryItemKind::Terminal,
                DeliveryItemKind::StatefulWrite,
            ]),
            Err(PlanError::TerminalNotLast)
        );
        assert_eq!(
            DeliveryPlan::new(vec![DeliveryItemKind::Terminal, DeliveryItemKind::Terminal,]),
            Err(PlanError::TerminalNotLast)
        );
        // Resolution with nothing uncertain is a typed refusal too.
        let mut engine = DeliveryEngine::new(mixed_plan());
        assert_eq!(
            engine.resolve_uncertain(DestinationInspection::EffectLanded),
            Err(DeliveryError::NothingUncertain)
        );
    }
    // -----------------------------------------------------------------
    // J031: the stateful lane's WIRE messages. No message conflates
    // intent, acknowledgement, uncertainty, or completion (R124), and
    // reconnect fixtures interpret each by its constructor alone.
    // -----------------------------------------------------------------

    fn transcript_stateful_terminal_plan() -> DeliveryPlan {
        DeliveryPlan::new(vec![
            DeliveryItemKind::Transcript,
            DeliveryItemKind::StatefulWrite,
            DeliveryItemKind::Terminal,
        ])
        .expect("valid plan")
    }

    #[test]
    fn intent_ack_and_completion_are_distinct_wire_events() {
        let mut engine = DeliveryEngine::new(transcript_stateful_terminal_plan());
        let mut world = VisibleWorld::default();

        // Completion is NEVER implied before the terminal ack — not by
        // intents, not by frontier progress.
        assert_eq!(edge_complete_message(&engine), None);

        // seq 1 is a TRANSCRIPT item: it needs NO commit intent (the
        // stateful lane must not conflate lanes either).
        engine.begin_expose(1, &mut world).expect("exposes");
        assert_eq!(
            edge_apply_stateful_ack(&mut engine, 1),
            Ok(StatefulAckOutcome::Acknowledged)
        );
        assert_eq!(edge_complete_message(&engine), None);

        // seq 2 IS stateful: its CommitIntent arrives BEFORE any
        // visible effect (I43 on the wire).
        engine.record_intent(2).expect("stateful item takes intent");
        engine.begin_expose(2, &mut world).expect("exposes");
        assert_eq!(edge_complete_message(&engine), None);
        assert_eq!(
            edge_apply_stateful_ack(&mut engine, 2),
            Ok(StatefulAckOutcome::Acknowledged)
        );

        // Only the TERMINAL acknowledgement completes — and then the
        // completion message names exactly the last sequence.
        engine.begin_expose(3, &mut world).expect("exposes");
        assert_eq!(
            edge_apply_stateful_ack(&mut engine, 3),
            Ok(StatefulAckOutcome::Acknowledged)
        );
        assert_eq!(
            edge_complete_message(&engine),
            Some(StatefulLaneMessage::SubscriberDeliveryComplete { last_seq: 3 })
        );
    }

    #[test]
    fn duplicate_stateful_acks_are_idempotent_no_ops() {
        let mut engine = DeliveryEngine::new(transcript_stateful_terminal_plan());
        let mut world = VisibleWorld::default();
        engine.begin_expose(1, &mut world).expect("exposes");
        assert_eq!(
            edge_apply_stateful_ack(&mut engine, 1),
            Ok(StatefulAckOutcome::Acknowledged)
        );
        // The replayed ack: harmless, and the frontier did not move.
        assert_eq!(
            edge_apply_stateful_ack(&mut engine, 1),
            Ok(StatefulAckOutcome::AlreadyAcknowledged)
        );
        assert_eq!(engine.acked_frontier(), 1);
        // A post-completion replay of the terminal ack behaves the
        // same once delivery finished.
        engine.record_intent(2).expect("intents");
        engine.begin_expose(2, &mut world).expect("exposes");
        edge_apply_stateful_ack(&mut engine, 2).expect("acks");
        engine.begin_expose(3, &mut world).expect("exposes");
        edge_apply_stateful_ack(&mut engine, 3).expect("acks");
        assert_eq!(
            edge_apply_stateful_ack(&mut engine, 3),
            Ok(StatefulAckOutcome::AlreadyAcknowledged)
        );
    }

    #[test]
    fn an_ack_for_an_item_not_being_exposed_refuses_with_the_expectation() {
        let mut engine = DeliveryEngine::new(transcript_stateful_terminal_plan());
        let mut world = VisibleWorld::default();
        // Nothing exposed yet: an ack for seq 1 refuses, naming what
        // the loop expected — it never advances anything.
        assert_eq!(
            edge_apply_stateful_ack(&mut engine, 1),
            Ok(StatefulAckOutcome::RefusedNotExposing { expected: 1 })
        );
        assert_eq!(engine.acked_frontier(), 0);
        // Skipping ahead past a live exposure refuses too.
        engine.begin_expose(1, &mut world).expect("exposes");
        assert_eq!(
            edge_apply_stateful_ack(&mut engine, 2),
            Ok(StatefulAckOutcome::RefusedNotExposing { expected: 1 })
        );
        assert_eq!(engine.acked_frontier(), 0);
    }

    #[test]
    fn reconnect_uncertainty_is_interpreted_without_conflation() {
        let mut world = VisibleWorld::default();
        let mut engine = DeliveryEngine::new(transcript_stateful_terminal_plan());
        engine.begin_expose(1, &mut world).expect("exposes");
        edge_apply_stateful_ack(&mut engine, 1).expect("acks");
        // Intent recorded, effect visible, ack NOT yet arrived: crash.
        engine.record_intent(2).expect("intents");
        engine.begin_expose(2, &mut world).expect("effect lands");

        let recovered = engine.crash();
        // The wrapper's reconnect report carries EXACTLY the uncertain
        // interval — a frontier plus at most one possibly-landed item,
        // never an implied completion or a fabricated intent.
        assert_eq!(
            wrapper_uncertainty_message(&recovered),
            StatefulLaneMessage::SubscriberStatefulDeliveryUncertain {
                last_acked_seq: 1,
                uncertain_seq: Some(2),
            }
        );
        // The report is PURE: asking twice answers identically and
        // mutates nothing (no blind replay may hide in a report).
        assert_eq!(
            wrapper_uncertainty_message(&recovered),
            wrapper_uncertainty_message(&recovered)
        );

        // Destination inspection resolves the interval; each answer is
        // interpreted per ITS meaning only:
        let mut landed = recovered.clone();
        landed
            .resolve_uncertain(world.inspect(2))
            .expect("resolves");
        // Landed ⇒ completed WITHOUT re-exposure (only the ack was
        // lost): the world shows ONE exposure for seq 2.
        assert_eq!(landed.acked_frontier(), 2);
        assert_eq!(
            world.exposed.iter().filter(|s| **s == 2).count(),
            1,
            "EffectLanded must not double-apply (R97)"
        );

        // The ABSENT twin: a separate engine crashed AFTER the intent
        // but BEFORE any effect — same uncertain interval on the wire,
        // opposite destination truth.
        let mut absent_world = VisibleWorld::default();
        let mut pre_effect = DeliveryEngine::new(transcript_stateful_terminal_plan());
        pre_effect
            .begin_expose(1, &mut absent_world)
            .expect("exposes");
        edge_apply_stateful_ack(&mut pre_effect, 1).expect("acks");
        pre_effect.record_intent(2).expect("intents");
        let absent = pre_effect.crash();
        assert_eq!(
            wrapper_uncertainty_message(&absent),
            StatefulLaneMessage::SubscriberStatefulDeliveryUncertain {
                last_acked_seq: 1,
                uncertain_seq: Some(2),
            },
            "same wire shape — the DESTINATION decides the meaning"
        );
        assert_eq!(absent_world.inspect(2), DestinationInspection::EffectAbsent);
        let mut absent = absent;
        absent
            .resolve_uncertain(absent_world.inspect(2))
            .expect("resolves");
        // Absent ⇒ re-exposure under the ALREADY-recorded intent.
        absent
            .begin_expose(2, &mut absent_world)
            .expect("re-exposes");
        assert_eq!(
            edge_apply_stateful_ack(&mut absent, 2),
            Ok(StatefulAckOutcome::Acknowledged)
        );
        assert_eq!(absent.acked_frontier(), 2);
    }

    #[test]
    fn completion_is_never_emitted_early_even_after_full_frontier_minus_one() {
        let mut engine = DeliveryEngine::new(transcript_stateful_terminal_plan());
        let mut world = VisibleWorld::default();
        engine.begin_expose(1, &mut world).expect("exposes");
        edge_apply_stateful_ack(&mut engine, 1).expect("acks");
        engine.record_intent(2).expect("intents");
        engine.begin_expose(2, &mut world).expect("exposes");
        edge_apply_stateful_ack(&mut engine, 2).expect("acks");
        // Everything but the terminal is acknowledged: still no
        // completion message — SubscriberDeliveryComplete exists ONLY
        // behind the terminal ack.
        assert_eq!(engine.acked_frontier(), 2);
        assert_eq!(edge_complete_message(&engine), None);
    }
}
