//! Client disconnect = subscriber cancellation; shared work survives
//! (bead C011; invariant I6).
//!
//! One action, N subscribers: wrappers that intercepted the same
//! command share a single execution. A wrapper that goes away — clean
//! UDS disconnect, explicit release, or a SIGKILLed process detected
//! from UDS/PID liveness — loses exactly ITS OWN retained interest and
//! its delivery obligation closes; the shared action keeps running
//! while ANY retained interest remains. Only when the LAST interest
//! releases does the registry report that the scheduler may cancel the
//! shared work.
//!
//! This is the pure registry core: sockets, poll loops, and PID
//! probing live in the edge daemon; liveness arrives here as evidence
//! (a predicate over recorded PIDs), never as guesswork. The lab
//! acceptance `cancel_one_subscriber_shared_action_survives` is a test
//! below.

use std::collections::BTreeMap;

/// Why a subscriber's interest ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectCause {
    /// The wrapper's UDS connection closed.
    UdsDisconnect,
    /// The wrapper process is gone (SIGKILL — detected from UDS/PID
    /// liveness, the wrapper never got to say goodbye).
    ProcessDead,
    /// The wrapper explicitly released its interest.
    ExplicitRelease,
    /// The wrapper received a catchable termination signal and
    /// forwarded its own cancellation before dying by it (C016).
    Signal(WrapperSignal),
    /// The wrapper's parent died (PDEATHSIG or platform equivalent).
    ParentDeath,
}

/// The catchable termination signals the wrapper maps exactly (C016).
/// SIGKILL is uncatchable by definition — it arrives here as
/// [`DisconnectCause::ProcessDead`] via the liveness sweep instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperSignal {
    /// SIGINT (Ctrl-C).
    Interrupt,
    /// SIGTERM.
    Terminate,
    /// SIGHUP (controlling terminal gone).
    Hangup,
}

impl WrapperSignal {
    /// The POSIX signal number — the EXACT number stock Cargo would
    /// die by, so observers cannot tell the wrapper from the real
    /// thing.
    #[must_use]
    pub const fn number(self) -> i32 {
        match self {
            Self::Hangup => 1,
            Self::Interrupt => 2,
            Self::Terminate => 15,
        }
    }

    /// The wait-status exit code an observing shell reports
    /// (`128 + N`) — the signal-vs-exit classification the wrapper
    /// must preserve.
    #[must_use]
    pub const fn observed_exit_code(self) -> i32 {
        128 + self.number()
    }
}

/// What ends a wrapper's participation, as observed at the wrapper
/// (signals, parent death) or at the edge (disconnect, liveness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationTrigger {
    /// A catchable termination signal was delivered to the wrapper.
    Signal(WrapperSignal),
    /// The wrapper's parent died (delivered as the configured
    /// PDEATHSIG, conventionally SIGTERM, or the platform equivalent).
    ParentDeath,
    /// The edge observed the wrapper's UDS connection close.
    UdsDisconnect,
    /// The edge's liveness sweep found the wrapper's PID gone
    /// (SIGKILL — nothing was catchable).
    ProcessDead,
    /// The wrapper completed normally and released its interest.
    ExplicitRelease,
}

/// How the wrapper process itself must end after forwarding its
/// cancellation — the EXACT stock classification (I6/C016): a signal
/// death stays a signal death, an exit stays an exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperFate {
    /// Re-raise the SAME signal with the default disposition restored,
    /// so the parent observes death-by-signal (`128 + N`), exactly as
    /// stock Cargo would have died.
    DieBySignal(WrapperSignal),
    /// Exit normally with the build's own exit code.
    ExitWithBuildCode,
    /// The wrapper process is not ours to end (the trigger was
    /// observed at the edge; the process is already gone or detached).
    NotOurProcess,
}

/// The C016 exact mapping: trigger → (registry release cause, wrapper
/// fate). One table, no per-call judgment.
#[must_use]
pub const fn map_cancellation(trigger: CancellationTrigger) -> (DisconnectCause, WrapperFate) {
    match trigger {
        CancellationTrigger::Signal(signal) => (
            DisconnectCause::Signal(signal),
            // Forward cancellation FIRST, then die by the same signal:
            // the observer's signal-vs-exit view is byte-identical to
            // stock.
            WrapperFate::DieBySignal(signal),
        ),
        CancellationTrigger::ParentDeath => (
            DisconnectCause::ParentDeath,
            // PDEATHSIG delivers SIGTERM (the configured convention):
            // the orphaned wrapper dies by it after forwarding.
            WrapperFate::DieBySignal(WrapperSignal::Terminate),
        ),
        CancellationTrigger::UdsDisconnect => {
            (DisconnectCause::UdsDisconnect, WrapperFate::NotOurProcess)
        }
        CancellationTrigger::ProcessDead => {
            (DisconnectCause::ProcessDead, WrapperFate::NotOurProcess)
        }
        CancellationTrigger::ExplicitRelease => (
            DisconnectCause::ExplicitRelease,
            WrapperFate::ExitWithBuildCode,
        ),
    }
}

/// How the wrapped tool ended, read from its wait status — locally, or
/// relayed over the protocol when the tool ran on a worker (C024).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildTermination {
    /// Normal exit with a code.
    Exited(i32),
    /// Killed by a signal (ANY signal — including SIGKILL and SIGSEGV,
    /// which the wrapper only ever observes in the CHILD's status).
    Signaled {
        /// The terminating signal number.
        signal_number: i32,
    },
}

/// What the wrapper does to relay the child's termination so Cargo
/// observes semantics IDENTICAL to stock (C024): an exit stays an
/// exit with the same code; a signal death stays a signal death by
/// the same signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAction {
    /// Exit with the child's own code, unchanged.
    ExitWith(i32),
    /// Restore the DEFAULT disposition for the signal, then raise it
    /// on the wrapper itself — the wrapper dies by the same signal and
    /// Cargo's wait status is byte-identical to stock.
    RestoreDefaultAndResignal {
        /// The signal to die by.
        signal_number: i32,
    },
    /// Platform without re-signal support: the DOCUMENTED
    /// approximation — exit with the shell-conventional `128 + N`.
    /// Cargo sees the right number but an exit, not a signal; the
    /// approximation is named, never silent.
    ExitWithConventionalCode(i32),
}

/// The C024 relay decision. `resignal_supported` is the platform
/// capability (true on Unix).
#[must_use]
pub const fn relay_child_termination(
    termination: ChildTermination,
    resignal_supported: bool,
) -> RelayAction {
    match termination {
        ChildTermination::Exited(code) => RelayAction::ExitWith(code),
        ChildTermination::Signaled { signal_number } => {
            if resignal_supported {
                RelayAction::RestoreDefaultAndResignal { signal_number }
            } else {
                RelayAction::ExitWithConventionalCode(128 + signal_number)
            }
        }
    }
}

/// Whether the SHARED attempt may be cancelled after a release — the
/// reference-counted policy (I6): never because one subscriber left,
/// only when NO retained interest remains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptCancellation {
    /// Retained interest remains: the shared attempt keeps running.
    NotPermitted {
        /// Interests still retained.
        retained: usize,
    },
    /// The last interest released: cancelling the shared attempt is
    /// now permitted.
    PermittedNow,
}

impl ReleaseOutcome {
    /// The refcounted shared-attempt cancellation decision this
    /// release yields.
    #[must_use]
    pub const fn attempt_cancellation(&self) -> AttemptCancellation {
        match self.disposition {
            ActionDisposition::SurvivesWithRemaining { retained } => {
                AttemptCancellation::NotPermitted { retained }
            }
            ActionDisposition::LastInterestReleased => AttemptCancellation::PermittedNow,
        }
    }
}

/// What the shared action looks like after one interest ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionDisposition {
    /// Retained interest remains: the shared action SURVIVES (I6).
    SurvivesWithRemaining {
        /// Interests still retained.
        retained: usize,
    },
    /// The last interest released: the scheduler MAY now cancel or
    /// park the shared work (its decision, reported here).
    LastInterestReleased,
}

/// Typed registry refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterestError {
    /// The subscriber is already registered (a second registration
    /// under the same id would double-count interest).
    AlreadyRegistered {
        /// The duplicate id.
        subscriber: u128,
    },
    /// No such retained interest (already released or never
    /// registered) — the repeat release is reported as a no-op by
    /// [`SharedActionInterest::release`], this error is for lookups.
    UnknownSubscriber {
        /// The unknown id.
        subscriber: u128,
    },
}

/// One subscriber's registered connection evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SubscriberConn {
    /// Wrapper PID recorded at admission (liveness evidence key).
    pid: u32,
    /// Whether this subscriber's delivery obligation is still open.
    obligation_open: bool,
}

/// Result of a release: what closed, and what the action does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseOutcome {
    /// Whether an interest actually released (false = idempotent
    /// repeat: nothing was retained under that id).
    pub released: bool,
    /// Whether that subscriber's delivery obligation closed with it.
    pub obligation_closed: bool,
    /// The cause recorded for the release.
    pub cause: DisconnectCause,
    /// The shared action's disposition afterward.
    pub disposition: ActionDisposition,
}

/// The per-action interest registry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedActionInterest {
    subscribers: BTreeMap<u128, SubscriberConn>,
}

impl SharedActionInterest {
    /// An action with no subscribers yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a subscriber's retained interest (with its PID as
    /// liveness evidence).
    ///
    /// # Errors
    /// [`InterestError::AlreadyRegistered`] on a duplicate id.
    pub fn register(&mut self, subscriber: u128, pid: u32) -> Result<(), InterestError> {
        if self.subscribers.contains_key(&subscriber) {
            return Err(InterestError::AlreadyRegistered { subscriber });
        }
        self.subscribers.insert(
            subscriber,
            SubscriberConn {
                pid,
                obligation_open: true,
            },
        );
        Ok(())
    }

    /// Retained interests.
    #[must_use]
    pub fn retained(&self) -> usize {
        self.subscribers.len()
    }

    /// Whether a subscriber's delivery obligation is open.
    ///
    /// # Errors
    /// [`InterestError::UnknownSubscriber`] when no interest is
    /// retained under the id.
    pub fn obligation_open(&self, subscriber: u128) -> Result<bool, InterestError> {
        self.subscribers
            .get(&subscriber)
            .map(|c| c.obligation_open)
            .ok_or(InterestError::UnknownSubscriber { subscriber })
    }

    /// Release ONE subscriber's interest: its delivery obligation
    /// closes, everyone else is untouched, and the action survives
    /// while any interest remains (I6). Idempotent: releasing an
    /// unknown/already-released id is a no-op that still reports the
    /// current disposition truthfully.
    pub fn release(&mut self, subscriber: u128, cause: DisconnectCause) -> ReleaseOutcome {
        let removed = self.subscribers.remove(&subscriber);
        let disposition = if self.subscribers.is_empty() {
            ActionDisposition::LastInterestReleased
        } else {
            ActionDisposition::SurvivesWithRemaining {
                retained: self.subscribers.len(),
            }
        };
        ReleaseOutcome {
            released: removed.is_some(),
            obligation_closed: removed.is_some_and(|c| c.obligation_open),
            cause,
            disposition,
        }
    }

    /// Liveness sweep: `alive` is the edge's UDS/PID evidence. Every
    /// subscriber whose process is gone (SIGKILLed wrapper — it never
    /// said goodbye) loses exactly its own subscription; survivors are
    /// untouched. Returns one outcome per reaped subscriber, in id
    /// order.
    pub fn sweep_dead(&mut self, alive: impl Fn(u32) -> bool) -> Vec<(u128, ReleaseOutcome)> {
        let dead: Vec<u128> = self
            .subscribers
            .iter()
            .filter(|(_, conn)| !alive(conn.pid))
            .map(|(id, _)| *id)
            .collect();
        dead.into_iter()
            .map(|id| (id, self.release(id, DisconnectCause::ProcessDead)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_one_subscriber_shared_action_survives() {
        // THE C011 lab acceptance at this layer: two wrappers share
        // one action; one disconnects (UDS) — only ITS interest and
        // obligation close, the shared action survives on the other's
        // retained interest.
        let mut action = SharedActionInterest::new();
        action.register(1, 1001).unwrap();
        action.register(2, 1002).unwrap();
        assert_eq!(action.retained(), 2);

        let outcome = action.release(1, DisconnectCause::UdsDisconnect);
        assert!(outcome.released);
        assert!(outcome.obligation_closed, "its own obligation closes");
        assert_eq!(
            outcome.disposition,
            ActionDisposition::SurvivesWithRemaining { retained: 1 },
            "shared work survives while any interest remains (I6)"
        );
        // The survivor is untouched: interest retained, obligation open.
        assert_eq!(action.obligation_open(2), Ok(true));
        // The released subscriber is gone, and a repeat release is an
        // idempotent no-op that cannot re-close anything.
        assert_eq!(
            action.obligation_open(1),
            Err(InterestError::UnknownSubscriber { subscriber: 1 })
        );
        let repeat = action.release(1, DisconnectCause::ExplicitRelease);
        assert!(!repeat.released);
        assert!(!repeat.obligation_closed);

        // The LAST interest releasing reports the cancel-eligible
        // disposition — only then.
        let last = action.release(2, DisconnectCause::ExplicitRelease);
        assert!(last.released);
        assert_eq!(last.disposition, ActionDisposition::LastInterestReleased);
    }

    #[test]
    fn sigkilled_wrapper_loses_only_its_own_subscription() {
        // Three wrappers; PID 1002's process is SIGKILLed (no goodbye).
        // The liveness sweep reaps exactly that subscription.
        let mut action = SharedActionInterest::new();
        action.register(1, 1001).unwrap();
        action.register(2, 1002).unwrap();
        action.register(3, 1003).unwrap();

        let reaped = action.sweep_dead(|pid| pid != 1002);
        assert_eq!(reaped.len(), 1);
        let (id, outcome) = &reaped[0];
        assert_eq!(*id, 2);
        assert_eq!(outcome.cause, DisconnectCause::ProcessDead);
        assert!(outcome.obligation_closed);
        assert_eq!(
            outcome.disposition,
            ActionDisposition::SurvivesWithRemaining { retained: 2 }
        );
        assert_eq!(action.retained(), 2);
        assert_eq!(action.obligation_open(1), Ok(true));
        assert_eq!(action.obligation_open(3), Ok(true));

        // A sweep with everyone alive reaps nobody.
        assert!(action.sweep_dead(|_| true).is_empty());
    }

    #[test]
    fn c016_exact_signal_mapping_matches_stock() {
        // The differential-vs-stock table: for each catchable signal,
        // stock Cargo dies BY that signal and the shell observes
        // 128+N. The wrapper's mapping must be indistinguishable:
        // cancellation forwarded with the signal recorded, then death
        // by the SAME signal — never a plain exit code.
        let stock: [(WrapperSignal, i32, i32); 3] = [
            (WrapperSignal::Hangup, 1, 129),
            (WrapperSignal::Interrupt, 2, 130),
            (WrapperSignal::Terminate, 15, 143),
        ];
        for (signal, number, observed) in stock {
            assert_eq!(signal.number(), number);
            assert_eq!(signal.observed_exit_code(), observed);
            let (cause, fate) = map_cancellation(CancellationTrigger::Signal(signal));
            assert_eq!(cause, DisconnectCause::Signal(signal));
            assert_eq!(
                fate,
                WrapperFate::DieBySignal(signal),
                "signal-vs-exit classification must be preserved exactly"
            );
        }
        // Normal completion exits with the build's code — an exit
        // stays an exit.
        assert_eq!(
            map_cancellation(CancellationTrigger::ExplicitRelease),
            (
                DisconnectCause::ExplicitRelease,
                WrapperFate::ExitWithBuildCode
            )
        );
    }

    #[test]
    fn c016_parent_death_forwards_then_dies_by_sigterm() {
        // PDEATHSIG (or platform equivalent) → the orphaned wrapper
        // cancels ITS OWN subscription and dies by SIGTERM, exactly as
        // an unwrapped child with the same PDEATHSIG would.
        let (cause, fate) = map_cancellation(CancellationTrigger::ParentDeath);
        assert_eq!(cause, DisconnectCause::ParentDeath);
        assert_eq!(fate, WrapperFate::DieBySignal(WrapperSignal::Terminate));

        // And the release touches only that subscriber.
        let mut action = SharedActionInterest::new();
        action.register(1, 1001).unwrap();
        action.register(2, 1002).unwrap();
        let outcome = action.release(1, cause);
        assert!(outcome.released);
        assert_eq!(
            outcome.disposition,
            ActionDisposition::SurvivesWithRemaining { retained: 1 }
        );
        assert_eq!(action.obligation_open(2), Ok(true));
    }

    #[test]
    fn c016_shared_attempt_cancels_only_through_the_refcount_policy() {
        // Three subscribers; SIGINT one, SIGTERM another: the shared
        // attempt is NOT cancellable while interest remains. Only the
        // LAST release (parent death here) permits attempt
        // cancellation.
        let mut action = SharedActionInterest::new();
        action.register(1, 1001).unwrap();
        action.register(2, 1002).unwrap();
        action.register(3, 1003).unwrap();

        let (cause1, _) = map_cancellation(CancellationTrigger::Signal(WrapperSignal::Interrupt));
        assert_eq!(
            action.release(1, cause1).attempt_cancellation(),
            AttemptCancellation::NotPermitted { retained: 2 }
        );
        let (cause2, _) = map_cancellation(CancellationTrigger::Signal(WrapperSignal::Terminate));
        assert_eq!(
            action.release(2, cause2).attempt_cancellation(),
            AttemptCancellation::NotPermitted { retained: 1 }
        );
        let (cause3, _) = map_cancellation(CancellationTrigger::ParentDeath);
        assert_eq!(
            action.release(3, cause3).attempt_cancellation(),
            AttemptCancellation::PermittedNow
        );
    }

    #[test]
    fn c016_edge_observed_triggers_have_no_wrapper_fate() {
        // UDS disconnect and liveness-detected SIGKILL are observed at
        // the EDGE: the wrapper process is not ours to end (it is gone
        // or detached) — the mapping must never invent a signal death.
        assert_eq!(
            map_cancellation(CancellationTrigger::UdsDisconnect),
            (DisconnectCause::UdsDisconnect, WrapperFate::NotOurProcess)
        );
        assert_eq!(
            map_cancellation(CancellationTrigger::ProcessDead),
            (DisconnectCause::ProcessDead, WrapperFate::NotOurProcess)
        );
    }

    #[test]
    fn c024_child_signal_termination_relays_identically_to_stock() {
        // THE differential table vs stock: when the wrapped tool is
        // signal-terminated — SIGINT, SIGTERM, SIGKILL(child), SIGSEGV
        // — stock Cargo observes a wait status of "signaled N". The
        // wrapper must present EXACTLY that: restore the default
        // disposition and die by the same signal. Exits relay
        // unchanged (including cargo-test's 101).
        for signal_number in [2, 15, 9, 11] {
            assert_eq!(
                relay_child_termination(ChildTermination::Signaled { signal_number }, true),
                RelayAction::RestoreDefaultAndResignal { signal_number },
                "signal {signal_number}: classification must never flip to exit"
            );
        }
        for code in [0, 1, 101] {
            assert_eq!(
                relay_child_termination(ChildTermination::Exited(code), true),
                RelayAction::ExitWith(code)
            );
        }
    }

    #[test]
    fn c024_unsupported_platform_uses_the_named_conventional_code() {
        // Where re-signalling is unsupported, the approximation is the
        // shell-conventional 128+N — DOCUMENTED and typed, never a
        // silent 1.
        assert_eq!(
            relay_child_termination(ChildTermination::Signaled { signal_number: 11 }, false),
            RelayAction::ExitWithConventionalCode(139)
        );
        assert_eq!(
            relay_child_termination(ChildTermination::Signaled { signal_number: 9 }, false),
            RelayAction::ExitWithConventionalCode(137)
        );
        // Plain exits are exact on every platform.
        assert_eq!(
            relay_child_termination(ChildTermination::Exited(101), false),
            RelayAction::ExitWith(101)
        );
    }

    #[test]
    fn duplicate_registration_is_a_typed_refusal() {
        let mut action = SharedActionInterest::new();
        action.register(1, 1001).unwrap();
        assert_eq!(
            action.register(1, 9999),
            Err(InterestError::AlreadyRegistered { subscriber: 1 })
        );
        assert_eq!(action.retained(), 1);
    }
}
