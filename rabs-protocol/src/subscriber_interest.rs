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
