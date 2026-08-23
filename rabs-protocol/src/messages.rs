//! The session/health/action/attempt/reconciliation message families
//! (bead J012; plan §88's catalog; risks R63/R64).
//!
//! The message schemas from `RabsEdgeHello` through
//! `ReconcileSubscriberDeliveryState`, with the idempotency rules the
//! handlers must honor as PURE decision functions:
//!
//! - a repeated `SubmitAction` with the same idempotency key JOINS
//!   the existing actor (one action, N subscribers) — never a second
//!   execution;
//! - repeated lease acceptance returns the EXISTING lease state;
//! - repeated cancel/release cannot double-release (the second is a
//!   no-op acknowledgement);
//! - a stale coordinator authority fails CLOSED (the message is
//!   rejected before any state is touched).

use crate::authority::CoordinatorAuthority;
use crate::durable_ids::DurableWireIdentity;
use crate::wire_time::PeerId;

/// The catalog's message kinds (schema names; payloads by family).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum RabsMessage {
    /// Edge session open.
    RabsEdgeHello { edge: PeerId, session_id: u128 },
    /// Worker session open (F029 fields ride the fence records).
    RabsWorkerHello { worker: PeerId, session_id: u128 },
    /// Periodic health heartbeat.
    Heartbeat { peer: PeerId, causal_seq: u64 },
    /// Submit an action for execution/subscription.
    SubmitAction {
        identity: DurableWireIdentity,
        idempotency_key: u128,
    },
    /// Offer/accept an execution lease.
    AcceptLease { identity: DurableWireIdentity },
    /// Cancel an attempt.
    CancelAttempt { identity: DurableWireIdentity },
    /// Release a subscriber's interest.
    ReleaseInterest { subscriber_id: u128 },
    /// Coordinator authority update.
    AuthorityUpdate { authority: CoordinatorAuthority },
    /// Ordered attempt event.
    AttemptEvent {
        identity: DurableWireIdentity,
        event_seq: u64,
    },
    /// Reconcile subscriber delivery state after reconnect.
    ReconcileSubscriberDeliveryState {
        subscriber_id: u128,
        acked_high_water: u64,
    },
}

/// Handler outcomes encoding the idempotency rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerOutcome {
    /// New state created (first arrival).
    Created,
    /// Joined existing state (idempotent repeat).
    JoinedExisting,
    /// The existing state returned unchanged (idempotent repeat).
    ReturnedExisting,
    /// No-op acknowledgement (already cancelled/released).
    AlreadyDone,
    /// Rejected: stale authority (fails closed, nothing touched).
    RejectedStaleAuthority,
}

/// Pure session state the handlers fold over.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionState {
    /// Submitted action idempotency keys.
    submitted: Vec<u128>,
    /// Accepted lease identities.
    leases: Vec<DurableWireIdentity>,
    /// Cancelled attempt identities.
    cancelled: Vec<DurableWireIdentity>,
    /// Released subscriber ids.
    released: Vec<u128>,
    /// Current authority term.
    pub current_term: u64,
}

impl SessionState {
    /// The submitted action idempotency keys, in arrival order
    /// (read-only view for reconciliation gates and suite audits).
    #[must_use]
    pub fn submitted_keys(&self) -> &[u128] {
        &self.submitted
    }

    /// The accepted lease identities (read-only view).
    #[must_use]
    pub fn leases(&self) -> &[DurableWireIdentity] {
        &self.leases
    }

    /// The cancelled attempt identities (read-only view).
    #[must_use]
    pub fn cancelled(&self) -> &[DurableWireIdentity] {
        &self.cancelled
    }

    /// Handle a message under the catalog's idempotency rules.
    pub fn handle(&mut self, message: &RabsMessage, message_term: u64) -> HandlerOutcome {
        // Stale authority fails closed BEFORE any state is touched.
        if message_term < self.current_term {
            return HandlerOutcome::RejectedStaleAuthority;
        }
        match message {
            RabsMessage::SubmitAction {
                idempotency_key, ..
            } => {
                if self.submitted.contains(idempotency_key) {
                    HandlerOutcome::JoinedExisting
                } else {
                    self.submitted.push(*idempotency_key);
                    HandlerOutcome::Created
                }
            }
            RabsMessage::AcceptLease { identity } => {
                if self.leases.contains(identity) {
                    HandlerOutcome::ReturnedExisting
                } else {
                    self.leases.push(*identity);
                    HandlerOutcome::Created
                }
            }
            RabsMessage::CancelAttempt { identity } => {
                if self.cancelled.contains(identity) {
                    HandlerOutcome::AlreadyDone
                } else {
                    self.cancelled.push(*identity);
                    HandlerOutcome::Created
                }
            }
            RabsMessage::ReleaseInterest { subscriber_id } => {
                if self.released.contains(subscriber_id) {
                    HandlerOutcome::AlreadyDone
                } else {
                    self.released.push(*subscriber_id);
                    HandlerOutcome::Created
                }
            }
            RabsMessage::AuthorityUpdate { authority } => {
                self.current_term = self.current_term.max(authority.term);
                HandlerOutcome::Created
            }
            RabsMessage::RabsEdgeHello { .. }
            | RabsMessage::RabsWorkerHello { .. }
            | RabsMessage::Heartbeat { .. }
            | RabsMessage::AttemptEvent { .. }
            | RabsMessage::ReconcileSubscriberDeliveryState { .. } => HandlerOutcome::Created,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{ClusterId, CoordinatorIncarnationId};
    use crate::durable_ids::BuildOperationId;
    use crate::generation::{ActionGenerationId, AttemptId, ExecutionLeaseId};

    fn identity(tag: u128) -> DurableWireIdentity {
        DurableWireIdentity {
            operation: BuildOperationId(tag),
            generation: ActionGenerationId(tag),
            attempt: AttemptId(tag),
            lease: ExecutionLeaseId(tag),
        }
    }

    #[test]
    fn repeated_submit_joins_the_existing_actor() {
        let mut state = SessionState::default();
        let submit = RabsMessage::SubmitAction {
            identity: identity(1),
            idempotency_key: 42,
        };
        assert_eq!(state.handle(&submit, 1), HandlerOutcome::Created);
        // The replay (retry, second subscriber): JOINS, never a second
        // execution.
        assert_eq!(state.handle(&submit, 1), HandlerOutcome::JoinedExisting);
        assert_eq!(state.handle(&submit, 1), HandlerOutcome::JoinedExisting);
    }

    #[test]
    fn repeated_lease_acceptance_returns_existing_state() {
        let mut state = SessionState::default();
        let accept = RabsMessage::AcceptLease {
            identity: identity(7),
        };
        assert_eq!(state.handle(&accept, 1), HandlerOutcome::Created);
        assert_eq!(state.handle(&accept, 1), HandlerOutcome::ReturnedExisting);
    }

    #[test]
    fn cancel_and_release_cannot_double_release() {
        let mut state = SessionState::default();
        let cancel = RabsMessage::CancelAttempt {
            identity: identity(9),
        };
        assert_eq!(state.handle(&cancel, 1), HandlerOutcome::Created);
        assert_eq!(state.handle(&cancel, 1), HandlerOutcome::AlreadyDone);
        let release = RabsMessage::ReleaseInterest { subscriber_id: 5 };
        assert_eq!(state.handle(&release, 1), HandlerOutcome::Created);
        assert_eq!(state.handle(&release, 1), HandlerOutcome::AlreadyDone);
    }

    #[test]
    fn stale_authority_fails_closed_before_state_changes() {
        let mut state = SessionState::default();
        let update = RabsMessage::AuthorityUpdate {
            authority: CoordinatorAuthority {
                cluster_id: ClusterId("fleet".into()),
                credential_generation: 1,
                term: 5,
                incarnation_id: CoordinatorIncarnationId(1),
            },
        };
        assert_eq!(state.handle(&update, 5), HandlerOutcome::Created);
        assert_eq!(state.current_term, 5);
        // A submit carrying term 3 (stale): rejected, NOTHING touched.
        let before = state.clone();
        let stale_submit = RabsMessage::SubmitAction {
            identity: identity(1),
            idempotency_key: 99,
        };
        assert_eq!(
            state.handle(&stale_submit, 3),
            HandlerOutcome::RejectedStaleAuthority
        );
        assert_eq!(state, before, "fails closed: no state was touched");
        // The same submit at the current term succeeds.
        assert_eq!(state.handle(&stale_submit, 5), HandlerOutcome::Created);
    }

    #[test]
    fn the_catalog_covers_the_bead_families() {
        // Schema presence: hello/heartbeat/action/lease/cancel/
        // authority/event/reconciliation all constructible.
        let messages = [
            RabsMessage::RabsEdgeHello {
                edge: PeerId("e".into()),
                session_id: 1,
            },
            RabsMessage::RabsWorkerHello {
                worker: PeerId("w".into()),
                session_id: 2,
            },
            RabsMessage::Heartbeat {
                peer: PeerId("w".into()),
                causal_seq: 1,
            },
            RabsMessage::SubmitAction {
                identity: identity(1),
                idempotency_key: 1,
            },
            RabsMessage::AcceptLease {
                identity: identity(1),
            },
            RabsMessage::CancelAttempt {
                identity: identity(1),
            },
            RabsMessage::ReleaseInterest { subscriber_id: 1 },
            RabsMessage::AuthorityUpdate {
                authority: CoordinatorAuthority {
                    cluster_id: ClusterId("fleet".into()),
                    credential_generation: 1,
                    term: 1,
                    incarnation_id: CoordinatorIncarnationId(1),
                },
            },
            RabsMessage::AttemptEvent {
                identity: identity(1),
                event_seq: 1,
            },
            RabsMessage::ReconcileSubscriberDeliveryState {
                subscriber_id: 1,
                acked_high_water: 3,
            },
        ];
        assert_eq!(messages.len(), 10);
    }
}
