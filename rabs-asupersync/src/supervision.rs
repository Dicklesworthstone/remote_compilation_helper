//! Supervision policies + restart budgets (bead G010; Epic G's
//! supervision matrix; risk R63).
//!
//! Every supervised component gets ONE policy row from the plan's
//! matrix — what happens on failure, whether restarts are allowed, and
//! the restart BUDGET (restarts are a consumable, trace-visible
//! resource, never an infinite loop):
//!
//! - wrapper connection → STOP (a broken client connection is not
//!   retried by the daemon);
//! - worker session → restart with bounded backoff, and durable
//!   operations RECONCILE before any new authoritative work admits;
//! - ATP endpoint → restart, escalating to transport fallback on
//!   repeated failure;
//! - action actor → stop or controlled retry via NEW FENCED attempts
//!   (never actor-replacement ambiguity);
//! - health collector → restart (its stale evidence already fails
//!   closed downstream — I007);
//! - CAS writer → ESCALATE on invariant violation: publication must
//!   not continue over storage corruption;
//! - compat HTTP/OTel islands → restart/stop isolated (may fail
//!   without preventing local execution);
//! - GC → restart with cadence backoff; speculation → optional.

/// The supervised components (matrix rows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Plan vocabulary.
pub enum Component {
    WrapperConnection,
    WorkerSession,
    AtpEndpoint,
    ActionActor,
    HealthCollector,
    CasWriter,
    CompatIsland,
    GarbageCollection,
    Speculation,
}

impl Component {
    /// All components.
    pub const ALL: [Self; 9] = [
        Self::WrapperConnection,
        Self::WorkerSession,
        Self::AtpEndpoint,
        Self::ActionActor,
        Self::HealthCollector,
        Self::CasWriter,
        Self::CompatIsland,
        Self::GarbageCollection,
        Self::Speculation,
    ];
}

/// What supervision does on failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePolicy {
    /// Stop; no restart.
    Stop,
    /// Restart under a budget, with a precondition class.
    Restart {
        /// Restarts allowed before escalation/stop.
        budget: u32,
        /// Backoff base in milliseconds (doubles per consecutive
        /// failure; deterministic — no jitter here).
        backoff_base_ms: u64,
        /// What must happen before the restarted component admits
        /// authoritative work.
        precondition: RestartPrecondition,
        /// What happens when the budget is exhausted.
        on_exhaustion: Exhaustion,
    },
    /// Escalate immediately: the failure invalidates continuing at all.
    Escalate {
        /// Why escalation is the only sound response.
        reason: &'static str,
    },
}

/// Preconditions a restart must satisfy first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPrecondition {
    /// None beyond process start.
    None,
    /// Durable operations reconcile before new authoritative work.
    ReconcileDurableOperations,
    /// Retry happens through NEW FENCED attempts only.
    NewFencedAttemptsOnly,
}

/// Budget-exhaustion behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exhaustion {
    /// Stop the component.
    Stop,
    /// Escalate to the parent.
    Escalate,
    /// Degrade to a fallback transport.
    DegradeToFallbackTransport,
}

/// The matrix row for a component.
#[must_use]
pub const fn policy(component: Component) -> FailurePolicy {
    match component {
        Component::WrapperConnection => FailurePolicy::Stop,
        Component::WorkerSession => FailurePolicy::Restart {
            budget: 5,
            backoff_base_ms: 500,
            precondition: RestartPrecondition::ReconcileDurableOperations,
            on_exhaustion: Exhaustion::Escalate,
        },
        Component::AtpEndpoint => FailurePolicy::Restart {
            budget: 3,
            backoff_base_ms: 250,
            precondition: RestartPrecondition::None,
            on_exhaustion: Exhaustion::DegradeToFallbackTransport,
        },
        Component::ActionActor => FailurePolicy::Restart {
            budget: 2,
            backoff_base_ms: 0,
            precondition: RestartPrecondition::NewFencedAttemptsOnly,
            on_exhaustion: Exhaustion::Stop,
        },
        Component::HealthCollector => FailurePolicy::Restart {
            budget: 10,
            backoff_base_ms: 1_000,
            precondition: RestartPrecondition::None,
            on_exhaustion: Exhaustion::Stop, // stale evidence fails closed anyway
        },
        Component::CasWriter => FailurePolicy::Escalate {
            reason: "publication must not continue after storage corruption",
        },
        Component::CompatIsland => FailurePolicy::Restart {
            budget: 3,
            backoff_base_ms: 1_000,
            precondition: RestartPrecondition::None,
            on_exhaustion: Exhaustion::Stop, // isolated: local execution unaffected
        },
        Component::GarbageCollection => FailurePolicy::Restart {
            budget: u32::MAX, // cadence-driven; backoff bounds the rate
            backoff_base_ms: 60_000,
            precondition: RestartPrecondition::None,
            on_exhaustion: Exhaustion::Stop,
        },
        Component::Speculation => FailurePolicy::Restart {
            budget: 1,
            backoff_base_ms: 5_000,
            precondition: RestartPrecondition::None,
            on_exhaustion: Exhaustion::Stop, // optional subsystem
        },
    }
}

/// One component's live restart accounting (trace-visible).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartBudget {
    /// The component.
    pub component: Component,
    /// Restarts consumed.
    pub consumed: u32,
}

/// What the supervisor does for THIS failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorAction {
    /// Stop the component now.
    Stop,
    /// Restart after the given backoff, under the given precondition.
    RestartAfter {
        /// Deterministic backoff for this consecutive failure.
        backoff_ms: u64,
        /// The precondition to satisfy first.
        precondition: RestartPrecondition,
    },
    /// Escalate to the parent region.
    Escalate,
    /// Degrade transport to the fallback path.
    DegradeToFallbackTransport,
}

/// Decide the action for a failure, consuming budget.
pub fn on_failure(budget: &mut RestartBudget) -> SupervisorAction {
    match policy(budget.component) {
        FailurePolicy::Stop => SupervisorAction::Stop,
        FailurePolicy::Escalate { .. } => SupervisorAction::Escalate,
        FailurePolicy::Restart {
            budget: allowed,
            backoff_base_ms,
            precondition,
            on_exhaustion,
        } => {
            if budget.consumed >= allowed {
                return match on_exhaustion {
                    Exhaustion::Stop => SupervisorAction::Stop,
                    Exhaustion::Escalate => SupervisorAction::Escalate,
                    Exhaustion::DegradeToFallbackTransport => {
                        SupervisorAction::DegradeToFallbackTransport
                    }
                };
            }
            let backoff_ms = backoff_base_ms.saturating_mul(1u64 << budget.consumed.min(16));
            budget.consumed += 1;
            SupervisorAction::RestartAfter {
                backoff_ms,
                precondition,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_matrix_covers_every_component_with_the_plan_policies() {
        for component in Component::ALL {
            let _ = policy(component); // total by match
        }
        assert_eq!(policy(Component::WrapperConnection), FailurePolicy::Stop);
        assert!(matches!(
            policy(Component::CasWriter),
            FailurePolicy::Escalate { .. }
        ));
        assert!(matches!(
            policy(Component::WorkerSession),
            FailurePolicy::Restart {
                precondition: RestartPrecondition::ReconcileDurableOperations,
                on_exhaustion: Exhaustion::Escalate,
                ..
            }
        ));
        assert!(matches!(
            policy(Component::ActionActor),
            FailurePolicy::Restart {
                precondition: RestartPrecondition::NewFencedAttemptsOnly,
                ..
            }
        ));
        assert!(matches!(
            policy(Component::AtpEndpoint),
            FailurePolicy::Restart {
                on_exhaustion: Exhaustion::DegradeToFallbackTransport,
                ..
            }
        ));
    }

    #[test]
    fn restarts_consume_budget_and_back_off_deterministically() {
        let mut budget = RestartBudget {
            component: Component::AtpEndpoint,
            consumed: 0,
        };
        // 3 restarts with doubling backoff: 250, 500, 1000.
        for expected in [250u64, 500, 1000] {
            let action = on_failure(&mut budget);
            assert_eq!(
                action,
                SupervisorAction::RestartAfter {
                    backoff_ms: expected,
                    precondition: RestartPrecondition::None
                }
            );
        }
        assert_eq!(budget.consumed, 3, "budget consumption is trace-visible");
        // Budget exhausted: the ATP endpoint DEGRADES to fallback
        // transport rather than looping.
        assert_eq!(
            on_failure(&mut budget),
            SupervisorAction::DegradeToFallbackTransport
        );
    }

    #[test]
    fn worker_sessions_reconcile_before_new_authoritative_work() {
        let mut budget = RestartBudget {
            component: Component::WorkerSession,
            consumed: 0,
        };
        let SupervisorAction::RestartAfter { precondition, .. } = on_failure(&mut budget) else {
            panic!("worker sessions restart");
        };
        assert_eq!(
            precondition,
            RestartPrecondition::ReconcileDurableOperations,
            "durable operations reconcile before admitting new work"
        );
        // Exhaustion escalates (a worker that cannot hold a session is
        // a fleet problem, not a retry loop).
        budget.consumed = 5;
        assert_eq!(on_failure(&mut budget), SupervisorAction::Escalate);
    }

    #[test]
    fn cas_writer_escalates_immediately_and_stops_never_retry() {
        // Storage corruption: continuing publication would launder
        // corrupt bytes — escalate on the FIRST failure, budget
        // irrelevant.
        let mut budget = RestartBudget {
            component: Component::CasWriter,
            consumed: 0,
        };
        assert_eq!(on_failure(&mut budget), SupervisorAction::Escalate);
        assert_eq!(budget.consumed, 0, "no restart was ever an option");
        // Wrapper connections stop outright.
        let mut wrapper = RestartBudget {
            component: Component::WrapperConnection,
            consumed: 0,
        };
        assert_eq!(on_failure(&mut wrapper), SupervisorAction::Stop);
    }
}
