//! Action/attempt crashpack generation (bead G011; Epic G; risks
//! R63/R90's evidence arm).
//!
//! A panic or invariant failure inside an attempt must leave EVIDENCE,
//! not a mystery: the crashpack binds the G001 region attribution, the
//! G002 obligations still outstanding, the recent event window, and
//! REDACTED context (the D012 privacy classes govern what may leave
//! the edge). Consequences are mandatory and typed:
//!
//! - the attempt is QUARANTINED along with any uncommitted outputs;
//! - escalation follows the G010 supervision matrix;
//! - local execution may fail OPEN where safe (the user's build
//!   continues via fallback), but publication NEVER continues from an
//!   uncertain state — the decision type has no
//!   continue-publication arm to reach.

use crate::obligations::{ObligationKind, ObligationSet};
use crate::region_tree::Attribution;
use crate::supervision::{RestartBudget, SupervisorAction, on_failure};

/// One redacted context entry (already passed the privacy filter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedContext {
    /// Context key.
    pub key: String,
    /// Redacted value (hidden-world strings already stripped).
    pub value: String,
}

/// The crashpack: everything a human or tool needs to attribute the
/// failure, with nothing the privacy policy forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crashpack {
    /// What failed (panic message / invariant name).
    pub failure: String,
    /// Full region attribution (G001 chain).
    pub attribution: Attribution,
    /// Obligations still outstanding at failure time (G002).
    pub outstanding_obligations: Vec<ObligationKind>,
    /// Recent event window, oldest first (bounded).
    pub recent_events: Vec<String>,
    /// Redacted context entries.
    pub context: Vec<RedactedContext>,
}

/// The mandatory consequences of an attempt crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashConsequences {
    /// The crashpack produced.
    pub crashpack: Crashpack,
    /// The attempt is quarantined (always true — carried as data so
    /// downstream records it, not so it can be false).
    pub attempt_quarantined: bool,
    /// Uncommitted output staging paths quarantined with it.
    pub quarantined_outputs: Vec<String>,
    /// The supervision escalation decided by the G010 matrix.
    pub supervision: SupervisorAction,
    /// Whether LOCAL fallback may proceed (fail-open where safe).
    pub local_fallback_permitted: bool,
}

/// Maximum recent events retained.
pub const MAX_RECENT_EVENTS: usize = 64;

/// The crash-scene evidence bundle handed to the generator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrashScene {
    /// Recent event window, oldest first.
    pub recent_events: Vec<String>,
    /// Redacted context entries.
    pub context: Vec<RedactedContext>,
    /// Uncommitted output staging paths.
    pub uncommitted_outputs: Vec<String>,
    /// Whether ANY exposure/publication step had begun.
    pub publication_exposed: bool,
}

/// Generate the crashpack + consequences for a failed attempt.
///
/// `scene.publication_exposed` — whether ANY exposure/publication step
/// had begun; if so, local fail-open is NOT safe (the two-frontier
/// rules govern) and the flag comes back false.
#[must_use]
pub fn on_attempt_crash(
    failure: &str,
    attribution: &Attribution,
    obligations: &ObligationSet,
    scene: CrashScene,
    supervision_budget: &mut RestartBudget,
) -> CrashConsequences {
    let outstanding = match obligations.may_close_region() {
        Ok(()) => Vec::new(),
        Err(crate::obligations::ObligationError::Unresolved(kinds)) => kinds,
        Err(_) => Vec::new(),
    };
    let start = scene.recent_events.len().saturating_sub(MAX_RECENT_EVENTS);
    let crashpack = Crashpack {
        failure: failure.to_owned(),
        attribution: attribution.clone(),
        outstanding_obligations: outstanding,
        recent_events: scene.recent_events[start..].to_vec(),
        context: scene.context,
    };
    CrashConsequences {
        crashpack,
        attempt_quarantined: true,
        quarantined_outputs: scene.uncommitted_outputs,
        supervision: on_failure(supervision_budget),
        // Fail open locally ONLY when nothing was exposed; a crash
        // after exposure follows the delivery frontier rules instead.
        local_fallback_permitted: !scene.publication_exposed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obligations::ObligationKind as K;
    use crate::region_tree::{attribution_chains, worker_attempt_region};
    use crate::supervision::Component;

    fn attribution() -> Attribution {
        let tree =
            worker_attempt_region("key-abc", "generation-42", "attempt-7", "lease-1", "boot-3");
        attribution_chains(&tree)
            .into_iter()
            .find(|(path, _)| path.ends_with("CompilerProcessRegion"))
            .map(|(_, a)| a)
            .unwrap()
    }

    fn crashed() -> CrashConsequences {
        let mut obligations = ObligationSet::default();
        obligations.open(K::SandboxCleanup);
        obligations.open(K::OutputStagingPin);
        let mut budget = RestartBudget {
            component: Component::ActionActor,
            consumed: 0,
        };
        on_attempt_crash(
            "invariant violated: output outside declared set",
            &attribution(),
            &obligations,
            CrashScene {
                recent_events: vec!["spawned rustc".into(), "read src/lib.rs".into()],
                context: vec![RedactedContext {
                    key: "unit".into(),
                    value: "serde-1".into(),
                }],
                uncommitted_outputs: vec!["/staging/out/libserde.rlib.partial".into()],
                publication_exposed: false,
            },
            &mut budget,
        )
    }

    #[test]
    fn induced_panic_yields_a_complete_crashpack_and_quarantined_attempt() {
        // THE acceptance: the crashpack carries the full attribution
        // chain, the outstanding obligations BY NAME, the event
        // window, and the redacted context; the attempt and its
        // uncommitted outputs are quarantined.
        let consequences = crashed();
        let pack = &consequences.crashpack;
        assert_eq!(pack.attribution.action_key.as_deref(), Some("key-abc"));
        assert_eq!(pack.attribution.attempt.as_deref(), Some("attempt-7"));
        assert_eq!(pack.attribution.lease.as_deref(), Some("lease-1"));
        assert_eq!(
            pack.outstanding_obligations,
            vec![K::SandboxCleanup, K::OutputStagingPin],
            "leaked obligations attribute by name"
        );
        assert_eq!(pack.recent_events.len(), 2);
        assert!(consequences.attempt_quarantined);
        assert_eq!(
            consequences.quarantined_outputs,
            vec!["/staging/out/libserde.rlib.partial".to_owned()]
        );
        // Supervision followed the G010 matrix: an action actor
        // retries via new fenced attempts.
        assert!(matches!(
            consequences.supervision,
            SupervisorAction::RestartAfter { .. }
        ));
    }

    #[test]
    fn publication_never_continues_from_an_uncertain_state() {
        // Structurally: CrashConsequences has NO continue-publication
        // field — the exhaustive destructure proves it, and a crash
        // after exposure additionally forbids local fail-open.
        let CrashConsequences {
            crashpack: _,
            attempt_quarantined: _,
            quarantined_outputs: _,
            supervision: _,
            local_fallback_permitted: _,
        } = crashed();
        let mut budget = RestartBudget {
            component: Component::ActionActor,
            consumed: 0,
        };
        let exposed = on_attempt_crash(
            "panic after exposure",
            &attribution(),
            &ObligationSet::default(),
            CrashScene {
                publication_exposed: true, // exposure had begun
                ..CrashScene::default()
            },
            &mut budget,
        );
        assert!(
            !exposed.local_fallback_permitted,
            "after exposure, the delivery frontier rules govern — no fail-open"
        );
        // Before exposure, fail-open locally is safe.
        assert!(crashed().local_fallback_permitted);
    }

    #[test]
    fn event_window_is_bounded() {
        let many: Vec<String> = (0..200).map(|i| format!("event-{i}")).collect();
        let mut budget = RestartBudget {
            component: Component::ActionActor,
            consumed: 0,
        };
        let consequences = on_attempt_crash(
            "panic",
            &attribution(),
            &ObligationSet::default(),
            CrashScene {
                recent_events: many,
                ..CrashScene::default()
            },
            &mut budget,
        );
        assert_eq!(
            consequences.crashpack.recent_events.len(),
            MAX_RECENT_EVENTS
        );
        assert_eq!(
            consequences.crashpack.recent_events.last().unwrap(),
            "event-199",
            "the newest events are kept"
        );
    }
}
