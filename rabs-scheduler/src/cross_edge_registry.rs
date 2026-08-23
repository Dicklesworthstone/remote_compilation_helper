//! Cross-edge demand convergence on the ONE coordinator registry
//! (bead I018; invariant I5; risk R44).
//!
//! Edges never host authoritative actors. Every edge submits its
//! final action keys to the single coordinator registry, and IDENTICAL
//! demands from different edges converge onto ONE actor — the
//! fleet-wide single-flight. Without this, each host daemon gives only
//! PER-HOST singleflight while the fleet claim is false (R44): two
//! edges demanding the same key would run two actors and duplicate the
//! whole pipeline.
//!
//! This module is the registry's pure decision core:
//!
//! - [`CrossEdgeRegistry::submit`] returns [`DemandOutcome`]:
//!   `ActorCreated` for the first demand of a key, `JoinedExistingActor`
//!   for every identical demand after — the saved-work counter is the
//!   dedup measurement, per submission, deterministic;
//! - an edge attempting to host a LOCAL authoritative actor for a key
//!   the coordinator already converges is a typed refusal
//!   ([`refuse_local_actor_claim`]) — that claim is exactly how the
//!   fleet-wide singleflight silently becomes per-host;
//! - replay discipline: identical submission sequences produce
//!   identical outcome sequences (the lib-level promise).

use std::collections::{BTreeSet, HashMap};

use rabs_protocol::result_identity::TypedDigest;

/// One converged actor entry: who demanded it first, and every edge
/// that has since joined.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ActorEntry {
    first_edge: String,
    joined_edges: BTreeSet<String>,
}

/// The cross-edge demand registry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrossEdgeRegistry {
    entries: HashMap<TypedDigest, ActorEntry>,
    /// Total submissions that JOINED an existing actor (the saved-work
    /// measurement: each one would have been a duplicate pipeline).
    saved_submissions: u64,
    /// Total submissions seen (denominator for the ratio).
    total_submissions: u64,
}

/// The outcome of one edge demand submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DemandOutcome {
    /// First demand for this key: THE coordinator actor was created.
    ActorCreated,
    /// An identical demand from another edge joined the EXISTING
    /// actor — no second pipeline was built.
    JoinedExistingActor {
        /// How many edges had already joined before this one.
        prior_joins: u64,
    },
}

/// A local-actor-claim refusal: hosting an authoritative actor on an
/// edge for a key the coordinator registry converges would split the
/// fleet-wide singleflight into per-host singleflights (I5/R44).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalClaimRefusal {
    /// The key whose single authority lives in the coordinator
    /// registry.
    pub key: TypedDigest,
}

impl CrossEdgeRegistry {
    /// Submit one edge's final demand for `key`.
    pub fn submit(&mut self, edge: &str, key: TypedDigest) -> DemandOutcome {
        self.total_submissions += 1;
        match self.entries.get_mut(&key) {
            None => {
                let mut joined = BTreeSet::new();
                joined.insert(edge.to_owned());
                self.entries.insert(
                    key,
                    ActorEntry {
                        first_edge: edge.to_owned(),
                        joined_edges: joined,
                    },
                );
                DemandOutcome::ActorCreated
            }
            Some(entry) => {
                let prior_joins = u64::try_from(entry.joined_edges.len()).unwrap_or(u64::MAX);
                entry.joined_edges.insert(edge.to_owned());
                self.saved_submissions += 1;
                DemandOutcome::JoinedExistingActor { prior_joins }
            }
        }
    }

    /// Distinct actors the coordinator hosts (one per distinct key —
    /// NEVER one per edge-demand).
    #[must_use]
    pub fn actor_count(&self) -> usize {
        self.entries.len()
    }

    /// Submissions that joined instead of duplicating (the saved-work
    /// measurement).
    #[must_use]
    pub fn saved_submissions(&self) -> u64 {
        self.saved_submissions
    }

    /// Total submissions (the ratio's denominator).
    #[must_use]
    pub fn total_submissions(&self) -> u64 {
        self.total_submissions
    }

    /// Saved-work share of all submissions: dedups / submissions as a
    /// rational pair (numerator, denominator) so callers cannot lose
    /// precision to floats. `(0, 0)` when nothing was submitted.
    #[must_use]
    pub fn saved_work_ratio(&self) -> (u64, u64) {
        (self.saved_submissions, self.total_submissions)
    }

    /// Every edge currently converged on `key`.
    #[must_use]
    pub fn edges_for(&self, key: &TypedDigest) -> Vec<&str> {
        match self.entries.get(key) {
            None => Vec::new(),
            Some(entry) => {
                let mut v: Vec<&str> = entry.joined_edges.iter().map(String::as_str).collect();
                v.sort_unstable();
                v
            }
        }
    }

    /// Whether the coordinator registry owns `key`.
    #[must_use]
    pub fn owns(&self, key: &TypedDigest) -> bool {
        self.entries.contains_key(key)
    }
}

/// Refuse an edge's attempt to host a LOCAL authoritative actor for a
/// key the coordinator registry already converges. All edges submit
/// final keys to THE registry; the local-hosting shortcut is the R44
/// failure mode in person.
///
/// # Errors
/// [`LocalClaimRefusal`] naming the owned key; `Ok(())` only for a
/// key the registry does not own (nothing to split — yet; the edge
/// should SUBMIT instead of hosting).
pub fn refuse_local_actor_claim(
    registry: &CrossEdgeRegistry,
    key: &TypedDigest,
) -> Result<(), LocalClaimRefusal> {
    if registry.owns(key) {
        return Err(LocalClaimRefusal { key: key.clone() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.action-key.sha256.v1",
            bytes: [tag; 32],
        }
    }

    use rabs_protocol::result_identity::DigestAlgorithm;

    #[test]
    fn cross_edge_identical_demands_join_one_actor() {
        // THE acceptance: three edges demand the SAME key. Exactly one
        // actor exists; the second and third JOINED it.
        let mut reg = CrossEdgeRegistry::default();
        assert_eq!(reg.submit("edge-a", key(1)), DemandOutcome::ActorCreated);
        assert_eq!(
            reg.submit("edge-b", key(1)),
            DemandOutcome::JoinedExistingActor { prior_joins: 1 }
        );
        assert_eq!(
            reg.submit("edge-c", key(1)),
            DemandOutcome::JoinedExistingActor { prior_joins: 2 }
        );
        assert_eq!(reg.actor_count(), 1, "one actor, not three");
        assert_eq!(
            reg.edges_for(&key(1)),
            vec!["edge-a", "edge-b", "edge-c"],
            "all three edges converged on the ONE actor"
        );
    }

    #[test]
    fn distinct_keys_create_distinct_actors() {
        let mut reg = CrossEdgeRegistry::default();
        assert_eq!(reg.submit("edge-a", key(1)), DemandOutcome::ActorCreated);
        assert_eq!(reg.submit("edge-a", key(2)), DemandOutcome::ActorCreated);
        assert_eq!(reg.actor_count(), 2);
        // Same edge re-submitting a key it created is still a JOIN of
        // the existing actor, not a second one.
        assert_eq!(
            reg.submit("edge-a", key(1)),
            DemandOutcome::JoinedExistingActor { prior_joins: 1 }
        );
        assert_eq!(reg.actor_count(), 2);
    }

    #[test]
    fn saved_work_is_measured_per_submission_with_exact_denominator() {
        // 5 submissions over 2 keys: 3 joins, 2 creations.
        let mut reg = CrossEdgeRegistry::default();
        reg.submit("e1", key(1));
        reg.submit("e2", key(1));
        reg.submit("e3", key(1));
        reg.submit("e1", key(2));
        reg.submit("e4", key(2));
        // Per-subscriber latency/work SAVING: each join skipped one
        // whole duplicate pipeline. Deterministic counters, exact
        // rational — 3/5 saved.
        assert_eq!(reg.saved_work_ratio(), (3, 5));
        assert_eq!(reg.saved_submissions(), 3);
        assert_eq!(reg.total_submissions(), 5);
        // Empty registry reports (0, 0), not a fake ratio.
        assert_eq!(CrossEdgeRegistry::default().saved_work_ratio(), (0, 0));
    }

    #[test]
    fn local_actor_claims_on_coordinator_keys_are_refused() {
        let mut reg = CrossEdgeRegistry::default();
        reg.submit("edge-a", key(7));
        // Edge-b tries to host its OWN actor for key 7: refused typed —
        // that is the R44 per-host-singleflight lie in person.
        assert_eq!(
            refuse_local_actor_claim(&reg, &key(7)),
            Err(LocalClaimRefusal { key: key(7) })
        );
        // A key nobody demanded yet: nothing to split, allowed — but
        // the honest move remains SUBMITTING it.
        assert!(refuse_local_actor_claim(&reg, &key(8)).is_ok());
    }

    #[test]
    fn identical_sequences_replay_identically() {
        // The lib-level promise: identical inputs → identical decision
        // sequences. Two registries fed the same script agree at every
        // step AND end equal.
        let script = [
            ("edge-a", 1u8),
            ("edge-b", 1),
            ("edge-b", 1),
            ("edge-c", 2),
            ("edge-a", 2),
        ];
        let mut a = CrossEdgeRegistry::default();
        let mut b = CrossEdgeRegistry::default();
        for (edge, tag) in script {
            assert_eq!(a.submit(edge, key(tag)), b.submit(edge, key(tag)));
        }
        assert_eq!(a, b);
    }
}
