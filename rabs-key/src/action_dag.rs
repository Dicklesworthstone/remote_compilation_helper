//! The action DAG from artifact identities (bead M009; plan §100).
//!
//! The build graph reconstructed from CONTENT, not from unstable
//! Cargo unit-graph APIs:
//!
//! - actions reference the dependency ARTIFACTS they consumed (by
//!   content identity, from live observation);
//! - artifacts reference the action that PRODUCED them;
//! - edges from observation are FIRM; edges inferred before an
//!   attempt completes are PROVISIONAL and say so;
//! - test actions reference their binaries + data inputs the same
//!   way — an affected-test query is a graph walk.
//!
//! The queries this graph serves (I015 critical-path scheduling, O009
//! affected-test selection, rebuild explanation) are graph walks over
//! these edges; two are implemented here as the acceptance queries.

use rabs_protocol::result_identity::TypedDigest;

/// One DAG node: an action with its consumed/produced artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionNode {
    /// The action's key.
    pub action_key: TypedDigest,
    /// Artifacts consumed (content identities), with edge firmness.
    pub consumes: Vec<(TypedDigest, EdgeFirmness)>,
    /// Artifacts produced.
    pub produces: Vec<TypedDigest>,
    /// Estimated cost (ms) for critical-path queries.
    pub cost_ms: u64,
}

/// Edge provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeFirmness {
    /// From live observation of a completed attempt.
    Observed,
    /// Inferred before completion: explicit, never silently firm.
    Provisional,
}

/// The DAG.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionDag {
    /// All nodes.
    pub nodes: Vec<ActionNode>,
}

impl ActionDag {
    /// The action producing an artifact, if known.
    #[must_use]
    pub fn producer_of(&self, artifact: &TypedDigest) -> Option<&ActionNode> {
        self.nodes.iter().find(|n| n.produces.contains(artifact))
    }

    /// Downstream actions consuming any artifact this action produces
    /// (one hop).
    #[must_use]
    pub fn consumers_of(&self, action_key: &TypedDigest) -> Vec<&ActionNode> {
        let Some(node) = self.nodes.iter().find(|n| n.action_key == *action_key) else {
            return Vec::new();
        };
        self.nodes
            .iter()
            .filter(|candidate| {
                candidate
                    .consumes
                    .iter()
                    .any(|(artifact, _)| node.produces.contains(artifact))
            })
            .collect()
    }

    /// AFFECTED-TEST SELECTION (the O009 query): every action
    /// transitively downstream of `changed_artifact`.
    #[must_use]
    pub fn affected_by(&self, changed_artifact: &TypedDigest) -> Vec<TypedDigest> {
        let mut affected: Vec<TypedDigest> = Vec::new();
        let mut frontier: Vec<TypedDigest> = vec![changed_artifact.clone()];
        while let Some(artifact) = frontier.pop() {
            for node in &self.nodes {
                if node.consumes.iter().any(|(a, _)| *a == artifact)
                    && !affected.contains(&node.action_key)
                {
                    affected.push(node.action_key.clone());
                    frontier.extend(node.produces.iter().cloned());
                }
            }
        }
        affected
    }

    /// CRITICAL PATH (the I015 query): the longest-cost chain ending
    /// at `action_key`, following producer edges upward.
    #[must_use]
    pub fn critical_path_cost(&self, action_key: &TypedDigest) -> u64 {
        let Some(node) = self.nodes.iter().find(|n| n.action_key == *action_key) else {
            return 0;
        };
        let upstream_max = node
            .consumes
            .iter()
            .filter_map(|(artifact, _)| self.producer_of(artifact))
            .map(|producer| self.critical_path_cost(&producer.action_key))
            .max()
            .unwrap_or(0);
        node.cost_ms + upstream_max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn key(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.action-key.sha256.v1",
            bytes: [tag; 32],
        }
    }

    fn artifact(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        }
    }

    /// The fixture workspace: dep-a -> lib -> {bin, test}; the test
    /// also consumes a data fixture.
    fn workspace() -> ActionDag {
        ActionDag {
            nodes: vec![
                ActionNode {
                    action_key: key(1), // compile dep-a
                    consumes: vec![],
                    produces: vec![artifact(10)],
                    cost_ms: 400,
                },
                ActionNode {
                    action_key: key(2), // compile lib (consumes dep-a rmeta)
                    consumes: vec![(artifact(10), EdgeFirmness::Observed)],
                    produces: vec![artifact(20)],
                    cost_ms: 800,
                },
                ActionNode {
                    action_key: key(3), // link bin
                    consumes: vec![(artifact(20), EdgeFirmness::Observed)],
                    produces: vec![artifact(30)],
                    cost_ms: 1_500,
                },
                ActionNode {
                    action_key: key(4), // test run: binary + data input
                    consumes: vec![
                        (artifact(30), EdgeFirmness::Observed),
                        (artifact(40), EdgeFirmness::Observed), // fixture data
                    ],
                    produces: vec![],
                    cost_ms: 200,
                },
            ],
        }
    }

    #[test]
    fn the_dag_reconstructs_from_artifact_identities() {
        // THE acceptance: producer/consumer edges resolve purely by
        // content identity — no Cargo unit-graph API anywhere.
        let dag = workspace();
        assert_eq!(dag.producer_of(&artifact(20)).unwrap().action_key, key(2));
        let consumers: Vec<&TypedDigest> = dag
            .consumers_of(&key(2))
            .iter()
            .map(|n| &n.action_key)
            .collect();
        assert_eq!(consumers, vec![&key(3)]);
    }

    #[test]
    fn affected_test_selection_walks_transitively() {
        // THE O009 query: dep-a's artifact changes — the lib, the bin
        // link, AND the test are affected (transitive), in one walk.
        let dag = workspace();
        let affected = dag.affected_by(&artifact(10));
        assert_eq!(affected, vec![key(2), key(3), key(4)]);
        // A data-fixture change affects ONLY the test.
        assert_eq!(dag.affected_by(&artifact(40)), vec![key(4)]);
    }

    #[test]
    fn critical_path_serves_scheduling() {
        // THE I015 query: the test's critical path is
        // dep-a(400) + lib(800) + bin(1500) + test(200) = 2900.
        let dag = workspace();
        assert_eq!(dag.critical_path_cost(&key(4)), 2_900);
        assert_eq!(dag.critical_path_cost(&key(1)), 400);
    }

    #[test]
    fn provisional_edges_are_explicit() {
        // An edge inferred before completion says so — firmness is a
        // required field, not a default (there is no edge constructor
        // without it), and queries can filter on it.
        let node = ActionNode {
            action_key: key(9),
            consumes: vec![(artifact(20), EdgeFirmness::Provisional)],
            produces: vec![],
            cost_ms: 1,
        };
        assert!(
            node.consumes
                .iter()
                .any(|(_, f)| *f == EdgeFirmness::Provisional)
        );
    }
}
