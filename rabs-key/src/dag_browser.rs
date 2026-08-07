//! Action DAG browser + critical-path report (bead R011; plan §105;
//! navigates the M009 DAG; the report must match the I015 estimates).
//!
//! The explanation surface over the provenance DAG:
//!
//! - BROWSE: a node view carries the action's consumed artifacts
//!   (each with its producer, when known) and its downstream
//!   consumers — navigation is link-following, upstream and down;
//! - CRITICAL-PATH REPORT: the actual costed CHAIN ending at an
//!   action, not just the number — and its total is asserted equal
//!   to the M009/I015 `critical_path_cost` estimate (one estimator,
//!   two renderings, no drift);
//! - REBUILD TAIL: for a changed artifact, which actions rebuild and
//!   how long the serial tail is (the longest dependent chain the
//!   change drags behind it).

use rabs_protocol::result_identity::TypedDigest;

use crate::action_dag::ActionDag;

/// One consumed artifact with its producer, when known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedLink {
    /// The artifact.
    pub artifact: TypedDigest,
    /// The producing action, if the DAG knows one.
    pub producer: Option<TypedDigest>,
}

/// A browsable node view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeView {
    /// The action.
    pub action_key: TypedDigest,
    /// Own cost (ms).
    pub cost_ms: u64,
    /// Upstream links.
    pub consumes: Vec<ConsumedLink>,
    /// Downstream consumer actions.
    pub consumers: Vec<TypedDigest>,
}

/// Browse one action.
#[must_use]
pub fn view(dag: &ActionDag, action_key: &TypedDigest) -> Option<NodeView> {
    let node = dag.nodes.iter().find(|n| n.action_key == *action_key)?;
    let consumes = node
        .consumes
        .iter()
        .map(|(artifact, _)| ConsumedLink {
            artifact: artifact.clone(),
            producer: dag.producer_of(artifact).map(|p| p.action_key.clone()),
        })
        .collect();
    let consumers = dag
        .consumers_of(action_key)
        .into_iter()
        .map(|n| n.action_key.clone())
        .collect();
    Some(NodeView {
        action_key: node.action_key.clone(),
        cost_ms: node.cost_ms,
        consumes,
        consumers,
    })
}

/// One step of a critical-path chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStep {
    /// The action at this step.
    pub action_key: TypedDigest,
    /// Its cost (ms).
    pub cost_ms: u64,
}

/// The costed critical-path report for an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalPathReport {
    /// The chain, upstream first, target last.
    pub chain: Vec<ChainStep>,
    /// Total (must equal the I015 estimate).
    pub total_ms: u64,
}

/// The critical-path chain ending at `action_key`.
#[must_use]
pub fn critical_path_report(
    dag: &ActionDag,
    action_key: &TypedDigest,
) -> Option<CriticalPathReport> {
    let node = dag.nodes.iter().find(|n| n.action_key == *action_key)?;
    // The most expensive upstream producer chain, recursively.
    let upstream = node
        .consumes
        .iter()
        .filter_map(|(artifact, _)| dag.producer_of(artifact))
        .map(|producer| critical_path_report(dag, &producer.action_key).expect("producer exists"))
        .max_by_key(|report| report.total_ms);
    let mut chain = upstream
        .as_ref()
        .map(|r| r.chain.clone())
        .unwrap_or_default();
    chain.push(ChainStep {
        action_key: node.action_key.clone(),
        cost_ms: node.cost_ms,
    });
    let total_ms = upstream.map_or(0, |r| r.total_ms) + node.cost_ms;
    Some(CriticalPathReport { chain, total_ms })
}

/// The rebuild tail for a changed artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildTail {
    /// Every action that rebuilds (the O009 walk).
    pub affected: Vec<TypedDigest>,
    /// The serial tail: the longest dependent chain (ms).
    pub tail_ms: u64,
}

fn longest_downstream(dag: &ActionDag, artifact: &TypedDigest) -> u64 {
    dag.nodes
        .iter()
        .filter(|n| n.consumes.iter().any(|(a, _)| a == artifact))
        .map(|consumer| {
            let below = consumer
                .produces
                .iter()
                .map(|out| longest_downstream(dag, out))
                .max()
                .unwrap_or(0);
            consumer.cost_ms + below
        })
        .max()
        .unwrap_or(0)
}

/// Report the rebuild tail behind a changed artifact.
#[must_use]
pub fn rebuild_tail(dag: &ActionDag, changed_artifact: &TypedDigest) -> RebuildTail {
    RebuildTail {
        affected: dag.affected_by(changed_artifact),
        tail_ms: longest_downstream(dag, changed_artifact),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_dag::{ActionNode, EdgeFirmness};
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

    /// The M009 fixture: dep-a → lib → bin → test (+ data fixture).
    fn workspace() -> ActionDag {
        let observed = |tag: u8| (artifact(tag), EdgeFirmness::Observed);
        ActionDag {
            nodes: vec![
                ActionNode {
                    action_key: key(1),
                    consumes: vec![],
                    produces: vec![artifact(10)],
                    cost_ms: 400,
                },
                ActionNode {
                    action_key: key(2),
                    consumes: vec![observed(10)],
                    produces: vec![artifact(20)],
                    cost_ms: 800,
                },
                ActionNode {
                    action_key: key(3),
                    consumes: vec![observed(20)],
                    produces: vec![artifact(30)],
                    cost_ms: 1_500,
                },
                ActionNode {
                    action_key: key(4),
                    consumes: vec![observed(30), observed(40)],
                    produces: vec![],
                    cost_ms: 200,
                },
            ],
        }
    }

    #[test]
    fn the_browser_navigates_by_links_both_directions() {
        let dag = workspace();
        let lib = view(&dag, &key(2)).expect("lib node");
        assert_eq!(lib.cost_ms, 800);
        // Upstream: the consumed artifact links to its producer.
        assert_eq!(
            lib.consumes,
            vec![ConsumedLink {
                artifact: artifact(10),
                producer: Some(key(1)),
            }]
        );
        // Downstream: the bin link consumes lib's output.
        assert_eq!(lib.consumers, vec![key(3)]);
        // Follow the links: up to dep-a (no producers), down to test.
        let dep_a = view(&dag, &key(1)).expect("dep-a");
        assert!(dep_a.consumes.is_empty());
        let test = view(&dag, &key(4)).expect("test");
        // The data fixture has no producer — the link says so
        // honestly instead of inventing one.
        assert_eq!(
            test.consumes[1],
            ConsumedLink {
                artifact: artifact(40),
                producer: None,
            }
        );
        // Unknown key: None, not a panic.
        assert!(view(&dag, &key(99)).is_none());
    }

    #[test]
    fn the_critical_path_report_matches_the_i015_estimate() {
        // THE acceptance: the rendered chain's total equals the M009
        // critical_path_cost estimate exactly.
        let dag = workspace();
        let report = critical_path_report(&dag, &key(4)).expect("report");
        assert_eq!(
            report.chain,
            vec![
                ChainStep {
                    action_key: key(1),
                    cost_ms: 400,
                },
                ChainStep {
                    action_key: key(2),
                    cost_ms: 800,
                },
                ChainStep {
                    action_key: key(3),
                    cost_ms: 1_500,
                },
                ChainStep {
                    action_key: key(4),
                    cost_ms: 200,
                },
            ]
        );
        assert_eq!(report.total_ms, 2_900);
        assert_eq!(
            report.total_ms,
            dag.critical_path_cost(&key(4)),
            "one estimator, two renderings, no drift"
        );
        // And for every node in the fixture, report == estimate.
        for tag in [1, 2, 3, 4] {
            assert_eq!(
                critical_path_report(&dag, &key(tag))
                    .expect("node")
                    .total_ms,
                dag.critical_path_cost(&key(tag))
            );
        }
    }

    #[test]
    fn rebuild_tails_price_a_change() {
        let dag = workspace();
        // dep-a's artifact changes: lib+bin+test rebuild; the serial
        // tail is lib(800)+bin(1500)+test(200) = 2500.
        let tail = rebuild_tail(&dag, &artifact(10));
        assert_eq!(tail.affected, vec![key(2), key(3), key(4)]);
        assert_eq!(tail.tail_ms, 2_500);
        // The data fixture changes: only the test, tail 200.
        let tail = rebuild_tail(&dag, &artifact(40));
        assert_eq!(tail.affected, vec![key(4)]);
        assert_eq!(tail.tail_ms, 200);
        // An unknown artifact drags nothing.
        let tail = rebuild_tail(&dag, &artifact(99));
        assert!(tail.affected.is_empty());
        assert_eq!(tail.tail_ms, 0);
    }
}
