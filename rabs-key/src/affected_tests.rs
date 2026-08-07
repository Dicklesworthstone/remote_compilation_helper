//! Affected-test advisory graph (bead O009; plan §102; serves the
//! agent inner loop; built on the M009 action DAG).
//!
//! Given changed source/artifact/data identities, suggest which test
//! actions are affected — so an agent inner loop runs the twelve
//! tests that matter instead of the whole suite. Two hard rules:
//!
//! - ADVISORY ONLY: the suggestion orders and selects test RUNS; it
//!   never feeds cache keys or serving decisions. Result-cache
//!   correctness is carried entirely by the F-series keys — the
//!   suggestion type has no serving field to misuse (structural).
//! - FAIL-SAFE over-approximation: a changed identity the DAG has
//!   never seen suggests EVERY test (recall stays total; precision
//!   pays, and the measurement says so honestly).
//!
//! Precision/recall are measured against ground truth computed by an
//! INDEPENDENT walk (upstream input closure per test, not the
//! downstream suggestion walk) — two implementations must agree.

use rabs_protocol::result_identity::TypedDigest;

use crate::action_dag::ActionDag;

/// The advisory suggestion: which test actions to run. Nothing here
/// is a serving decision — there is no field for one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisorySuggestion {
    /// Suggested test action keys, in DAG walk order.
    pub suggested: Vec<TypedDigest>,
    /// True when an unknown changed identity forced the fail-safe
    /// full-suite suggestion.
    pub over_approximated: bool,
}

/// Suggest affected tests for a set of changed identities.
///
/// `tests` — the test-action keys of the suite (the O002 keys).
#[must_use]
pub fn suggest(
    dag: &ActionDag,
    changed: &[TypedDigest],
    tests: &[TypedDigest],
) -> AdvisorySuggestion {
    // An identity the DAG has never seen: fail safe, suggest all.
    let known = |artifact: &TypedDigest| {
        dag.nodes
            .iter()
            .any(|n| n.produces.contains(artifact) || n.consumes.iter().any(|(a, _)| a == artifact))
    };
    if changed.iter().any(|c| !known(c)) {
        return AdvisorySuggestion {
            suggested: tests.to_vec(),
            over_approximated: true,
        };
    }
    let mut suggested = Vec::new();
    for change in changed {
        for affected in dag.affected_by(change) {
            if tests.contains(&affected) && !suggested.contains(&affected) {
                suggested.push(affected);
            }
        }
    }
    AdvisorySuggestion {
        suggested,
        over_approximated: false,
    }
}

/// Ground truth by the INDEPENDENT walk: a test is truly affected
/// when its transitive upstream input closure contains a changed
/// identity.
#[must_use]
pub fn ground_truth(
    dag: &ActionDag,
    changed: &[TypedDigest],
    tests: &[TypedDigest],
) -> Vec<TypedDigest> {
    tests
        .iter()
        .filter(|test| {
            let closure = upstream_closure(dag, test);
            changed.iter().any(|c| closure.contains(c))
        })
        .cloned()
        .collect()
}

/// Every artifact transitively consumed by an action (upstream).
fn upstream_closure(dag: &ActionDag, action_key: &TypedDigest) -> Vec<TypedDigest> {
    let mut closure: Vec<TypedDigest> = Vec::new();
    let mut frontier = vec![action_key.clone()];
    while let Some(key) = frontier.pop() {
        let Some(node) = dag.nodes.iter().find(|n| n.action_key == key) else {
            continue;
        };
        for (artifact, _) in &node.consumes {
            if !closure.contains(artifact) {
                closure.push(artifact.clone());
                if let Some(producer) = dag.producer_of(artifact) {
                    frontier.push(producer.action_key.clone());
                }
            }
        }
    }
    closure
}

/// Precision/recall of a suggestion against ground truth, in
/// permille (deterministic integers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecisionRecall {
    /// Of the suggested tests, how many were truly affected.
    pub precision_permille: u32,
    /// Of the truly affected tests, how many were suggested.
    pub recall_permille: u32,
}

/// Measure a suggestion. Empty denominators score 1000 (a suggestion
/// of nothing when nothing was affected is perfect, not undefined).
#[must_use]
pub fn measure(suggested: &[TypedDigest], truth: &[TypedDigest]) -> PrecisionRecall {
    let permille = |hits: usize, total: usize| -> u32 {
        // An empty denominator scores perfect, not undefined.
        (hits * 1_000)
            .checked_div(total)
            .map_or(1_000, |v| u32::try_from(v).unwrap_or(0))
    };
    let true_positives = suggested.iter().filter(|s| truth.contains(s)).count();
    PrecisionRecall {
        precision_permille: permille(true_positives, suggested.len()),
        recall_permille: permille(true_positives, truth.len()),
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

    /// dep-a → lib → {bin → test1, test2}; a data fixture feeds only
    /// test1; test3 exercises an unrelated crate.
    fn workspace() -> ActionDag {
        let observed = |tag: u8| (artifact(tag), EdgeFirmness::Observed);
        ActionDag {
            nodes: vec![
                ActionNode {
                    action_key: key(1), // compile dep-a
                    consumes: vec![],
                    produces: vec![artifact(10)],
                    cost_ms: 400,
                },
                ActionNode {
                    action_key: key(2), // compile lib
                    consumes: vec![observed(10)],
                    produces: vec![artifact(20)],
                    cost_ms: 800,
                },
                ActionNode {
                    action_key: key(3), // link bin
                    consumes: vec![observed(20)],
                    produces: vec![artifact(30)],
                    cost_ms: 1_500,
                },
                ActionNode {
                    action_key: key(4), // test1: bin + data fixture
                    consumes: vec![observed(30), observed(40)],
                    produces: vec![],
                    cost_ms: 200,
                },
                ActionNode {
                    action_key: key(5), // test2: lib directly
                    consumes: vec![observed(20)],
                    produces: vec![],
                    cost_ms: 150,
                },
                ActionNode {
                    action_key: key(6), // unrelated crate
                    consumes: vec![],
                    produces: vec![artifact(60)],
                    cost_ms: 300,
                },
                ActionNode {
                    action_key: key(7), // test3: unrelated crate only
                    consumes: vec![observed(60)],
                    produces: vec![],
                    cost_ms: 100,
                },
            ],
        }
    }

    fn tests_of(dag: &ActionDag) -> Vec<TypedDigest> {
        let _ = dag;
        vec![key(4), key(5), key(7)]
    }

    #[test]
    fn fixture_edits_suggest_exactly_the_affected_tests() {
        // THE acceptance, part 1: suggestions computed per fixture
        // edit, each checked against the independent ground truth.
        let dag = workspace();
        let tests = tests_of(&dag);
        // dep-a edit: test1 (via lib→bin) and test2 (via lib) — not
        // test3.
        let change = [artifact(10)];
        let s = suggest(&dag, &change, &tests);
        // Walk order: test2 (direct lib consumer) surfaces before
        // test1 (reached through the bin link).
        assert_eq!(s.suggested, vec![key(5), key(4)]);
        assert!(!s.over_approximated);
        // Ground truth is suite-ordered; compare as SETS of tests.
        let truth = ground_truth(&dag, &change, &tests);
        assert_eq!(truth, vec![key(4), key(5)]);
        assert!(s.suggested.iter().all(|t| truth.contains(t)));
        assert_eq!(s.suggested.len(), truth.len());
        // Data-fixture edit: ONLY test1.
        let change = [artifact(40)];
        assert_eq!(suggest(&dag, &change, &tests).suggested, vec![key(4)]);
        assert_eq!(ground_truth(&dag, &change, &tests), vec![key(4)]);
        // Unrelated-crate edit: only test3.
        let change = [artifact(60)];
        assert_eq!(suggest(&dag, &change, &tests).suggested, vec![key(7)]);
    }

    #[test]
    fn precision_and_recall_measured_against_full_runs() {
        // THE acceptance, part 2: measurement. On known identities the
        // downstream walk matches the upstream ground truth exactly.
        let dag = workspace();
        let tests = tests_of(&dag);
        for change in [[artifact(10)], [artifact(40)], [artifact(60)]] {
            let s = suggest(&dag, &change, &tests);
            let truth = ground_truth(&dag, &change, &tests);
            let pr = measure(&s.suggested, &truth);
            assert_eq!(pr.precision_permille, 1_000);
            assert_eq!(pr.recall_permille, 1_000);
        }
    }

    #[test]
    fn unknown_identities_fail_safe_to_the_full_suite() {
        // An identity the DAG never saw: suggest EVERYTHING — recall
        // stays total, precision pays, and the record says so.
        let dag = workspace();
        let tests = tests_of(&dag);
        let change = [artifact(99)]; // never observed
        let s = suggest(&dag, &change, &tests);
        assert_eq!(s.suggested, tests);
        assert!(s.over_approximated, "over-approximation is recorded");
        // Honest measurement vs a truth where nothing was affected by
        // the DAG's lights: recall holds at 1000 (empty denominator),
        // precision honestly reports 0.
        let truth = ground_truth(&dag, &change, &tests);
        assert!(truth.is_empty());
        let pr = measure(&s.suggested, &truth);
        assert_eq!(pr.recall_permille, 1_000);
        assert_eq!(pr.precision_permille, 0);
    }

    #[test]
    fn the_suggestion_is_advisory_by_construction() {
        // Structural: the suggestion carries test keys and the over-
        // approximation flag — NOTHING else. No serve/skip/cache
        // field exists to leak advisory data into correctness.
        let AdvisorySuggestion {
            suggested: _,
            over_approximated: _,
        } = suggest(&workspace(), &[artifact(10)], &tests_of(&workspace()));
    }

    #[test]
    fn measurement_edges_are_defined() {
        // Suggesting nothing when something was affected: recall 0.
        let pr = measure(&[], &[key(4)]);
        assert_eq!(pr.recall_permille, 0);
        assert_eq!(pr.precision_permille, 1_000, "empty suggestion set");
        // Nothing affected, nothing suggested: perfect, not NaN.
        let pr = measure(&[], &[]);
        assert_eq!(pr.precision_permille, 1_000);
        assert_eq!(pr.recall_permille, 1_000);
        // Half-wrong suggestion measures 500.
        let pr = measure(&[key(4), key(7)], &[key(4)]);
        assert_eq!(pr.precision_permille, 500);
        assert_eq!(pr.recall_permille, 1_000);
    }
}
