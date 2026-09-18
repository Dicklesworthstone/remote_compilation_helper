//! T029 fuzz corpus: manifest cycles, closure bounds and pack range
//! overlap (beads H031/H030; risks R95/R81).
//!
//! H031 ships a hand-built corpus — a self-cycle, a two-node cycle, a
//! depth bomb, a fan-out bomb, dangling references, a diamond DAG that
//! must still ADMIT — and H030's concurrent mixed-profile race covers
//! the representation half, which its close reason defers to this bead
//! for the fuzz harness. Hand-built cases prove the validator handles
//! the shapes someone thought of. A corpus asks whether it handles the
//! ones nobody did.
//!
//! Three things make this a corpus rather than a loop of assertions:
//!
//! - **Clean graphs must ADMIT.** A validator that rejects everything
//!   passes any suite built only from attacks, so every iteration first
//!   proves a randomly shaped DAG — including shared subtrees, which are
//!   not cycles — is accepted.
//! - **Coverage is asserted, not hoped.** Every attack class must appear
//!   in the corpus; a generator that silently stopped producing depth
//!   bombs would otherwise leave that arm untested while still passing.
//! - **The bound ORDER is checked, not just the bounds.** H031's rule is
//!   that limits are counters enforced DURING traversal, so a hostile
//!   graph is refused before allocation-heavy expansion. A fan-out bomb
//!   whose children are all dangling distinguishes the two: checking
//!   fan-out before descent gives `FanoutExceeded`; descending first
//!   gives `DanglingReference`. Only the first is bounded work.
//!
//! This suite passed on its first run, which for a fuzz corpus is when
//! to distrust it, so it was mutation-tested against a verbatim copy of
//! `closure_validation.rs` (stub `ObjectId`, outside the workspace).
//! Five mutants, five killed: cycle detection disabled (fuzz RED),
//! fan-out moved after descent (ordering + fuzz RED), the pack overlap
//! check disabled (pack RED), the pack bounds + overflow checks disabled
//! (pack RED), and both validators made to reject unconditionally (ALL
//! FIVE RED — no vacuous pass). What that does NOT establish: these are
//! hand-picked mutants, not a mutation-coverage score, and nothing here
//! exercises the callers of these two functions.

use rabs_cas::closure_validation::{
    ClosureError, GraphBounds, ManifestNode, PackError, PackMember, validate_closure,
    validate_pack_ranges,
};
use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};

/// splitmix64 — the deterministic generator the sibling fuzz corpora use.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }
}

/// Small bounds keep the corpus fast while still exercising every limit.
const FUZZ_BOUNDS: GraphBounds = GraphBounds {
    max_depth: 8,
    max_fanout: 6,
    max_nodes: 64,
};

fn id(tag: u64) -> ObjectId {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&tag.to_be_bytes());
    ObjectId(TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: "rabs.object.sha256.v1",
        bytes,
    })
}

/// Build a random DAG whose every node is reachable from node 0.
///
/// A spine (`i -> i+1`) guarantees reachability, so an injected back
/// edge is guaranteed to CLOSE a cycle rather than merely add an edge —
/// a fuzzer whose "cycle" injections sometimes produced valid DAGs would
/// report coverage it did not have. Extra edges only ever point forward,
/// which is what keeps the clean graph acyclic by construction.
fn random_dag(rng: &mut Rng, size: usize) -> Vec<ManifestNode> {
    (0..size)
        .map(|i| {
            let mut references = Vec::new();
            if i + 1 < size {
                references.push(id(i as u64 + 1)); // the spine
            }
            // A few extra forward edges: shared subtrees and diamonds.
            let extra = rng.below(3);
            for _ in 0..extra {
                let span = size - i - 1;
                if span > 1 {
                    let target = i + 2 + rng.below(span - 1);
                    if target < size {
                        references.push(id(target as u64));
                    }
                }
            }
            ManifestNode {
                id: id(i as u64),
                references,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attack {
    SelfCycle,
    BackEdge,
    Dangling,
    FanoutBomb,
    DepthBomb,
}

const ATTACKS: [Attack; 5] = [
    Attack::SelfCycle,
    Attack::BackEdge,
    Attack::Dangling,
    Attack::FanoutBomb,
    Attack::DepthBomb,
];

/// Inject one attack, returning the error it must produce.
fn inject(rng: &mut Rng, nodes: &mut Vec<ManifestNode>, attack: Attack) -> ClosureError {
    let size = nodes.len();
    match attack {
        Attack::SelfCycle => {
            let victim = rng.below(size);
            nodes[victim].references.push(id(victim as u64));
            ClosureError::Cycle(id(victim as u64))
        }
        Attack::BackEdge => {
            // DFS follows the spine first, so the stack on reaching node
            // `from` is exactly [0, 1, .., from]. An edge back to any
            // earlier node therefore always re-enters an ancestor — the
            // injection cannot silently degrade into a valid forward
            // edge, which would be coverage this suite did not have. The
            // reported identity is the ancestor re-entered, the target.
            let from = 1 + rng.below(size - 1);
            let to = rng.below(from);
            nodes[from].references.push(id(to as u64));
            ClosureError::Cycle(id(to as u64))
        }
        Attack::Dangling => {
            let victim = rng.below(size);
            let missing = id(10_000 + victim as u64);
            nodes[victim].references.push(missing.clone());
            ClosureError::DanglingReference(missing)
        }
        Attack::FanoutBomb => {
            // Children are all DANGLING on purpose: fan-out must be
            // rejected before any descent, so the error must name fan-out
            // and not the missing children.
            let victim = rng.below(size);
            for k in 0..=FUZZ_BOUNDS.max_fanout {
                nodes[victim].references.push(id(20_000 + k as u64));
            }
            ClosureError::FanoutExceeded(id(victim as u64))
        }
        Attack::DepthBomb => {
            // Extend the spine past max_depth with fresh nodes.
            let mut previous = size - 1;
            for k in 0..=FUZZ_BOUNDS.max_depth {
                let fresh = 30_000 + k;
                nodes[previous].references.push(id(fresh as u64));
                nodes.push(ManifestNode {
                    id: id(fresh as u64),
                    references: Vec::new(),
                });
                previous = nodes.len() - 1;
            }
            ClosureError::DepthExceeded
        }
    }
}

#[test]
fn t029_closure_fuzz_admits_clean_dags_and_rejects_every_injected_attack() {
    let mut rng = Rng(0x7029_0000_0000_0001);
    let mut seen = Vec::new();
    let mut clean_admitted = 0usize;

    for iteration in 0..600u64 {
        // Keep graphs shallow enough that a clean DAG cannot trip the
        // depth bound by accident — the clean half must be clean for a
        // reason, not by luck.
        let size = 2 + rng.below(FUZZ_BOUNDS.max_depth - 1);
        let clean = random_dag(&mut rng, size);

        // 1. The clean graph must ADMIT. This is the half that makes the
        //    attack half meaningful.
        assert_eq!(
            validate_closure(&id(0), &clean, FUZZ_BOUNDS),
            Ok(()),
            "iteration {iteration}: a forward-only DAG of {size} nodes must validate"
        );
        clean_admitted += 1;

        // 2. The same graph with exactly one attack must reject, with the
        //    error that names the attack.
        let attack = ATTACKS[rng.below(ATTACKS.len())];
        let mut hostile = clean.clone();
        let expected = inject(&mut rng, &mut hostile, attack);
        let actual = match validate_closure(&id(0), &hostile, FUZZ_BOUNDS) {
            Ok(()) => panic!("iteration {iteration}: {attack:?} must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            actual, expected,
            "iteration {iteration}: {attack:?} produced the wrong refusal"
        );
        if !seen.contains(&attack) {
            seen.push(attack);
        }
    }

    assert_eq!(
        clean_admitted, 600,
        "every clean graph must have been admitted"
    );
    for attack in ATTACKS {
        assert!(
            seen.contains(&attack),
            "the corpus never generated {attack:?}: that arm is untested, not passing"
        );
    }
}

#[test]
fn t029_bounds_are_counters_checked_before_expansion_not_after() {
    // H031's doctrine is that a hostile graph is refused BEFORE
    // allocation-heavy expansion. Two shapes distinguish "checked as a
    // counter during traversal" from "checked after building something".
    //
    // Fan-out bomb whose children are all dangling: fan-out first gives
    // FanoutExceeded, descending first gives DanglingReference.
    let victim = ManifestNode {
        id: id(0),
        references: (0..=FUZZ_BOUNDS.max_fanout)
            .map(|k| id(20_000 + k as u64))
            .collect(),
    };
    assert_eq!(
        validate_closure(&id(0), &[victim], FUZZ_BOUNDS),
        Err(ClosureError::FanoutExceeded(id(0))),
        "fan-out must be refused before descending into the children"
    );

    // Depth bomb whose deepest node is dangling: depth first gives
    // DepthExceeded, following references first gives DanglingReference.
    let mut chain: Vec<ManifestNode> = (0..=FUZZ_BOUNDS.max_depth as u64)
        .map(|i| ManifestNode {
            id: id(i),
            references: vec![id(i + 1)],
        })
        .collect();
    chain.push(ManifestNode {
        id: id(FUZZ_BOUNDS.max_depth as u64 + 1),
        references: vec![id(99_999)], // dangling, one step past the bound
    });
    assert_eq!(
        validate_closure(&id(0), &chain, FUZZ_BOUNDS),
        Err(ClosureError::DepthExceeded),
        "depth must be refused before the traversal reaches deeper references"
    );
}

#[test]
fn t029_a_wide_shallow_tree_is_stopped_by_the_node_budget() {
    // The remaining bound. Depth and fan-out both catch a graph that is
    // pathological in ONE dimension; a graph that stays legal in both and
    // is simply enormous — fan-out 4, depth 4, every node distinct — is
    // caught only by the node budget. Without it a manifest could be
    // legal at every node and still exhaust memory, which is exactly the
    // allocation bomb R95 names.
    let fanout = 4u64;
    let depth = 4u64;
    assert!(fanout <= FUZZ_BOUNDS.max_fanout as u64 && depth <= FUZZ_BOUNDS.max_depth as u64);

    let mut nodes = Vec::new();
    let mut frontier = vec![0u64];
    let mut next = 1u64;
    for _ in 0..depth {
        let mut children_of_level = Vec::new();
        for parent in frontier {
            let children: Vec<u64> = (0..fanout)
                .map(|_| {
                    let child = next;
                    next += 1;
                    child
                })
                .collect();
            nodes.push(ManifestNode {
                id: id(parent),
                references: children.iter().map(|c| id(*c)).collect(),
            });
            children_of_level.extend(children);
        }
        frontier = children_of_level;
    }
    for leaf in frontier {
        nodes.push(ManifestNode {
            id: id(leaf),
            references: Vec::new(),
        });
    }
    assert!(
        nodes.len() > FUZZ_BOUNDS.max_nodes,
        "the fixture must actually exceed the budget it is testing"
    );

    assert_eq!(
        validate_closure(&id(0), &nodes, FUZZ_BOUNDS),
        Err(ClosureError::NodeCountExceeded),
        "a legal-at-every-node but oversized graph must still be refused"
    );

    // And the budget is a budget, not a blanket refusal of large graphs:
    // the same shape validates when the bound allows it.
    let generous = GraphBounds {
        max_nodes: nodes.len() + 1,
        ..FUZZ_BOUNDS
    };
    assert_eq!(validate_closure(&id(0), &nodes, generous), Ok(()));
}

#[test]
fn t029_a_shared_subtree_is_not_a_cycle_however_often_it_is_reached() {
    // The false-positive that matters most: a diamond is a DAG. Fuzzing
    // random forward edges already produces these, but pinning it
    // explicitly keeps the intent legible — an implementation that
    // treated "already visited" as "cycle" would pass an attacks-only
    // suite and reject half of real manifests.
    let shared = id(3);
    let nodes = vec![
        ManifestNode {
            id: id(0),
            references: vec![id(1), id(2)],
        },
        ManifestNode {
            id: id(1),
            references: vec![shared.clone()],
        },
        ManifestNode {
            id: id(2),
            references: vec![shared.clone()],
        },
        ManifestNode {
            id: shared,
            references: Vec::new(),
        },
    ];
    assert_eq!(validate_closure(&id(0), &nodes, FUZZ_BOUNDS), Ok(()));
}

/// Cut `pack_len` into `count` contiguous non-empty members.
fn random_cut(rng: &mut Rng, pack_len: u64, count: usize) -> Vec<PackMember> {
    let mut members = Vec::new();
    let mut offset = 0u64;
    for i in 0..count {
        let remaining = pack_len - offset;
        let left = (count - i) as u64;
        // Leave at least one byte for each remaining member.
        let max_here = remaining - (left - 1);
        let length = 1 + (rng.next() % max_here);
        members.push(PackMember { offset, length });
        offset += length;
    }
    // Absorb any remainder into the last member so the cut is exact.
    if let Some(last) = members.last_mut() {
        last.length = pack_len - last.offset;
    }
    members
}

#[test]
fn t029_pack_fuzz_admits_valid_cuts_in_any_order_and_rejects_every_violation() {
    let mut rng = Rng(0x7029_0000_0000_0002);
    let mut seen: Vec<&'static str> = Vec::new();

    for iteration in 0..600u64 {
        let pack_len = 16 + rng.next() % 4_096;
        let count = 1 + rng.below(8);
        let mut members = random_cut(&mut rng, pack_len, count);

        // Order independence: the validator sorts, so a shuffled cut is
        // the same cut. Reversing is the cheapest shuffle that is never a
        // no-op for count > 1.
        if rng.next().is_multiple_of(2) {
            members.reverse();
        }
        assert_eq!(
            validate_pack_ranges(&members, pack_len),
            Ok(()),
            "iteration {iteration}: an exact cut of {pack_len} into {count} must validate"
        );

        // One injected violation.
        let mut hostile = members.clone();
        let (expected, label) = match rng.below(4) {
            0 => {
                // Overlap: stretch one member over its neighbour. Needs
                // two members to be meaningful.
                if hostile.len() < 2 {
                    continue;
                }
                hostile.sort_by_key(|m| m.offset);
                hostile[0].length += 1;
                (PackError::Overlap, "overlap")
            }
            1 => {
                hostile.sort_by_key(|m| m.offset);
                let last = hostile.len() - 1;
                hostile[last].length += 1; // past the declared pack end
                (PackError::OutOfBounds, "out-of-bounds")
            }
            2 => {
                let victim = rng.below(hostile.len());
                hostile[victim].length = 0;
                (PackError::EmptyMember, "zero-length")
            }
            _ => {
                // offset + length must not wrap into a "valid" range.
                hostile.push(PackMember {
                    offset: u64::MAX - 1,
                    length: 16,
                });
                (PackError::OutOfBounds, "overflow")
            }
        };
        assert_eq!(
            validate_pack_ranges(&hostile, pack_len),
            Err(expected),
            "iteration {iteration}: {label} must be refused"
        );
        if !seen.contains(&label) {
            seen.push(label);
        }
    }

    for label in ["overlap", "out-of-bounds", "zero-length", "overflow"] {
        assert!(
            seen.contains(&label),
            "the pack corpus never generated {label}: that arm is untested, not passing"
        );
    }
}
