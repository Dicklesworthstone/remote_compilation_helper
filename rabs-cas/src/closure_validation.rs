//! Manifest-closure, depth/fan-out, and pack range validation (bead
//! H031; plan §92; risk R95).
//!
//! Manifests reference other manifests and objects by digest; packs
//! carry member ranges into one blob. Attacker-shaped or corrupted
//! graphs can encode cycles (infinite traversal), pathological
//! depth/fan-out (allocation bombs), dangling references (closure
//! holes), and overlapping or out-of-bounds pack ranges (aliased
//! bytes). Validation rejects ALL of it with BOUNDED work.
//!
//! The claimed closure is bounded before indexing. An iterative DFS
//! visits each reachable node and edge once, without consuming the
//! process stack. Completed nodes retain their longest descendant path:
//! sharing a subtree cannot hide an over-depth path through another
//! parent, even when the shallow path was visited first.

use std::collections::HashMap;

use rabs_protocol::result_identity::ObjectId;

/// Bounds for manifest graphs (fleet policy; conservative defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphBounds {
    /// Maximum reference depth, measured in edges from the root.
    pub max_depth: usize,
    /// Maximum children per node.
    pub max_fanout: usize,
    /// Maximum entries in the supplied closure, including unreachable
    /// entries. Checked before allocating the lookup index.
    pub max_nodes: usize,
}

/// Conservative defaults.
pub const DEFAULT_BOUNDS: GraphBounds = GraphBounds {
    max_depth: 64,
    max_fanout: 65_536,
    max_nodes: 1_048_576,
};

/// One manifest node in the reference graph: its identity and the
/// identities it references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestNode {
    /// This manifest's object identity.
    pub id: ObjectId,
    /// Referenced object/manifest identities.
    pub references: Vec<ObjectId>,
}

/// Graph-validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClosureError {
    /// A reference cycle (the offending identity).
    Cycle(ObjectId),
    /// Depth bound exceeded.
    DepthExceeded,
    /// Fan-out bound exceeded at a node.
    FanoutExceeded(ObjectId),
    /// Node-count bound exceeded.
    NodeCountExceeded,
    /// A referenced identity is absent from the closure.
    DanglingReference(ObjectId),
    /// The claimed closure defines an identity more than once. Even
    /// identical duplicates are refused rather than making lookup order
    /// or a consumer's choice of duplicate part of the graph's meaning.
    DuplicateNode(ObjectId),
}

#[derive(Clone, Copy)]
enum VisitState {
    Unseen,
    Active,
    /// Longest path from this node to a reachable leaf, in edges.
    Complete(usize),
}

struct Frame {
    node: usize,
    next_child: usize,
    height: usize,
}

/// Validate the manifest graph rooted at `root`: acyclic, bounded,
/// closed. `nodes` is the claimed closure (id → node).
///
/// The input count, duplicate identities and fan-out are checked before
/// traversal. Reachable nodes are indexed, not repeatedly searched, and
/// completed subtree heights are checked at EVERY incoming edge. Work is
/// linear in the supplied nodes and reachable edges (expected hash-map
/// lookup cost); memory is linear in the supplied nodes, not path count.
///
/// # Errors
/// The first [`ClosureError`] encountered.
pub fn validate_closure(
    root: &ObjectId,
    nodes: &[ManifestNode],
    bounds: GraphBounds,
) -> Result<(), ClosureError> {
    if nodes.len() > bounds.max_nodes {
        return Err(ClosureError::NodeCountExceeded);
    }
    let mut index = HashMap::with_capacity(nodes.len());
    for (position, node) in nodes.iter().enumerate() {
        if node.references.len() > bounds.max_fanout {
            return Err(ClosureError::FanoutExceeded(node.id.clone()));
        }
        if index.insert(&node.id, position).is_some() {
            return Err(ClosureError::DuplicateNode(node.id.clone()));
        }
    }
    let Some(&root_index) = index.get(root) else {
        return Err(ClosureError::DanglingReference(root.clone()));
    };
    let mut states = vec![VisitState::Unseen; nodes.len()];
    states[root_index] = VisitState::Active;
    let mut stack = vec![Frame {
        node: root_index,
        next_child: 0,
        height: 0,
    }];

    while let Some(mut frame) = stack.pop() {
        // After popping, the remaining frames are exactly this node's
        // ancestors. No recursion or caller-selected stack depth is used.
        let depth = stack.len();
        let node = &nodes[frame.node];
        if let Some(child) = node.references.get(frame.next_child) {
            frame.next_child += 1;
            let child_depth = depth.checked_add(1).ok_or(ClosureError::DepthExceeded)?;
            if child_depth > bounds.max_depth {
                return Err(ClosureError::DepthExceeded);
            }
            let Some(&child_index) = index.get(child) else {
                return Err(ClosureError::DanglingReference(child.clone()));
            };
            match states[child_index] {
                VisitState::Active => return Err(ClosureError::Cycle(child.clone())),
                VisitState::Complete(height) => {
                    // A shallow visit does not prove a deeper incoming
                    // path safe. Account for the ENTIRE cached subtree.
                    if height > bounds.max_depth - child_depth {
                        return Err(ClosureError::DepthExceeded);
                    }
                    let through_child =
                        height.checked_add(1).ok_or(ClosureError::DepthExceeded)?;
                    frame.height = frame.height.max(through_child);
                    stack.push(frame);
                }
                VisitState::Unseen => {
                    stack.push(frame);
                    states[child_index] = VisitState::Active;
                    stack.push(Frame {
                        node: child_index,
                        next_child: 0,
                        height: 0,
                    });
                }
            }
        } else {
            if frame.height > bounds.max_depth - depth {
                return Err(ClosureError::DepthExceeded);
            }
            states[frame.node] = VisitState::Complete(frame.height);
            if let Some(parent) = stack.last_mut() {
                let through_child = frame
                    .height
                    .checked_add(1)
                    .ok_or(ClosureError::DepthExceeded)?;
                parent.height = parent.height.max(through_child);
            }
        }
    }
    Ok(())
}

/// One pack member: byte range inside the pack blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackMember {
    /// Start offset.
    pub offset: u64,
    /// Length.
    pub length: u64,
}

/// Pack-validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackError {
    /// Two members overlap.
    Overlap,
    /// A member extends past the pack end (or overflows).
    OutOfBounds,
    /// Zero-length member.
    EmptyMember,
}

/// Validate pack member ranges: in-bounds, non-overlapping.
///
/// # Errors
/// The first [`PackError`] found.
pub fn validate_pack_ranges(members: &[PackMember], pack_len: u64) -> Result<(), PackError> {
    let mut sorted: Vec<&PackMember> = members.iter().collect();
    sorted.sort_by_key(|m| m.offset);
    let mut previous_end: u64 = 0;
    for member in sorted {
        if member.length == 0 {
            return Err(PackError::EmptyMember);
        }
        let end = member
            .offset
            .checked_add(member.length)
            .ok_or(PackError::OutOfBounds)?;
        if end > pack_len {
            return Err(PackError::OutOfBounds);
        }
        if member.offset < previous_end {
            return Err(PackError::Overlap);
        }
        previous_end = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

    fn id(tag: u8) -> ObjectId {
        ObjectId(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        })
    }

    fn node(tag: u8, refs: &[u8]) -> ManifestNode {
        ManifestNode {
            id: id(tag),
            references: refs.iter().map(|t| id(*t)).collect(),
        }
    }

    #[test]
    fn clean_dags_validate_including_shared_subtrees() {
        // Diamond: 1 -> {2, 3} -> 4 (shared). A DAG, not a cycle.
        let nodes = vec![node(1, &[2, 3]), node(2, &[4]), node(3, &[4]), node(4, &[])];
        assert_eq!(validate_closure(&id(1), &nodes, DEFAULT_BOUNDS), Ok(()));
    }

    #[test]
    fn shared_subtrees_respect_longest_path_in_either_visit_order() {
        // The shallow path 1 -> 2 -> 4 -> 5 has depth 3. Visiting it
        // first must not hide 1 -> 3 -> 2 -> 4 -> 5, whose depth is 4.
        for references in [[2, 3], [3, 2]] {
            let mut nodes = vec![
                node(1, &references),
                node(2, &[4]),
                node(3, &[2]),
                node(4, &[5]),
                node(5, &[]),
            ];
            for _ in 0..2 {
                assert_eq!(
                    validate_closure(
                        &id(1),
                        &nodes,
                        GraphBounds {
                            max_depth: 3,
                            ..DEFAULT_BOUNDS
                        },
                    ),
                    Err(ClosureError::DepthExceeded)
                );
                assert_eq!(
                    validate_closure(
                        &id(1),
                        &nodes,
                        GraphBounds {
                            max_depth: 4,
                            ..DEFAULT_BOUNDS
                        },
                    ),
                    Ok(())
                );
                nodes.reverse();
            }
        }
    }

    #[test]
    fn duplicate_identities_cannot_hide_a_different_graph() {
        for duplicate in [node(1, &[]), node(1, &[1]), node(1, &[99])] {
            let mut nodes = vec![node(1, &[]), duplicate];
            for _ in 0..2 {
                assert_eq!(
                    validate_closure(&id(1), &nodes, DEFAULT_BOUNDS),
                    Err(ClosureError::DuplicateNode(id(1)))
                );
                nodes.reverse();
            }
        }
    }

    #[test]
    fn input_budget_and_zero_depth_are_enforced() {
        let root_only = [node(1, &[])];
        let zero_depth = GraphBounds {
            max_depth: 0,
            max_fanout: 1,
            max_nodes: 1,
        };
        assert_eq!(validate_closure(&id(1), &root_only, zero_depth), Ok(()));
        assert_eq!(
            validate_closure(
                &id(1),
                &root_only,
                GraphBounds {
                    max_nodes: 0,
                    ..zero_depth
                },
            ),
            Err(ClosureError::NodeCountExceeded)
        );
        assert_eq!(
            validate_closure(&id(1), &[], zero_depth),
            Err(ClosureError::DanglingReference(id(1)))
        );
        assert_eq!(
            validate_closure(&id(1), &[node(1, &[1])], zero_depth),
            Err(ClosureError::DepthExceeded)
        );
        // Unreachable padding must not bypass the pre-allocation budget.
        assert_eq!(
            validate_closure(&id(1), &[node(1, &[]), node(2, &[])], zero_depth),
            Err(ClosureError::NodeCountExceeded)
        );
    }

    #[test]
    fn large_depth_policy_does_not_recurse_on_process_stack() {
        fn numbered_id(number: usize) -> ObjectId {
            let mut object = id(0);
            object.0.bytes[..8].copy_from_slice(&u64::try_from(number).unwrap().to_be_bytes());
            object
        }
        let count = 20_000;
        let nodes: Vec<_> = (0..count)
            .map(|number| ManifestNode {
                id: numbered_id(number),
                references: if number + 1 == count {
                    Vec::new()
                } else {
                    vec![numbered_id(number + 1)]
                },
            })
            .collect();
        let result = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                validate_closure(
                    &numbered_id(0),
                    &nodes,
                    GraphBounds {
                        max_depth: usize::MAX,
                        max_fanout: 1,
                        max_nodes: count,
                    },
                )
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn cycle_corpus_rejected_before_heavy_traversal() {
        // Self-cycle.
        let self_cycle = vec![node(1, &[1])];
        assert_eq!(
            validate_closure(&id(1), &self_cycle, DEFAULT_BOUNDS),
            Err(ClosureError::Cycle(id(1)))
        );
        // Two-node cycle reached through a chain.
        let chained = vec![node(1, &[2]), node(2, &[3]), node(3, &[2])];
        assert_eq!(
            validate_closure(&id(1), &chained, DEFAULT_BOUNDS),
            Err(ClosureError::Cycle(id(2)))
        );
    }

    #[test]
    fn bounds_and_closure_holes_reject() {
        // Depth bomb: a chain longer than max_depth.
        let tight = GraphBounds {
            max_depth: 3,
            max_fanout: 10,
            max_nodes: 100,
        };
        let chain = vec![
            node(1, &[2]),
            node(2, &[3]),
            node(3, &[4]),
            node(4, &[5]),
            node(5, &[]),
        ];
        assert_eq!(
            validate_closure(&id(1), &chain, tight),
            Err(ClosureError::DepthExceeded)
        );
        // Fan-out bomb.
        let wide_refs: Vec<u8> = (10..=30).collect();
        let mut wide = vec![ManifestNode {
            id: id(1),
            references: wide_refs.iter().map(|t| id(*t)).collect(),
        }];
        wide.extend(wide_refs.iter().map(|t| node(*t, &[])));
        assert_eq!(
            validate_closure(&id(1), &wide, tight),
            Err(ClosureError::FanoutExceeded(id(1)))
        );
        // Dangling reference: not closed under referenced identity.
        let dangling = vec![node(1, &[2])];
        assert_eq!(
            validate_closure(&id(1), &dangling, DEFAULT_BOUNDS),
            Err(ClosureError::DanglingReference(id(2)))
        );
    }

    #[test]
    fn pack_range_corpus_rejected() {
        // Clean pack.
        let ok = [
            PackMember {
                offset: 0,
                length: 10,
            },
            PackMember {
                offset: 10,
                length: 5,
            },
            PackMember {
                offset: 20,
                length: 4,
            },
        ];
        assert_eq!(validate_pack_ranges(&ok, 24), Ok(()));
        // Overlap (order-independent: unsorted input still caught).
        let overlap = [
            PackMember {
                offset: 8,
                length: 5,
            },
            PackMember {
                offset: 0,
                length: 10,
            },
        ];
        assert_eq!(validate_pack_ranges(&overlap, 100), Err(PackError::Overlap));
        // Out of bounds.
        let oob = [PackMember {
            offset: 20,
            length: 10,
        }];
        assert_eq!(validate_pack_ranges(&oob, 25), Err(PackError::OutOfBounds));
        // Offset+length overflow must not wrap into "valid".
        let wrap = [PackMember {
            offset: u64::MAX - 1,
            length: 10,
        }];
        assert_eq!(
            validate_pack_ranges(&wrap, u64::MAX),
            Err(PackError::OutOfBounds)
        );
        // Zero-length member.
        let empty = [PackMember {
            offset: 0,
            length: 0,
        }];
        assert_eq!(
            validate_pack_ranges(&empty, 10),
            Err(PackError::EmptyMember)
        );
    }
}
