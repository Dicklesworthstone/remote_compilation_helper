//! Manifest-closure, depth/fan-out, and pack range validation (bead
//! H031; plan §92; risk R95).
//!
//! Manifests reference other manifests and objects by digest; packs
//! carry member ranges into one blob. Attacker-shaped or corrupted
//! graphs can encode cycles (infinite traversal), pathological
//! depth/fan-out (allocation bombs), dangling references (closure
//! holes), and overlapping or out-of-bounds pack ranges (aliased
//! bytes). Validation rejects ALL of it with BOUNDED work — limits are
//! checked as counters during one traversal, so a hostile graph is
//! refused before any allocation-heavy expansion.

use rabs_protocol::result_identity::ObjectId;

/// Bounds for manifest graphs (fleet policy; conservative defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphBounds {
    /// Maximum reference depth.
    pub max_depth: usize,
    /// Maximum children per node.
    pub max_fanout: usize,
    /// Maximum total nodes visited.
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
}

/// Validate the manifest graph rooted at `root`: acyclic, bounded,
/// closed. `nodes` is the claimed closure (id → node).
///
/// # Errors
/// The first [`ClosureError`] encountered.
pub fn validate_closure(
    root: &ObjectId,
    nodes: &[ManifestNode],
    bounds: GraphBounds,
) -> Result<(), ClosureError> {
    fn visit(
        id: &ObjectId,
        nodes: &[ManifestNode],
        bounds: GraphBounds,
        depth: usize,
        stack: &mut Vec<ObjectId>,
        visited: &mut Vec<ObjectId>,
    ) -> Result<(), ClosureError> {
        if depth > bounds.max_depth {
            return Err(ClosureError::DepthExceeded);
        }
        if stack.contains(id) {
            return Err(ClosureError::Cycle(id.clone()));
        }
        if visited.contains(id) {
            return Ok(()); // shared subtree (DAG): fine, already checked
        }
        if visited.len() >= bounds.max_nodes {
            return Err(ClosureError::NodeCountExceeded);
        }
        let Some(node) = nodes.iter().find(|n| n.id == *id) else {
            return Err(ClosureError::DanglingReference(id.clone()));
        };
        if node.references.len() > bounds.max_fanout {
            return Err(ClosureError::FanoutExceeded(id.clone()));
        }
        visited.push(id.clone());
        stack.push(id.clone());
        for reference in &node.references {
            visit(reference, nodes, bounds, depth + 1, stack, visited)?;
        }
        stack.pop();
        Ok(())
    }
    let mut stack = Vec::new();
    let mut visited = Vec::new();
    visit(root, nodes, bounds, 0, &mut stack, &mut visited)
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
