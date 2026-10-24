//! Tree manifests + missing-chunk diff (bead H006; plan §90; risk
//! R25's transfer arm).
//!
//! Large trees (sysroots, registry sets, snapshots) transfer as
//! HIERARCHICAL manifests: every directory node's digest summarizes
//! its subtree, so comparison short-circuits — an unchanged subtree is
//! one digest equality, not a walk. The missing-diff walks only into
//! subtrees whose digests differ and returns exactly the chunk set the
//! receiver lacks.

use crate::closure_validation::{ClosureError, GraphBounds, ManifestNode, validate_closure};
use rabs_protocol::result_identity::{ObjectId, TypedDigest};

/// Domain tag for synthetic file-node identities when projecting a [`TreeNode`]
/// into a [`ManifestNode`] closure graph.
const TREE_FILE_NODE_DOMAIN: &str = "rabs.tree.file.v1";

/// A tree node: leaf (file with chunk digests) or directory (children
/// with a summarizing digest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeNode {
    /// A file: the chunk digests that reassemble it.
    File {
        /// Entry name.
        name: String,
        /// Chunk digests in order.
        chunks: Vec<TypedDigest>,
    },
    /// A directory: children plus the subtree digest that
    /// short-circuits comparison.
    Directory {
        /// Entry name.
        name: String,
        /// The subtree summary digest (computed over children by the
        /// H002 hasher; carried here as data).
        subtree_digest: TypedDigest,
        /// Child nodes, sorted by name.
        children: Vec<TreeNode>,
    },
}

impl TreeNode {
    /// The node's name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::File { name, .. } | Self::Directory { name, .. } => name,
        }
    }

    /// Validate this tree manifest's reference closure against `bounds`
    /// via [`validate_closure`] (`bd-i7zop` / H031 / R95).
    ///
    /// Projects directories by `subtree_digest`, files by path-scoped content
    /// digest, and chunks as leaf nodes. Rejects self-referential directory
    /// digest cycles, conflicting duplicate directory digests, excessive
    /// directory/chunk fan-out, excessive nesting depth, and node-count bombs.
    ///
    /// # Errors
    /// Returns the first [`ClosureError`] found by [`validate_closure`].
    pub fn validate_closure(&self, bounds: GraphBounds) -> Result<(), ClosureError> {
        let mut nodes = Vec::new();
        let mut active_ancestors = Vec::new();
        let root_id = collect_manifest_nodes(
            self,
            b"",
            &mut nodes,
            &mut active_ancestors,
            bounds.max_nodes,
        );
        validate_closure(&root_id, &nodes, bounds)
    }
}

fn file_node_object_id(parent_scope: &[u8], name: &str, chunks: &[TypedDigest]) -> ObjectId {
    let mut payload = Vec::with_capacity(parent_scope.len() + 1 + name.len() + chunks.len() * 32);
    payload.extend_from_slice(&(parent_scope.len() as u64).to_be_bytes());
    payload.extend_from_slice(parent_scope);
    payload.extend_from_slice(&(name.len() as u64).to_be_bytes());
    payload.extend_from_slice(name.as_bytes());
    for chunk in chunks {
        payload.extend_from_slice(chunk.domain.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&chunk.bytes);
    }
    ObjectId(rabs_key::typed_digest::compute(
        TREE_FILE_NODE_DOMAIN,
        &payload,
    ))
}

fn collect_manifest_nodes(
    node: &TreeNode,
    parent_scope: &[u8],
    nodes: &mut Vec<ManifestNode>,
    active_ancestors: &mut Vec<ObjectId>,
    max_nodes: usize,
) -> ObjectId {
    match node {
        TreeNode::File { name, chunks } => {
            let id = file_node_object_id(parent_scope, name, chunks);
            if nodes.len() > max_nodes {
                return id;
            }
            let references: Vec<ObjectId> = chunks.iter().cloned().map(ObjectId).collect();
            for chunk_id in &references {
                if nodes.len() > max_nodes {
                    break;
                }
                if !nodes.iter().any(|existing| &existing.id == chunk_id) {
                    nodes.push(ManifestNode {
                        id: chunk_id.clone(),
                        references: Vec::new(),
                    });
                }
            }
            if nodes.len() <= max_nodes
                && !nodes
                    .iter()
                    .any(|existing| existing.id == id && existing.references == references)
            {
                nodes.push(ManifestNode {
                    id: id.clone(),
                    references,
                });
            }
            id
        }
        TreeNode::Directory {
            name,
            subtree_digest,
            children,
        } => {
            let id = ObjectId(subtree_digest.clone());
            // If an ancestor directory on the current path already claims this
            // subtree_digest, return the id so the ancestor's references form a
            // cycle that `validate_closure` reports as `ClosureError::Cycle`.
            if active_ancestors.contains(&id) || nodes.len() > max_nodes {
                return id;
            }
            let mut scope = Vec::with_capacity(parent_scope.len() + 1 + name.len() + 32);
            scope.extend_from_slice(parent_scope);
            scope.push(b'/');
            scope.extend_from_slice(name.as_bytes());
            scope.extend_from_slice(&subtree_digest.bytes);

            active_ancestors.push(id.clone());
            let mut references = Vec::with_capacity(children.len());
            for child in children {
                let child_id =
                    collect_manifest_nodes(child, &scope, nodes, active_ancestors, max_nodes);
                references.push(child_id);
            }
            active_ancestors.pop();

            // Identical repeated subtrees deduplicate cleanly; conflicting
            // directories under the same digest are both pushed so
            // `validate_closure` rejects them with `ClosureError::DuplicateNode`.
            let identical_exists = nodes
                .iter()
                .any(|existing| existing.id == id && existing.references == references);
            if !identical_exists {
                nodes.push(ManifestNode {
                    id: id.clone(),
                    references,
                });
            }
            id
        }
    }
}

/// Statistics from one diff run (proves the short-circuit happened).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiffStats {
    /// Directory nodes whose digests matched and were SKIPPED whole.
    pub subtrees_skipped: u64,
    /// Nodes actually visited.
    pub nodes_visited: u64,
}

/// Validate `want` (and `have` when present) against `bounds` via
/// [`TreeNode::validate_closure`], then compute the missing chunks (`bd-i7zop`).
///
/// # Errors
/// Returns [`ClosureError`] if either tree violates `bounds` or contains a
/// self-referential or conflicting directory digest.
pub fn missing_chunks_validated(
    want: &TreeNode,
    have: Option<&TreeNode>,
    bounds: GraphBounds,
) -> Result<(Vec<TypedDigest>, DiffStats), ClosureError> {
    want.validate_closure(bounds)?;
    if let Some(have_tree) = have {
        have_tree.validate_closure(bounds)?;
    }
    Ok(missing_chunks(want, have))
}

/// Compute the chunks `have` is missing relative to `want`
/// (receiver-side diff: what must transfer). Returns the missing chunk
/// digests and the walk statistics.
#[must_use]
pub fn missing_chunks(want: &TreeNode, have: Option<&TreeNode>) -> (Vec<TypedDigest>, DiffStats) {
    let mut missing = Vec::new();
    let mut stats = DiffStats::default();
    walk(want, have, &mut missing, &mut stats);
    (missing, stats)
}

fn walk(
    want: &TreeNode,
    have: Option<&TreeNode>,
    missing: &mut Vec<TypedDigest>,
    stats: &mut DiffStats,
) {
    stats.nodes_visited += 1;
    match want {
        TreeNode::File { chunks, .. } => {
            let have_chunks: &[TypedDigest] = match have {
                Some(TreeNode::File { chunks, .. }) => chunks,
                _ => &[],
            };
            for chunk in chunks {
                if !have_chunks.contains(chunk) && !missing.contains(chunk) {
                    missing.push(chunk.clone());
                }
            }
        }
        TreeNode::Directory {
            subtree_digest,
            children,
            ..
        } => {
            // SHORT-CIRCUIT: identical subtree digest ⇒ nothing below
            // can be missing; skip the whole subtree.
            if let Some(TreeNode::Directory {
                subtree_digest: have_digest,
                ..
            }) = have
                && have_digest == subtree_digest
            {
                stats.subtrees_skipped += 1;
                return;
            }
            for child in children {
                let have_child = match have {
                    Some(TreeNode::Directory {
                        children: have_children,
                        ..
                    }) => have_children.iter().find(|c| c.name() == child.name()),
                    _ => None,
                };
                walk(child, have_child, missing, stats);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::closure_validation::DEFAULT_BOUNDS;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.chunk.v1",
            bytes: [tag; 32],
        }
    }

    fn subtree(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.tree.v1",
            bytes: [tag; 32],
        }
    }

    fn file(name: &str, chunk_tags: &[u8]) -> TreeNode {
        TreeNode::File {
            name: name.into(),
            chunks: chunk_tags.iter().map(|t| d(*t)).collect(),
        }
    }

    fn dir(name: &str, digest_tag: u8, children: Vec<TreeNode>) -> TreeNode {
        TreeNode::Directory {
            name: name.into(),
            subtree_digest: subtree(digest_tag),
            children,
        }
    }

    /// A tree with two subtrees: `deps` (large) and `src` (small).
    fn want_tree(src_chunk: u8) -> TreeNode {
        dir(
            "root",
            if src_chunk == 30 { 100 } else { 101 },
            vec![
                dir(
                    "deps",
                    50,
                    vec![file("liba.rlib", &[1, 2, 3]), file("libb.rlib", &[4, 5])],
                ),
                dir("src", 60 + src_chunk, vec![file("main.o", &[src_chunk])]),
            ],
        )
    }

    #[test]
    fn empty_receiver_needs_everything() {
        let (missing, stats) = missing_chunks(&want_tree(30), None);
        assert_eq!(missing.len(), 6, "all chunks missing");
        assert_eq!(stats.subtrees_skipped, 0);
    }

    #[test]
    fn unchanged_subtrees_skip_transfer_and_traversal() {
        // THE acceptance fixture: receiver HAS an identical `deps`
        // subtree (same digest) but an older `src`. The diff must (a)
        // return exactly the changed chunk, (b) SKIP the deps subtree
        // without walking into it.
        let have = want_tree(29); // src differs (chunk 29 vs 30)
        let want = want_tree(30);
        let (missing, stats) = missing_chunks(&want, Some(&have));
        assert_eq!(missing, vec![d(30)], "exactly the changed chunk");
        assert_eq!(stats.subtrees_skipped, 1, "deps skipped whole");
        // Visited: root + deps(short-circuit visit) + src + main.o = 4
        // — NOT the deps children.
        assert_eq!(stats.nodes_visited, 4);
    }

    #[test]
    fn identical_trees_diff_to_nothing_in_one_comparison() {
        let (missing, stats) = missing_chunks(&want_tree(30), Some(&want_tree(30)));
        assert!(missing.is_empty());
        assert_eq!(stats.subtrees_skipped, 1, "root itself short-circuits");
        assert_eq!(stats.nodes_visited, 1);
    }

    #[test]
    fn missing_diff_is_correct_under_partial_overlap() {
        // Receiver has liba but not libb; chunk 2 shared inside liba.
        let have = dir(
            "root",
            200,
            vec![dir("deps", 51, vec![file("liba.rlib", &[1, 2])])],
        );
        let want = dir(
            "root",
            100,
            vec![dir(
                "deps",
                50,
                vec![file("liba.rlib", &[1, 2, 3]), file("libb.rlib", &[4, 5])],
            )],
        );
        let (missing, _) = missing_chunks(&want, Some(&have));
        assert_eq!(missing, vec![d(3), d(4), d(5)], "exactly the gap");
        // Duplicate chunks across files count once.
        let want_dup = dir("root", 100, vec![file("x", &[7]), file("y", &[7])]);
        let (missing_dup, _) = missing_chunks(&want_dup, None);
        assert_eq!(missing_dup, vec![d(7)]);
    }

    #[test]
    fn tree_validate_closure_enforces_bounds_cycles_and_conflicting_digests() {
        let valid = want_tree(30);
        let (missing, stats) =
            missing_chunks_validated(&valid, Some(&want_tree(29)), DEFAULT_BOUNDS).unwrap();
        assert_eq!(missing, vec![d(30)]);
        assert_eq!(stats.subtrees_skipped, 1);

        // Self-referential directory digest cycle: parent and child share digest 77.
        let cyclic = dir("root", 77, vec![dir("child", 77, vec![])]);
        assert_eq!(
            cyclic.validate_closure(DEFAULT_BOUNDS),
            Err(ClosureError::Cycle(ObjectId(subtree(77))))
        );

        // Conflicting sibling directories claiming the same subtree_digest (88).
        let conflicting = dir(
            "root",
            99,
            vec![
                dir("a", 88, vec![file("x", &[1])]),
                dir("b", 88, vec![file("y", &[2])]),
            ],
        );
        assert_eq!(
            conflicting.validate_closure(DEFAULT_BOUNDS),
            Err(ClosureError::DuplicateNode(ObjectId(subtree(88))))
        );

        // Depth, fan-out, and node-count bounds.
        assert_eq!(
            valid.validate_closure(GraphBounds {
                max_depth: 2,
                ..DEFAULT_BOUNDS
            }),
            Err(ClosureError::DepthExceeded)
        );
        assert!(matches!(
            valid.validate_closure(GraphBounds {
                max_fanout: 1,
                ..DEFAULT_BOUNDS
            }),
            Err(ClosureError::FanoutExceeded(_))
        ));
        assert_eq!(
            valid.validate_closure(GraphBounds {
                max_nodes: 3,
                ..DEFAULT_BOUNDS
            }),
            Err(ClosureError::NodeCountExceeded)
        );
    }
}
