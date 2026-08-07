//! Tree manifests + missing-chunk diff (bead H006; plan §90; risk
//! R25's transfer arm).
//!
//! Large trees (sysroots, registry sets, snapshots) transfer as
//! HIERARCHICAL manifests: every directory node's digest summarizes
//! its subtree, so comparison short-circuits — an unchanged subtree is
//! one digest equality, not a walk. The missing-diff walks only into
//! subtrees whose digests differ and returns exactly the chunk set the
//! receiver lacks.

use rabs_protocol::result_identity::TypedDigest;

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
}

/// Statistics from one diff run (proves the short-circuit happened).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiffStats {
    /// Directory nodes whose digests matched and were SKIPPED whole.
    pub subtrees_skipped: u64,
    /// Nodes actually visited.
    pub nodes_visited: u64,
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
}
