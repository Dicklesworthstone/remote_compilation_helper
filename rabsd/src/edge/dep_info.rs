//! Dep-info rewriting + materialization for Cargo freshness (bead
//! D009; plan §27/§28).
//!
//! When a served hit materializes into a subscriber's real target tree,
//! the dep-info Cargo will read must speak the subscriber's LIVE path
//! model — canonical `/__rabs` paths would make every listed input
//! "missing" and trigger a full rebuild. Rewriting reuses the D008
//! subscriber mapping and its completeness rule: any canonical residue
//! is a typed bypass (serve nothing rather than serve dep-info that
//! lies about where inputs live).
//!
//! The mtime side has one hard rule: **RABS never mutates immutable CAS
//! inodes to adjust mtimes.** Cargo's freshness comparison is "output
//! at least as new as every input", so materialization computes an
//! output mtime floor from the live input mtimes and then either
//! hardlinks (only when the CAS inode's mtime already satisfies the
//! floor — sharing is free) or writes a NEW inode stamped at the floor.
//! There is deliberately no "touch the CAS inode" variant to reach for.

use super::diagnostic_rewrite::{SubscriberMapping, TranslationOutcome};

/// Rewrite one dep-info file (makefile-style rustc `.d` content) to a
/// subscriber's live path model. Same completeness rule as D008: any
/// surviving canonical marker is a bypass, listing the offending lines.
#[must_use]
pub fn rewrite_dep_info(mapping: &SubscriberMapping, content: &str) -> TranslationOutcome {
    // Dep-info is a text surface (rule lines + env-dep comments);
    // prefix rewriting with the rendered-surface completeness rule is
    // exactly the semantics wanted here.
    super::diagnostic_rewrite::translate_rendered(mapping, content)
}

/// The output mtime floor for a served hit: at least as new as every
/// live input (Cargo's dirtiness rule is "output older than an input").
/// No inputs ⇒ no constraint (floor 0).
#[must_use]
pub fn output_mtime_floor_ns(input_mtimes_ns: &[u128]) -> u128 {
    input_mtimes_ns.iter().copied().max().unwrap_or(0)
}

/// How one artifact reaches the subscriber's target tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationStep {
    /// Hardlink the immutable CAS inode — permitted ONLY because its
    /// existing mtime already satisfies the floor; the inode is shared
    /// and therefore never touched.
    HardlinkSharedInode,
    /// Write a fresh private inode stamped at the floor. The CAS copy
    /// stays byte- and mtime-immutable.
    WriteNewInodeAt {
        /// The mtime (ns) the new inode is stamped with.
        mtime_ns: u128,
    },
}

/// Decide the materialization step for one artifact. `cas_mtime_ns` is
/// the immutable CAS inode's mtime; `floor_ns` from
/// [`output_mtime_floor_ns`]. The decision NEVER mutates the CAS inode:
/// an insufficient CAS mtime always yields a new-inode write.
#[must_use]
pub fn materialization_step(cas_mtime_ns: u128, floor_ns: u128) -> MaterializationStep {
    if cas_mtime_ns >= floor_ns {
        MaterializationStep::HardlinkSharedInode
    } else {
        MaterializationStep::WriteNewInodeAt { mtime_ns: floor_ns }
    }
}

#[cfg(test)]
mod tests {
    use super::super::diagnostic_rewrite::MappingEntry;
    use super::*;

    fn mapping() -> SubscriberMapping {
        SubscriberMapping::new(vec![
            MappingEntry {
                canonical: "/__rabs/workspace".into(),
                worktree: "/home/alice/proj".into(),
            },
            MappingEntry {
                canonical: "/__rabs/out/fixture".into(),
                worktree: "/home/alice/proj/target".into(),
            },
        ])
        .unwrap()
    }

    const DEP_INFO: &str = "/__rabs/out/fixture/debug/deps/fx-abc: \
                            /__rabs/workspace/src/main.rs /__rabs/workspace/build.rs\n\n\
                            /__rabs/workspace/src/main.rs:\n/__rabs/workspace/build.rs:\n";

    #[test]
    fn dep_info_rewrites_to_the_subscribers_live_path_model() {
        let TranslationOutcome::Translated(out) = rewrite_dep_info(&mapping(), DEP_INFO) else {
            panic!("expected full translation");
        };
        assert!(out.contains("/home/alice/proj/target/debug/deps/fx-abc:"));
        assert!(out.contains("/home/alice/proj/src/main.rs"));
        assert!(!out.contains("/__rabs"), "no canonical residue");
    }

    #[test]
    fn unmapped_canonical_input_bypasses_rather_than_lying() {
        let content = "/__rabs/out/fixture/debug/deps/fx-abc: /__rabs/registry/abc/serde/lib.rs\n";
        let TranslationOutcome::Bypass { untranslated } = rewrite_dep_info(&mapping(), content)
        else {
            panic!("expected bypass");
        };
        assert!(untranslated[0].contains("/__rabs/registry/abc"));
    }

    #[test]
    fn output_floor_is_the_newest_input() {
        assert_eq!(output_mtime_floor_ns(&[5, 9, 3]), 9);
        assert_eq!(output_mtime_floor_ns(&[]), 0);
    }

    #[test]
    fn cas_inodes_are_never_touched_only_shared_or_copied() {
        // CAS mtime already satisfies the floor: share the inode.
        assert_eq!(
            materialization_step(100, 90),
            MaterializationStep::HardlinkSharedInode
        );
        // CAS mtime too old: a NEW inode is written at the floor — the
        // enum has no touch-the-CAS variant to even express the
        // forbidden operation.
        assert_eq!(
            materialization_step(50, 90),
            MaterializationStep::WriteNewInodeAt { mtime_ns: 90 }
        );
        match materialization_step(0, 1) {
            MaterializationStep::HardlinkSharedInode
            | MaterializationStep::WriteNewInodeAt { .. } => {}
        }
    }
}
