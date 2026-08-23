//! Pre-run state in keys + atomic post-state replacement (bead N012;
//! plan §196 Epic N; R66/T022; consumes the N003
//! [`crate::output_manifest`] surface).
//!
//! Two mechanisms, one goal — **replay == clean run**:
//!
//! 1. **Pre-state is a KEY INPUT when observable.** The OUT_DIR /
//!    output-cache state BEFORE a replay contributes canonical key
//!    material ([`pre_state_key_material`]). Each section stamps its own
//!    PROVEN-EMPTY marker ([`PROVEN_EMPTY_OUT_DIR`] /
//!    [`PROVEN_EMPTY_OUTPUT_CACHE`]) so "recorded empty" is
//!    distinguishable from "recorded populated" AND from "unrecorded"
//!    (callers omit the input entirely for unrecorded).
//!
//! 2. **Post-state replacement is ATOMIC-BY-PLAN.** [`plan_swap`]
//!    computes the operation list PURELY (no fs): DELETE for every live
//!    path the target does not declare (ghosts of failed runs die here —
//!    T022), CREATE for target paths absent from live or drifted in
//!    length. Paths present with equal length need NO action and appear
//!    in NO list — a plan applied to an identical state is a no-op by
//!    construction. Callers execute DELETE-then-CREATE in a private dir
//!    and swap atomically.
//!
//! Zero deps; pure planning like everything in this crate.

use crate::output_manifest::{OutputSection, OutputTreeManifest};

/// Marker: the OUT_DIR section was recorded and is EMPTY.
pub const PROVEN_EMPTY_OUT_DIR: &[u8] = b"proven-empty:out-dir";
/// Marker: the output-cache section was recorded and is EMPTY.
pub const PROVEN_EMPTY_OUTPUT_CACHE: &[u8] = b"proven-empty:output-cache";

/// Version tag for the key-material framing.
pub const PRE_STATE_KEY_MATERIAL_VERSION: u32 = 1;

/// Canonical key material for a captured pre-run state: versioned,
/// section-tagged, ascending paths with lengths (the N003 walk order).
#[must_use]
pub fn pre_state_key_material(manifest: &OutputTreeManifest) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PRE_STATE_KEY_MATERIAL_VERSION.to_le_bytes());
    for (tag, empty_marker, entries) in [
        (
            1u8,
            PROVEN_EMPTY_OUT_DIR,
            manifest.section(OutputSection::OutDir),
        ),
        (
            2u8,
            PROVEN_EMPTY_OUTPUT_CACHE,
            manifest.section(OutputSection::OutputCache),
        ),
    ] {
        out.push(tag);
        if entries.is_empty() {
            out.extend_from_slice(empty_marker);
        } else {
            out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
            for e in entries {
                out.extend_from_slice(&(e.path.len() as u64).to_le_bytes());
                out.extend_from_slice(&e.path);
                out.extend_from_slice(&e.len.to_le_bytes());
            }
        }
    }
    out
}

/// One atomic-swap operation list computed purely from live vs target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostStatePlan {
    /// Target paths to CREATE: absent from live, or present with
    /// DRIFTED length (re-materialization required). Sorted by path.
    pub create: Vec<Vec<u8>>,
    /// Live paths to DELETE: ghosts of earlier failed runs, stale
    /// partials, drifted leftovers. Sorted by path.
    pub delete: Vec<Vec<u8>>,
}

impl PostStatePlan {
    /// Whether applying this plan changes nothing (live == target).
    #[must_use]
    pub const fn is_noop(&self) -> bool {
        self.create.is_empty() && self.delete.is_empty()
    }
}

fn all_paths(manifest: &OutputTreeManifest) -> Vec<(Vec<u8>, u64)> {
    let mut all: Vec<(Vec<u8>, u64)> = manifest
        .section(OutputSection::OutDir)
        .iter()
        .map(|e| (e.path.clone(), e.len))
        .collect();
    all.extend(
        manifest
            .section(OutputSection::OutputCache)
            .iter()
            .map(|e| (e.path.clone(), e.len)),
    );
    all.sort();
    all
}

/// Plan the atomic replacement of `live` with `target`.
///
/// # Errors
/// Reserved for digest-verified variants; pure planning on valid N003
/// manifests cannot fail.
pub fn plan_swap(
    live: &OutputTreeManifest,
    target: &OutputTreeManifest,
) -> std::io::Result<PostStatePlan> {
    let live_map = all_paths(live);
    let target_map = all_paths(target);

    let mut create = Vec::new();
    let mut delete = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < live_map.len() || j < target_map.len() {
        match (live_map.get(i), target_map.get(j)) {
            (Some((lp, ll)), Some((tp, tl))) => match lp.cmp(tp) {
                std::cmp::Ordering::Less => {
                    delete.push(lp.clone());
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    create.push(tp.clone());
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    if ll != tl {
                        // Drift: the old bytes must go, the new must be
                        // materialized.
                        delete.push(lp.clone());
                        create.push(tp.clone());
                    }
                    // Equal: NO row — silence is the no-op proof.
                    i += 1;
                    j += 1;
                }
            },
            (Some((lp, _)), None) => {
                delete.push(lp.clone());
                i += 1;
            }
            (None, Some((tp, _))) => {
                create.push(tp.clone());
                j += 1;
            }
            (None, None) => break,
        }
    }

    Ok(PostStatePlan { create, delete })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output_manifest::OutputEntry;

    fn manifest(out: &[(&str, u64)], cache: &[(&str, u64)]) -> OutputTreeManifest {
        OutputTreeManifest::new(
            out.iter().map(|(p, l)| OutputEntry::new(*p, *l)).collect(),
            cache
                .iter()
                .map(|(p, l)| OutputEntry::new(*p, *l))
                .collect(),
        )
        .expect("valid")
    }

    /// T022 core: ghosts from an earlier failed run are planned for
    /// DELETE; applying the plan to the live tree yields exactly the
    /// clean-run set — replay == clean run.
    #[test]
    fn t022_ghosts_are_planned_for_deletion_replay_equals_clean_run() {
        let clean = manifest(&[("out/gen.rs", 26)], &[("output", 107)]);
        let live_with_ghosts = manifest(
            &[
                ("out/gen.rs", 26),
                ("out/partial_one.rs", 31),
                ("out/partial_two.dat", 8),
            ],
            &[("output", 107)],
        );
        let plan = plan_swap(&live_with_ghosts, &clean).expect("plans");
        assert_eq!(
            plan.delete,
            vec![
                b"out/partial_one.rs".to_vec(),
                b"out/partial_two.dat".to_vec(),
            ]
        );
        assert!(
            plan.create.is_empty(),
            "gen.rs is present with equal length: no action"
        );
        assert!(!plan.is_noop());

        // Simulated atomic swap: live minus deletes == clean set.
        let mut final_paths: Vec<Vec<u8>> = all_paths(&live_with_ghosts)
            .into_iter()
            .map(|(p, _)| p)
            .filter(|p| !plan.delete.contains(p))
            .collect();
        final_paths.extend(plan.create.clone());
        final_paths.sort();
        assert_eq!(
            final_paths,
            all_paths(&clean)
                .into_iter()
                .map(|(p, _)| p)
                .collect::<Vec<_>>()
        );
    }

    /// Identical states produce a NO-OP plan (no keep-rows exist to
    /// pollute it).
    #[test]
    fn t022_identical_states_are_a_noop() {
        let m = manifest(&[("out/gen.rs", 26)], &[("output", 107)]);
        let plan = plan_swap(&m, &m).expect("plans");
        assert!(plan.is_noop());
        assert_eq!(
            plan,
            PostStatePlan {
                create: vec![],
                delete: vec![]
            }
        );
    }

    /// Length drift re-materializes: delete old + create new.
    #[test]
    fn t022_length_drift_rematerializes() {
        let old = manifest(&[("out/gen.rs", 10)], &[]);
        let new = manifest(&[("out/gen.rs", 99)], &[]);
        let plan = plan_swap(&old, &new).expect("plans");
        assert_eq!(plan.delete, vec![b"out/gen.rs".to_vec()]);
        assert_eq!(plan.create, vec![b"out/gen.rs".to_vec()]);
        assert!(!plan.is_noop());
    }

    /// Per-section proven-empty markers: recorded-empty OUT_DIR is
    /// distinguishable from recorded-empty cache, from populated, and
    /// from the other sections' markers.
    #[test]
    fn t022_proven_empty_pre_state_is_per_section_distinct() {
        let both_empty = manifest(&[], &[]);
        let out_only = manifest(&[("out/x", 1)], &[]);
        let cache_only = manifest(&[], &[("output", 5)]);

        let both = pre_state_key_material(&both_empty);
        let out_populated = pre_state_key_material(&out_only);
        let cache_populated = pre_state_key_material(&cache_only);

        assert!(bytes_contain(&both, PROVEN_EMPTY_OUT_DIR));
        assert!(bytes_contain(&both, PROVEN_EMPTY_OUTPUT_CACHE));

        assert!(!bytes_contain(&out_populated, PROVEN_EMPTY_OUT_DIR));
        assert!(bytes_contain(&out_populated, PROVEN_EMPTY_OUTPUT_CACHE));

        assert!(bytes_contain(&cache_populated, PROVEN_EMPTY_OUT_DIR));
        assert!(!bytes_contain(&cache_populated, PROVEN_EMPTY_OUTPUT_CACHE));

        assert_ne!(both, out_populated);
        assert_ne!(both, cache_populated);
        assert_ne!(out_populated, cache_populated);
        // Deterministic.
        assert_eq!(both, pre_state_key_material(&both_empty));
    }

    fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
