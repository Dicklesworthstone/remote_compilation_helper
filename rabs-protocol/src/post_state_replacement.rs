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
//!    T022), CREATE for target paths absent from live or changed in
//!    length or content digest. Every operation retains its output
//!    section, so an OUT_DIR path cannot alias an output-cache path.
//!    Callers execute DELETE-then-CREATE in a private dir and swap
//!    atomically; unchanged captured file bytes produce a no-op.
//!
//! Zero deps; pure planning like everything in this crate.

use crate::output_manifest::{
    ManifestValidationError, OutputSection, OutputTreeManifest, TreeDeltaRow, diff_manifests,
};

/// Marker: the OUT_DIR section was recorded and is EMPTY.
pub const PROVEN_EMPTY_OUT_DIR: &[u8] = b"proven-empty:out-dir";
/// Marker: the output-cache section was recorded and is EMPTY.
pub const PROVEN_EMPTY_OUTPUT_CACHE: &[u8] = b"proven-empty:output-cache";

/// Version tag for the key-material framing.
pub const PRE_STATE_KEY_MATERIAL_VERSION: u32 = 2;

/// Canonical key material for a captured pre-run state: versioned,
/// section-tagged, ascending paths with lengths and SHA-256 content
/// digests (the N003 walk order). V1 length-only material cannot name
/// the same pre-state. Each section carries its entry count, including
/// zero for a proven-empty section.
#[must_use]
pub fn pre_state_key_material(manifest: &OutputTreeManifest) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PRE_STATE_KEY_MATERIAL_VERSION.to_le_bytes());
    out.extend_from_slice(&manifest.schema_version.to_le_bytes());
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
        out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        if entries.is_empty() {
            out.extend_from_slice(empty_marker);
        } else {
            for e in entries {
                out.extend_from_slice(&(e.path.len() as u64).to_le_bytes());
                out.extend_from_slice(&e.path);
                out.extend_from_slice(&e.len.to_le_bytes());
                out.extend_from_slice(&e.content_sha256);
            }
        }
    }
    out
}

/// One path together with the output section that owns it. A caller
/// uses the same section-to-root mapping that produced the capture;
/// paths are preserved verbatim, including any recorded `out/` prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputPath {
    /// OUT_DIR and Cargo's output cache are distinct destinations.
    pub section: OutputSection,
    /// Byte-preserving relative path recorded in the selected section.
    pub path: Vec<u8>,
}

impl OutputPath {
    /// Construct a section-qualified output destination.
    #[must_use]
    pub fn new(section: OutputSection, path: impl Into<Vec<u8>>) -> Self {
        Self {
            section,
            path: path.into(),
        }
    }
}

/// One atomic-swap operation list computed purely from live vs target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostStatePlan {
    /// Target paths to CREATE: absent from live, or present with
    /// changed length or content digest. Sorted by section and path.
    pub create: Vec<OutputPath>,
    /// Live paths to DELETE: ghosts of earlier failed runs, stale
    /// partials, drifted leftovers. Sorted by section and path.
    pub delete: Vec<OutputPath>,
}

impl PostStatePlan {
    /// Whether applying this plan changes nothing (live == target).
    #[must_use]
    pub const fn is_noop(&self) -> bool {
        self.create.is_empty() && self.delete.is_empty()
    }
}

/// Plan the atomic replacement of `live` with `target`.
///
/// # Errors
/// Unsupported manifest versions, invalid ordering, duplicate paths or
/// sections exceeding their bound. No plan is returned for invalid input.
pub fn plan_swap(
    live: &OutputTreeManifest,
    target: &OutputTreeManifest,
) -> Result<PostStatePlan, ManifestValidationError> {
    let mut create = Vec::new();
    let mut delete = Vec::new();
    // Share the manifest's validated, section-aware identity comparison
    // instead of building another projection that could omit a field.
    for row in diff_manifests(live, target)? {
        match row {
            TreeDeltaRow::Added { entry, section } => {
                create.push(OutputPath::new(section, entry.path));
            }
            TreeDeltaRow::Removed {
                last_entry,
                section,
            } => {
                delete.push(OutputPath::new(section, last_entry.path));
            }
            TreeDeltaRow::Modified {
                new_entry, section, ..
            } => {
                let destination = OutputPath::new(section, new_entry.path);
                delete.push(destination.clone());
                create.push(destination);
            }
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
            out.iter()
                .map(|(p, l)| OutputEntry::new(*p, *l, [7; 32]))
                .collect(),
            cache
                .iter()
                .map(|(p, l)| OutputEntry::new(*p, *l, [7; 32]))
                .collect(),
        )
        .expect("valid")
    }

    fn all_paths(manifest: &OutputTreeManifest) -> Vec<OutputPath> {
        [OutputSection::OutDir, OutputSection::OutputCache]
            .into_iter()
            .flat_map(|section| {
                manifest
                    .section(section)
                    .iter()
                    .map(move |entry| OutputPath::new(section, entry.path.clone()))
            })
            .collect()
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
                OutputPath::new(OutputSection::OutDir, b"out/partial_one.rs".to_vec()),
                OutputPath::new(OutputSection::OutDir, b"out/partial_two.dat".to_vec()),
            ]
        );
        assert!(
            plan.create.is_empty(),
            "gen.rs has equal length and content identity: no action"
        );
        assert!(!plan.is_noop());

        // Simulated atomic swap: live minus deletes == clean set.
        let mut final_paths: Vec<OutputPath> = all_paths(&live_with_ghosts)
            .into_iter()
            .filter(|p| !plan.delete.contains(p))
            .collect();
        final_paths.extend(plan.create.clone());
        final_paths.sort();
        assert_eq!(final_paths, all_paths(&clean));
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
        let changed = OutputPath::new(OutputSection::OutDir, b"out/gen.rs".to_vec());
        assert_eq!(plan.delete, vec![changed.clone()]);
        assert_eq!(plan.create, vec![changed]);
        assert!(!plan.is_noop());
    }

    #[test]
    fn t022_same_length_content_drift_changes_key_and_rematerializes() {
        let old = manifest(&[("out/gen.rs", 18)], &[("output", 18)]);
        let mut new = old.clone();
        new.out_dir_entries[0].content_sha256 = [8; 32];
        new.cache_entries[0].content_sha256 = [9; 32];
        let expected = vec![
            OutputPath::new(OutputSection::OutDir, b"out/gen.rs".to_vec()),
            OutputPath::new(OutputSection::OutputCache, b"output".to_vec()),
        ];
        let plan = plan_swap(&old, &new).expect("valid content identities");
        assert_eq!(plan.delete, expected);
        assert_eq!(plan.create, expected);
        assert_ne!(pre_state_key_material(&old), pre_state_key_material(&new));
    }

    #[test]
    fn t022_matching_relative_paths_keep_their_section_ownership() {
        let original = manifest(&[("same", 18)], &[("same", 18)]);
        let mut target = original.clone();
        target.cache_entries[0].content_sha256 = [8; 32];
        let plan = plan_swap(&original, &target).expect("independent sections");
        let cache_path = OutputPath::new(OutputSection::OutputCache, b"same".to_vec());
        assert_eq!(plan.delete, vec![cache_path.clone()]);
        assert_eq!(plan.create, vec![cache_path]);

        let out_only = manifest(&[("same", 18)], &[]);
        let cache_only = manifest(&[], &[("same", 18)]);
        let moved = plan_swap(&out_only, &cache_only).expect("section move");
        assert_eq!(
            moved.delete,
            vec![OutputPath::new(OutputSection::OutDir, b"same".to_vec())]
        );
        assert_eq!(
            moved.create,
            vec![OutputPath::new(
                OutputSection::OutputCache,
                b"same".to_vec()
            )]
        );
        assert_ne!(
            pre_state_key_material(&out_only),
            pre_state_key_material(&cache_only)
        );
    }

    #[test]
    fn t022_invalid_or_old_manifests_cannot_produce_a_plan() {
        let valid = manifest(&[("same", 18)], &[]);
        let mut old = valid.clone();
        old.schema_version = 1;
        assert_eq!(
            plan_swap(&valid, &old),
            Err(ManifestValidationError::UnsupportedSchemaVersion(1))
        );
        let mut duplicate = valid.clone();
        duplicate
            .out_dir_entries
            .push(duplicate.out_dir_entries[0].clone());
        assert_eq!(
            plan_swap(&duplicate, &valid),
            Err(ManifestValidationError::DuplicatePath(
                OutputSection::OutDir
            ))
        );
        assert_eq!(&pre_state_key_material(&valid)[..4], &2_u32.to_le_bytes());
        assert_ne!(pre_state_key_material(&valid), pre_state_key_material(&old));
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
