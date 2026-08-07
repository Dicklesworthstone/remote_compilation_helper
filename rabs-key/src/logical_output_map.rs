//! Logical-output-map bundle root + derived indexes (bead F035; risk
//! R125; plan §66/§113; acceptance fixture family T047).
//!
//! `CanonicalActionResultManifest.logical_outputs` is THE single
//! authoritative role-tagged output/side-effect map (A031 fixed the
//! shape; A022 proved deterministic failures carry none). This module
//! adds the parts that keep it single:
//!
//! - **Derived indexes are functions, never fields.** Dep-info,
//!   build-script, and provisional-metadata lookups filter the one map
//!   on demand; there is no second stored list to drift out of sync
//!   (R125's exact failure mode).
//! - **The artifact bundle root is COMPUTED, never asserted.**
//!   `compute_bundle_root` derives it deterministically from the sorted
//!   map; `verify_manifest_bundle_root` recomputes on decode and at
//!   publication admission and rejects any manifest whose stored root
//!   disagrees — a tampered or drifted root cannot survive to serving.
//! - **Deterministic failures**: empty map ⇒ no bundle root, enforced
//!   in both directions.

use rabs_protocol::result_identity::{
    CanonicalActionResultManifest, LogicalOutput, ObjectId, OutputRole, ResultKind,
};

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for the artifact bundle root.
pub const DOMAIN_ARTIFACT_BUNDLE_ROOT: &str = "rabs.artifact-bundle-root.v1";

/// Wire-stable role tag (enum reordering cannot silently re-root).
#[must_use]
pub const fn role_tag(role: OutputRole) -> u32 {
    match role {
        OutputRole::Materializable => 1,
        OutputRole::DepInfo => 2,
        OutputRole::ProvisionalMetadata => 3,
        OutputRole::BuildScriptMetadata => 4,
        OutputRole::TestSideEffect => 5,
    }
}

/// Deterministically compute the bundle root from the output map.
/// `None` for an empty map (the deterministic-failure form).
#[must_use]
pub fn compute_bundle_root(outputs: &[LogicalOutput]) -> Option<ObjectId> {
    if outputs.is_empty() {
        return None;
    }
    // Canonical order: (virtual_path bytes, role tag) — the map is a
    // set; whatever order rows arrived in, one root.
    let mut rows: Vec<&LogicalOutput> = outputs.iter().collect();
    rows.sort_by(|a, b| {
        (a.virtual_path.as_bytes(), role_tag(a.role))
            .cmp(&(b.virtual_path.as_bytes(), role_tag(b.role)))
    });
    let mut enc = CanonicalEncoder::new();
    enc.u64(rows.len() as u64);
    for row in rows {
        enc.bytes(row.virtual_path.as_bytes())
            .u32(role_tag(row.role))
            .str(row.object.0.domain)
            .bytes(&row.object.0.bytes);
    }
    Some(ObjectId(compute(
        DOMAIN_ARTIFACT_BUNDLE_ROOT,
        &enc.finish(),
    )))
}

/// Why a manifest's bundle root was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleRootError {
    /// Structural validation failed first (duplicate rows, failure
    /// carrying outputs, …) — the A031 rules.
    Structural(&'static str),
    /// The stored root differs from the recomputation.
    RootMismatch,
    /// Success manifests with outputs must carry a root.
    MissingRoot,
}

/// Full decode/publication-admission check: structure, then root.
///
/// # Errors
/// [`BundleRootError`] naming the violated rule.
pub fn verify_manifest_bundle_root(
    manifest: &CanonicalActionResultManifest,
) -> Result<(), BundleRootError> {
    manifest.validate().map_err(BundleRootError::Structural)?;
    let recomputed = compute_bundle_root(&manifest.logical_outputs);
    match (&manifest.artifact_bundle_root, &recomputed) {
        (None, None) => Ok(()),
        (Some(stored), Some(expected)) if stored == expected => Ok(()),
        (Some(_), Some(_)) => Err(BundleRootError::RootMismatch),
        (Some(_), None) => Err(BundleRootError::Structural(
            "bundle root present with empty output map",
        )),
        (None, Some(_)) => Err(BundleRootError::MissingRoot),
    }
}

/// Derived dep-info view (a filter, never a second list).
pub fn dep_info_entries(
    manifest: &CanonicalActionResultManifest,
) -> impl Iterator<Item = &LogicalOutput> {
    manifest
        .logical_outputs
        .iter()
        .filter(|o| o.role == OutputRole::DepInfo)
}

/// Derived build-script-metadata view.
pub fn build_script_entries(
    manifest: &CanonicalActionResultManifest,
) -> impl Iterator<Item = &LogicalOutput> {
    manifest
        .logical_outputs
        .iter()
        .filter(|o| o.role == OutputRole::BuildScriptMetadata)
}

/// Derived provisional-metadata view.
pub fn provisional_metadata_entries(
    manifest: &CanonicalActionResultManifest,
) -> impl Iterator<Item = &LogicalOutput> {
    manifest
        .logical_outputs
        .iter()
        .filter(|o| o.role == OutputRole::ProvisionalMetadata)
}

/// Convenience: is this a deterministic failure (empty map, no root)?
#[must_use]
pub fn is_failure_shape(manifest: &CanonicalActionResultManifest) -> bool {
    manifest.result_kind == ResultKind::DeterministicFailure
        && manifest.logical_outputs.is_empty()
        && manifest.artifact_bundle_root.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

    fn object(tag: u8) -> ObjectId {
        ObjectId(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        })
    }

    fn digest(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn row(role: OutputRole, path: &str, tag: u8) -> LogicalOutput {
        LogicalOutput {
            role,
            virtual_path: RawBytes::new(path.as_bytes().to_vec()),
            object: object(tag),
        }
    }

    fn manifest(outputs: Vec<LogicalOutput>) -> CanonicalActionResultManifest {
        let root = compute_bundle_root(&outputs);
        CanonicalActionResultManifest {
            action_key: digest("rabs.action-key.sha256.v1", 1),
            canonical_descriptor_digest: digest("rabs.descriptor.sha256.v1", 2),
            key_epoch: 1,
            projection_epoch: 1,
            result_kind: if outputs.is_empty() {
                ResultKind::DeterministicFailure
            } else {
                ResultKind::Success
            },
            artifact_bundle_root: root,
            logical_outputs: outputs,
            semantic_result_digest: digest("rabs.semantic-result.v1", 3),
            observable_result_digest: digest("rabs.observable-result.v1", 4),
        }
    }

    fn rows() -> Vec<LogicalOutput> {
        vec![
            row(OutputRole::Materializable, "/__rabs/out/lib.rlib", 1),
            row(OutputRole::DepInfo, "/__rabs/out/lib.d", 2),
            row(OutputRole::ProvisionalMetadata, "/__rabs/out/lib.rmeta", 3),
            row(OutputRole::BuildScriptMetadata, "/__rabs/out/bs.txt", 4),
        ]
    }

    #[test]
    fn bundle_root_is_deterministic_and_order_insensitive() {
        let root_a = compute_bundle_root(&rows());
        let mut reversed = rows();
        reversed.reverse();
        assert_eq!(root_a, compute_bundle_root(&reversed));
        // Any row change moves the root.
        let mut changed = rows();
        changed[0].object = object(99);
        assert_ne!(root_a, compute_bundle_root(&changed));
        // Role participates: same path/object under a different role.
        let mut re_roled = rows();
        re_roled[0].role = OutputRole::TestSideEffect;
        assert_ne!(root_a, compute_bundle_root(&re_roled));
    }

    #[test]
    fn bundle_root_mismatch_fixture_is_rejected() {
        // The T047 acceptance fixture: a manifest whose stored root
        // disagrees with its map is refused on decode/publication.
        let mut m = manifest(rows());
        m.artifact_bundle_root = Some(object(42));
        assert_eq!(
            verify_manifest_bundle_root(&m),
            Err(BundleRootError::RootMismatch)
        );
        // A success manifest with outputs but NO root is also refused.
        let mut missing = manifest(rows());
        missing.artifact_bundle_root = None;
        assert_eq!(
            verify_manifest_bundle_root(&missing),
            Err(BundleRootError::MissingRoot)
        );
        // Intact manifests verify.
        assert_eq!(verify_manifest_bundle_root(&manifest(rows())), Ok(()));
    }

    #[test]
    fn duplicate_role_path_fixture_is_rejected_before_root_checking() {
        let mut m = manifest(rows());
        m.logical_outputs.push(m.logical_outputs[0].clone());
        m.artifact_bundle_root = compute_bundle_root(&m.logical_outputs);
        assert!(matches!(
            verify_manifest_bundle_root(&m),
            Err(BundleRootError::Structural(_))
        ));
    }

    #[test]
    fn deterministic_failures_have_empty_map_and_no_root_both_ways() {
        let failure = manifest(vec![]);
        assert!(is_failure_shape(&failure));
        assert_eq!(verify_manifest_bundle_root(&failure), Ok(()));
        // A failure that smuggles a root is structurally refused.
        let mut smuggled = manifest(vec![]);
        smuggled.artifact_bundle_root = Some(object(7));
        assert!(matches!(
            verify_manifest_bundle_root(&smuggled),
            Err(BundleRootError::Structural(_))
        ));
    }

    #[test]
    fn derived_indexes_are_views_over_the_one_map() {
        let m = manifest(rows());
        assert_eq!(dep_info_entries(&m).count(), 1);
        assert_eq!(build_script_entries(&m).count(), 1);
        assert_eq!(provisional_metadata_entries(&m).count(), 1);
        // The views are filters over logical_outputs — there is no
        // second stored list anywhere to mutate independently; removing
        // a row from THE map updates every view.
        let mut smaller = manifest(rows());
        smaller
            .logical_outputs
            .retain(|o| o.role != OutputRole::DepInfo);
        smaller.artifact_bundle_root = compute_bundle_root(&smaller.logical_outputs);
        assert_eq!(dep_info_entries(&smaller).count(), 0);
        assert_eq!(verify_manifest_bundle_root(&smaller), Ok(()));
    }

    #[test]
    fn role_tags_are_wire_stable_and_distinct() {
        let all = [
            OutputRole::Materializable,
            OutputRole::DepInfo,
            OutputRole::ProvisionalMetadata,
            OutputRole::BuildScriptMetadata,
            OutputRole::TestSideEffect,
        ];
        let mut tags: Vec<u32> = all.iter().map(|r| role_tag(*r)).collect();
        assert_eq!(tags, vec![1, 2, 3, 4, 5]);
        tags.dedup();
        assert_eq!(tags.len(), all.len());
    }
}
