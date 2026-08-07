//! Canonical result vs attempt evidence vs publication record, with the
//! divergence taxonomy (bead A018; invariants I34/I37/I48; risks
//! R80/R103/R115).
//!
//! The architectural point, encoded structurally: **canonical result
//! identity contains only output/exit/observable facts an ordinary cache
//! hit may replay.** Worker identity, attempt IDs, timings, resources,
//! verification runs, trust tier, provenance, provisional lineage, and
//! incremental snapshots live in a *separate* evidence bundle — so two
//! equivalent attempts can never "diverge" merely by having been run by
//! different workers at different speeds (R80/R115), and the publication
//! record is immutable history distinct from both (I50).
//!
//! Digest values here are TYPED (algorithm + domain + bytes) so raw
//! 32-byte arrays from different domains can never compare equal (R121).
//! The digest *computation* (length-delimited canonical framing) lands
//! with bead F034; the type contract lives here so schemas can use it now.

use crate::raw_bytes::RawBytes;

/// Digest algorithms admitted for authoritative V1 identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// SHA-256 over length-delimited canonical bytes (the V1 authoritative
    /// algorithm; bead F034 owns the framing).
    Sha256V1,
}

/// A typed digest: algorithm + semantic domain + bytes. Two digests are
/// equal only when ALL THREE match — cross-domain comparison of raw bytes
/// is structurally impossible (risk R121).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedDigest {
    /// Algorithm that produced the bytes.
    pub algorithm: DigestAlgorithm,
    /// Semantic domain separator, e.g. `rabs.action-key.sha256.v1`.
    pub domain: &'static str,
    /// The digest bytes.
    pub bytes: [u8; 32],
}

/// Content-addressed object identity (a typed digest in an object domain).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectId(pub TypedDigest);

/// Success or admitted deterministic failure — one immutable publication
/// path for both (no second failure-cache identity; plan §66).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultKind {
    /// Normal successful completion.
    Success,
    /// Admitted deterministic failure (normal nonzero exit, closed inputs,
    /// complete canonical observations; NEVER OOM/signal/cancel — I16).
    DeterministicFailure,
}

/// Role tag for one row of the single authoritative logical-output map
/// (risk R125: specialized lists are derived views, never duplicates).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputRole {
    /// Materializable file/tree output.
    Materializable,
    /// Canonical dep-info (subscriber-specific derivations are private).
    DepInfo,
    /// Provisional metadata (`.rmeta`) output.
    ProvisionalMetadata,
    /// Build-script metadata / directive manifest.
    BuildScriptMetadata,
    /// Declared test side-effect object.
    TestSideEffect,
}

/// One row of the logical-output map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalOutput {
    /// Role tag.
    pub role: OutputRole,
    /// Canonical virtual path (byte-preserving).
    pub virtual_path: RawBytes,
    /// The object this output resolves to.
    pub object: ObjectId,
}

/// Canonical action-result identity: ONLY replayable output/exit/observable
/// facts. No attempt evidence, by construction (I37).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalActionResultManifest {
    /// The action key this result answers.
    pub action_key: TypedDigest,
    /// Digest of the canonical descriptor (byte-verified on every hit).
    pub canonical_descriptor_digest: TypedDigest,
    /// Key epoch at publication.
    pub key_epoch: u32,
    /// Projection epoch at publication.
    pub projection_epoch: u32,
    /// Success or admitted deterministic failure.
    pub result_kind: ResultKind,
    /// Deterministically derived from `logical_outputs`; `None` for
    /// deterministic failures (which carry no materializable outputs).
    pub artifact_bundle_root: Option<ObjectId>,
    /// The single authoritative sorted logical-output map.
    pub logical_outputs: Vec<LogicalOutput>,
    /// Digest over the versioned semantic projection (excludes both digest
    /// fields themselves).
    pub semantic_result_digest: TypedDigest,
    /// Digest over semantic projection + canonical observations (excludes
    /// both digest fields themselves).
    pub observable_result_digest: TypedDigest,
}

impl CanonicalActionResultManifest {
    /// Structural validity: deterministic failures carry no outputs and no
    /// bundle root; (role, path) pairs are unique.
    ///
    /// # Errors
    /// A static description of the violated rule.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.result_kind == ResultKind::DeterministicFailure {
            if !self.logical_outputs.is_empty() {
                return Err("deterministic failures must have an empty output map");
            }
            if self.artifact_bundle_root.is_some() {
                return Err("deterministic failures must have no artifact bundle root");
            }
        }
        for (i, a) in self.logical_outputs.iter().enumerate() {
            for b in &self.logical_outputs[i + 1..] {
                if a.role == b.role && a.virtual_path == b.virtual_path {
                    return Err("duplicate (role, virtual_path) in logical-output map");
                }
            }
        }
        Ok(())
    }
}

/// Attempt evidence: everything about HOW a result was produced. Kept in a
/// separate object so it can differ freely across equivalent attempts.
/// (Fields are object references; their schemas land with their beads.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptEvidenceBundle {
    /// The action key (correlation only; carries no result identity).
    pub action_key: TypedDigest,
    /// The canonical result this evidence supports.
    pub canonical_result_manifest_id: ObjectId,
    /// Producing snapshot root (full snapshot is provenance, not key — I4).
    pub execution_snapshot_root: ObjectId,
    /// Observed-input report object.
    pub observed_input_report: ObjectId,
    /// Raw process/event evidence object.
    pub raw_process_and_event_evidence: ObjectId,
    /// Provenance receipt object.
    pub provenance_receipt: ObjectId,
    /// Optional incremental snapshot (attempt auxiliary, never identity).
    pub incremental_snapshot: Option<ObjectId>,
}

/// Immutable publication history: which generation/attempt won, under which
/// authority, pointing at which canonical result. Serving disposition is a
/// SEPARATE versioned record (I50; bead A020/A022).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionPublicationRecord {
    /// The action key.
    pub action_key: TypedDigest,
    /// The committed canonical result manifest.
    pub canonical_result_manifest_id: ObjectId,
    /// The winning attempt's evidence bundle.
    pub winner_evidence_bundle_id: ObjectId,
    /// Causal commit sequence at the coordinator.
    pub committed_causal_sequence: u64,
}

/// The same-key divergence taxonomy (I34/I48).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DivergenceClass {
    /// Same canonical manifest object: idempotent re-offer; append the new
    /// evidence bundle, nothing else changes.
    IdempotentSameResult,
    /// Different semantic result digest: determinism/key-soundness
    /// incident; quarantine the ACTION, preserve both candidates.
    SemanticDivergence,
    /// Semantic digests equal, observable digests differ: narrower
    /// presentation/observability quarantine; ordinary replay disabled.
    ObservableOnlyDivergence,
    /// Both declared digests equal but the canonical manifest bytes/IDs
    /// differ: a serializer/projection-completeness incident — never
    /// "evidence-only variation" (risk R103).
    ProjectionCompletenessIncident,
}

/// Classify a same-key candidate against the committed result.
#[must_use]
pub fn classify_same_key_candidate(
    committed: &CanonicalActionResultManifest,
    committed_manifest_id: &ObjectId,
    candidate: &CanonicalActionResultManifest,
    candidate_manifest_id: &ObjectId,
) -> DivergenceClass {
    if committed_manifest_id == candidate_manifest_id {
        return DivergenceClass::IdempotentSameResult;
    }
    if committed.semantic_result_digest != candidate.semantic_result_digest {
        return DivergenceClass::SemanticDivergence;
    }
    if committed.observable_result_digest != candidate.observable_result_digest {
        return DivergenceClass::ObservableOnlyDivergence;
    }
    // Equal declared digests, different manifest objects.
    DivergenceClass::ProjectionCompletenessIncident
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn object(tag: u8) -> ObjectId {
        ObjectId(digest("rabs.object.v1", tag))
    }

    fn manifest(sem: u8, obs: u8) -> CanonicalActionResultManifest {
        CanonicalActionResultManifest {
            action_key: digest("rabs.action-key.sha256.v1", 1),
            canonical_descriptor_digest: digest("rabs.descriptor.v1", 2),
            key_epoch: 1,
            projection_epoch: 1,
            result_kind: ResultKind::Success,
            artifact_bundle_root: Some(object(9)),
            logical_outputs: vec![LogicalOutput {
                role: OutputRole::Materializable,
                virtual_path: RawBytes::from("/__rabs/out/u1/lib.rlib"),
                object: object(3),
            }],
            semantic_result_digest: digest("rabs.semantic-result.v1", sem),
            observable_result_digest: digest("rabs.observable-result.v1", obs),
        }
    }

    #[test]
    fn typed_digests_never_compare_across_domains() {
        let a = digest("rabs.action-key.sha256.v1", 7);
        let b = digest("rabs.coordinator-authority.v1", 7);
        assert_ne!(a, b, "same bytes, different domain: must differ (R121)");
    }

    #[test]
    fn divergence_taxonomy_covers_all_four_classes() {
        let committed = manifest(10, 20);
        let cid = object(100);
        // Same manifest object: idempotent.
        assert_eq!(
            classify_same_key_candidate(&committed, &cid, &committed.clone(), &cid),
            DivergenceClass::IdempotentSameResult
        );
        // Different semantic digest: action quarantine.
        assert_eq!(
            classify_same_key_candidate(&committed, &cid, &manifest(11, 20), &object(101)),
            DivergenceClass::SemanticDivergence
        );
        // Semantic equal, observable differs: presentation quarantine.
        assert_eq!(
            classify_same_key_candidate(&committed, &cid, &manifest(10, 21), &object(101)),
            DivergenceClass::ObservableOnlyDivergence
        );
        // Equal digests, different manifest object: projection incident.
        assert_eq!(
            classify_same_key_candidate(&committed, &cid, &manifest(10, 20), &object(101)),
            DivergenceClass::ProjectionCompletenessIncident
        );
    }

    #[test]
    fn equivalent_attempts_with_different_evidence_do_not_diverge() {
        // The I37 point: evidence lives OUTSIDE the manifest, so two
        // attempts by different workers with different timings share one
        // manifest object and classify idempotent.
        let m = manifest(10, 20);
        let mid = object(100);
        let ev_worker_a = AttemptEvidenceBundle {
            action_key: m.action_key.clone(),
            canonical_result_manifest_id: mid.clone(),
            execution_snapshot_root: object(50),
            observed_input_report: object(51),
            raw_process_and_event_evidence: object(52),
            provenance_receipt: object(53),
            incremental_snapshot: None,
        };
        let ev_worker_b = AttemptEvidenceBundle {
            execution_snapshot_root: object(60),
            observed_input_report: object(61),
            raw_process_and_event_evidence: object(62),
            provenance_receipt: object(63),
            incremental_snapshot: Some(object(64)),
            ..ev_worker_a.clone()
        };
        assert_ne!(ev_worker_a, ev_worker_b, "evidence differs freely");
        assert_eq!(
            classify_same_key_candidate(&m, &mid, &m.clone(), &mid),
            DivergenceClass::IdempotentSameResult,
            "differing evidence must never manufacture result divergence"
        );
    }

    #[test]
    fn deterministic_failures_carry_no_outputs() {
        let mut m = manifest(1, 2);
        m.result_kind = ResultKind::DeterministicFailure;
        assert!(m.validate().is_err(), "outputs present: invalid");
        m.logical_outputs.clear();
        assert!(m.validate().is_err(), "bundle root present: invalid");
        m.artifact_bundle_root = None;
        assert!(m.validate().is_ok());
    }

    #[test]
    fn duplicate_role_path_rows_are_rejected() {
        let mut m = manifest(1, 2);
        m.logical_outputs.push(m.logical_outputs[0].clone());
        assert!(m.validate().is_err());
    }
}
