//! Failure post-state preservation for the LIVE operation (bead N013;
//! plan §196 Epic N; operational complement of N010; T034 differential).
//!
//! Stock Cargo/build-script retry semantics are ACCUMULATING: a failed
//! run leaves partial OUT_DIR contents in place, and the live retry
//! observes them (MEASURED — probe encoded in
//! `rabs-wrap/tests/n010_failed_run.rs`, which also serves as this
//! bead's stock-differential fixture). N013's contract for RABS:
//!
//! - **PRESERVE**: when RABS drives the live operation, the exact
//!   observed failure post-state must be what the retry sees — byte-
//!   for-byte the same section, path, length and content identity stock
//!   would have left.
//!   [`verify_preserved_parity`] is the checker.
//! - **OR EXECUTE LOCALLY**: when exact preservation cannot be
//!   guaranteed by available capabilities, refuse to drive the live
//!   operation remotely and fall back ([`LiveOperationDecision::ExecuteLocally`]).
//! - **NEVER PUBLISH**: the failure post-state is live-operation data,
//!   NEVER a shared cache entry. That law lives in N010's
//!   [`crate::run_publish_policy::publish_decision`] and is referenced —
//!   not duplicated — here.
//!
//! Zero deps; pure comparison like everything in this crate.

use crate::output_manifest::{
    ManifestValidationError, OutputEntry, OutputSection, OutputTreeManifest, TreeDeltaRow,
    diff_manifests,
};

/// Whether the executor can stage an EXACT tree (create listed files
/// with their captured bytes, apply deletions) into the operation destination
/// atomically. Capability, not ambition: false forces local fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreservationCapabilities {
    /// Exact-tree staging available (staging dir + atomic swap wired).
    pub can_stage_exact_tree: bool,
}

/// What RABS does with the live operation after a failed/cancelled run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveOperationDecision {
    /// Drive the live retry against the preserved exact failure
    /// post-state (parity verified below before exposure).
    PreserveExactObservedState,
    /// Preservation cannot be guaranteed: run the operation locally so
    /// stock semantics hold by construction. Fail-open arm.
    ExecuteLocally,
}

/// Decide the live-operation handling. Fail-open rule: without exact-
/// staging capability the answer is ALWAYS local execution — a guessed
/// preservation is worse than stock behavior.
#[must_use]
pub const fn decide_live_operation(
    capabilities: &PreservationCapabilities,
) -> LiveOperationDecision {
    if capabilities.can_stage_exact_tree {
        LiveOperationDecision::PreserveExactObservedState
    } else {
        LiveOperationDecision::ExecuteLocally
    }
}

/// Result of comparing the LIVE post-state against the OBSERVED failure
/// post-state (what stock left behind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParityResult {
    /// Sections, paths, lengths and content digests match exactly.
    Identical,
    /// Invalid manifests cannot establish preservation parity.
    InvalidManifest(ManifestValidationError),
    /// Divergence, fully enumerated (both directions, sorted).
    Diverged {
        /// In OBSERVED but missing from LIVE (stock saw them; retry
        /// will not).
        missing: Vec<PreservedOutput>,
        /// In LIVE but absent from OBSERVED (retry sees ghosts stock
        /// never produced).
        extra: Vec<PreservedOutput>,
    },
}

/// One missing or unexpected captured output, retaining its section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedOutput {
    /// The independently owned filesystem surface.
    pub section: OutputSection,
    /// Captured path, file length and content digest.
    pub entry: OutputEntry,
}

impl ParityResult {
    /// Convenience for gates: parity holds iff Identical.
    #[must_use]
    pub const fn is_parity(&self) -> bool {
        matches!(self, Self::Identical)
    }
}

/// Compare the LIVE post-state against the OBSERVED failure post-state
/// across BOTH sections (a divergence on either surface breaks retry
/// parity). Both directions enumerated; ordering is section-then-path.
#[must_use]
pub fn verify_preserved_parity(
    live: &OutputTreeManifest,
    observed_failure: &OutputTreeManifest,
) -> ParityResult {
    let rows = match diff_manifests(observed_failure, live) {
        Ok(rows) => rows,
        Err(error) => return ParityResult::InvalidManifest(error),
    };
    let mut missing = Vec::new();
    let mut extra = Vec::new();
    for row in rows {
        match row {
            TreeDeltaRow::Added { entry, section } => {
                extra.push(PreservedOutput { section, entry });
            }
            TreeDeltaRow::Removed {
                last_entry,
                section,
            } => {
                missing.push(PreservedOutput {
                    section,
                    entry: last_entry,
                });
            }
            TreeDeltaRow::Modified {
                new_entry,
                previous_len,
                previous_content_sha256,
                section,
            } => {
                missing.push(PreservedOutput {
                    section,
                    entry: OutputEntry::new(
                        new_entry.path.clone(),
                        previous_len,
                        previous_content_sha256,
                    ),
                });
                extra.push(PreservedOutput {
                    section,
                    entry: new_entry,
                });
            }
        }
    }

    if missing.is_empty() && extra.is_empty() {
        ParityResult::Identical
    } else {
        ParityResult::Diverged { missing, extra }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(out: &[(&str, u64)], cache: &[(&str, u64)]) -> OutputTreeManifest {
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

    /// MEASURED stock shape (N010 probe): failed run left two partials;
    /// the live retry observes EXACTLY those. Parity holds.
    #[test]
    fn n013_parity_holds_when_live_matches_observed_failure_exactly() {
        let observed = m(
            &[("out/partial_one.rs", 31), ("out/partial_two.dat", 8)],
            &[("output", 107)],
        );
        let live = m(
            &[("out/partial_one.rs", 31), ("out/partial_two.dat", 8)],
            &[("output", 107)],
        );
        assert!(verify_preserved_parity(&live, &observed).is_parity());
        // And the capability gate admits driving it.
        let d = decide_live_operation(&PreservationCapabilities {
            can_stage_exact_tree: true,
        });
        assert_eq!(d, LiveOperationDecision::PreserveExactObservedState);
    }

    /// Both divergence directions enumerate with full entries: a ghost
    /// EXTRA file and a MISSING observed partial each surface by path.
    #[test]
    fn n013_divergence_enumerates_missing_and_extra() {
        let observed = m(&[("out/partial_one.rs", 31)], &[]);
        let live = m(&[("out/ghost.dat", 5)], &[]);
        match verify_preserved_parity(&live, &observed) {
            ParityResult::Diverged { missing, extra } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0].section, OutputSection::OutDir);
                assert_eq!(missing[0].entry.path, b"out/partial_one.rs");
                assert_eq!(extra.len(), 1);
                assert_eq!(extra[0].section, OutputSection::OutDir);
                assert_eq!(extra[0].entry.path, b"out/ghost.dat");
            }
            other => panic!("expected divergence, got {other:?}"),
        }
    }

    /// Length drift on the SAME path counts as both missing and extra —
    /// the retry would observe different BYTES than stock did.
    #[test]
    fn n013_length_drift_is_a_both_directions_divergence() {
        let observed = m(&[("out/x.bin", 10)], &[]);
        let live = m(&[("out/x.bin", 99)], &[]);
        match verify_preserved_parity(&live, &observed) {
            ParityResult::Diverged { missing, extra } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0].entry.len, 10);
                assert_eq!(extra.len(), 1);
                assert_eq!(extra[0].entry.len, 99);
            }
            other => panic!("expected divergence, got {other:?}"),
        }
    }

    /// Fail-open: without exact-staging capability the decision is
    /// ALWAYS ExecuteLocally — stock semantics by construction.
    #[test]
    fn n013_without_capability_decision_is_local_fallback() {
        let d = decide_live_operation(&PreservationCapabilities {
            can_stage_exact_tree: false,
        });
        assert_eq!(d, LiveOperationDecision::ExecuteLocally);
    }

    /// Cross-section parity: an OUT_DIR-perfect preservation still
    /// diverges if the output-cache section drifted.
    #[test]
    fn n013_cache_section_drift_breaks_parity() {
        let observed = m(&[("out/gen.rs", 26)], &[("output", 100)]);
        let live = m(&[("out/gen.rs", 26)], &[("output", 200)]);
        assert!(!verify_preserved_parity(&live, &observed).is_parity());
    }

    #[test]
    fn n013_same_length_content_drift_names_both_versions() {
        let observed = m(&[("generated", 18)], &[("generated", 18)]);
        let mut live = observed.clone();
        live.cache_entries[0].content_sha256 = [8; 32];
        assert_eq!(
            verify_preserved_parity(&live, &observed),
            ParityResult::Diverged {
                missing: vec![PreservedOutput {
                    section: OutputSection::OutputCache,
                    entry: observed.cache_entries[0].clone(),
                }],
                extra: vec![PreservedOutput {
                    section: OutputSection::OutputCache,
                    entry: live.cache_entries[0].clone(),
                }],
            }
        );
    }

    #[test]
    fn n013_moving_identical_bytes_between_sections_breaks_parity() {
        let observed = m(&[("same", 18)], &[]);
        let live = m(&[], &[("same", 18)]);
        assert_eq!(
            verify_preserved_parity(&live, &observed),
            ParityResult::Diverged {
                missing: vec![PreservedOutput {
                    section: OutputSection::OutDir,
                    entry: observed.out_dir_entries[0].clone(),
                }],
                extra: vec![PreservedOutput {
                    section: OutputSection::OutputCache,
                    entry: live.cache_entries[0].clone(),
                }],
            }
        );
    }

    #[test]
    fn n013_old_schema_cannot_establish_parity() {
        let observed = m(&[("same", 18)], &[]);
        let mut live = observed.clone();
        live.schema_version = 1;
        assert_eq!(
            verify_preserved_parity(&live, &observed),
            ParityResult::InvalidManifest(ManifestValidationError::UnsupportedSchemaVersion(1))
        );
    }
}
