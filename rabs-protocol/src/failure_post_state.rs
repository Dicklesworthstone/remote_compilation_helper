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
//!   for-byte the same PATH SET (and lengths) stock would have left.
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

use crate::output_manifest::{OutputEntry, OutputSection, OutputTreeManifest};

/// Whether the executor can stage an EXACT tree (create listed files
/// with listed lengths, apply deletions) into the operation destination
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
    /// Path sets and lengths match exactly: the live retry will observe
    /// precisely what stock observed.
    Identical,
    /// Divergence, fully enumerated (both directions, sorted).
    Diverged {
        /// In OBSERVED but missing from LIVE (stock saw them; retry
        /// will not).
        missing: Vec<OutputEntry>,
        /// In LIVE but absent from OBSERVED (retry sees ghosts stock
        /// never produced).
        extra: Vec<OutputEntry>,
    },
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
/// parity). Both directions enumerated; ordering is path-then-length.
fn entries(manifest: &OutputTreeManifest) -> Vec<OutputEntry> {
    let mut e: Vec<OutputEntry> = manifest
        .section(OutputSection::OutDir)
        .iter()
        .chain(manifest.section(OutputSection::OutputCache))
        .cloned()
        .collect();
    e.sort_by(|a, b| a.path.cmp(&b.path).then(a.len.cmp(&b.len)));
    e
}

#[must_use]
pub fn verify_preserved_parity(
    live: &OutputTreeManifest,
    observed_failure: &OutputTreeManifest,
) -> ParityResult {
    let live_e = entries(live);
    let obs_e = entries(observed_failure);

    let mut missing = Vec::new();
    let mut extra = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < obs_e.len() || j < live_e.len() {
        match (obs_e.get(i), live_e.get(j)) {
            (Some(o), Some(l)) => match o.path.cmp(&l.path) {
                std::cmp::Ordering::Less => {
                    missing.push(o.clone());
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    extra.push(l.clone());
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    if o.len != l.len {
                        // Same path, different bytes-length: the stock
                        // version is MISSING and the live one EXTRA.
                        missing.push(o.clone());
                        extra.push(l.clone());
                    }
                    i += 1;
                    j += 1;
                }
            },
            (Some(o), None) => {
                missing.push(o.clone());
                i += 1;
            }
            (None, Some(l)) => {
                extra.push(l.clone());
                j += 1;
            }
            (None, None) => break,
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
            out.iter().map(|(p, l)| OutputEntry::new(*p, *l)).collect(),
            cache
                .iter()
                .map(|(p, l)| OutputEntry::new(*p, *l))
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
                assert_eq!(missing[0].path, b"out/partial_one.rs");
                assert_eq!(extra.len(), 1);
                assert_eq!(extra[0].path, b"out/ghost.dat");
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
                assert_eq!(missing[0].len, 10);
                assert_eq!(extra.len(), 1);
                assert_eq!(extra[0].len, 99);
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
}
