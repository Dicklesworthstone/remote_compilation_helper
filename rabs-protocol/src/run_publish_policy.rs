//! Run publish policy + retry-parity post-state handling (bead N010;
//! plan §196 Epic N; R101/R66; T034 fixtures; consumes N002/N003).
//!
//! Two laws, both fail-open where honesty demands it:
//!
//! **LAW 1 — FAILED/CANCELLED RUNS NEVER PUBLISH.** A build-script run
//! that exited nonzero or died by signal MUST NOT become a shared cache
//! hit, no matter how complete its captured OUT_DIR looks: the capture
//! of a failed run is partial by definition (the script did not finish)
//! and publishing it would serve truncated state to every subscriber.
//! The decision function is total and boring: [`RunOutcomeKind::Failed`]
//! and [`RunOutcomeKind::Cancelled`] map to [`PublishDecision::NeverPublish`]
//! with a typed reason; only [`RunOutcomeKind::Succeeded`] maps to
//! [`PublishDecision::Publish`].
//!
//! **LAW 2 — RETRY PARITY HAS EXACTLY THREE ARMS (R101).** MEASURED
//! against stock stable cargo (probe encoded in
//! `rabs-wrap/tests/n010_failed_run.rs`): a build script that FAILS
//! after writing partial OUT_DIR files leaves them in place, and a
//! subsequent FIXED retry runs in the SAME directory — new outputs land
//! BESIDE the stale partials, which persist indefinitely. Stock Cargo's
//! retry semantics are therefore
//! [`PostStatePolicy::OperationOwnedDestination`] (accumulate, never
//! clean). Replay must either reproduce exactly that, or execute in an
//! operation-owned destination, or refuse and run LOCALLY — and while
//! live-operation semantics are UNRESOLVED, the resolver answers
//! [`PostStatePolicy::LocalFallback`] (fail-open, never silently
//! diverge from stock).
//!
//! **LAW 3 — SHARED STAGING IS HELD UNTIL THE POLICY RESOLVES.**
//! Cleanup of shared staging happens only after the post-state policy
//! is resolved ([`StagingState::releasable`]); releasing earlier would
//! destroy the evidence a LocalFallback decision needs.

/// How a build-script run terminated (from the captured transcript's
/// terminal record + directive completeness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcomeKind {
    /// Exited zero: the script finished.
    Succeeded,
    /// Nonzero exit (admitted deterministic failure — still NOT
    /// publishable: partial OUT_DIR by construction, plan §66/I16 keep
    /// deterministic-failure identity separate from serving state).
    Failed,
    /// Signal death or cancellation before a terminal record existed.
    Cancelled,
}

/// The publish decision for one completed run. Total: every outcome
/// kind maps to exactly one decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishDecision {
    /// Outcome was Succeeded: eligible for the publication pipeline
    /// (downstream admission still applies — this grants nothing by
    /// itself, see N014/N004).
    Publish,
    /// Outcome was Failed/Cancelled: NEVER a shared hit.
    NeverPublish {
        /// Stable reason code (`failed-run-partial-state`,
        /// `cancelled-run-partial-state`).
        reason: &'static str,
    },
}

/// Decide publishability from the outcome kind alone. Structural law:
/// there is NO input that turns Failed/Cancelled into Publish.
#[must_use]
pub const fn publish_decision(outcome: RunOutcomeKind) -> PublishDecision {
    match outcome {
        RunOutcomeKind::Succeeded => PublishDecision::Publish,
        RunOutcomeKind::Failed => PublishDecision::NeverPublish {
            reason: "failed-run-partial-state",
        },
        RunOutcomeKind::Cancelled => PublishDecision::NeverPublish {
            reason: "cancelled-run-partial-state",
        },
    }
}

/// The three retry-parity arms (R101). Stock-measured default arm is
/// documented on [`PostStatePolicy::OperationOwnedDestination`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostStatePolicy {
    /// Execute in the operation-owned destination: the same OUT_DIR the
    /// failed run used, accumulating exactly as stock Cargo does
    /// (MEASURED: stale partials persist beside new outputs across a
    /// fixed retry).
    OperationOwnedDestination,
    /// Reproduce the EXACT observed failure post-state (including
    /// tombstones via the N003 diff) in a private staging dir before
    /// exposing anything downstream.
    ReproduceObservedFailureState,
    /// Semantics unresolved / capabilities missing: run locally rather
    /// than risk divergence. The fail-open arm.
    LocalFallback,
}

/// Resolve which retry-parity arm applies. Fail-open rule: an explicit
/// resolved capability choice wins; WITHOUT one (semantics unresolved),
/// the answer is [`PostStatePolicy::LocalFallback`] — never a guess.
#[must_use]
pub const fn resolve_retry_parity(resolved: Option<PostStatePolicy>) -> PostStatePolicy {
    match resolved {
        Some(policy) => policy,
        None => PostStatePolicy::LocalFallback,
    }
}

/// Shared-staging lifecycle (LAW 3): held from capture until a resolved
/// post-state policy says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingState {
    /// Captured evidence intact; cleanup FORBIDDEN.
    Held,
    /// Policy resolved; cleanup permitted.
    Releasable,
}

impl StagingState {
    /// Whether shared staging may be cleaned NOW.
    #[must_use]
    pub const fn releasable(self) -> bool {
        matches!(self, Self::Releasable)
    }

    /// Transition to releasable — requires the resolved policy. No
    /// constructor path skips the policy argument (LAW 3 in types).
    #[must_use]
    pub const fn release_after_policy_resolved(self, _resolved: PostStatePolicy) -> Self {
        Self::Releasable
    }
}

/// Ghost-file analysis over the T034 probe shape: paths present after
/// the FIXED retry that were NOT produced by the successful script's
/// own capture (they are survivors of the earlier FAILED run — stock
/// accumulates them forever).
///
/// Deterministic; inputs are sorted path lists as N003 walks produce.
#[must_use]
pub fn ghost_files(
    retry_capture: &[Vec<u8>],
    successful_script_outputs: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    retry_capture
        .iter()
        .filter(|p| !successful_script_outputs.contains(p))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn n010_failed_and_cancelled_outcomes_never_publish() {
        // LAW 1: the total mapping, all three arms.
        assert_eq!(
            publish_decision(RunOutcomeKind::Succeeded),
            PublishDecision::Publish
        );
        assert_eq!(
            publish_decision(RunOutcomeKind::Failed),
            PublishDecision::NeverPublish {
                reason: "failed-run-partial-state"
            }
        );
        assert_eq!(
            publish_decision(RunOutcomeKind::Cancelled),
            PublishDecision::NeverPublish {
                reason: "cancelled-run-partial-state"
            }
        );
    }

    #[test]
    fn n010_unresolved_semantics_fall_back_to_local() {
        // LAW 2 fail-open arm: no resolved capability => LocalFallback,
        // never a guessed OperationOwnedDestination.
        assert_eq!(resolve_retry_parity(None), PostStatePolicy::LocalFallback);
        assert_eq!(
            resolve_retry_parity(Some(PostStatePolicy::OperationOwnedDestination)),
            PostStatePolicy::OperationOwnedDestination
        );
        assert_eq!(
            resolve_retry_parity(Some(PostStatePolicy::ReproduceObservedFailureState)),
            PostStatePolicy::ReproduceObservedFailureState
        );
    }

    #[test]
    fn n010_staging_cleanup_requires_a_resolved_policy() {
        // LAW 3: held staging is not releasable, period.
        let held = StagingState::Held;
        assert!(!held.releasable());
        // Release REQUIRES naming the resolved policy (no skip path).
        let released = held.release_after_policy_resolved(PostStatePolicy::LocalFallback);
        assert!(released.releasable());
    }

    /// MEASURED table (probe: failing-after-writes then fixed retry):
    /// stale partials survive into the retry capture and are GHOSTS
    /// relative to the successful script's own outputs.
    #[test]
    fn n010_ghost_files_survive_stock_retry_accumulation() {
        let retry_capture: Vec<Vec<u8>> = vec![
            b"out/gen.rs".to_vec(),
            b"out/partial_one.rs".to_vec(),
            b"out/partial_two.dat".to_vec(),
        ];
        let successful_outputs: Vec<Vec<u8>> = vec![b"out/gen.rs".to_vec()];
        let ghosts = ghost_files(&retry_capture, &successful_outputs);
        assert_eq!(
            ghosts,
            vec![
                b"out/partial_one.rs".to_vec(),
                b"out/partial_two.dat".to_vec(),
            ]
        );
        // Clean capture: no ghosts.
        assert!(ghost_files(&[b"out/gen.rs".to_vec()], &successful_outputs).is_empty());
    }

    /// Byte-level regression guard on reason spellings (receipts quote
    /// these verbatim).
    #[test]
    fn n010_reason_codes_are_stable_spellings() {
        if let PublishDecision::NeverPublish { reason } = publish_decision(RunOutcomeKind::Failed) {
            assert_eq!(reason, "failed-run-partial-state");
        } else {
            panic!("Failed must never publish");
        }
        if let PublishDecision::NeverPublish { reason } =
            publish_decision(RunOutcomeKind::Cancelled)
        {
            assert_eq!(reason, "cancelled-run-partial-state");
        } else {
            panic!("Cancelled must never publish");
        }
    }
}
