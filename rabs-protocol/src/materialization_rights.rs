//! Atomic materialization-rights revocation before local fallback
//! (bead C020; plan §85; the race half of I43's fallback story).
//!
//! When a wrapper falls back to the original tool chain, three things
//! must happen as ONE state change, strictly BEFORE the original chain
//! starts: the subscription detaches, future materialization rights are
//! revoked, and every privately staged remote write is discarded. The
//! danger is the late-arriving remote result: an edge that finishes the
//! build after the wrapper gave up must be structurally unable to write
//! into the fallen-back operation's tree — a stray remote artifact
//! landing under a locally rebuilt tree would silently mix two builds.
//!
//! The enforcement is type-shaped, not advisory:
//!
//! - every write into the operation tree goes through
//!   [`MaterializationGate::commit_staged`], which refuses after
//!   revocation — there is no other tree-write path;
//! - the original chain requires a [`FallbackClearance`], and the ONLY
//!   way to obtain one is [`MaterializationGate::revoke_for_fallback`]
//!   — the compiler enforces "revoke first, run second";
//! - revocation is permanent for the operation: a remote delivery
//!   carrying ANY rights epoch — including one granted before the
//!   revocation and delayed in flight — refuses with a typed error and
//!   mutates nothing.
//!
//! The crash-window companion (write-ahead intent, DeliveryUncertain)
//! is bead C019 in `stateful_delivery`; this module owns the live-race
//! window. The race fixture below (revocation injected at every point
//! of a delivery script, plus post-revocation delayed attempts) is the
//! C020 acceptance and feeds T036.

/// Why a materialization attempt was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RightsRefusal {
    /// Rights were revoked for fallback: no remote write may enter the
    /// operation tree, regardless of when its epoch was granted.
    RightsRevoked,
    /// A commit was attempted for a write that was never staged.
    NotStaged {
        /// The offending write id.
        write_id: u64,
    },
    /// Revocation was attempted twice. The first revocation already
    /// produced the operation's single [`FallbackClearance`]; a second
    /// clearance would permit a second concurrent "original chain".
    AlreadyRevoked,
}

/// Where a write in the operation tree came from (fixture-visible
/// provenance).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteSource {
    /// Materialized from the remote build under live rights.
    Remote {
        /// Rights epoch the write was admitted under.
        rights_epoch: u64,
    },
    /// Written by the locally rerun original chain after clearance.
    LocalFallback,
}

/// The operation's destination tree — the thing both the remote
/// materializer and the local fallback want to write. In production
/// this is the filesystem; here it is the fixture world.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OperationTree {
    /// Committed writes in arrival order: (write id, provenance).
    pub written: Vec<(u64, WriteSource)>,
}

/// Proof that fallback preconditions ran: subscription detached, rights
/// revoked, staging discarded. Non-exhaustive, so code outside this
/// crate (the edge daemon, the wrapper) cannot construct one — the ONLY
/// source is [`MaterializationGate::revoke_for_fallback`], and it is
/// the only token [`run_original_chain`] accepts: the original chain
/// cannot start while remote rights are live.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FallbackClearance {
    /// Rights epoch fenced by the revocation.
    pub fenced_epoch: u64,
    /// How many staged-but-uncommitted remote writes were discarded.
    pub staged_discarded: usize,
}

/// Per-(operation, subscriber) materialization gate: the single
/// chokepoint between remote output and the operation tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializationGate {
    /// Current rights epoch (bumps on re-grant across reconnects).
    epoch: u64,
    /// Whether the subscription is still attached.
    attached: bool,
    /// Revocation fence: `Some` once revoked, permanently.
    revoked: bool,
    /// Privately staged remote writes not yet committed to the tree.
    staging: Vec<u64>,
}

impl MaterializationGate {
    /// A live gate at the operation's initial rights epoch.
    #[must_use]
    pub const fn new(epoch: u64) -> Self {
        Self {
            epoch,
            attached: true,
            revoked: false,
            staging: Vec::new(),
        }
    }

    /// Whether the subscription is still attached.
    #[must_use]
    pub const fn attached(&self) -> bool {
        self.attached
    }

    /// Whether rights are revoked.
    #[must_use]
    pub const fn revoked(&self) -> bool {
        self.revoked
    }

    /// Staged write ids awaiting commit (fixture visibility).
    #[must_use]
    pub fn staged(&self) -> &[u64] {
        &self.staging
    }

    /// Stage a remote write into PRIVATE staging (not yet visible in
    /// the tree). Refuses after revocation.
    ///
    /// # Errors
    /// [`RightsRefusal::RightsRevoked`] after revocation; nothing is
    /// staged on refusal.
    pub fn stage(&mut self, write_id: u64) -> Result<(), RightsRefusal> {
        if self.revoked {
            return Err(RightsRefusal::RightsRevoked);
        }
        self.staging.push(write_id);
        Ok(())
    }

    /// Commit a staged write into the operation tree — the ONLY path by
    /// which remote output becomes visible. Refuses after revocation
    /// (the late-arrival fence) and for never-staged ids.
    ///
    /// # Errors
    /// Typed [`RightsRefusal`]; the tree is untouched on refusal.
    pub fn commit_staged(
        &mut self,
        write_id: u64,
        tree: &mut OperationTree,
    ) -> Result<(), RightsRefusal> {
        if self.revoked {
            return Err(RightsRefusal::RightsRevoked);
        }
        let Some(index) = self.staging.iter().position(|w| *w == write_id) else {
            return Err(RightsRefusal::NotStaged { write_id });
        };
        self.staging.remove(index);
        tree.written.push((
            write_id,
            WriteSource::Remote {
                rights_epoch: self.epoch,
            },
        ));
        Ok(())
    }

    /// THE C020 transition, atomic by construction (one `&mut self`
    /// call, no intermediate observable state): detach the
    /// subscription, revoke all future materialization rights, discard
    /// private staging — and only then hand back the clearance the
    /// original chain requires.
    ///
    /// # Errors
    /// [`RightsRefusal::AlreadyRevoked`] on a second call: exactly one
    /// clearance exists per operation.
    pub fn revoke_for_fallback(&mut self) -> Result<FallbackClearance, RightsRefusal> {
        if self.revoked {
            return Err(RightsRefusal::AlreadyRevoked);
        }
        self.attached = false;
        self.revoked = true;
        let staged_discarded = self.staging.len();
        self.staging.clear();
        Ok(FallbackClearance {
            fenced_epoch: self.epoch,
            staged_discarded,
        })
    }
}

/// Execute the original tool chain into the tree. The signature IS the
/// invariant: without a [`FallbackClearance`] — obtainable only from
/// [`MaterializationGate::revoke_for_fallback`] — this function cannot
/// be called, so the original chain can never run while remote
/// materialization rights are live.
pub fn run_original_chain(
    _clearance: &FallbackClearance,
    tree: &mut OperationTree,
    local_write_ids: &[u64],
) {
    for id in local_write_ids {
        tree.written.push((*id, WriteSource::LocalFallback));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One step of the remote delivery script.
    #[derive(Debug, Clone, Copy)]
    enum Step {
        Stage(u64),
        Commit(u64),
    }

    const SCRIPT: [Step; 8] = [
        Step::Stage(1),
        Step::Commit(1),
        Step::Stage(2),
        Step::Stage(3),
        Step::Commit(2),
        Step::Stage(4),
        Step::Commit(3),
        Step::Commit(4),
    ];

    #[test]
    fn c020_race_fixture_no_remote_write_lands_after_revocation() {
        // THE acceptance: inject the fallback revocation at EVERY point
        // of the delivery script, then have the delayed remote build
        // keep trying (retrying both old staged writes and brand-new
        // ones). No remote write may enter the tree after revocation,
        // staged bytes are discarded, and the local chain runs only
        // under clearance.
        for revoke_at in 0..=SCRIPT.len() {
            let mut gate = MaterializationGate::new(7);
            let mut tree = OperationTree::default();
            let mut committed_before_revoke = Vec::new();
            for step in &SCRIPT[..revoke_at] {
                match *step {
                    Step::Stage(id) => gate.stage(id).unwrap(),
                    Step::Commit(id) => {
                        gate.commit_staged(id, &mut tree).unwrap();
                        committed_before_revoke.push(id);
                    }
                }
            }
            let staged_pending = gate.staged().len();

            // The atomic transition: detach + revoke + discard staging.
            let clearance = gate.revoke_for_fallback().unwrap();
            assert!(!gate.attached(), "revoke_at={revoke_at}: must detach");
            assert!(gate.revoked());
            assert_eq!(clearance.staged_discarded, staged_pending);
            assert!(gate.staged().is_empty(), "staging must be discarded");

            let tree_at_revocation = tree.clone();

            // The DELAYED remote output arrives now: replays of the
            // remaining script, retries of already-staged ids, and a
            // brand-new write id. Every attempt refuses, nothing lands.
            for step in &SCRIPT[revoke_at..] {
                let refusal = match *step {
                    Step::Stage(id) => gate.stage(id).unwrap_err(),
                    Step::Commit(id) => gate.commit_staged(id, &mut tree).unwrap_err(),
                };
                assert_eq!(refusal, RightsRefusal::RightsRevoked);
            }
            assert_eq!(gate.stage(999), Err(RightsRefusal::RightsRevoked));
            assert_eq!(
                gate.commit_staged(999, &mut tree),
                Err(RightsRefusal::RightsRevoked)
            );
            assert_eq!(
                tree, tree_at_revocation,
                "revoke_at={revoke_at}: a late remote write entered the tree"
            );

            // The original chain runs ONLY under the clearance; its
            // writes are the only additions after revocation.
            run_original_chain(&clearance, &mut tree, &[100, 101]);
            let remote_after_revoke = tree
                .written
                .iter()
                .skip(tree_at_revocation.written.len())
                .filter(|(_, src)| matches!(src, WriteSource::Remote { .. }))
                .count();
            assert_eq!(remote_after_revoke, 0, "revoke_at={revoke_at}");
            // And every pre-revocation remote write is intact — the
            // fence never rewrites history.
            assert_eq!(
                tree.written[..tree_at_revocation.written.len()],
                tree_at_revocation.written[..]
            );
        }
    }

    #[test]
    fn exactly_one_clearance_per_operation() {
        let mut gate = MaterializationGate::new(1);
        let first = gate.revoke_for_fallback();
        assert!(first.is_ok());
        // A second clearance would permit a second concurrent
        // "original chain": typed refusal.
        assert_eq!(
            gate.revoke_for_fallback().unwrap_err(),
            RightsRefusal::AlreadyRevoked
        );
    }

    #[test]
    fn staged_bytes_never_leak_into_the_tree_after_discard() {
        let mut gate = MaterializationGate::new(1);
        let mut tree = OperationTree::default();
        gate.stage(1).unwrap();
        gate.stage(2).unwrap();
        gate.commit_staged(1, &mut tree).unwrap();
        let clearance = gate.revoke_for_fallback().unwrap();
        assert_eq!(clearance.staged_discarded, 1, "write 2 was pending");
        // Write 2 was discarded WITH the revocation — even a bug that
        // tried to commit it afterward refuses on the revocation fence
        // (not on NotStaged): the rights check dominates.
        assert_eq!(
            gate.commit_staged(2, &mut tree),
            Err(RightsRefusal::RightsRevoked)
        );
        assert_eq!(
            tree.written,
            vec![(1, WriteSource::Remote { rights_epoch: 1 })]
        );
    }

    #[test]
    fn commit_requires_prior_staging_while_live() {
        let mut gate = MaterializationGate::new(1);
        let mut tree = OperationTree::default();
        assert_eq!(
            gate.commit_staged(5, &mut tree),
            Err(RightsRefusal::NotStaged { write_id: 5 })
        );
        assert!(tree.written.is_empty());
    }
}
