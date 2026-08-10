//! Requested→resolved execution snapshot lineage for Cargo
//! fetch/resolution/lockfile mutation (bead D032; invariant I53; risk
//! R110).
//!
//! Cargo resolution MUTATES state (lockfile, config, source selection),
//! and a command that half-runs against pre-mutation state and half
//! against post-mutation state has no coherent identity at all. The
//! lineage state machine makes the boundary explicit:
//!
//! - resolution runs from the [`RequestedCommandSnapshot`] against a
//!   PRIVATE writable overlay (the requested snapshot never mutates);
//! - before the first resolution-dependent compile action the edge
//!   SEALS a [`ResolvedExecutionSnapshot`] generation;
//! - every fine-grained action names EXACTLY ONE sealed generation —
//!   registration returns that single reference or a typed refusal;
//! - post-seal mutation forces a RESEAL (new generation; already-run
//!   actions keep their old generation forever) or a coherent
//!   DOWNGRADE (no further sealed actions) — never a mixed state;
//! - lockfile replay to the worktree runs under a content precondition
//!   and cannot express mutation of sealed history (there is no API
//!   that changes a generation's digest).

/// The immutable requested-command snapshot (D018 manifest identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestedCommandSnapshot {
    /// The D018 manifest digest.
    pub manifest_sha256: [u8; 32],
}

/// One sealed resolved-execution generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedExecutionSnapshot {
    /// Generation number (1-based, monotonic per command).
    pub generation: u32,
    /// The requested snapshot this resolution derived from.
    pub requested_sha256: [u8; 32],
    /// Digest of the derived lockfile/config/source-selection state.
    pub resolution_sha256: [u8; 32],
}

/// Typed refusals from the lineage machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageError {
    /// An action asked to run before any generation was sealed.
    NotSealed,
    /// The command was downgraded: no further sealed actions exist.
    Downgraded,
    /// Sealing twice without an intervening mutation observation.
    AlreadySealed,
}

/// The response to a post-seal mutation observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationResponse {
    /// A new generation was sealed; new actions bind to it, old
    /// actions keep their old generation untouched.
    Resealed(ResolvedExecutionSnapshot),
    /// No reseal lane: the command coherently downgrades — every
    /// subsequent registration refuses.
    Downgraded,
}

/// One registered action's binding: exactly one sealed generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionBinding {
    /// The action's id.
    pub action: String,
    /// The single sealed generation it ran under.
    pub sealed: ResolvedExecutionSnapshot,
}

/// The per-command lineage state machine.
#[derive(Debug)]
pub struct SnapshotLineage {
    requested: RequestedCommandSnapshot,
    current: Option<ResolvedExecutionSnapshot>,
    downgraded: bool,
    bindings: Vec<ActionBinding>,
}

impl SnapshotLineage {
    /// Start a command from its requested snapshot.
    #[must_use]
    pub fn new(requested: RequestedCommandSnapshot) -> Self {
        Self {
            requested,
            current: None,
            downgraded: false,
            bindings: Vec::new(),
        }
    }

    /// Seal the first resolved generation from the private overlay's
    /// derived state. Must happen before any action registers.
    pub fn seal(
        &mut self,
        resolution_sha256: [u8; 32],
    ) -> Result<ResolvedExecutionSnapshot, LineageError> {
        if self.current.is_some() {
            return Err(LineageError::AlreadySealed);
        }
        let sealed = ResolvedExecutionSnapshot {
            generation: 1,
            requested_sha256: self.requested.manifest_sha256,
            resolution_sha256,
        };
        self.current = Some(sealed);
        Ok(sealed)
    }

    /// Register one fine-grained action: it binds to EXACTLY the
    /// current sealed generation, or refuses.
    pub fn register_action(&mut self, action: &str) -> Result<ActionBinding, LineageError> {
        if self.downgraded {
            return Err(LineageError::Downgraded);
        }
        let Some(sealed) = self.current else {
            return Err(LineageError::NotSealed);
        };
        let binding = ActionBinding {
            action: action.to_string(),
            sealed,
        };
        self.bindings.push(binding.clone());
        Ok(binding)
    }

    /// A post-seal mutation was observed (lockfile/config/source state
    /// changed under the command). `reseal_with` is the newly derived
    /// resolution digest where a reseal/replan lane exists; `None`
    /// downgrades coherently.
    pub fn observe_post_seal_mutation(
        &mut self,
        reseal_with: Option<[u8; 32]>,
    ) -> MutationResponse {
        match reseal_with {
            Some(resolution_sha256) => {
                let next_generation = self.current.map_or(1, |sealed| sealed.generation + 1);
                let sealed = ResolvedExecutionSnapshot {
                    generation: next_generation,
                    requested_sha256: self.requested.manifest_sha256,
                    resolution_sha256,
                };
                self.current = Some(sealed);
                MutationResponse::Resealed(sealed)
            }
            None => {
                self.downgraded = true;
                self.current = None;
                MutationResponse::Downgraded
            }
        }
    }

    /// Every action binding recorded so far (history is append-only;
    /// nothing here can rewrite a past binding's generation).
    #[must_use]
    pub fn bindings(&self) -> &[ActionBinding] {
        &self.bindings
    }
}

/// Typed refusal from lockfile replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayPreconditionFailed {
    /// The digest the worktree lockfile was required to have.
    pub expected_sha256: [u8; 32],
    /// What it actually had.
    pub actual_sha256: [u8; 32],
}

/// Replay the resolved lockfile bytes to the subscriber worktree under
/// a content PRECONDITION: the current worktree lockfile must be
/// byte-identical to what resolution started from — anything else means
/// the user (or another agent) touched it, and overwriting would lose
/// their change. Returns the bytes to install; sealed history is not
/// even reachable from here.
pub fn replay_lockfile(
    precondition_sha256: [u8; 32],
    observed_worktree_sha256: [u8; 32],
    resolved_bytes: Vec<u8>,
) -> Result<Vec<u8>, ReplayPreconditionFailed> {
    if precondition_sha256 == observed_worktree_sha256 {
        Ok(resolved_bytes)
    } else {
        Err(ReplayPreconditionFailed {
            expected_sha256: precondition_sha256,
            actual_sha256: observed_worktree_sha256,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lineage() -> SnapshotLineage {
        SnapshotLineage::new(RequestedCommandSnapshot {
            manifest_sha256: [3; 32],
        })
    }

    #[test]
    fn actions_before_seal_refuse_and_after_seal_bind_one_generation() {
        let mut machine = lineage();
        assert_eq!(
            machine.register_action("compile-serde"),
            Err(LineageError::NotSealed)
        );
        let sealed = machine.seal([10; 32]).unwrap();
        assert_eq!(sealed.generation, 1);
        assert_eq!(sealed.requested_sha256, [3; 32]);
        let binding = machine.register_action("compile-serde").unwrap();
        assert_eq!(binding.sealed, sealed, "exactly one sealed generation");
        assert_eq!(machine.seal([11; 32]), Err(LineageError::AlreadySealed));
    }

    #[test]
    fn t041_mutation_mid_command_reseals_and_never_mixes_state() {
        // THE T041 acceptance: actions run under gen 1, resolution
        // state mutates mid-command, the machine reseals gen 2 — new
        // actions bind gen 2, the ALREADY-RUN action's binding still
        // names gen 1 (history immutable), and no action ever holds a
        // mixed identity.
        let mut machine = lineage();
        machine.seal([10; 32]).unwrap();
        machine.register_action("early-action").unwrap();

        let MutationResponse::Resealed(gen2) = machine.observe_post_seal_mutation(Some([20; 32]))
        else {
            panic!("reseal lane exists");
        };
        assert_eq!(gen2.generation, 2);
        machine.register_action("late-action").unwrap();

        let bindings = machine.bindings();
        assert_eq!(bindings[0].sealed.generation, 1);
        assert_eq!(bindings[0].sealed.resolution_sha256, [10; 32]);
        assert_eq!(bindings[1].sealed.generation, 2);
        assert_eq!(bindings[1].sealed.resolution_sha256, [20; 32]);
        // Each binding names exactly one generation — a mixed binding
        // is unrepresentable (single `sealed` field), and the early
        // binding was not retroactively rewritten.
    }

    #[test]
    fn t041_downgrade_arm_is_coherent_not_mixed() {
        let mut machine = lineage();
        machine.seal([10; 32]).unwrap();
        machine.register_action("early-action").unwrap();
        // No reseal lane: coherent downgrade.
        assert_eq!(
            machine.observe_post_seal_mutation(None),
            MutationResponse::Downgraded
        );
        // No further sealed actions — typed refusal, not a stale run.
        assert_eq!(
            machine.register_action("late-action"),
            Err(LineageError::Downgraded)
        );
        // The early binding's identity survives the downgrade intact.
        assert_eq!(machine.bindings()[0].sealed.resolution_sha256, [10; 32]);
    }

    #[test]
    fn lockfile_replay_requires_its_content_precondition() {
        // Precondition holds: the resolved bytes install.
        assert_eq!(
            replay_lockfile([5; 32], [5; 32], b"lock v2".to_vec()),
            Ok(b"lock v2".to_vec())
        );
        // The worktree lockfile changed under us: typed refusal with
        // both digests — never an overwrite, never a history rewrite.
        let err = replay_lockfile([5; 32], [6; 32], b"lock v2".to_vec()).unwrap_err();
        assert_eq!(err.expected_sha256, [5; 32]);
        assert_eq!(err.actual_sha256, [6; 32]);
    }
}
