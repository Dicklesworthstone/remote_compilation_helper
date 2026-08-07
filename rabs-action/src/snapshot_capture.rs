//! Atomic output + incremental-state capture after quiescence (bead
//! P002; plan §103; invariant I4's capture arm; risk R31; fixture
//! family T050).
//!
//! Incremental state is only useful with the outputs it MATCHES: an
//! incremental directory captured against different output bytes
//! poisons every warm start it seeds. The capture discipline as a
//! typestate:
//!
//! ```text
//! ProducersRunning → Quiescent → Staged → Committed
//! ```
//!
//! - capture may BEGIN only at `Quiescent` (the compiler and every
//!   output writer have exited/synced — a running writer means the
//!   bytes are still moving);
//! - the incremental manifest and the matching outputs stage TOGETHER
//!   and commit as ONE auxiliary snapshot unit — there is no API to
//!   commit either half alone;
//! - crash/cancel before commit leaves only DISPOSABLE staging: abort
//!   discards the staged pair and the committed state is untouched.

/// The capture lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureState {
    /// The compiler/output writers may still be running.
    ProducersRunning,
    /// Everything quiescent: capture may begin.
    Quiescent,
    /// The PAIRED unit is staged (not yet visible).
    Staged {
        /// Digest of the incremental-directory manifest.
        incremental_manifest: [u8; 32],
        /// Digest of the matching ordinary-output set.
        matching_outputs: [u8; 32],
    },
    /// The unit committed atomically.
    Committed {
        /// The incremental manifest digest.
        incremental_manifest: [u8; 32],
        /// The matching outputs digest.
        matching_outputs: [u8; 32],
    },
}

/// Capture errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureError {
    /// Capture attempted while producers were still running.
    ProducersNotQuiescent,
    /// Commit attempted without a staged unit.
    NothingStaged,
}

/// One capture pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotCapture {
    /// Current state.
    pub state: CaptureState,
}

impl Default for SnapshotCapture {
    fn default() -> Self {
        Self {
            state: CaptureState::ProducersRunning,
        }
    }
}

impl SnapshotCapture {
    /// The producing compiler and all output writers reported
    /// exit/sync.
    pub fn producers_quiescent(&mut self) {
        if self.state == CaptureState::ProducersRunning {
            self.state = CaptureState::Quiescent;
        }
    }

    /// Stage the PAIRED unit: incremental manifest + matching outputs
    /// together — there is no single-half staging API.
    ///
    /// # Errors
    /// [`CaptureError::ProducersNotQuiescent`] before quiescence.
    pub fn stage_pair(
        &mut self,
        incremental_manifest: [u8; 32],
        matching_outputs: [u8; 32],
    ) -> Result<(), CaptureError> {
        if self.state != CaptureState::Quiescent {
            return Err(CaptureError::ProducersNotQuiescent);
        }
        self.state = CaptureState::Staged {
            incremental_manifest,
            matching_outputs,
        };
        Ok(())
    }

    /// Commit the staged unit atomically.
    ///
    /// # Errors
    /// [`CaptureError::NothingStaged`].
    pub fn commit(&mut self) -> Result<(), CaptureError> {
        match self.state {
            CaptureState::Staged {
                incremental_manifest,
                matching_outputs,
            } => {
                self.state = CaptureState::Committed {
                    incremental_manifest,
                    matching_outputs,
                };
                Ok(())
            }
            _ => Err(CaptureError::NothingStaged),
        }
    }

    /// Crash/cancel before commit: staging is DISPOSABLE — the state
    /// returns to quiescent with nothing published.
    pub fn abort(&mut self) {
        if matches!(self.state, CaptureState::Staged { .. }) {
            self.state = CaptureState::Quiescent;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_requires_quiescence_first() {
        // THE T050 quiescence half: staging while producers run is a
        // typed refusal — moving bytes cannot be captured.
        let mut capture = SnapshotCapture::default();
        assert_eq!(
            capture.stage_pair([1; 32], [2; 32]),
            Err(CaptureError::ProducersNotQuiescent)
        );
        capture.producers_quiescent();
        assert_eq!(capture.stage_pair([1; 32], [2; 32]), Ok(()));
        assert_eq!(capture.commit(), Ok(()));
        assert_eq!(
            capture.state,
            CaptureState::Committed {
                incremental_manifest: [1; 32],
                matching_outputs: [2; 32],
            }
        );
    }

    #[test]
    fn the_pair_commits_as_one_unit_and_halves_are_unrepresentable() {
        // THE T050 atomicity half: the staged/committed states carry
        // BOTH digests in one variant — a committed manifest without
        // its matching outputs is unrepresentable (the exhaustive
        // match is the tripwire).
        let mut capture = SnapshotCapture::default();
        capture.producers_quiescent();
        capture.stage_pair([1; 32], [2; 32]).unwrap();
        capture.commit().unwrap();
        match &capture.state {
            CaptureState::Committed {
                incremental_manifest,
                matching_outputs,
            } => {
                assert_eq!(*incremental_manifest, [1; 32]);
                assert_eq!(*matching_outputs, [2; 32]);
            }
            CaptureState::ProducersRunning
            | CaptureState::Quiescent
            | CaptureState::Staged { .. } => {
                panic!("must be committed")
            }
        }
    }

    #[test]
    fn crash_before_commit_leaves_only_disposable_staging() {
        // THE T050 crash case: stage, then crash/cancel — abort
        // discards the staging, nothing was published, and a fresh
        // capture can proceed.
        let mut capture = SnapshotCapture::default();
        capture.producers_quiescent();
        capture.stage_pair([1; 32], [2; 32]).unwrap();
        capture.abort();
        assert_eq!(capture.state, CaptureState::Quiescent, "staging discarded");
        assert_eq!(capture.commit(), Err(CaptureError::NothingStaged));
        // A new pair stages and commits cleanly afterwards.
        capture.stage_pair([3; 32], [4; 32]).unwrap();
        assert_eq!(capture.commit(), Ok(()));
    }
}
