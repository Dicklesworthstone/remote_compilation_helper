//! Never-reused generation IDs and ABA-fence tombstones (bead F031;
//! invariant I51; risk R108).
//!
//! The pure fencing model the coordinator drives (durable tables land
//! with H038): a generation ID, once minted for an action key, may NEVER
//! be accepted again — not after the generation fails, not after the
//! active entry is evicted, not after metadata compaction, not after a
//! per-key ordinal wraps. Tombstones outlive active metadata through the
//! full stale-lease/conflict window, so an old attempt tuple can never
//! pass the fence by matching a recreated generation (the ABA hazard).

use rabs_protocol::generation::ActionGenerationId;

/// Outcome of attempting to admit a generation ID at the fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceDecision {
    /// Fresh, never-seen ID: admitted and recorded.
    Admitted,
    /// The ID was seen before (active OR tombstoned): rejected — reuse is
    /// the ABA hazard regardless of the earlier generation's fate.
    RejectReused,
}

/// Pure generation fence: remembers every ID ever admitted. The active
/// set and the tombstone set are tracked separately so eviction from the
/// ACTIVE index provably does not forget the identity (I51).
#[derive(Debug, Default, Clone)]
pub struct GenerationFence {
    active: Vec<ActionGenerationId>,
    tombstones: Vec<ActionGenerationId>,
}

impl GenerationFence {
    /// New empty fence.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active: Vec::new(),
            tombstones: Vec::new(),
        }
    }

    /// Whether an ID has ever been seen (active or tombstoned).
    #[must_use]
    pub fn seen(&self, id: ActionGenerationId) -> bool {
        self.active.contains(&id) || self.tombstones.contains(&id)
    }

    /// Admit a newly minted generation ID.
    pub fn admit(&mut self, id: ActionGenerationId) -> FenceDecision {
        if self.seen(id) {
            return FenceDecision::RejectReused;
        }
        self.active.push(id);
        FenceDecision::Admitted
    }

    /// Close a generation (failed without an eligible candidate, or
    /// superseded): it leaves the active set but its identity is
    /// TOMBSTONED, never forgotten.
    pub fn close(&mut self, id: ActionGenerationId) {
        if let Some(pos) = self.active.iter().position(|g| *g == id) {
            self.active.swap_remove(pos);
            self.tombstones.push(id);
        }
    }

    /// Evict from the active index (retention/compaction): identical to
    /// close for fencing purposes — eviction that forgot identities would
    /// reopen the ABA window (risk R108/R113).
    pub fn evict(&mut self, id: ActionGenerationId) {
        self.close(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_ids_admit_and_immediate_reuse_rejects() {
        let mut f = GenerationFence::new();
        assert_eq!(f.admit(ActionGenerationId(1)), FenceDecision::Admitted);
        assert_eq!(f.admit(ActionGenerationId(1)), FenceDecision::RejectReused);
        assert_eq!(f.admit(ActionGenerationId(2)), FenceDecision::Admitted);
    }

    #[test]
    fn closed_generations_never_readmit() {
        // The core ABA scenario (R108): generation fails, its active
        // entry closes, and a later mint (bug or replay) presents the
        // same ID — the tombstone rejects it.
        let mut f = GenerationFence::new();
        f.admit(ActionGenerationId(7));
        f.close(ActionGenerationId(7));
        assert_eq!(f.admit(ActionGenerationId(7)), FenceDecision::RejectReused);
    }

    #[test]
    fn eviction_and_repair_do_not_forget_identities() {
        // Eviction from the ACTIVE index (retention, compaction, metadata
        // repair) must not reopen the window: the tombstone survives.
        let mut f = GenerationFence::new();
        f.admit(ActionGenerationId(9));
        f.evict(ActionGenerationId(9));
        assert!(f.seen(ActionGenerationId(9)));
        assert_eq!(f.admit(ActionGenerationId(9)), FenceDecision::RejectReused);
    }

    #[test]
    fn distinct_ids_with_equal_ordinals_are_independent() {
        // Ordinals are diagnostic aids (F023); the fence keys on the
        // opaque ID alone — two generations that shared an ordinal do not
        // interfere here.
        let mut f = GenerationFence::new();
        assert_eq!(f.admit(ActionGenerationId(100)), FenceDecision::Admitted);
        assert_eq!(f.admit(ActionGenerationId(200)), FenceDecision::Admitted);
        f.close(ActionGenerationId(100));
        assert_eq!(
            f.admit(ActionGenerationId(200)),
            FenceDecision::RejectReused
        );
        assert!(f.seen(ActionGenerationId(100)));
    }
}
