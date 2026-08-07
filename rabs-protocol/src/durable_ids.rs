//! Durable wire identifiers + reconnect reconciliation (bead J005;
//! Asupersync blocker 44.3; risk R63).
//!
//! Asupersync's remote task handles are process-local numerics: a
//! daemon restart mints new numbers for the same logical work, so a
//! handle alone can never reconcile a reconnect. RABS messages
//! therefore carry DURABLE identities — build operation, action
//! generation, attempt, execution lease — and the adapter maps them
//! to whatever transient handle the current process uses:
//!
//! - the durable tuple is minted once and survives restarts (it lives
//!   in the coordinator's durable state, not in any socket);
//! - the adapter's handle map is REBUILT from durable IDs after every
//!   reconnect: an old handle number reappearing by coincidence maps
//!   to nothing (handles are looked up through the durable ID, never
//!   the reverse);
//! - reconciliation is exact-match on the full tuple: a reconnect
//!   claiming a known operation with a WRONG generation/attempt/lease
//!   resolves to nothing (the F029/F031 fences then judge it).

use crate::generation::{ActionGenerationId, AttemptId, ExecutionLeaseId};

/// Durable build-operation identity (random 128-bit, coordinator-minted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BuildOperationId(pub u128);

/// The durable identity tuple every remote message carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DurableWireIdentity {
    /// The build operation.
    pub operation: BuildOperationId,
    /// The action generation.
    pub generation: ActionGenerationId,
    /// The attempt.
    pub attempt: AttemptId,
    /// The execution lease.
    pub lease: ExecutionLeaseId,
}

/// A process-local transient handle (Asupersync's remote task number).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransientHandle(pub u64);

/// The adapter's mapping between durable identities and the CURRENT
/// process's transient handles. Rebuilt after every restart; lookup
/// direction is durable → transient ONLY.
#[derive(Debug, Default, Clone)]
pub struct HandleMap {
    entries: Vec<(DurableWireIdentity, TransientHandle)>,
}

/// Reconciliation outcome for one incoming durable identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconciliation {
    /// Known durable identity: resolved to this process's handle.
    Resolved(TransientHandle),
    /// Unknown identity (or a stale/partial tuple): nothing to attach
    /// to — the caller consults durable state, never guesses.
    Unknown,
}

impl HandleMap {
    /// Bind a durable identity to the current process's handle
    /// (registration or post-restart rebuild).
    pub fn bind(&mut self, durable: DurableWireIdentity, handle: TransientHandle) {
        match self.entries.iter_mut().find(|(d, _)| *d == durable) {
            Some((_, existing)) => *existing = handle,
            None => self.entries.push((durable, handle)),
        }
    }

    /// Resolve an incoming message's durable identity. EXACT tuple
    /// match only.
    #[must_use]
    pub fn resolve(&self, durable: &DurableWireIdentity) -> Reconciliation {
        self.entries
            .iter()
            .find(|(d, _)| d == durable)
            .map_or(Reconciliation::Unknown, |(_, handle)| {
                Reconciliation::Resolved(*handle)
            })
    }

    /// Simulate a daemon restart: every transient handle dies; durable
    /// identities are re-bound by re-registration from durable state.
    pub fn restart(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(op: u128, generation: u128, attempt: u128, lease: u128) -> DurableWireIdentity {
        DurableWireIdentity {
            operation: BuildOperationId(op),
            generation: ActionGenerationId(generation),
            attempt: AttemptId(attempt),
            lease: ExecutionLeaseId(lease),
        }
    }

    #[test]
    fn reconnect_reconciliation_survives_daemon_restart() {
        // THE acceptance case: durable IDs resolve operations across a
        // restart even though every transient handle number changed.
        let durable = identity(1, 2, 3, 4);
        let mut map = HandleMap::default();
        map.bind(durable, TransientHandle(17));
        assert_eq!(
            map.resolve(&durable),
            Reconciliation::Resolved(TransientHandle(17))
        );
        // Daemon restarts: all transient handles die.
        map.restart();
        assert_eq!(map.resolve(&durable), Reconciliation::Unknown);
        // Rebuild from durable state: the SAME durable identity binds
        // to a brand-new handle number — reconciliation is unbroken.
        map.bind(durable, TransientHandle(1));
        assert_eq!(
            map.resolve(&durable),
            Reconciliation::Resolved(TransientHandle(1))
        );
    }

    #[test]
    fn handle_numbers_are_never_an_identity_channel() {
        // After a restart, an OLD handle number reappearing for a
        // DIFFERENT durable identity resolves only through its own
        // durable tuple; the old identity stays Unknown.
        let old = identity(1, 2, 3, 4);
        let new = identity(9, 8, 7, 6);
        let mut map = HandleMap::default();
        map.bind(old, TransientHandle(17));
        map.restart();
        map.bind(new, TransientHandle(17)); // same NUMBER, new identity
        assert_eq!(
            map.resolve(&new),
            Reconciliation::Resolved(TransientHandle(17))
        );
        assert_eq!(
            map.resolve(&old),
            Reconciliation::Unknown,
            "a recycled handle number must not resurrect an old identity"
        );
    }

    #[test]
    fn reconciliation_is_exact_on_the_full_tuple() {
        // A reconnect claiming the right operation with a wrong
        // generation/attempt/lease resolves to NOTHING (the fences
        // then judge the claim).
        let bound = identity(1, 2, 3, 4);
        let mut map = HandleMap::default();
        map.bind(bound, TransientHandle(5));
        for wrong in [
            identity(1, 99, 3, 4),
            identity(1, 2, 99, 4),
            identity(1, 2, 3, 99),
            identity(99, 2, 3, 4),
        ] {
            assert_eq!(map.resolve(&wrong), Reconciliation::Unknown);
        }
    }

    #[test]
    fn rebinding_updates_in_place() {
        let durable = identity(1, 2, 3, 4);
        let mut map = HandleMap::default();
        map.bind(durable, TransientHandle(5));
        map.bind(durable, TransientHandle(6)); // reconnect within one life
        assert_eq!(
            map.resolve(&durable),
            Reconciliation::Resolved(TransientHandle(6))
        );
    }
}
