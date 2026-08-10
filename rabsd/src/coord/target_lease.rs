//! Exclusive/private mutable target-state leases + whole-command
//! cloning (bead D024; invariant I35; risk R67).
//!
//! A mutable target/build/incremental directory is single-writer state:
//! two unrelated Cargo operations mutating it concurrently corrupt
//! fingerprints in ways that look like flaky rebuilds for weeks (R67).
//! The coordinator therefore admits mutation through exactly three
//! doors, and the decision type has no fourth variant to reach for:
//!
//! - **Exclusive lease** — the operation owns the whole target state
//!   until release;
//! - **Private clone** — when the state is busy and the worker lane can
//!   clone, the operation gets a private operation root cloned from the
//!   hot state and mutates THAT;
//! - **Queue** — no clone lane: the operation waits (serialization).
//!
//! Fine-grained reuse across operations flows ONLY through immutable
//! CAS objects — there is deliberately no "shared mutable" channel in
//! [`ReuseChannel`] either.

use std::collections::{BTreeMap, VecDeque};

/// Identity of one mutable target state (worker + target-dir key).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TargetStateId(pub String);

/// Identity of one requesting operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationId(pub String);

/// The coordinator's admission decision for one mutation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseDecision {
    /// The operation holds the state exclusively until release.
    GrantedExclusive,
    /// State is busy; the operation receives a PRIVATE root cloned from
    /// the hot state and mutates that instead.
    CloneIntoPrivateRoot {
        /// The private operation root (hidden backing path token).
        private_root: String,
    },
    /// State is busy and no clone lane exists: wait (serialization).
    Queued,
}

/// How results may be reused across operations. Deliberately closed:
/// there is no shared-mutable variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReuseChannel {
    /// Immutable content-addressed object (the only cross-op channel).
    ImmutableCasObject,
    /// Private to one operation (its lease or its clone).
    OperationPrivate,
}

/// The lease registry — one per coordinator.
#[derive(Debug, Default)]
pub struct TargetLeaseRegistry {
    holders: BTreeMap<TargetStateId, OperationId>,
    queues: BTreeMap<TargetStateId, VecDeque<OperationId>>,
}

impl TargetLeaseRegistry {
    /// New empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request mutation rights on `state` for `operation`.
    /// `clone_capable` is whether the worker lane can clone the hot
    /// state into a private root.
    pub fn request(
        &mut self,
        state: &TargetStateId,
        operation: &OperationId,
        clone_capable: bool,
    ) -> LeaseDecision {
        match self.holders.get(state) {
            None => {
                self.holders.insert(state.clone(), operation.clone());
                LeaseDecision::GrantedExclusive
            }
            Some(holder) if holder == operation => LeaseDecision::GrantedExclusive,
            Some(_) if clone_capable => LeaseDecision::CloneIntoPrivateRoot {
                private_root: format!("op-private/{}/{}", operation.0, state.0),
            },
            Some(_) => {
                let queue = self.queues.entry(state.clone()).or_default();
                if !queue.contains(operation) {
                    queue.push_back(operation.clone());
                }
                LeaseDecision::Queued
            }
        }
    }

    /// Release `operation`'s exclusive lease on `state`; the next
    /// queued operation (if any) is granted and returned.
    pub fn release(
        &mut self,
        state: &TargetStateId,
        operation: &OperationId,
    ) -> Option<OperationId> {
        if self.holders.get(state) != Some(operation) {
            return None; // not the holder: nothing to release
        }
        self.holders.remove(state);
        let next = self
            .queues
            .get_mut(state)
            .and_then(std::collections::VecDeque::pop_front);
        if let Some(next_op) = &next {
            self.holders.insert(state.clone(), next_op.clone());
        }
        next
    }

    /// Current exclusive holder of `state`, if any.
    #[must_use]
    pub fn holder(&self, state: &TargetStateId) -> Option<&OperationId> {
        self.holders.get(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(name: &str) -> TargetStateId {
        TargetStateId(name.to_string())
    }
    fn op(name: &str) -> OperationId {
        OperationId(name.to_string())
    }

    #[test]
    fn overlapping_operations_serialize_or_clone_never_share() {
        // THE acceptance shape: op1 holds; op2 overlaps.
        let mut registry = TargetLeaseRegistry::new();
        let target = state("hz2:/data/rch-target-pool-1");

        assert_eq!(
            registry.request(&target, &op("op1"), true),
            LeaseDecision::GrantedExclusive
        );
        // Clone lane available: op2 gets a PRIVATE root, not the state.
        let LeaseDecision::CloneIntoPrivateRoot { private_root } =
            registry.request(&target, &op("op2"), true)
        else {
            panic!("expected private clone");
        };
        assert!(private_root.contains("op2"));
        assert_eq!(registry.holder(&target), Some(&op("op1")));

        // No clone lane: op3 queues (serialization).
        assert_eq!(
            registry.request(&target, &op("op3"), false),
            LeaseDecision::Queued
        );
        // Release hands the lease to the queued op, exclusively.
        assert_eq!(registry.release(&target, &op("op1")), Some(op("op3")));
        assert_eq!(registry.holder(&target), Some(&op("op3")));
    }

    #[test]
    fn at_most_one_exclusive_holder_ever_exists_per_state() {
        // Property sweep: interleaved requests/releases across states
        // and ops; after every step the holder map is consistent and a
        // busy state never grants a second exclusive.
        let mut registry = TargetLeaseRegistry::new();
        let states = [state("s1"), state("s2")];
        let ops: Vec<OperationId> = (0..6).map(|i| op(&format!("op{i}"))).collect();
        let mut exclusive: BTreeMap<TargetStateId, OperationId> = BTreeMap::new();
        for round in 0..50u32 {
            let target = &states[(round % 2) as usize];
            let requester = &ops[(round % 6) as usize];
            match registry.request(target, requester, round % 3 == 0) {
                LeaseDecision::GrantedExclusive => {
                    if let Some(existing) = exclusive.get(target) {
                        assert_eq!(
                            existing, requester,
                            "second exclusive on a held state (round {round})"
                        );
                    }
                    exclusive.insert(target.clone(), requester.clone());
                }
                LeaseDecision::CloneIntoPrivateRoot { private_root } => {
                    assert!(private_root.contains(&requester.0), "clone must be private");
                }
                LeaseDecision::Queued => {}
            }
            if round % 7 == 0
                && let Some(holder) = exclusive.get(target).cloned()
            {
                let next = registry.release(target, &holder);
                exclusive.remove(target);
                if let Some(next_op) = next {
                    exclusive.insert(target.clone(), next_op);
                }
            }
            assert_eq!(
                registry.holder(target).cloned(),
                exclusive.get(target).cloned(),
                "registry and model diverged (round {round})"
            );
        }
    }

    #[test]
    fn re_request_by_the_holder_is_idempotent_and_stranger_release_is_inert() {
        let mut registry = TargetLeaseRegistry::new();
        let target = state("s");
        registry.request(&target, &op("op1"), false);
        assert_eq!(
            registry.request(&target, &op("op1"), false),
            LeaseDecision::GrantedExclusive
        );
        // A non-holder releasing is a no-op, not a theft.
        assert_eq!(registry.release(&target, &op("op2")), None);
        assert_eq!(registry.holder(&target), Some(&op("op1")));
    }

    #[test]
    fn reuse_channels_have_no_shared_mutable_variant() {
        // Exhaustive match: adding a shared-mutable channel would force
        // this match to face it.
        for channel in [
            ReuseChannel::ImmutableCasObject,
            ReuseChannel::OperationPrivate,
        ] {
            match channel {
                ReuseChannel::ImmutableCasObject | ReuseChannel::OperationPrivate => {}
            }
        }
    }

    #[test]
    fn threaded_overlap_never_produces_shared_mutation() {
        // Real threads race for one target state; a thread writes into
        // the SHARED dir only under an exclusive grant (guarded by
        // create_new, which would collide on any double-grant) and into
        // its PRIVATE clone dir otherwise.
        use std::sync::{Arc, Mutex};
        let registry = Arc::new(Mutex::new(TargetLeaseRegistry::new()));
        let root = Arc::new(tempfile::tempdir().unwrap());
        std::fs::create_dir_all(root.path().join("shared")).unwrap();
        let target = state("shared");

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let registry = Arc::clone(&registry);
                let root = Arc::clone(&root);
                let target = target.clone();
                std::thread::spawn(move || {
                    let me = op(&format!("op{i}"));
                    loop {
                        let decision = registry.lock().unwrap().request(&target, &me, i % 2 == 0);
                        match decision {
                            LeaseDecision::GrantedExclusive => {
                                // create_new collides iff two threads
                                // ever hold the lease simultaneously.
                                let guard = root.path().join("shared/.mutating");
                                std::fs::File::options()
                                    .write(true)
                                    .create_new(true)
                                    .open(&guard)
                                    .expect("SHARED MUTATION: double exclusive grant");
                                std::fs::write(root.path().join(format!("shared/{i}")), b"x")
                                    .unwrap();
                                std::fs::remove_file(&guard).unwrap();
                                registry.lock().unwrap().release(&target, &me);
                                return;
                            }
                            LeaseDecision::CloneIntoPrivateRoot { private_root } => {
                                let private = root.path().join(private_root);
                                std::fs::create_dir_all(&private).unwrap();
                                std::fs::write(private.join("out"), b"x").unwrap();
                                return;
                            }
                            LeaseDecision::Queued => std::thread::yield_now(),
                        }
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    }
}
