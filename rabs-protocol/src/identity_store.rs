//! Durable coordinator/worker identity store + rotation (bead S001;
//! plan §106; the mismatch verdicts feed the R008
//! `WorkerIdentityMismatch` incident).
//!
//! Identity is public-key-derived and HISTORY-SHAPED:
//!
//! - a peer is its key-derived id plus a fingerprint at a
//!   GENERATION; rotation appends a new generation, it never edits
//!   the past — the store is append-only (no delete API exists) and
//!   the current view is DERIVED from history, never stored beside
//!   it;
//! - verification is exact: the presented fingerprint must match the
//!   CURRENT generation's — an old fingerprint after rotation is a
//!   typed mismatch, not a fallback;
//! - revocation is terminal: no rotation, no verification, ever
//!   again under that peer id;
//! - sessions BIND to the generation they handshook at: after a
//!   rotation, a stale-generation binding refuses typed — the peer
//!   must re-handshake under the new key.

/// Trust scopes an identity can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustScope {
    /// The coordinator role.
    Coordinator,
    /// A worker.
    Worker,
    /// An edge/wrapper host.
    Edge,
}

/// One durable history event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityEvent {
    /// Identity created at generation 1.
    Created {
        /// The initial key fingerprint.
        fingerprint: [u8; 32],
        /// The trust scope granted.
        scope: TrustScope,
    },
    /// Key rotated to a new generation.
    Rotated {
        /// The new fingerprint.
        fingerprint: [u8; 32],
        /// The generation rotated TO.
        to_generation: u32,
    },
    /// Identity revoked (terminal).
    Revoked,
}

/// One history record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRecord {
    /// The peer (public-key-derived id bytes).
    pub peer_id: [u8; 32],
    /// Sequence the event landed at.
    pub seq: u64,
    /// The event.
    pub event: IdentityEvent,
}

/// Typed store refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRefusal {
    /// Peer id already exists.
    AlreadyExists,
    /// Peer id unknown.
    Unknown,
    /// The identity was revoked (terminal).
    Revoked,
}

/// Verification verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyVerdict {
    /// Fingerprint matches the current generation.
    Valid {
        /// The current generation.
        generation: u32,
        /// The identity's trust scope.
        scope: TrustScope,
    },
    /// Fingerprint does NOT match the current generation (the R008
    /// WorkerIdentityMismatch signal).
    Mismatch {
        /// The generation whose fingerprint WOULD have matched, if
        /// the presented one belongs to history (a stale key), or
        /// `None` for a fingerprint never seen.
        matches_generation: Option<u32>,
    },
    /// The identity is revoked.
    RevokedIdentity,
    /// The peer id is unknown.
    UnknownPeer,
}

/// A session's binding to the identity generation it handshook at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBinding {
    /// The peer.
    pub peer_id: [u8; 32],
    /// The generation at handshake.
    pub generation: u32,
    /// The session.
    pub session_id: u64,
}

/// Session-binding verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingVerdict {
    /// The binding is current.
    Bound,
    /// The identity rotated since the handshake: re-handshake.
    StaleGeneration {
        /// The binding's generation.
        bound: u32,
        /// The current generation.
        current: u32,
    },
    /// Revoked or unknown identity.
    IdentityGone,
}

/// The append-only identity store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityStore {
    records: Vec<IdentityRecord>,
}

/// The derived current view of one peer.
struct CurrentView {
    fingerprint: [u8; 32],
    generation: u32,
    scope: TrustScope,
    revoked: bool,
}

impl IdentityStore {
    fn view(&self, peer_id: &[u8; 32]) -> Option<CurrentView> {
        let mut view: Option<CurrentView> = None;
        for record in self.records.iter().filter(|r| r.peer_id == *peer_id) {
            match (&record.event, &mut view) {
                (IdentityEvent::Created { fingerprint, scope }, None) => {
                    view = Some(CurrentView {
                        fingerprint: *fingerprint,
                        generation: 1,
                        scope: *scope,
                        revoked: false,
                    });
                }
                (
                    IdentityEvent::Rotated {
                        fingerprint,
                        to_generation,
                    },
                    Some(v),
                ) => {
                    v.fingerprint = *fingerprint;
                    v.generation = *to_generation;
                }
                (IdentityEvent::Revoked, Some(v)) => v.revoked = true,
                _ => {}
            }
        }
        view
    }

    /// Create an identity (generation 1).
    ///
    /// # Errors
    /// [`IdentityRefusal::AlreadyExists`].
    pub fn create(
        &mut self,
        peer_id: [u8; 32],
        fingerprint: [u8; 32],
        scope: TrustScope,
        seq: u64,
    ) -> Result<(), IdentityRefusal> {
        if self.view(&peer_id).is_some() {
            return Err(IdentityRefusal::AlreadyExists);
        }
        self.records.push(IdentityRecord {
            peer_id,
            seq,
            event: IdentityEvent::Created { fingerprint, scope },
        });
        Ok(())
    }

    /// Rotate to a new key fingerprint (next generation).
    ///
    /// # Errors
    /// [`IdentityRefusal::Unknown`] or [`IdentityRefusal::Revoked`].
    pub fn rotate(
        &mut self,
        peer_id: [u8; 32],
        new_fingerprint: [u8; 32],
        seq: u64,
    ) -> Result<u32, IdentityRefusal> {
        let view = self.view(&peer_id).ok_or(IdentityRefusal::Unknown)?;
        if view.revoked {
            return Err(IdentityRefusal::Revoked);
        }
        let to_generation = view.generation + 1;
        self.records.push(IdentityRecord {
            peer_id,
            seq,
            event: IdentityEvent::Rotated {
                fingerprint: new_fingerprint,
                to_generation,
            },
        });
        Ok(to_generation)
    }

    /// Revoke (terminal).
    ///
    /// # Errors
    /// [`IdentityRefusal::Unknown`]; revoking twice is idempotent.
    pub fn revoke(&mut self, peer_id: [u8; 32], seq: u64) -> Result<(), IdentityRefusal> {
        let _ = self.view(&peer_id).ok_or(IdentityRefusal::Unknown)?;
        self.records.push(IdentityRecord {
            peer_id,
            seq,
            event: IdentityEvent::Revoked,
        });
        Ok(())
    }

    /// Verify a presented fingerprint against the CURRENT generation.
    #[must_use]
    pub fn verify(&self, peer_id: &[u8; 32], presented: &[u8; 32]) -> VerifyVerdict {
        let Some(view) = self.view(peer_id) else {
            return VerifyVerdict::UnknownPeer;
        };
        if view.revoked {
            return VerifyVerdict::RevokedIdentity;
        }
        if view.fingerprint == *presented {
            return VerifyVerdict::Valid {
                generation: view.generation,
                scope: view.scope,
            };
        }
        // A stale key from history is named by its generation.
        let matches_generation = self
            .records
            .iter()
            .filter(|r| r.peer_id == *peer_id)
            .find_map(|r| match &r.event {
                IdentityEvent::Created { fingerprint, .. } if fingerprint == presented => Some(1),
                IdentityEvent::Rotated {
                    fingerprint,
                    to_generation,
                } if fingerprint == presented => Some(*to_generation),
                _ => None,
            });
        VerifyVerdict::Mismatch { matches_generation }
    }

    /// Check a session binding against the current generation.
    #[must_use]
    pub fn check_binding(&self, binding: &SessionBinding) -> BindingVerdict {
        let Some(view) = self.view(&binding.peer_id) else {
            return BindingVerdict::IdentityGone;
        };
        if view.revoked {
            return BindingVerdict::IdentityGone;
        }
        if binding.generation == view.generation {
            BindingVerdict::Bound
        } else {
            BindingVerdict::StaleGeneration {
                bound: binding.generation,
                current: view.generation,
            }
        }
    }

    /// The full durable history for a peer, in order.
    #[must_use]
    pub fn history(&self, peer_id: &[u8; 32]) -> Vec<&IdentityRecord> {
        self.records
            .iter()
            .filter(|r| r.peer_id == *peer_id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: [u8; 32] = [7; 32];
    const KEY_1: [u8; 32] = [1; 32];
    const KEY_2: [u8; 32] = [2; 32];
    const KEY_3: [u8; 32] = [3; 32];

    #[test]
    fn the_lifecycle_leaves_a_durable_ordered_history() {
        // THE acceptance: create → rotate → rotate → revoke, every
        // event durable and ordered.
        let mut store = IdentityStore::default();
        store
            .create(PEER, KEY_1, TrustScope::Worker, 10)
            .expect("creates");
        assert_eq!(store.rotate(PEER, KEY_2, 20), Ok(2));
        assert_eq!(store.rotate(PEER, KEY_3, 30), Ok(3));
        store.revoke(PEER, 40).expect("revokes");
        let history = store.history(&PEER);
        assert_eq!(history.len(), 4);
        assert_eq!(
            history[0].event,
            IdentityEvent::Created {
                fingerprint: KEY_1,
                scope: TrustScope::Worker,
            }
        );
        assert_eq!(
            history[2].event,
            IdentityEvent::Rotated {
                fingerprint: KEY_3,
                to_generation: 3,
            }
        );
        assert_eq!(history[3].event, IdentityEvent::Revoked);
        assert_eq!(
            history.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![10, 20, 30, 40],
            "sequence-stamped, in order"
        );
    }

    #[test]
    fn verification_is_exact_per_generation() {
        let mut store = IdentityStore::default();
        store
            .create(PEER, KEY_1, TrustScope::Worker, 1)
            .expect("creates");
        assert_eq!(
            store.verify(&PEER, &KEY_1),
            VerifyVerdict::Valid {
                generation: 1,
                scope: TrustScope::Worker,
            }
        );
        store.rotate(PEER, KEY_2, 2).expect("rotates");
        // The OLD key after rotation: a typed mismatch naming the
        // generation it belonged to (the R008 incident signal).
        assert_eq!(
            store.verify(&PEER, &KEY_1),
            VerifyVerdict::Mismatch {
                matches_generation: Some(1),
            }
        );
        // A never-seen key: mismatch with no historical generation.
        assert_eq!(
            store.verify(&PEER, &[9; 32]),
            VerifyVerdict::Mismatch {
                matches_generation: None,
            }
        );
        // Unknown peer / revoked identity are their own verdicts.
        assert_eq!(store.verify(&[8; 32], &KEY_1), VerifyVerdict::UnknownPeer);
        store.revoke(PEER, 3).expect("revokes");
        assert_eq!(store.verify(&PEER, &KEY_2), VerifyVerdict::RevokedIdentity);
    }

    #[test]
    fn rotation_and_creation_refusals_are_typed() {
        let mut store = IdentityStore::default();
        assert_eq!(
            store.rotate(PEER, KEY_2, 1),
            Err(IdentityRefusal::Unknown),
            "cannot rotate what was never created"
        );
        store
            .create(PEER, KEY_1, TrustScope::Coordinator, 1)
            .expect("creates");
        assert_eq!(
            store.create(PEER, KEY_2, TrustScope::Worker, 2),
            Err(IdentityRefusal::AlreadyExists)
        );
        store.revoke(PEER, 3).expect("revokes");
        assert_eq!(
            store.rotate(PEER, KEY_2, 4),
            Err(IdentityRefusal::Revoked),
            "revocation is terminal"
        );
    }

    #[test]
    fn sessions_bind_to_the_generation_they_handshook_at() {
        let mut store = IdentityStore::default();
        store
            .create(PEER, KEY_1, TrustScope::Worker, 1)
            .expect("creates");
        let binding = SessionBinding {
            peer_id: PEER,
            generation: 1,
            session_id: 77,
        };
        assert_eq!(store.check_binding(&binding), BindingVerdict::Bound);
        // Rotation invalidates the old binding — re-handshake.
        store.rotate(PEER, KEY_2, 2).expect("rotates");
        assert_eq!(
            store.check_binding(&binding),
            BindingVerdict::StaleGeneration {
                bound: 1,
                current: 2,
            }
        );
        let fresh = SessionBinding {
            peer_id: PEER,
            generation: 2,
            session_id: 78,
        };
        assert_eq!(store.check_binding(&fresh), BindingVerdict::Bound);
        // Revocation kills every binding.
        store.revoke(PEER, 3).expect("revokes");
        assert_eq!(store.check_binding(&fresh), BindingVerdict::IdentityGone);
    }

    #[test]
    fn the_store_is_append_only_and_peers_are_isolated() {
        // Structural: records are private and the API is create/
        // rotate/revoke/history — no removal or edit path exists.
        let mut store = IdentityStore::default();
        store
            .create(PEER, KEY_1, TrustScope::Worker, 1)
            .expect("creates");
        let before: Vec<IdentityRecord> = store.history(&PEER).into_iter().cloned().collect();
        // Operations on ANOTHER peer leave this history untouched.
        store
            .create([8; 32], KEY_2, TrustScope::Edge, 2)
            .expect("creates");
        store.rotate([8; 32], KEY_3, 3).expect("rotates");
        let after: Vec<IdentityRecord> = store.history(&PEER).into_iter().cloned().collect();
        assert_eq!(before, after);
    }
}
