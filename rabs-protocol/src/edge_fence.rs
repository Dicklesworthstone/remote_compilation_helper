//! Edge boot/incarnation/handoff fencing for live wrapper resumption
//! (bead C025; risk R118; the protocol face of the H038 store rows).
//!
//! Wrappers resume against "the edge" — but which edge process? After
//! a restart or a live upgrade there may briefly be two. The ownership
//! law: **exactly one incarnation owns subscriber/materialization
//! rights per boot generation**, with ONE exception — a bounded,
//! explicit handoff window in which:
//!
//! - the successor presents a coordinator-authorized [`HandoffToken`]
//!   naming the exact predecessor and the session set moving over;
//! - BOTH incarnations report their delivery frontiers during
//!   reconciliation (a successor that never heard the predecessor's
//!   frontiers would guess at wrapper exposure state);
//! - the predecessor is FENCED — durably recorded in the
//!   [`EdgeIncarnationFenceRecord`] — before the successor becomes
//!   sole owner;
//! - the window is bounded by a deadline sequence: an incomplete
//!   handoff expires, the successor never owned anything, and the
//!   predecessor simply keeps its rights.
//!
//! Arbitrary multi-incarnation overlap is forbidden in every other
//! form: a second concurrent handoff, a successor exercising rights
//! before the fence, a fenced predecessor coming back, or a stranger
//! incarnation exercising anything — all typed refusals. The C014
//! reconnect view honors exactly the current incarnation and, during
//! the window, its ONE named predecessor.

use crate::result_identity::TypedDigest;

/// THE C025 schema: the durable record a completed fence writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeIncarnationFenceRecord {
    /// The edge identity (stable across restarts).
    pub edge_id: String,
    /// Boot generation AFTER the fence (advances monotonically).
    pub boot_generation: u64,
    /// The incarnation that now solely owns rights.
    pub owner_incarnation: u128,
    /// The predecessor incarnation this record fences out.
    pub fenced_incarnation: u128,
    /// Sessions that moved over in the handoff.
    pub session_set: Vec<u128>,
    /// Sequence at which the fence landed.
    pub fenced_at_seq: u64,
}

/// Coordinator-authorized permission for one explicit handoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffToken {
    /// The edge this token is for.
    pub edge_id: String,
    /// The exact predecessor being succeeded.
    pub predecessor_incarnation: u128,
    /// The successor presenting the token.
    pub successor_incarnation: u128,
    /// The named session set moving over.
    pub session_set: Vec<u128>,
    /// Digest of the coordinator authority that authorized this token.
    pub authorized_by: TypedDigest,
}

/// Typed fencing refusals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceError {
    /// The token names a predecessor that is not the current sole
    /// owner (stale token, or an attempt to skip a generation).
    PredecessorMismatch {
        /// The token's claimed predecessor.
        claimed: u128,
        /// The actual sole owner.
        actual: u128,
    },
    /// The token's edge id is not this edge.
    WrongEdge,
    /// The token was not authorized by the active coordinator
    /// authority.
    NotAuthorized,
    /// A handoff window is already open — at most ONE, ever
    /// (arbitrary multi-incarnation overlap forbidden).
    HandoffAlreadyActive,
    /// No handoff window is open.
    NoActiveHandoff,
    /// The window's deadline passed: the handoff expired; the
    /// predecessor keeps its rights.
    HandoffExpired {
        /// The deadline that passed.
        deadline_seq: u64,
    },
    /// Completion requires BOTH incarnations' frontier reports.
    FrontiersIncomplete {
        /// Predecessor reported.
        predecessor_reported: bool,
        /// Successor reported.
        successor_reported: bool,
    },
    /// The incarnation does not own subscriber/materialization rights.
    NotSoleOwner {
        /// The incarnation that tried.
        incarnation: u128,
        /// The actual owner.
        owner: u128,
    },
    /// A frontier report from an incarnation that is not part of the
    /// open window.
    NotInHandoff {
        /// The reporting incarnation.
        incarnation: u128,
    },
}

/// The open handoff window.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveHandoff {
    token: HandoffToken,
    deadline_seq: u64,
    predecessor_reported: bool,
    successor_reported: bool,
}

/// Per-edge ownership state machine: one boot generation, one sole
/// owner, at most one bounded handoff window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeOwnership {
    edge_id: String,
    boot_generation: u64,
    sole_owner: u128,
    handoff: Option<ActiveHandoff>,
}

impl EdgeOwnership {
    /// A freshly booted edge: durable boot generation + fresh
    /// incarnation, sole owner immediately (a COLD restart has no
    /// predecessor to hand off from — prior wrappers reconcile via
    /// C014 or start new operations).
    #[must_use]
    pub fn cold_boot(edge_id: &str, boot_generation: u64, incarnation: u128) -> Self {
        Self {
            edge_id: edge_id.to_owned(),
            boot_generation,
            sole_owner: incarnation,
            handoff: None,
        }
    }

    /// Current boot generation.
    #[must_use]
    pub const fn boot_generation(&self) -> u64 {
        self.boot_generation
    }

    /// Whether `incarnation` may exercise subscriber/materialization
    /// rights RIGHT NOW. During an open window the PREDECESSOR still
    /// owns (until fenced); every other incarnation is refused.
    ///
    /// # Errors
    /// [`FenceError::NotSoleOwner`].
    pub const fn check_rights(&self, incarnation: u128) -> Result<(), FenceError> {
        if incarnation == self.sole_owner {
            Ok(())
        } else {
            Err(FenceError::NotSoleOwner {
                incarnation,
                owner: self.sole_owner,
            })
        }
    }

    /// The predecessor the C014 reconnect view honors: only during an
    /// open window, and only the ONE named predecessor.
    #[must_use]
    pub fn honored_predecessor(&self) -> Option<u128> {
        self.handoff
            .as_ref()
            .map(|h| h.token.predecessor_incarnation)
    }

    /// Open the bounded handoff window.
    ///
    /// # Errors
    /// Typed [`FenceError`]; nothing changes on refusal.
    pub fn begin_handoff(
        &mut self,
        token: HandoffToken,
        active_authority: &TypedDigest,
        deadline_seq: u64,
    ) -> Result<(), FenceError> {
        if self.handoff.is_some() {
            return Err(FenceError::HandoffAlreadyActive);
        }
        if token.edge_id != self.edge_id {
            return Err(FenceError::WrongEdge);
        }
        if token.authorized_by != *active_authority {
            return Err(FenceError::NotAuthorized);
        }
        if token.predecessor_incarnation != self.sole_owner {
            return Err(FenceError::PredecessorMismatch {
                claimed: token.predecessor_incarnation,
                actual: self.sole_owner,
            });
        }
        self.handoff = Some(ActiveHandoff {
            token,
            deadline_seq,
            predecessor_reported: false,
            successor_reported: false,
        });
        Ok(())
    }

    /// Record one side's delivery-frontier report during
    /// reconciliation.
    ///
    /// # Errors
    /// Typed [`FenceError`].
    pub fn report_frontier(&mut self, incarnation: u128) -> Result<(), FenceError> {
        let Some(handoff) = &mut self.handoff else {
            return Err(FenceError::NoActiveHandoff);
        };
        if incarnation == handoff.token.predecessor_incarnation {
            handoff.predecessor_reported = true;
            Ok(())
        } else if incarnation == handoff.token.successor_incarnation {
            handoff.successor_reported = true;
            Ok(())
        } else {
            Err(FenceError::NotInHandoff { incarnation })
        }
    }

    /// Complete the handoff: predecessor fenced FIRST (the record is
    /// the durable fence), then the successor becomes sole owner and
    /// the boot generation advances.
    ///
    /// # Errors
    /// Typed [`FenceError`]; an expired window also clears itself —
    /// the predecessor keeps its rights.
    pub fn complete_handoff(
        &mut self,
        current_seq: u64,
    ) -> Result<EdgeIncarnationFenceRecord, FenceError> {
        let Some(handoff) = &self.handoff else {
            return Err(FenceError::NoActiveHandoff);
        };
        if current_seq > handoff.deadline_seq {
            let deadline_seq = handoff.deadline_seq;
            // Bounded window: expiry aborts the handoff outright.
            self.handoff = None;
            return Err(FenceError::HandoffExpired { deadline_seq });
        }
        if !(handoff.predecessor_reported && handoff.successor_reported) {
            return Err(FenceError::FrontiersIncomplete {
                predecessor_reported: handoff.predecessor_reported,
                successor_reported: handoff.successor_reported,
            });
        }
        let handoff = self.handoff.take().expect("checked above");
        self.boot_generation += 1;
        self.sole_owner = handoff.token.successor_incarnation;
        Ok(EdgeIncarnationFenceRecord {
            edge_id: self.edge_id.clone(),
            boot_generation: self.boot_generation,
            owner_incarnation: handoff.token.successor_incarnation,
            fenced_incarnation: handoff.token.predecessor_incarnation,
            session_set: handoff.token.session_set,
            fenced_at_seq: current_seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::DigestAlgorithm;

    fn digest(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.coordinator-authority.sha256.v1",
            bytes: [tag; 32],
        }
    }

    fn token(predecessor: u128, successor: u128) -> HandoffToken {
        HandoffToken {
            edge_id: "edge-a".to_owned(),
            predecessor_incarnation: predecessor,
            successor_incarnation: successor,
            session_set: vec![10, 11],
            authorized_by: digest(1),
        }
    }

    #[test]
    fn c025_happy_handoff_fences_predecessor_before_successor_owns() {
        let mut edge = EdgeOwnership::cold_boot("edge-a", 3, 5);
        edge.begin_handoff(token(5, 6), &digest(1), 100).unwrap();
        // During the window the PREDECESSOR still owns; the successor
        // is refused (no overlap, ever).
        assert_eq!(edge.check_rights(5), Ok(()));
        assert_eq!(
            edge.check_rights(6),
            Err(FenceError::NotSoleOwner {
                incarnation: 6,
                owner: 5
            })
        );
        // C014 honors exactly the one named predecessor while open.
        assert_eq!(edge.honored_predecessor(), Some(5));
        // Completion requires BOTH frontier reports.
        edge.report_frontier(5).unwrap();
        assert_eq!(
            edge.complete_handoff(50),
            Err(FenceError::FrontiersIncomplete {
                predecessor_reported: true,
                successor_reported: false,
            })
        );
        edge.report_frontier(6).unwrap();
        let record = edge.complete_handoff(50).unwrap();
        // THE schema: predecessor named as fenced, generation advanced.
        assert_eq!(record.edge_id, "edge-a");
        assert_eq!(record.boot_generation, 4);
        assert_eq!(record.owner_incarnation, 6);
        assert_eq!(record.fenced_incarnation, 5);
        assert_eq!(record.session_set, vec![10, 11]);
        assert_eq!(record.fenced_at_seq, 50);
        // After the fence: successor sole owner, predecessor refused.
        assert_eq!(edge.check_rights(6), Ok(()));
        assert_eq!(
            edge.check_rights(5),
            Err(FenceError::NotSoleOwner {
                incarnation: 5,
                owner: 6
            })
        );
        assert_eq!(edge.honored_predecessor(), None);
    }

    #[test]
    fn c025_overlap_rejection_in_every_form() {
        let mut edge = EdgeOwnership::cold_boot("edge-a", 3, 5);
        edge.begin_handoff(token(5, 6), &digest(1), 100).unwrap();
        // A SECOND concurrent handoff is refused — at most one window.
        assert_eq!(
            edge.begin_handoff(token(5, 7), &digest(1), 100),
            Err(FenceError::HandoffAlreadyActive)
        );
        // A stranger incarnation owns nothing and cannot report.
        assert_eq!(
            edge.check_rights(99),
            Err(FenceError::NotSoleOwner {
                incarnation: 99,
                owner: 5
            })
        );
        assert_eq!(
            edge.report_frontier(99),
            Err(FenceError::NotInHandoff { incarnation: 99 })
        );

        // Token gates: wrong edge, wrong authority, wrong predecessor.
        let mut fresh = EdgeOwnership::cold_boot("edge-a", 3, 5);
        let mut wrong_edge = token(5, 6);
        wrong_edge.edge_id = "edge-b".to_owned();
        assert_eq!(
            fresh.begin_handoff(wrong_edge, &digest(1), 100),
            Err(FenceError::WrongEdge)
        );
        assert_eq!(
            fresh.begin_handoff(token(5, 6), &digest(2), 100),
            Err(FenceError::NotAuthorized)
        );
        assert_eq!(
            fresh.begin_handoff(token(4, 6), &digest(1), 100),
            Err(FenceError::PredecessorMismatch {
                claimed: 4,
                actual: 5
            })
        );
    }

    #[test]
    fn c025_expired_window_leaves_the_predecessor_as_sole_owner() {
        let mut edge = EdgeOwnership::cold_boot("edge-a", 3, 5);
        edge.begin_handoff(token(5, 6), &digest(1), 100).unwrap();
        edge.report_frontier(5).unwrap();
        edge.report_frontier(6).unwrap();
        // Deadline passed: the handoff expires and clears; the
        // successor NEVER owned anything.
        assert_eq!(
            edge.complete_handoff(101),
            Err(FenceError::HandoffExpired { deadline_seq: 100 })
        );
        assert_eq!(edge.check_rights(5), Ok(()));
        assert_eq!(
            edge.check_rights(6),
            Err(FenceError::NotSoleOwner {
                incarnation: 6,
                owner: 5
            })
        );
        assert_eq!(edge.boot_generation(), 3, "no generation advance");
        assert_eq!(edge.honored_predecessor(), None, "window closed");
        // A fresh, properly completed handoff still works afterward.
        edge.begin_handoff(token(5, 6), &digest(1), 200).unwrap();
        edge.report_frontier(5).unwrap();
        edge.report_frontier(6).unwrap();
        assert!(edge.complete_handoff(150).is_ok());
    }

    #[test]
    fn c025_cold_boot_is_sole_owner_with_no_predecessor() {
        let edge = EdgeOwnership::cold_boot("edge-a", 7, 42);
        assert_eq!(edge.boot_generation(), 7);
        assert_eq!(edge.check_rights(42), Ok(()));
        assert_eq!(edge.honored_predecessor(), None);
    }
}
