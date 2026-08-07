//! Single-active coordinator authority: identity, acquisition contract, and
//! peer high-water evaluation (bead A013; plan Part I §1 and Part VI §22).
//!
//! ## The contract (binding)
//!
//! - V1 has **one statically configured coordinator authority** and **no
//!   automatic cross-host failover**. Disaster recovery to a different host
//!   is an explicit operator-fenced procedure that proves the old authority
//!   stopped or revokes/rotates its fleet credential.
//! - On every successful acquisition the coordinator: holds an **exclusive
//!   local authority lock**; **durably advances** a cluster-wide
//!   monotonically increasing `term` *before* issuing any authority-bearing
//!   message; carries a **nondecreasing credential generation**; and creates
//!   a **fresh incarnation ID** (never equal to the previous one).
//! - `CoordinatorAuthority` is a structured **fencing identity, not a
//!   substitute for consensus**: it detects and rejects stale authority; it
//!   cannot adjudicate two simultaneously live leaders (that situation is
//!   operator error, out of contract — invariant I40, risk R88).
//!
//! The combined-role deployment note: `rabs-edge` and `rabs-coord` may run
//! in one `rabsd` process, but this identity, its durable state, and the
//! protocol carrying it stay coordinator-owned either way.
//!
//! Everything here is pure: locks/durability/randomness are modeled so the
//! ordering rules are unit- and lab-testable; `rabsd` supplies the real
//! lock, storage, and entropy.

/// Opaque cluster identity (configured, not inferred).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClusterId(pub String);

/// Fresh-per-process random coordinator incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoordinatorIncarnationId(pub u128);

/// Monotonic operator-reset generation carried by a cluster-root-signed
/// reset record (the transport layer verifies the signature; this type
/// carries the already-verified generation number).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OperatorResetGeneration(pub u64);

/// The authority-bearing identity (plan §22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorAuthority {
    /// Which cluster this authority claims.
    pub cluster_id: ClusterId,
    /// Nondecreasing credential generation (rotates on credential change).
    pub credential_generation: u64,
    /// Cluster-wide monotonically increasing term, durably advanced before
    /// any authority-bearing message.
    pub term: u64,
    /// Fresh random incarnation for this coordinator process.
    pub incarnation_id: CoordinatorIncarnationId,
}

/// A peer's durable memory of the highest authority it ever accepted
/// (invariant I40: high-water marks survive rollback).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAuthorityHighWaterMark {
    /// Cluster this mark belongs to.
    pub cluster_id: ClusterId,
    /// Highest accepted credential generation.
    pub credential_generation: u64,
    /// Highest accepted term *within* that credential generation.
    pub highest_term_within_generation: u64,
    /// The incarnation that presented the accepted (generation, term).
    pub last_incarnation_id: CoordinatorIncarnationId,
    /// Highest operator-reset generation this peer has consumed.
    pub operator_reset_generation: OperatorResetGeneration,
}

/// Outcome of evaluating an offered authority against the high-water mark.
/// Comparison is **lexicographic**: credential generation first, then term
/// (plan revision 1.6; bead S024 wires this into session admission).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityDecision {
    /// Strictly newer term within the accepted generation: accept and
    /// advance the mark.
    AcceptAdvanceTerm,
    /// Same (generation, term) presented by the SAME incarnation the mark
    /// remembers: ordinary continuation.
    AcceptSameIncarnation,
    /// Higher credential generation: opens a new term namespace, but only
    /// the configured credential-chain proof (transport layer) may finish
    /// admission — never this comparison alone.
    AcceptNewGenerationPendingCredentialProof,
    /// Operator-reset proof consumed: accept and record the new reset
    /// generation.
    AcceptViaOperatorReset,
    /// Lower credential generation than accepted: always stale.
    RejectStaleCredentialGeneration,
    /// Lower term within the accepted generation: stale.
    RejectStaleTerm,
    /// Same (generation, term) but a DIFFERENT incarnation, without an
    /// operator-reset proof: a restored database or clone may not resume
    /// authority (risk R88).
    RejectIncarnationConflict,
    /// Authority claims a different cluster.
    RejectClusterMismatch,
}

impl PeerAuthorityHighWaterMark {
    /// Evaluate an offered authority. `reset_proof`, when present, is an
    /// already-signature-verified operator reset record's generation.
    #[must_use]
    pub fn evaluate(
        &self,
        offered: &CoordinatorAuthority,
        reset_proof: Option<OperatorResetGeneration>,
    ) -> AuthorityDecision {
        if offered.cluster_id != self.cluster_id {
            return AuthorityDecision::RejectClusterMismatch;
        }
        // A fresh operator reset outranks the ordinary lexicographic rule:
        // it exists precisely to recover from fenced/lost authority.
        if let Some(reset) = reset_proof
            && reset > self.operator_reset_generation
        {
            return AuthorityDecision::AcceptViaOperatorReset;
        }
        // Lexicographic: credential generation first ...
        if offered.credential_generation < self.credential_generation {
            return AuthorityDecision::RejectStaleCredentialGeneration;
        }
        if offered.credential_generation > self.credential_generation {
            return AuthorityDecision::AcceptNewGenerationPendingCredentialProof;
        }
        // ... then term within the generation.
        if offered.term < self.highest_term_within_generation {
            return AuthorityDecision::RejectStaleTerm;
        }
        if offered.term > self.highest_term_within_generation {
            return AuthorityDecision::AcceptAdvanceTerm;
        }
        // Equal pair: only the remembered incarnation may continue.
        if offered.incarnation_id == self.last_incarnation_id {
            AuthorityDecision::AcceptSameIncarnation
        } else {
            AuthorityDecision::RejectIncarnationConflict
        }
    }
}

/// Errors from the modeled acquisition sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionError {
    /// Another process holds the exclusive local authority lock.
    LockHeldElsewhere,
    /// Authority-bearing issuance attempted before the term was durably
    /// advanced (ordering violation).
    TermNotDurablyAdvanced,
    /// The new term does not strictly exceed the last durable term.
    TermNotMonotonic,
    /// The credential generation regressed.
    CredentialGenerationRegressed,
    /// The incarnation equals the previous one (must be fresh).
    IncarnationNotFresh,
    /// Steps executed out of order.
    OutOfOrder,
}

/// Pure model of the acquisition sequence:
/// `acquire_lock → advance_term_durably → set_fresh_incarnation → issue`.
/// `rabsd` drives this with a real file lock, real durable storage, and
/// real entropy; the model makes the ORDERING rules testable everywhere.
#[derive(Debug)]
pub struct CoordinatorBoot {
    cluster_id: ClusterId,
    last_durable_term: u64,
    last_credential_generation: u64,
    previous_incarnation: Option<CoordinatorIncarnationId>,
    lock_held: bool,
    term_advanced: Option<(u64, u64)>,
    incarnation: Option<CoordinatorIncarnationId>,
}

impl CoordinatorBoot {
    /// Begin a boot against the durable state a real store would supply.
    #[must_use]
    pub const fn new(
        cluster_id: ClusterId,
        last_durable_term: u64,
        last_credential_generation: u64,
        previous_incarnation: Option<CoordinatorIncarnationId>,
    ) -> Self {
        Self {
            cluster_id,
            last_durable_term,
            last_credential_generation,
            previous_incarnation,
            lock_held: false,
            term_advanced: None,
            incarnation: None,
        }
    }

    /// Step 1: take the exclusive local authority lock.
    ///
    /// # Errors
    /// [`AcquisitionError::LockHeldElsewhere`] when another holder exists.
    pub fn acquire_lock(&mut self, lock_free: bool) -> Result<(), AcquisitionError> {
        if !lock_free {
            return Err(AcquisitionError::LockHeldElsewhere);
        }
        self.lock_held = true;
        Ok(())
    }

    /// Step 2: durably advance the term (and carry the credential
    /// generation) BEFORE any authority-bearing message.
    ///
    /// # Errors
    /// Ordering, monotonicity, and credential-regression violations.
    pub fn advance_term_durably(
        &mut self,
        new_term: u64,
        credential_generation: u64,
    ) -> Result<(), AcquisitionError> {
        if !self.lock_held {
            return Err(AcquisitionError::OutOfOrder);
        }
        if new_term <= self.last_durable_term {
            return Err(AcquisitionError::TermNotMonotonic);
        }
        if credential_generation < self.last_credential_generation {
            return Err(AcquisitionError::CredentialGenerationRegressed);
        }
        self.term_advanced = Some((new_term, credential_generation));
        Ok(())
    }

    /// Step 3: install a fresh incarnation (caller supplies entropy).
    ///
    /// # Errors
    /// [`AcquisitionError::IncarnationNotFresh`] when it repeats the
    /// previous incarnation; [`AcquisitionError::OutOfOrder`] before step 2.
    pub fn set_fresh_incarnation(
        &mut self,
        incarnation: CoordinatorIncarnationId,
    ) -> Result<(), AcquisitionError> {
        if self.term_advanced.is_none() {
            return Err(AcquisitionError::OutOfOrder);
        }
        if self.previous_incarnation == Some(incarnation) {
            return Err(AcquisitionError::IncarnationNotFresh);
        }
        self.incarnation = Some(incarnation);
        Ok(())
    }

    /// Step 4: the first authority-bearing issuance. Only legal after the
    /// full ordered sequence completed.
    ///
    /// # Errors
    /// [`AcquisitionError::TermNotDurablyAdvanced`] /
    /// [`AcquisitionError::OutOfOrder`] on ordering violations.
    pub fn issue_authority(&self) -> Result<CoordinatorAuthority, AcquisitionError> {
        if !self.lock_held {
            return Err(AcquisitionError::OutOfOrder);
        }
        let Some((term, credential_generation)) = self.term_advanced else {
            return Err(AcquisitionError::TermNotDurablyAdvanced);
        };
        let Some(incarnation_id) = self.incarnation else {
            return Err(AcquisitionError::OutOfOrder);
        };
        Ok(CoordinatorAuthority {
            cluster_id: self.cluster_id.clone(),
            credential_generation,
            term,
            incarnation_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster() -> ClusterId {
        ClusterId("fleet-1".to_string())
    }

    fn boot() -> CoordinatorBoot {
        CoordinatorBoot::new(cluster(), 7, 2, Some(CoordinatorIncarnationId(11)))
    }

    #[test]
    fn happy_path_orders_lock_term_incarnation_issue() {
        let mut b = boot();
        b.acquire_lock(true).unwrap();
        b.advance_term_durably(8, 2).unwrap();
        b.set_fresh_incarnation(CoordinatorIncarnationId(42))
            .unwrap();
        let auth = b.issue_authority().unwrap();
        assert_eq!(auth.term, 8);
        assert_eq!(auth.credential_generation, 2);
        assert_eq!(auth.incarnation_id, CoordinatorIncarnationId(42));
    }

    #[test]
    fn lock_contention_fails_acquisition() {
        let mut b = boot();
        assert_eq!(
            b.acquire_lock(false),
            Err(AcquisitionError::LockHeldElsewhere)
        );
        // And nothing later may proceed.
        assert_eq!(
            b.advance_term_durably(8, 2),
            Err(AcquisitionError::OutOfOrder)
        );
    }

    #[test]
    fn authority_cannot_issue_before_durable_term_advance() {
        let mut b = boot();
        b.acquire_lock(true).unwrap();
        assert_eq!(
            b.issue_authority().unwrap_err(),
            AcquisitionError::TermNotDurablyAdvanced
        );
    }

    #[test]
    fn term_must_strictly_increase_and_credentials_never_regress() {
        let mut b = boot();
        b.acquire_lock(true).unwrap();
        assert_eq!(
            b.advance_term_durably(7, 2),
            Err(AcquisitionError::TermNotMonotonic)
        );
        assert_eq!(
            b.advance_term_durably(8, 1),
            Err(AcquisitionError::CredentialGenerationRegressed)
        );
        b.advance_term_durably(8, 3).unwrap();
    }

    #[test]
    fn incarnation_must_be_fresh() {
        let mut b = boot();
        b.acquire_lock(true).unwrap();
        b.advance_term_durably(8, 2).unwrap();
        assert_eq!(
            b.set_fresh_incarnation(CoordinatorIncarnationId(11)),
            Err(AcquisitionError::IncarnationNotFresh)
        );
        b.set_fresh_incarnation(CoordinatorIncarnationId(12))
            .unwrap();
    }

    fn mark() -> PeerAuthorityHighWaterMark {
        PeerAuthorityHighWaterMark {
            cluster_id: cluster(),
            credential_generation: 2,
            highest_term_within_generation: 7,
            last_incarnation_id: CoordinatorIncarnationId(11),
            operator_reset_generation: OperatorResetGeneration(0),
        }
    }

    fn offered(generation: u64, term: u64, inc: u128) -> CoordinatorAuthority {
        CoordinatorAuthority {
            cluster_id: cluster(),
            credential_generation: generation,
            term,
            incarnation_id: CoordinatorIncarnationId(inc),
        }
    }

    #[test]
    fn high_water_evaluation_is_lexicographic() {
        let m = mark();
        use AuthorityDecision as D;
        // Lower credential generation: always stale, even with a huge term.
        assert_eq!(
            m.evaluate(&offered(1, 999, 11), None),
            D::RejectStaleCredentialGeneration
        );
        // Same generation, lower term: stale.
        assert_eq!(m.evaluate(&offered(2, 6, 11), None), D::RejectStaleTerm);
        // Same generation, higher term: accept/advance.
        assert_eq!(m.evaluate(&offered(2, 8, 99), None), D::AcceptAdvanceTerm);
        // Same pair, same incarnation: continuation.
        assert_eq!(
            m.evaluate(&offered(2, 7, 11), None),
            D::AcceptSameIncarnation
        );
        // Same pair, DIFFERENT incarnation: restored DB / clone — reject.
        assert_eq!(
            m.evaluate(&offered(2, 7, 99), None),
            D::RejectIncarnationConflict
        );
        // Higher generation: new namespace, pending credential-chain proof.
        assert_eq!(
            m.evaluate(&offered(3, 1, 99), None),
            D::AcceptNewGenerationPendingCredentialProof
        );
        // Wrong cluster: reject outright.
        let other = CoordinatorAuthority {
            cluster_id: ClusterId("other".into()),
            ..offered(2, 8, 11)
        };
        assert_eq!(m.evaluate(&other, None), D::RejectClusterMismatch);
    }

    #[test]
    fn operator_reset_proof_recovers_fenced_authority() {
        let m = mark();
        use AuthorityDecision as D;
        // Without proof: incarnation conflict.
        assert_eq!(
            m.evaluate(&offered(2, 7, 99), None),
            D::RejectIncarnationConflict
        );
        // With a NEWER reset generation: accepted via reset.
        assert_eq!(
            m.evaluate(&offered(2, 7, 99), Some(OperatorResetGeneration(1))),
            D::AcceptViaOperatorReset
        );
        // A stale/replayed reset proof does not help.
        assert_eq!(
            m.evaluate(&offered(2, 7, 99), Some(OperatorResetGeneration(0))),
            D::RejectIncarnationConflict
        );
    }
}
