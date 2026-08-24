//! Worker boot-generation and process-incarnation fencing (bead F029;
//! invariants I47/I54; risks R106/R114).
//!
//! Every worker start increments a **durable boot generation** and mints a
//! **fresh random process-incarnation ID**. The coordinator admits ONE
//! active incarnation per worker identity/boot-generation and rejects
//! stale, duplicate, or non-increasing sessions. Two truths held apart:
//!
//! - incarnation fencing **detects** duplicate/overlapping sessions
//!   (a cloned disk image, a restored VM, two daemons racing);
//! - it does **not prove which clone is legitimate** (I54). Ambiguity
//!   fails closed — `RejectCloneAmbiguity` — until hardware-bound
//!   enrollment or an operator re-enrollment proof resolves it. The plan
//!   makes no anti-cloning claim without that evidence.

use crate::generation::{WorkerBootGeneration, WorkerIncarnationId};
use crate::wire_time::PeerId;

/// The coordinator's durable fence row for one worker identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerIncarnationFenceRecord {
    /// The worker's durable peer identity.
    pub worker_peer_id: PeerId,
    /// Highest boot generation ever admitted.
    pub highest_boot_generation: WorkerBootGeneration,
    /// The active incarnation for that generation, if a session is live.
    pub active_incarnation: Option<WorkerIncarnationId>,
    /// Highest operator re-enrollment generation consumed.
    pub operator_reenrollment_generation: u64,
}

/// A worker session offer at admission time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSessionOffer {
    /// Claimed worker identity.
    pub worker_peer_id: PeerId,
    /// Claimed durable boot generation.
    pub boot_generation: WorkerBootGeneration,
    /// Fresh process incarnation.
    pub incarnation: WorkerIncarnationId,
    /// Operator re-enrollment proof generation, if presented
    /// (signature-verified at the transport layer).
    pub reenrollment_proof: Option<u64>,
}

/// Session admission outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerAdmission {
    /// Strictly newer boot generation: admit; every lease from prior
    /// incarnations is invalid from this point.
    AdmitNewGeneration,
    /// Same generation, same incarnation as the live session: an ordinary
    /// reconnect of the admitted process.
    AdmitReconnect,
    /// Same generation, no live incarnation (coordinator restarted or the
    /// session dropped): admit this incarnation as the one active.
    AdmitResume,
    /// Fresh operator re-enrollment proof consumed at or above the
    /// durable boot-generation high-water: admit and record it.
    AdmitViaReenrollment,
    /// Boot generation lower than the high-water mark: a stale or
    /// restored daemon; reject.
    RejectStaleBootGeneration,
    /// Same generation but a DIFFERENT incarnation while one is active:
    /// duplicate/overlapping session. Detection, not legitimacy — fails
    /// closed pending re-enrollment (I54; R106/R114).
    RejectCloneAmbiguity,
    /// The offer names a different worker identity than this record.
    RejectIdentityMismatch,
}

impl WorkerIncarnationFenceRecord {
    /// Evaluate a session offer against this fence row.
    #[must_use]
    pub fn evaluate(&self, offer: &WorkerSessionOffer) -> WorkerAdmission {
        if offer.worker_peer_id != self.worker_peer_id {
            return WorkerAdmission::RejectIdentityMismatch;
        }
        // No proof may lower the durable high-water: otherwise a clone
        // from the old lineage could later present that old high-water
        // and look strictly newer than the operator-selected worker.
        if offer.boot_generation < self.highest_boot_generation {
            return WorkerAdmission::RejectStaleBootGeneration;
        }
        // A FRESH re-enrollment proof resolves same-generation clone
        // ambiguity (or accompanies a newer generation) by operator
        // decision; a stale/replayed proof does not.
        if let Some(proof) = offer.reenrollment_proof
            && proof > self.operator_reenrollment_generation
        {
            return WorkerAdmission::AdmitViaReenrollment;
        }
        if offer.boot_generation > self.highest_boot_generation {
            return WorkerAdmission::AdmitNewGeneration;
        }
        // Equal generation: exactly one active incarnation may exist.
        match self.active_incarnation {
            None => WorkerAdmission::AdmitResume,
            Some(active) if active == offer.incarnation => WorkerAdmission::AdmitReconnect,
            Some(_) => WorkerAdmission::RejectCloneAmbiguity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(generation: u64, active: Option<u128>) -> WorkerIncarnationFenceRecord {
        WorkerIncarnationFenceRecord {
            worker_peer_id: PeerId("wkr-1".into()),
            highest_boot_generation: WorkerBootGeneration(generation),
            active_incarnation: active.map(WorkerIncarnationId),
            operator_reenrollment_generation: 0,
        }
    }

    fn offer(generation: u64, incarnation: u128) -> WorkerSessionOffer {
        WorkerSessionOffer {
            worker_peer_id: PeerId("wkr-1".into()),
            boot_generation: WorkerBootGeneration(generation),
            incarnation: WorkerIncarnationId(incarnation),
            reenrollment_proof: None,
        }
    }

    #[test]
    fn restart_with_higher_generation_admits_and_fences_the_past() {
        let r = record(3, Some(11));
        assert_eq!(
            r.evaluate(&offer(4, 99)),
            WorkerAdmission::AdmitNewGeneration
        );
    }

    #[test]
    fn stale_and_restored_daemons_are_rejected() {
        let r = record(3, None);
        assert_eq!(
            r.evaluate(&offer(2, 99)),
            WorkerAdmission::RejectStaleBootGeneration,
            "a restored disk image presents an old boot generation"
        );
    }

    #[test]
    fn one_active_incarnation_per_generation() {
        let r = record(3, Some(11));
        // The admitted process reconnecting: fine.
        assert_eq!(r.evaluate(&offer(3, 11)), WorkerAdmission::AdmitReconnect);
        // A DIFFERENT incarnation at the same generation while one is
        // active: the clone/overlap case — fails closed (R106).
        assert_eq!(
            r.evaluate(&offer(3, 22)),
            WorkerAdmission::RejectCloneAmbiguity
        );
        // No live session: the incarnation may resume the generation.
        let idle = record(3, None);
        assert_eq!(idle.evaluate(&offer(3, 22)), WorkerAdmission::AdmitResume);
    }

    #[test]
    fn reenrollment_resolves_ambiguity_but_replays_do_not() {
        let r = record(3, Some(11));
        let mut o = offer(3, 22);
        o.reenrollment_proof = Some(1);
        assert_eq!(
            r.evaluate(&o),
            WorkerAdmission::AdmitViaReenrollment,
            "a FRESH operator proof is the sanctioned clone resolution (I54)"
        );
        // Replayed proof at or below the consumed generation: no effect.
        let mut consumed = record(3, Some(11));
        consumed.operator_reenrollment_generation = 1;
        assert_eq!(
            consumed.evaluate(&o),
            WorkerAdmission::RejectCloneAmbiguity,
            "a replayed proof must not resolve ambiguity"
        );
    }

    #[test]
    fn reenrollment_never_lowers_the_global_boot_high_water() {
        let r = record(5, Some(11));
        let mut restored = offer(1, 22);
        restored.reenrollment_proof = Some(1);
        assert_eq!(
            r.evaluate(&restored),
            WorkerAdmission::RejectStaleBootGeneration,
            "operator recovery must first advance the durable boot generation"
        );
    }

    #[test]
    fn identity_mismatch_rejects_outright() {
        let r = record(3, None);
        let mut o = offer(3, 22);
        o.worker_peer_id = PeerId("wkr-2".into());
        assert_eq!(r.evaluate(&o), WorkerAdmission::RejectIdentityMismatch);
    }
}
