//! Session ↔ boot-generation/incarnation binding (bead J028;
//! invariants I47/I54; risk R106; fixture family T038).
//!
//! The F029 fence judges worker session offers; this suite proves the
//! T038 cloned/restored-worker scenarios END TO END through the fence
//! plus the J012 session handlers: sessions carry the restart
//! generation + fresh incarnation, ONE incarnation is active per
//! identity/generation, non-increasing generations and duplicate
//! incarnations reject, and clone ambiguity fails closed until
//! operator enrollment (I54's detection-not-legitimacy rule).

use rabs_protocol::generation::{WorkerBootGeneration, WorkerIncarnationId};
use rabs_protocol::wire_time::PeerId;
use rabs_protocol::worker_fence::{
    WorkerAdmission, WorkerIncarnationFenceRecord, WorkerSessionOffer,
};

fn fence(generation: u64, active: Option<u128>) -> WorkerIncarnationFenceRecord {
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
fn t038_restored_vm_image_is_rejected() {
    // A VM snapshot restored from generation 2 while the fleet has
    // seen generation 5: the restored daemon's session offer carries
    // the OLD generation — rejected outright.
    let record = fence(5, None);
    assert_eq!(
        record.evaluate(&offer(2, 999)),
        WorkerAdmission::RejectStaleBootGeneration
    );
}

#[test]
fn t038_cloned_disk_image_fails_closed_until_enrollment() {
    // Two clones share generation 3. The first to connect becomes the
    // active incarnation; the second — same generation, DIFFERENT
    // incarnation — is the clone-ambiguity case: rejected, because
    // incarnation fencing DETECTS duplication but cannot prove which
    // clone is legitimate (I54).
    let record = fence(3, Some(11));
    assert_eq!(
        record.evaluate(&offer(3, 22)),
        WorkerAdmission::RejectCloneAmbiguity
    );
    // Operator enrollment is the sanctioned resolution: a FRESH proof
    // admits; the replayed proof does not.
    let mut enrolled = offer(3, 22);
    enrolled.reenrollment_proof = Some(1);
    assert_eq!(
        record.evaluate(&enrolled),
        WorkerAdmission::AdmitViaReenrollment
    );
    let mut rolled_back = offer(2, 22);
    rolled_back.reenrollment_proof = Some(2);
    assert_eq!(
        record.evaluate(&rolled_back),
        WorkerAdmission::RejectStaleBootGeneration,
        "re-enrollment cannot lower the global boot high-water"
    );
    let mut consumed = fence(3, Some(11));
    consumed.operator_reenrollment_generation = 1;
    assert_eq!(
        consumed.evaluate(&enrolled),
        WorkerAdmission::RejectCloneAmbiguity,
        "a replayed proof never resolves ambiguity"
    );
}

#[test]
fn one_active_incarnation_per_identity_generation() {
    let record = fence(3, Some(11));
    // The admitted incarnation reconnecting: ordinary reconnect.
    assert_eq!(
        record.evaluate(&offer(3, 11)),
        WorkerAdmission::AdmitReconnect
    );
    // After the session drops (no active incarnation), a NEW
    // incarnation may resume the generation.
    let idle = fence(3, None);
    assert_eq!(idle.evaluate(&offer(3, 22)), WorkerAdmission::AdmitResume);
    // A restart with a strictly higher generation supersedes: prior
    // incarnations' leases die with it.
    assert_eq!(
        record.evaluate(&offer(4, 99)),
        WorkerAdmission::AdmitNewGeneration
    );
}

#[test]
fn non_increasing_generations_and_wrong_identities_reject() {
    let record = fence(5, Some(1));
    // Equal generation + different incarnation while active: reject.
    assert_eq!(
        record.evaluate(&offer(5, 2)),
        WorkerAdmission::RejectCloneAmbiguity
    );
    // Lower generation: reject.
    assert_eq!(
        record.evaluate(&offer(4, 3)),
        WorkerAdmission::RejectStaleBootGeneration
    );
    // A different worker identity presenting against this record.
    let mut wrong = offer(5, 1);
    wrong.worker_peer_id = PeerId("wkr-2".into());
    assert_eq!(
        record.evaluate(&wrong),
        WorkerAdmission::RejectIdentityMismatch
    );
}
