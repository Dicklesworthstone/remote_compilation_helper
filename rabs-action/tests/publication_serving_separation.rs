//! Publication history vs mutable serving disposition: the separation
//! proof (bead A022; invariant I50).
//!
//! Composes the two halves built by A017 (rabs-action's
//! `PublicationSlotState`) and A020 (rabs-protocol's serving records) and
//! demonstrates, as executable fact:
//!
//! 1. a committed publication has NO outgoing transitions — quarantine,
//!    expiry, and eviction are expressible only against the serving layer;
//! 2. cycling a serving record through every disposition leaves the
//!    publication value bit-identical;
//! 3. eviction is a serving disposition, not a publication deletion — the
//!    record still names the publication it evicted (the bounded-tombstone
//!    rule: an eviction that forgets active lookup data retains identity
//!    long enough to detect later divergence, beads H034/F031).

use rabs_action::state_machines::PublicationSlotState;
use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};
use rabs_protocol::serving::{ActionServingDisposition, ActionServingStateRecord, ServingValidity};

fn object(tag: u8) -> ObjectId {
    ObjectId(TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: "rabs.object.v1",
        bytes: [tag; 32],
    })
}

fn authority_digest() -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: "rabs.coordinator-authority.v1",
        bytes: [7; 32],
    }
}

#[test]
fn committed_publication_has_no_exit_while_serving_changes_freely() {
    use PublicationSlotState as P;
    // 1. Commitment is a one-way door in the publication machine.
    for to in [P::Absent, P::Executing, P::Committed] {
        assert!(
            !P::may_transition(P::Committed, to),
            "Committed -> {to:?} must be unrepresentable (I50: history)"
        );
    }

    // 2. Meanwhile the serving layer cycles through every disposition,
    //    each step a strictly-newer revision naming the SAME publication.
    let publication = object(1);
    let publication_before = publication.clone();
    let mut record = ActionServingStateRecord {
        publication_record_id: publication,
        disposition: ActionServingDisposition::EvidencePending,
        blocking_quarantine_ids: vec![],
        state_revision: 1,
        coordinator_authority_digest: authority_digest(),
        validity: ServingValidity {
            evaluated_at_unix_micros: 0,
            maximum_age_micros: None,
            clock_uncertainty_micros: 0,
            coordinator_clock_epoch: 1,
        },
    };
    for (rev, disposition) in [
        (2, ActionServingDisposition::Eligible),
        (3, ActionServingDisposition::Quarantined),
        (4, ActionServingDisposition::ExpiredNeedsRevalidation),
        (5, ActionServingDisposition::ObjectsUnavailable),
        (6, ActionServingDisposition::EvictedFromActiveIndex),
    ] {
        let update = ActionServingStateRecord {
            disposition,
            state_revision: rev,
            ..record.clone()
        };
        assert!(
            record.accepts_update(&update),
            "rev {rev} must supersede rev {}",
            record.state_revision
        );
        record = update;
        // 3. The publication identity the record names never changes:
        //    serving mutates ITSELF, never the history it points at.
        assert_eq!(
            record.publication_record_id, publication_before,
            "a serving transition renamed/mutated the publication it governs"
        );
    }

    // Eviction reached: the record STILL names the publication (tombstone
    // identity retained), and serving is denied.
    assert_eq!(
        record.disposition,
        ActionServingDisposition::EvictedFromActiveIndex
    );
    assert!(!record.may_serve_now(100, 1));
    assert_eq!(record.publication_record_id, publication_before);
}

#[test]
fn serving_updates_cannot_cross_publications() {
    // A serving update for publication B can never replace the record
    // governing publication A — dispositions are per-publication, so one
    // action's quarantine cannot leak onto another's history.
    let a = ActionServingStateRecord {
        publication_record_id: object(1),
        disposition: ActionServingDisposition::Eligible,
        blocking_quarantine_ids: vec![],
        state_revision: 10,
        coordinator_authority_digest: authority_digest(),
        validity: ServingValidity {
            evaluated_at_unix_micros: 0,
            maximum_age_micros: None,
            clock_uncertainty_micros: 0,
            coordinator_clock_epoch: 1,
        },
    };
    let b_update = ActionServingStateRecord {
        publication_record_id: object(2),
        state_revision: 11,
        disposition: ActionServingDisposition::Quarantined,
        ..a.clone()
    };
    assert!(!a.accepts_update(&b_update));
}
