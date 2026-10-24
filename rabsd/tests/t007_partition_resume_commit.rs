//! T007's named acceptance: `partition_resume_journal_no_duplicate_commit`
//! (bead 38.7; builds on J017's transport suites and C019's resume
//! journal).
//!
//! The bead names that test explicitly and it existed nowhere but the
//! master plan. What DOES exist, and is not redone here:
//!
//! - J017's five transport-suite families over a deterministic
//!   fault-injecting link, whose gate `M7_ZERO_DOUBLE_EXECUTE` proves
//!   no submitted action ever folds to `Created` twice under any fault
//!   mix, and `M7_RECONCILE_EXACT` that a healed connection reconciles
//!   to the exact sent set;
//! - G019's `stale_attempt_result_rejected`, where a partition outlasts
//!   the term and the replay is refused `StaleAuthority` with zero
//!   publication rows;
//! - T004's `t004_a_retry_after_a_crash_converges_and_never_double_commits`.
//!
//! Those cover a different layer or a different fault. J017 proves the
//! SESSION FOLD never double-creates; this is about the PUBLICATION
//! COMMIT. And T004's retry runs in a NEW incarnation after a crash,
//! which is why it has to reissue with fresh attempt ids — a boot
//! closes the dead generation and the never-reuse high-water burns it.
//!
//! A partition is the harder case precisely because nothing died. The
//! coordinator is the same incarnation, holding the same authority, and
//! the resume journal replays the IDENTICAL offer — same manifest, same
//! generation, same attempt. Nothing about the replay looks new, so
//! nothing external distinguishes it from the first delivery. Committing
//! twice here would publish one result under two rows; refusing outright
//! would strand work that genuinely completed. The only correct answer
//! is idempotence, and that is what these scenarios pin.
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::metadata_store::{
    ActionEntryRow, RabsMetadataStore, RusqliteEngine, SqlMetadataStore, StoreError, digest_key,
};
use rabs_cas::publication::{
    AUTHORITY_DIGEST_DOMAIN, DIVERGENCE_EVIDENCE_PIN_CLASS, OfferPreparedActionResult,
    OfferRefusal, PublicationOutcome, authority_digest,
};
use rabs_cas::serving_state::{ServeDecision, serving_gate};
use rabs_cas::test_support::{
    FixtureAttemptIds, SAMPLE_ATTEMPT_IDS, divergent_offer_with_manifest_bytes,
    divergent_offer_with_manifest_bytes_with_ids, install_admission_world, install_offer_closure,
    offer_with_manifest_bytes, offer_with_manifest_bytes_with_ids, sample_action_key,
    sample_expected_descriptor, tagged_object,
};
use rabs_protocol::generation::{LeaseRenewal, LeaseRenewalSeq};
use rabs_protocol::result_identity::DivergenceClass;
use rabs_protocol::worker_fence::WorkerSessionOffer;
use rabsd::coord::live::{AttemptLeaseRefusal, CommitRefusal, CoordLive, cluster_id};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};

fn store_manifest_object(cas: &LiveCas, offer: &OfferPreparedActionResult, bytes: &[u8]) {
    let mut store = cas.store().lock().expect("store lock");
    let mut reader = bytes;
    put_if_absent(
        cas.layout(),
        &mut *store,
        &offer.manifest_id.0,
        &mut reader,
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .expect("put manifest bytes");
    install_offer_closure(&mut *store, offer);
}

fn open_store(state_dir: &std::path::Path) -> SqlMetadataStore<RusqliteEngine> {
    let engine = RusqliteEngine::open(&state_dir.join("cas").join("meta.sqlite")).expect("engine");
    let mut store = SqlMetadataStore::open(engine).expect("store");
    store.intern_domain(AUTHORITY_DIGEST_DOMAIN);
    store.intern_domain("rabs.action-key.sha256.v1");
    store
}

/// Publication rows for the fixture's action key.
fn publications(store: &mut SqlMetadataStore<RusqliteEngine>) -> Vec<String> {
    let key = digest_key(&sample_action_key());
    store
        .list_publications()
        .expect("publications")
        .into_iter()
        .filter(|(action, _)| *action == key)
        .map(|(_, pin_hex)| pin_hex)
        .collect()
}

#[test]
fn partition_resume_journal_no_duplicate_commit() {
    // THE named acceptance. A commit lands; the acknowledgement is lost
    // to a partition, so the peer never learns it succeeded; the resume
    // journal replays the identical offer on the healed link.
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().to_path_buf();
    let cas = Arc::new(mount_and_reconcile(&state_dir.join("cas")).expect("mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let authority = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");
    let (offer, manifest_bytes) = offer_with_manifest_bytes(&authority);
    {
        let mut store = cas.store().lock().expect("store lock");
        install_admission_world(&mut *store, &authority);
    }
    store_manifest_object(&cas, &offer, &manifest_bytes);

    let first = coord
        .commit_offer(&offer, &sample_expected_descriptor())
        .expect("commit");
    assert!(
        matches!(first, PublicationOutcome::Committed(_)),
        "the first delivery must commit, got {first:?}"
    );

    // ---- the partition: the ack never arrives ----
    //
    // Nothing crashed. Same incarnation, same authority, same
    // generation and attempt. The journal replays exactly what it sent.
    let replay = coord
        .commit_offer(&offer, &sample_expected_descriptor())
        .expect("the replay must be answered, not error out");
    assert_eq!(
        replay,
        PublicationOutcome::IdempotentEvidenceAppended,
        "a journal replay of an already-committed result must be idempotent — \
         neither a second publication nor a refusal that strands completed work"
    );

    // A flapping partition retries more than once.
    for attempt in 0..5 {
        let outcome = coord
            .commit_offer(&offer, &sample_expected_descriptor())
            .unwrap_or_else(|e| panic!("replay {attempt} errored: {e:?}"));
        assert_eq!(outcome, PublicationOutcome::IdempotentEvidenceAppended);
    }

    // The store holds ONE publication, and the same one.
    drop(coord);
    drop(cas);
    let mut store = open_store(&state_dir);
    let rows = publications(&mut store);
    assert_eq!(
        rows.len(),
        1,
        "six deliveries of one result must leave exactly ONE publication row, found {}",
        rows.len()
    );
    assert_eq!(
        store.pin_released_by_hex(&rows[0]).expect("pin"),
        Some(false),
        "the reachability pin must survive the replays unreleased"
    );
    assert_eq!(
        serving_gate(&mut store, &digest_key(&sample_action_key()), 1_000, 0).expect("gate"),
        ServeDecision::Servable,
        "the action must still serve after the replays"
    );
}

#[test]
fn t007_a_divergent_result_arriving_on_the_healed_link_quarantines() {
    // The dangerous partition case. While the link was down the action
    // was reassigned or hedged, and the resuming peer delivers a
    // DIFFERENT result for the same key. Idempotence must not be
    // stretched to cover this: same key plus different result is a
    // divergence, not a duplicate, and the committed pointer must
    // survive untouched.
    let dir = tempfile::tempdir().expect("tempdir");
    let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).expect("mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let authority = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");
    let (offer, manifest_bytes) = offer_with_manifest_bytes(&authority);
    {
        let mut store = cas.store().lock().expect("store lock");
        install_admission_world(&mut *store, &authority);
    }
    store_manifest_object(&cas, &offer, &manifest_bytes);
    let committed = coord
        .commit_offer(&offer, &sample_expected_descriptor())
        .expect("commit");
    let PublicationOutcome::Committed(record) = committed else {
        panic!("expected a commit, got {committed:?}");
    };
    let winner = digest_key(&record.canonical_result_manifest_id.0);

    // ---- healed link, different result ----
    let (divergent, divergent_bytes) = divergent_offer_with_manifest_bytes(&authority);
    store_manifest_object(&cas, &divergent, &divergent_bytes);
    let outcome = coord
        .commit_offer(&divergent, &sample_expected_descriptor())
        .expect("classified");
    assert!(
        matches!(outcome, PublicationOutcome::Quarantined(_)),
        "a different result for the same key after a partition is a divergence, \
         not a duplicate, got {outcome:?}"
    );

    // The committed pointer is untouched and there is still ONE row.
    drop(coord);
    drop(cas);
    let mut store = open_store(dir.path());
    assert_eq!(publications(&mut store).len(), 1);
    assert_eq!(
        store
            .published_manifest_key(&sample_action_key())
            .expect("published key"),
        Some(winner),
        "the quarantine must preserve the ORIGINAL winner, not adopt the late arrival"
    );
    // And serving is off: a quarantined action must not answer hits.
    assert!(
        !matches!(
            serving_gate(&mut store, &digest_key(&sample_action_key()), 1_000, 0).expect("gate"),
            ServeDecision::Servable
        ),
        "a quarantined action must stop serving"
    );
}

#[test]
fn t007_replaying_the_winner_after_a_quarantine_still_adds_no_row() {
    // The two faults composed, which is the state a real healed link
    // arrives in: the divergence has quarantined the action AND the
    // original peer is still replaying its own (winning) result from
    // its journal because it never saw an ack either.
    //
    // The replay must remain idempotent — a quarantine is not a licence
    // to publish again — and it must not resurrect serving.
    let dir = tempfile::tempdir().expect("tempdir");
    let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).expect("mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let authority = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");
    let (offer, manifest_bytes) = offer_with_manifest_bytes(&authority);
    {
        let mut store = cas.store().lock().expect("store lock");
        install_admission_world(&mut *store, &authority);
    }
    store_manifest_object(&cas, &offer, &manifest_bytes);
    coord
        .commit_offer(&offer, &sample_expected_descriptor())
        .expect("commit");

    let (divergent, divergent_bytes) = divergent_offer_with_manifest_bytes(&authority);
    store_manifest_object(&cas, &divergent, &divergent_bytes);
    coord
        .commit_offer(&divergent, &sample_expected_descriptor())
        .expect("quarantine");

    // The winner's own journal replay, arriving after the quarantine.
    let replay = coord
        .commit_offer(&offer, &sample_expected_descriptor())
        .expect("the replay must be answered");
    assert_eq!(
        replay,
        PublicationOutcome::IdempotentEvidenceAppended,
        "replaying the committed winner after a quarantine must stay idempotent"
    );

    drop(coord);
    drop(cas);
    let mut store = open_store(dir.path());
    assert_eq!(
        publications(&mut store).len(),
        1,
        "no replay may add a publication row"
    );
    assert!(
        !matches!(
            serving_gate(&mut store, &digest_key(&sample_action_key()), 1_000, 0).expect("gate"),
            ServeDecision::Servable
        ),
        "an idempotent replay must not clear a quarantine"
    );
}

#[test]
fn t007_expired_attempt_lease_retains_non_committing_candidate_blobs_and_reassigned_attempt_wins() {
    // bd-ljgmb arms (1) and (2):
    // 1. An execution lease expires on the coordinator's own monotonic clock
    //    during an idle partition (no causal sequence traffic).
    // 2. The partitioned attempt finishes anyway, uploads its verified blobs
    //    to CAS, and offers on the healed link. It is refused with
    //    `OfferRefusal::LeaseExpired` and cannot renew its lease, leaving
    //    zero publication rows — yet its uploaded manifest and output blobs
    //    remain durably located in CAS as non-committing candidate objects.
    // 3. A reassigned attempt in the same generation (under a fresh attempt
    //    and lease id) reuses those already-uploaded candidate blobs without
    //    re-uploading them and commits cleanly. Subsequent replays from the
    //    expired attempt (identical or divergent) are still refused at the
    //    lease fence and cannot append rogue evidence or quarantine the winner.
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().to_path_buf();
    let cas = Arc::new(mount_and_reconcile(&state_dir.join("cas")).expect("mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let authority = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");
    let (expired_offer, expired_bytes) = offer_with_manifest_bytes(&authority);

    // Install action entry, bound generation, and worker session, then admit
    // the primary attempt with a short 40ms monotonic execution lease.
    {
        let auth_digest = authority_digest(&authority);
        let mut store = cas.store().lock().expect("store lock");
        store
            .upsert_action_entry(&ActionEntryRow {
                action_key: sample_action_key(),
                key_epoch: 1,
                projection_epoch: 1,
            })
            .expect("upsert action entry");
        store
            .create_bound_generation(
                &auth_digest,
                &expired_offer.authority.action_generation,
                &sample_action_key(),
            )
            .expect("create bound generation");
    }
    coord
        .admit_worker_session(&WorkerSessionOffer {
            worker_peer_id: expired_offer.authority.worker_peer_id.clone(),
            boot_generation: expired_offer.authority.worker_boot_generation,
            incarnation: expired_offer.authority.worker_incarnation_id,
            reenrollment_proof: None,
        })
        .expect("admit worker session");
    coord
        .admit_attempt_lease(&expired_offer.authority, 40)
        .expect("admit short-lived primary attempt lease");

    // The partitioned worker finishes and uploads its candidate blobs to CAS,
    // but the partition outlasts its 40ms monotonic execution lease.
    store_manifest_object(&cas, &expired_offer, &expired_bytes);
    std::thread::sleep(Duration::from_millis(55));

    // Late renewal and late publication are both refused with LeaseExpired.
    assert_eq!(
        coord.renew_attempt_lease(
            &expired_offer.authority,
            LeaseRenewal {
                lease: expired_offer.authority.execution_lease_id,
                seq: LeaseRenewalSeq(expired_offer.authority.lease_renewal_seq.0 + 1),
            },
            60_000,
        ),
        Err(AttemptLeaseRefusal::Store(StoreError::LeaseExpired)),
        "an expired attempt lease must not be renewable after the partition heals"
    );
    assert_eq!(
        coord.commit_offer(&expired_offer, &sample_expected_descriptor()),
        Err(CommitRefusal::Offer(OfferRefusal::LeaseExpired)),
        "an offer from an expired attempt lease must not commit"
    );

    // Zero publications exist, yet the uploaded blobs remain durably located
    // in CAS as non-committing candidate objects.
    {
        let mut store = cas.store().lock().expect("store lock");
        assert!(
            !store
                .has_publication(&sample_action_key())
                .expect("has_publication"),
            "refused post-expiry offer must not create a publication row"
        );
        assert!(
            store
                .object_durably_located(&expired_offer.manifest_id.0)
                .expect("manifest located"),
            "post-expiry manifest blob must remain in CAS as a candidate object"
        );
        assert!(
            store
                .object_durably_located(&tagged_object(41).0)
                .expect("output located"),
            "post-expiry output blob must remain in CAS as a candidate object"
        );
    }

    // Reassign the action under a fresh attempt + lease id in the same generation.
    // Notice we do NOT call `store_manifest_object` again: the reassigned attempt
    // commits directly over the candidate objects already uploaded by the expired attempt.
    let reassigned_ids = FixtureAttemptIds {
        generation: SAMPLE_ATTEMPT_IDS.generation,
        attempt: 21,
        lease: 31,
    };
    let (reassigned_offer, _) = offer_with_manifest_bytes_with_ids(&authority, reassigned_ids);
    coord
        .admit_attempt_lease(&reassigned_offer.authority, 60_000)
        .expect("admit reassigned attempt lease");
    let committed = coord
        .commit_offer(&reassigned_offer, &sample_expected_descriptor())
        .expect("reassigned attempt must commit using retained candidate blobs");
    let PublicationOutcome::Committed(record) = committed else {
        panic!("expected Committed for reassigned attempt, got {committed:?}");
    };
    assert_eq!(
        record.canonical_result_manifest_id,
        expired_offer.manifest_id
    );

    // If the expired primary replays either its identical offer or a divergent
    // offer after the reassigned winner has committed, the lease fence refuses
    // it before evidence-append or divergence quarantine can run.
    assert_eq!(
        coord.commit_offer(&expired_offer, &sample_expected_descriptor()),
        Err(CommitRefusal::Offer(OfferRefusal::LeaseExpired)),
        "expired attempt replay after winner commit must still be refused as LeaseExpired"
    );
    let (expired_divergent, expired_divergent_bytes) =
        divergent_offer_with_manifest_bytes(&authority);
    store_manifest_object(&cas, &expired_divergent, &expired_divergent_bytes);
    assert_eq!(
        coord.commit_offer(&expired_divergent, &sample_expected_descriptor()),
        Err(CommitRefusal::Offer(OfferRefusal::LeaseExpired)),
        "divergent offer from an expired lease must not quarantine the reassigned winner"
    );

    drop(coord);
    drop(cas);
    let mut store = open_store(&state_dir);
    assert_eq!(publications(&mut store).len(), 1);
    assert_eq!(
        serving_gate(&mut store, &digest_key(&sample_action_key()), 1_000, 0).expect("gate"),
        ServeDecision::Servable,
        "reassigned winner must remain servable despite late post-expiry replays"
    );
    assert!(
        store
            .list_divergence_incidents(&digest_key(&sample_action_key()))
            .expect("incidents")
            .is_empty(),
        "expired attempt must not open a divergence incident"
    );
}

#[test]
fn t007_live_hedge_race_commits_first_finisher_and_merges_or_quarantines_sibling() {
    // bd-ljgmb arm (3): Hedge as a real mechanism with two distinct live
    // attempt leases (Primary attempt 20 / lease 30 and Hedge attempt 21 /
    // lease 31) racing in the same generation.
    let hedge_ids = FixtureAttemptIds {
        generation: SAMPLE_ATTEMPT_IDS.generation,
        attempt: 21,
        lease: 31,
    };

    // Case 1: Equivalent results — the hedge finishes first and commits;
    // the slower primary finishes while its lease is still live and appends
    // its distinct evidence bundle without double-committing.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).expect("mount"));
        let coord = CoordLive::with_cas(Arc::clone(&cas));
        let authority = coord
            .acquire_boot_authority(&cluster_id())
            .expect("authority");
        let (mut primary_offer, primary_bytes) = offer_with_manifest_bytes(&authority);
        primary_offer.evidence_id = tagged_object(54);
        let (hedge_offer, hedge_bytes) = offer_with_manifest_bytes_with_ids(&authority, hedge_ids);
        {
            let mut store = cas.store().lock().expect("store lock");
            install_admission_world(&mut *store, &authority);
        }
        coord
            .admit_attempt_lease(&hedge_offer.authority, 60_000)
            .expect("admit live hedge lease");
        store_manifest_object(&cas, &hedge_offer, &hedge_bytes);
        store_manifest_object(&cas, &primary_offer, &primary_bytes);

        // Hedge finishes first and wins compare-and-set.
        let first = coord
            .commit_offer(&hedge_offer, &sample_expected_descriptor())
            .expect("hedge commit");
        assert!(matches!(first, PublicationOutcome::Committed(_)));

        // Primary finishes second with the same canonical manifest and a live lease.
        let second = coord
            .commit_offer(&primary_offer, &sample_expected_descriptor())
            .expect("primary idempotent evidence append");
        assert_eq!(second, PublicationOutcome::IdempotentEvidenceAppended);

        drop(coord);
        drop(cas);
        let mut store = open_store(dir.path());
        assert_eq!(publications(&mut store).len(), 1);
        let manifest_key = digest_key(&hedge_offer.manifest_id.0);
        let evidence_keys = store
            .list_evidence_keys_for_manifest(&manifest_key)
            .expect("evidence keys for manifest");
        assert!(
            evidence_keys.contains(&digest_key(&hedge_offer.evidence_id.0))
                && evidence_keys.contains(&digest_key(&primary_offer.evidence_id.0)),
            "both live attempts' evidence bundles must bind to the committed manifest: {evidence_keys:?}"
        );
        assert_eq!(
            serving_gate(&mut store, &digest_key(&sample_action_key()), 1_000, 0).expect("gate"),
            ServeDecision::Servable
        );
    }

    // Case 2: Divergent results — the primary commits first, and the live
    // hedge (under its own distinct attempt + lease ids) finishes second with
    // a different output object. The action quarantines while preserving the
    // primary winner's committed pointer AND pinning the losing hedge's
    // candidate manifest under DIVERGENCE_EVIDENCE_PIN_CLASS.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).expect("mount"));
        let coord = CoordLive::with_cas(Arc::clone(&cas));
        let authority = coord
            .acquire_boot_authority(&cluster_id())
            .expect("authority");
        let (primary_offer, primary_bytes) = offer_with_manifest_bytes(&authority);
        let (divergent_hedge, divergent_bytes) =
            divergent_offer_with_manifest_bytes_with_ids(&authority, hedge_ids);
        {
            let mut store = cas.store().lock().expect("store lock");
            install_admission_world(&mut *store, &authority);
        }
        coord
            .admit_attempt_lease(&divergent_hedge.authority, 60_000)
            .expect("admit live hedge lease");
        store_manifest_object(&cas, &primary_offer, &primary_bytes);
        store_manifest_object(&cas, &divergent_hedge, &divergent_bytes);

        let committed = coord
            .commit_offer(&primary_offer, &sample_expected_descriptor())
            .expect("primary commit");
        let PublicationOutcome::Committed(record) = committed else {
            panic!("expected primary commit, got {committed:?}");
        };
        let winner_key = digest_key(&record.canonical_result_manifest_id.0);

        let outcome = coord
            .commit_offer(&divergent_hedge, &sample_expected_descriptor())
            .expect("divergent hedge classified");
        let PublicationOutcome::Quarantined(quarantine) = outcome else {
            panic!("expected semantic quarantine from divergent hedge, got {outcome:?}");
        };
        assert_eq!(quarantine.class, DivergenceClass::SemanticDivergence);

        drop(coord);
        drop(cas);
        let mut store = open_store(dir.path());
        assert_eq!(publications(&mut store).len(), 1);
        assert_eq!(
            store
                .published_manifest_key(&sample_action_key())
                .expect("published key"),
            Some(winner_key),
            "winner pointer must remain the primary's manifest"
        );
        let candidate_pin = store
            .pin_row(quarantine.candidate_pin_id)
            .expect("candidate pin query")
            .expect("candidate pin exists");
        assert_eq!(candidate_pin.class, DIVERGENCE_EVIDENCE_PIN_CLASS);
        assert_eq!(
            candidate_pin.root_key,
            digest_key(&divergent_hedge.manifest_id.0),
            "losing hedge's candidate manifest must be pinned as divergence evidence"
        );
        assert!(!candidate_pin.released);
        assert!(
            !matches!(
                serving_gate(&mut store, &digest_key(&sample_action_key()), 1_000, 0)
                    .expect("gate"),
                ServeDecision::Servable
            ),
            "divergent hedge must disable serving"
        );
    }
}
