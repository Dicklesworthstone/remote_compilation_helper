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

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::metadata_store::{RabsMetadataStore, RusqliteEngine, SqlMetadataStore, digest_key};
use rabs_cas::publication::{
    AUTHORITY_DIGEST_DOMAIN, OfferPreparedActionResult, PublicationOutcome,
};
use rabs_cas::serving_state::{ServeDecision, serving_gate};
use rabs_cas::test_support::{
    divergent_offer_with_manifest_bytes, install_admission_world, install_offer_closure,
    offer_with_manifest_bytes, sample_action_key, sample_expected_descriptor,
};
use rabsd::coord::live::{CoordLive, cluster_id};
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
