//! G019 lab scenarios: coordinator-authority fencing across restarts
//! (rabs-root-4pidu.25.19).
//!
//! `rabs-cas` proves `process_offer`'s publication fence at library
//! fidelity, and the `ActionActor` unit tests prove lease-admission
//! refusal. What was never proven END-TO-END is the property the bead
//! names: an attempt whose CoordinatorAuthority went STALE — because its
//! coordinator died and a newer incarnation advanced the term — is
//! rejected at the daemon's result-offer door, publishes nothing, and
//! leaves no serving-visible state behind.
//!
//! Scenarios (acceptance names verbatim):
//!
//! 1. `stale_attempt_result_rejected` — an attempt fully PREPARED under
//!    term 1 (admission world installed, manifest bytes in the real blob
//!    store, every closure object durably located) replays its offer into
//!    a coordinator holding term 3. The ONLY thing wrong with the offer is
//!    staleness — everything else would admit — and the refusal is the
//!    daemon-level typed [`CommitRefusal::StaleAuthority`], firing BEFORE
//!    any store transaction opens. A real `rabsd` binary boot sits between
//!    the two incarnations so the term's advance crosses a process
//!    boundary exactly as it would in production.
//!
//! 2. `coordinator_dies_after_prepare_before_commit` — the coordinator
//!    dies AFTER prepare (durable object closure) and BEFORE
//!    `commit_offer`. Post-crash: no publication row exists, nothing is
//!    servable-by-pointer, and the restarted coordinator refuses the dead
//!    attempt's replay while the store stays empty.
//!
//! NOT proven here (named so nothing is implied): wire arrival of offers
//! (J024 handlers), publication-layer divergence handling under a LIVE
//! authority (covered by `coord_commit_live.rs`), and actor-level lease
//! admission (unit tests beside `ActionActor`).

use std::process::{Command, Stdio};
use std::sync::Arc;

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, PutOutcome, put_if_absent};
use rabs_cas::metadata_store::RabsMetadataStore;
use rabs_cas::publication::OfferPreparedActionResult;
use rabs_cas::test_support::{
    install_admission_world, install_offer_closure, offer_with_manifest_bytes, sample_action_key,
    sample_expected_descriptor,
};
use rabsd::coord::live::{CommitRefusal, CoordLive, cluster_id};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};

/// Run the shipped `rabsd` binary over `state_dir` for a short bounded
/// life (the cross-process restart step).
fn boot_binary(state_dir: &std::path::Path, ms: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .args(["--run-for-ms", ms])
        .env("RABS_SOCKET_PATH", state_dir.join("rabsd.sock"))
        .env("RABS_BOOT_MARKER", state_dir.join("rabsd.boot"))
        .env("RABS_STATE_DIR", state_dir)
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run rabsd")
}

/// Put the offer's manifest canonical bytes into the REAL blob store and
/// mark every closure object durably located: the full PREPARE step a
/// worker's offer implies (same fixture discipline as
/// `coord_commit_live.rs`).
fn store_manifest_object(cas: &LiveCas, offer: &OfferPreparedActionResult, bytes: &[u8]) {
    let mut store = cas.store().lock().expect("store lock");
    let mut reader = bytes;
    let outcome = put_if_absent(
        cas.layout(),
        &mut *store,
        &offer.manifest_id.0,
        &mut reader,
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .expect("put manifest bytes");
    assert!(
        matches!(
            outcome,
            PutOutcome::Stored { .. } | PutOutcome::IdempotentDuplicate { .. }
        ),
        "manifest bytes must land in the store: {outcome:?}"
    );
    install_offer_closure(&mut *store, offer);
}

/// Nothing may be published for the sample action: no pointer row, ever.
fn assert_nothing_published(cas: &LiveCas) {
    let mut store = cas.store().lock().expect("store lock");
    assert_eq!(
        store
            .published_manifest_key(&sample_action_key())
            .expect("published key lookup"),
        None,
        "a stale/pre-crash attempt must never leave a publication row"
    );
}

#[test]
fn stale_attempt_result_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().to_path_buf();
    let cas_root = state_dir.join("cas");

    // Incarnation 1, term 1: an attempt is FULLY prepared — admission
    // world, real manifest bytes, durable closure — and then its
    // coordinator dies (the block drops every live handle).
    let stale_offer = {
        let cas = Arc::new(mount_and_reconcile(&cas_root).expect("mount"));
        let coord = CoordLive::with_cas(Arc::clone(&cas));
        let authority = coord
            .acquire_boot_authority(&cluster_id())
            .expect("authority");
        assert_eq!(authority.term, 1, "first incarnation holds term 1");

        let (offer, bytes) = offer_with_manifest_bytes(&authority);
        {
            let mut store = cas.store().lock().expect("store lock");
            install_admission_world(&mut *store, &authority);
        }
        store_manifest_object(&cas, &offer, &bytes);
        // Death mid-attempt: after prepare, before any commit.
        offer
    };

    // A REAL second incarnation boots as another PROCESS over the same
    // durable store: the term advances past the dead one off-process.
    let booted = boot_binary(&state_dir, "800");
    assert!(
        booted.status.success(),
        "reboot binary failed:\nSTDOUT:{}\nSTDERR:{}",
        String::from_utf8_lossy(&booted.stdout),
        String::from_utf8_lossy(&booted.stderr)
    );

    // Incarnation 3 (this process): acquires the next term over the same
    // store — 1 (dead) -> 2 (binary) -> 3 (here).
    let cas = Arc::new(mount_and_reconcile(&cas_root).expect("re-mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let live = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");
    assert_eq!(live.term, 3, "term must have crossed two incarnations");

    // Replay of the term-1 attempt: refused at the OFFER door with the
    // daemon-typed stale-authority refusal — before the store engine (and
    // its NotActiveAuthority fence) is even consulted.
    let refusal = coord
        .commit_offer(&stale_offer, &sample_expected_descriptor())
        .expect_err("a stale attempt's result must be rejected");
    assert_eq!(
        refusal,
        CommitRefusal::StaleAuthority {
            offered_term: 1,
            active_term: 3,
        },
        "expected the offer-door stale-authority refusal, got {refusal:?}"
    );

    // And the rejection wrote NOTHING: the stale attempt never published.
    assert_nothing_published(&cas);
}

#[test]
fn coordinator_dies_after_prepare_before_commit() {
    let dir = tempfile::tempdir().unwrap();
    let cas_root = dir.path().join("cas");

    // Term-1 coordinator: prepare completes (durable closure), commit
    // NEVER runs, the coordinator dies.
    let uncommitted_offer = {
        let cas = Arc::new(mount_and_reconcile(&cas_root).expect("mount"));
        let coord = CoordLive::with_cas(Arc::clone(&cas));
        let authority = coord
            .acquire_boot_authority(&cluster_id())
            .expect("authority");
        assert_eq!(authority.term, 1);

        let (offer, bytes) = offer_with_manifest_bytes(&authority);
        {
            let mut store = cas.store().lock().expect("store lock");
            install_admission_world(&mut *store, &authority);
        }
        store_manifest_object(&cas, &offer, &bytes);
        offer
        // <-- death here: prepare done, commit_offer never called
    };
    // Post-crash inspection over the same durable store: prepared-but-
    // uncommitted is INVISIBLE — no publication pointer exists.
    let cas = Arc::new(mount_and_reconcile(&cas_root).expect("re-mount"));
    assert_nothing_published(&cas);

    // The restarted coordinator advances the term and refuses the dead
    // attempt's replay; the store stays empty afterwards.
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let live = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");
    assert_eq!(live.term, 2, "the reboot must advance the term");

    let refusal = coord
        .commit_offer(&uncommitted_offer, &sample_expected_descriptor())
        .expect_err("the dead attempt must not publish posthumously");
    assert_eq!(
        refusal,
        CommitRefusal::StaleAuthority {
            offered_term: 1,
            active_term: 2,
        },
        "expected the offer-door stale-authority refusal, got {refusal:?}"
    );
    assert_nothing_published(&cas);
}

