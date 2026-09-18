//! T039 scenarios: action-generation ABA across tombstones, restart,
//! authority change and operator reset (beads F031/H038/H037; invariant
//! I51; risks R108/R113).
//!
//! F031 built the ABA fence as a PURE in-memory `GenerationFence` whose
//! rule is set membership: an id is refused if it is in the active set
//! or the tombstone set. Its own close reason defers the durable tables
//! to H038, and H038 implemented them with a DIFFERENT rule —
//! `action_generations` (a primary key on the id) plus
//! `generation_high_water` (a monotone watermark). The durable rule is
//! strictly stronger, and the gap between the two is where R108 lives:
//!
//! - a tombstone SET refuses ids it has SEEN;
//! - a high-water refuses every id at or below it, including ids that
//!   were **never minted at all**.
//!
//! That difference is the entire defense against F031's stated
//! wraparound case. A tombstone set that lost rows to eviction or DB
//! repair silently readmits; a watermark does not. Nothing tested it,
//! so this suite pins it — if someone ever "simplifies" the watermark
//! into a membership check, these go red rather than the ABA window
//! quietly reopening.
//!
//! The suite also covers the crossing H037 and F031 each stop short of:
//! an operator reset (R113) changes what may SERVE, and the question
//! nobody asked is whether it also changes what may be MINTED. It must
//! not — a reset opens a new lineage, it does not un-burn identities.
//!
//! NOT covered here, and deliberately: the publication-pin crash arm of
//! T039 (R111) is proven by the H015 crash matrix at every kill point on
//! both engines, by H036's pin-posture acceptance, and by T049's
//! release-attempt scenarios. Redoing it would be proof-class inflation,
//! not coverage.

use rabs_cas::metadata_store::{
    ActionEntryRow, AuthorityRow, RabsMetadataStore, RusqliteEngine, SqlEngine, SqlMetadataStore,
    StoreError,
};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use std::sync::atomic::{AtomicU64, Ordering};

/// The id `healthy` mints, and the high-water it leaves behind.
const MINTED: u128 = 11;
/// An id BELOW the high-water that was never minted. A tombstone-set
/// fence would admit it; a watermark must not.
const NEVER_MINTED_BELOW: u128 = 7;

// Enforced at compile time rather than in one test: if these two drift
// past each other the suite still passes while proving nothing, because
// every probe below the watermark would land above it instead.
const _: () = assert!(
    NEVER_MINTED_BELOW < MINTED,
    "the fixture must probe BELOW the watermark"
);

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fresh_path(tag: &str) -> std::path::PathBuf {
    let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("rabs-t039-{}-{}-{}.db", std::process::id(), tag, n))
}

fn digest(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn authority(tag: u8) -> TypedDigest {
    digest("rabs.authority.sha256.v1", tag)
}

fn action_key() -> TypedDigest {
    digest("rabs.action-key.sha256.v1", 7)
}

/// Install an authority and an action entry, then mint [`MINTED`].
fn seeded<E: SqlEngine>(store: &mut SqlMetadataStore<E>, authority_tag: u8, term: u64) {
    store
        .acquire_authority(&AuthorityRow {
            digest: authority(authority_tag),
            cluster_id: "c".to_owned(),
            incarnation: u128::from(authority_tag),
            term,
            acquired_seq: term,
        })
        .expect("authority");
    store
        .upsert_action_entry(&ActionEntryRow {
            action_key: action_key(),
            key_epoch: 0,
            projection_epoch: 0,
        })
        .expect("action entry");
    store
        .create_generation(&authority(authority_tag), MINTED, &action_key())
        .expect("mint");
}

fn in_memory() -> SqlMetadataStore<RusqliteEngine> {
    let mut store =
        SqlMetadataStore::open(RusqliteEngine::open_in_memory().expect("engine")).expect("store");
    seeded(&mut store, 1, 1);
    store
}

#[test]
fn t039_the_core_aba_a_failed_generation_id_is_burned_forever() {
    // F031's scenario, now against the DURABLE fence: a generation is
    // minted, fails, is tombstoned, and the same id is offered again.
    let mut store = in_memory();
    store.tombstone_generation(MINTED).expect("tombstone");
    assert!(
        store
            .generation_state(MINTED)
            .expect("state")
            .expect("exists")
            .tombstoned
    );

    assert_eq!(
        store.create_generation(&authority(1), MINTED, &action_key()),
        Err(StoreError::GenerationIdNotAboveHighWater),
        "a tombstoned id must never be re-minted"
    );
}

#[test]
fn t039_the_watermark_burns_ids_that_were_never_minted_at_all() {
    // THE distinction between the pure fence and the durable one, and
    // the reason the durable one exists. `GenerationFence::seen` is set
    // membership, so it would ADMIT an id it has never seen. The
    // watermark refuses everything at or below it.
    //
    // This is F031's stated wraparound case: a fence that only remembers
    // ids it saw will readmit after eviction, compaction or DB repair
    // drops rows. A watermark cannot, because it never needs the rows.
    let mut store = in_memory();
    assert_eq!(
        store
            .generation_state(NEVER_MINTED_BELOW)
            .expect("state lookup"),
        None,
        "precondition: this id was never minted, so no tombstone exists for it"
    );

    assert_eq!(
        store.create_generation(&authority(1), NEVER_MINTED_BELOW, &action_key()),
        Err(StoreError::GenerationIdNotAboveHighWater),
        "an id below the watermark must be refused even though nothing ever burned it"
    );

    // The watermark is a floor, not a freeze: above it still works.
    store
        .create_generation(&authority(1), MINTED + 1, &action_key())
        .expect("an id above the watermark must still be mintable");
}

#[test]
fn t039_the_fence_survives_a_coordinator_restart() {
    // R108 names restart and DB repair explicitly. An in-memory fence
    // would pass every test above and still lose everything here, so the
    // store is genuinely closed and reopened from disk.
    let path = fresh_path("restart");
    {
        let mut store =
            SqlMetadataStore::open(RusqliteEngine::open(&path).expect("engine")).expect("store");
        seeded(&mut store, 1, 1);
        store.tombstone_generation(MINTED).expect("tombstone");
    }

    let mut reopened =
        SqlMetadataStore::open(RusqliteEngine::open(&path).expect("reopen")).expect("store");
    assert_eq!(
        reopened.create_generation(&authority(1), MINTED, &action_key()),
        Err(StoreError::GenerationIdNotAboveHighWater),
        "a restart must not resurrect a burned id"
    );
    assert_eq!(
        reopened.create_generation(&authority(1), NEVER_MINTED_BELOW, &action_key()),
        Err(StoreError::GenerationIdNotAboveHighWater),
        "a restart must not lower the watermark either"
    );
}

#[test]
fn t039_an_operator_reset_does_not_reopen_the_generation_space() {
    // The R113 x R108 crossing, which neither bead tested. H037's reset
    // opens a new authority lineage so that SERVING may resume over a
    // torn store. A reader could reasonably expect "new lineage" to mean
    // the old identities are free again. It must not: a reset changes
    // what may be served, never what may be minted. If it did, the
    // cheapest way to defeat the ABA fence would be to ask an operator
    // for a reset.
    let mut store = in_memory();
    store.record_operator_reset(1, 500).expect("reset");
    assert_eq!(store.highest_operator_reset().expect("reset"), Some(1));

    assert_eq!(
        store.create_generation(&authority(1), MINTED, &action_key()),
        Err(StoreError::GenerationIdNotAboveHighWater),
        "an operator reset must not un-burn a minted id"
    );
    assert_eq!(
        store.create_generation(&authority(1), NEVER_MINTED_BELOW, &action_key()),
        Err(StoreError::GenerationIdNotAboveHighWater),
        "an operator reset must not lower the watermark"
    );

    // And the reset itself is still monotone afterwards (H037), so this
    // scenario has not quietly disabled the thing it is standing on.
    assert_eq!(
        store.record_operator_reset(1, 501),
        Err(StoreError::StaleOperatorReset)
    );
}

#[test]
fn t039_an_authority_change_closes_generations_without_freeing_their_ids() {
    // G020/R120: a term change closes every generation created under a
    // superseded authority. Closing is a tombstone, so the closed ids
    // must stay burned — reissued work belongs in FRESH generations, not
    // in the ids the old coordinator was using when it lost the term.
    let mut store = in_memory();
    store
        .release_authority(&authority(1))
        .expect("the old coordinator gives up the term");
    store
        .acquire_authority(&AuthorityRow {
            digest: authority(2),
            cluster_id: "c".to_owned(),
            incarnation: 2,
            term: 2,
            acquired_seq: 2,
        })
        .expect("new term");

    let closed = store
        .close_generations_for_other_authorities(&authority(2))
        .expect("close");
    assert_eq!(closed, 1, "the old authority's live generation must close");
    assert!(
        store
            .generation_state(MINTED)
            .expect("state")
            .expect("exists")
            .tombstoned
    );

    assert_eq!(
        store.create_generation(&authority(2), MINTED, &action_key()),
        Err(StoreError::GenerationIdNotAboveHighWater),
        "the new authority must not inherit the right to reuse the old id"
    );
    store
        .create_generation(&authority(2), MINTED + 1, &action_key())
        .expect("the new authority mints above the watermark instead");

    // Idempotent: a second close changes nothing.
    assert_eq!(
        store
            .close_generations_for_other_authorities(&authority(2))
            .expect("second close"),
        0
    );
}

#[test]
fn t039_allocation_advances_past_tombstones_not_merely_past_live_ids() {
    // `allocate_bound_generation` documents that it advances from
    // durable history "including tombstones". If it instead advanced
    // from the live rows, tombstoning the newest generation would let
    // the next allocation land back on a burned id — the ABA window,
    // reopened by the very call sites meant to be the safe path.
    let mut store = in_memory();
    let first = store
        .allocate_bound_generation(&authority(1), &action_key())
        .expect("first");
    assert!(
        first.generation_id.0 > MINTED,
        "allocation must start above the seeded watermark"
    );

    store
        .tombstone_generation(first.generation_id.0)
        .expect("tombstone the newest");

    let second = store
        .allocate_bound_generation(&authority(1), &action_key())
        .expect("second");
    assert!(
        second.generation_id.0 > first.generation_id.0,
        "allocation must advance past a tombstoned id ({} must exceed {})",
        second.generation_id.0,
        first.generation_id.0
    );
    assert!(
        second.per_key_ordinal > first.per_key_ordinal,
        "the per-key ordinal must advance too"
    );
}

#[test]
fn t039_an_attempt_id_cannot_be_replayed_under_its_generation() {
    // The fence one level down. A generation is burned by id; an attempt
    // is burned by its append-only row. Replaying an attempt id would
    // let a stale worker's result be attributed to a live generation,
    // which is the same ABA shape one layer in.
    let mut store = in_memory();
    store.record_attempt(20, MINTED, "w", 1).expect("attempt");
    assert!(store.attempt_exists(20, MINTED).expect("exists"));

    assert!(
        store.record_attempt(20, MINTED, "w", 2).is_err(),
        "a duplicate attempt id must be refused, not silently re-recorded"
    );
    // The original row is intact: a refused replay must not mutate it.
    assert!(store.attempt_exists(20, MINTED).expect("still exists"));
}
