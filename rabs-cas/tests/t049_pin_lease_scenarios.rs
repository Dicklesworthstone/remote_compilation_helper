//! T049 scenarios: pin-lease clock skew, restart, contradictory leases,
//! duplicate release, and what GC actually protects (beads H041/H014;
//! risk R127).
//!
//! H041's unit suite already covers linear expiry through grace, the
//! authority-scoped idempotent release, the worker-can-never-release
//! rule, and survival across restart. Two things it does not do, and
//! this suite does:
//!
//! - **Clock SKEW, not just clock advance.** Every existing expiry test
//!   walks `now_seq` forward. A real fleet's sequence source can jump
//!   backward (restored daemon, replaced coordinator, restart before the
//!   counter is durable), and "fail toward retention" has to mean
//!   something under that too — a pin must not become collectable
//!   because a clock moved the wrong way, and must not skip grace
//!   because one moved far the right way.
//!
//! - **What GC actually protects**, end to end. `pin_protection` is the
//!   lease judgement; `gc_snapshot` is what the collector really sees.
//!   Those are two different pieces of code and T049's "GC honors all of
//!   it" is a claim about the SECOND one. Asserting the judgement and
//!   assuming the collector agrees would prove nothing about the data.

use rabs_cas::metadata_store::{
    AuthorityRow, RabsMetadataStore, RusqliteEngine, SqlEngine, SqlMetadataStore, digest_key,
};
use rabs_cas::pin_leases::{
    PUBLICATION_PIN_CLASS, PinProtection, ReleaseOutcome, Releaser, pin_protection,
    release_pin_scoped,
};
use rabs_cas::publication::authority_digest;
use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

const GRACE: u64 = 10;
const EXPIRES_AT: u64 = 100;
/// The term the installed authority holds; anything below it is stale.
const ACTIVE_TERM: u64 = 3;

fn digest(tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: "rabs.object.sha256.v1",
        bytes: [tag; 32],
    }
}

fn authority(term: u64) -> CoordinatorAuthority {
    CoordinatorAuthority {
        cluster_id: ClusterId("c".to_owned()),
        credential_generation: 1,
        term,
        incarnation_id: CoordinatorIncarnationId(9),
    }
}

/// Pin 1: a publication root (no expiry). Pin 3: a worker transfer hold
/// that expires at `EXPIRES_AT`.
fn install<E: SqlEngine>(store: &mut SqlMetadataStore<E>) {
    store
        .acquire_authority(&AuthorityRow {
            digest: authority_digest(&authority(ACTIVE_TERM)),
            cluster_id: "c".to_owned(),
            incarnation: 9,
            term: ACTIVE_TERM,
            acquired_seq: 1,
        })
        .expect("active authority");
    store
        .create_pin(
            1,
            &digest(1),
            "coordinator",
            PUBLICATION_PIN_CLASS,
            None,
            None,
            true,
            "publication root",
        )
        .expect("publication pin");
    store
        .create_pin(
            3,
            &digest(3),
            "worker-a",
            "transfer",
            Some(EXPIRES_AT),
            None,
            false,
            "expiring hold",
        )
        .expect("expiring pin");
}

fn fresh() -> SqlMetadataStore<RusqliteEngine> {
    let mut store =
        SqlMetadataStore::open(RusqliteEngine::open_in_memory().expect("engine")).expect("store");
    install(&mut store);
    store
}

fn protection(
    store: &mut SqlMetadataStore<RusqliteEngine>,
    now: u64,
    confirmed: bool,
) -> PinProtection {
    pin_protection(store, 3, now, confirmed, GRACE)
        .expect("pin lookup")
        .expect("pin 3 exists")
}

#[test]
fn t049_a_clock_that_jumps_backward_never_makes_a_pin_collectable() {
    let mut store = fresh();
    // Walk past expiry and all the way through grace with reconciliation
    // confirmed: this is the ONE state H041 lets stop protecting.
    assert_eq!(
        protection(&mut store, EXPIRES_AT + GRACE + 1, true),
        PinProtection::Expired
    );

    // Now the sequence source jumps BACKWARD — a restored daemon, a
    // replaced coordinator, a restart before the counter was durable.
    // Retention must not depend on the direction a clock moved.
    for skewed in [EXPIRES_AT + GRACE, EXPIRES_AT + 1, EXPIRES_AT, 1, 0] {
        assert_ne!(
            protection(&mut store, skewed, true),
            PinProtection::Expired,
            "now_seq={skewed}: a backward clock must not leave the pin collectable"
        );
    }
}

#[test]
fn t049_a_clock_that_jumps_far_forward_still_cannot_skip_reconciliation() {
    let mut store = fresh();
    // An enormous forward jump is not evidence that anything was
    // reconciled. Without confirmation the pin stays in grace no matter
    // how far the clock ran — otherwise a skewed clock alone would be
    // enough to collect live data.
    for far in [EXPIRES_AT + GRACE + 1, EXPIRES_AT * 1_000, u64::MAX] {
        assert_eq!(
            protection(&mut store, far, false),
            PinProtection::GraceProtecting,
            "now_seq={far}: unconfirmed expiry must stay protecting however far the clock ran"
        );
    }
    // And with confirmation, the same far clock does expire it — so the
    // assertion above is about reconciliation, not about saturation.
    assert_eq!(
        protection(&mut store, u64::MAX, true),
        PinProtection::Expired
    );
}

#[test]
fn t049_a_pin_with_no_expiry_is_immune_to_any_clock() {
    let mut store = fresh();
    // The publication root carries no lease. No clock value, skewed in
    // either direction, and no reconciliation state may ever make it
    // stop protecting — only an authorized release can.
    for now in [0, 1, EXPIRES_AT, u64::MAX] {
        for confirmed in [false, true] {
            assert_eq!(
                pin_protection(&mut store, 1, now, confirmed, GRACE)
                    .expect("lookup")
                    .expect("pin 1"),
                PinProtection::Protecting,
                "now={now} confirmed={confirmed}: an unexpiring pin must always protect"
            );
        }
    }
}

#[test]
fn t049_gc_keeps_protecting_a_root_a_worker_failed_to_release() {
    // The safety claim T049 makes about GC, checked against the
    // collector's OWN view rather than against the lease judgement.
    let mut store = fresh();
    let root = digest_key(&digest(1));
    assert!(
        store
            .gc_snapshot(1)
            .expect("snapshot")
            .pinned_roots
            .contains(&root),
        "a fresh publication root must be a GC root"
    );

    // A worker tries to release it — twice, and once while claiming the
    // coordinator's own owner string.
    for claimed in ["worker-a", "coordinator", "worker-a"] {
        assert_eq!(
            release_pin_scoped(&mut store, 1, &Releaser::Worker(claimed.to_owned()))
                .expect("release attempt"),
            ReleaseOutcome::RefusedWorkerOnPublicationRoot
        );
    }
    // The refusal is not merely reported: the collector still sees the
    // root. A refusal that left GC free to delete would be worse than an
    // accepted release, because nothing would look wrong.
    assert!(
        store
            .gc_snapshot(1)
            .expect("snapshot")
            .pinned_roots
            .contains(&root),
        "a refused worker release must leave the GC protection intact"
    );
}

#[test]
fn t049_duplicate_release_is_idempotent_all_the_way_into_gc() {
    let mut store = fresh();
    let root = digest_key(&digest(3));
    assert!(
        store
            .gc_snapshot(1)
            .expect("snapshot")
            .pinned_roots
            .contains(&root)
    );

    assert_eq!(
        release_pin_scoped(&mut store, 3, &Releaser::Worker("worker-a".to_owned()))
            .expect("release"),
        ReleaseOutcome::Released
    );
    let after_first = store.gc_snapshot(1).expect("snapshot").pinned_roots;
    assert!(
        !after_first.contains(&root),
        "a released pin stops being a GC root"
    );

    // Releasing again is a typed no-op, and — the part that matters —
    // the collector's view does not change either. An idempotent API
    // whose second call perturbed GC would be idempotent in name only.
    assert_eq!(
        release_pin_scoped(&mut store, 3, &Releaser::Worker("worker-a".to_owned()))
            .expect("second release"),
        ReleaseOutcome::AlreadyReleased
    );
    assert_eq!(
        store.gc_snapshot(1).expect("snapshot").pinned_roots,
        after_first,
        "a duplicate release must not change what GC protects"
    );
}

#[test]
fn t049_gc_protects_by_release_state_alone_not_by_lease_expiry() {
    // A DOCUMENTED DIVERGENCE, not a wish: `pin_protection` and
    // `gc_snapshot` are different code answering related questions, and
    // they do not agree at one end.
    //
    // `gc_snapshot` selects `pins WHERE released = 0`. It never reads
    // `expires_at_seq`. So a lease that `pin_protection` has fully
    // retired — expired, reconciliation confirmed, grace elapsed — is
    // STILL a GC root.
    //
    // The direction is the safe one: GC retains more than the lease rule
    // strictly requires, and T049's "GC honors all of it" is a retention
    // claim, which holds. But it also means lease EXPIRY alone never
    // frees anything; only a release does. Pinning that here so the next
    // person reads it as a property rather than discovering it while
    // wondering why disk never comes back (filed as its own bead).
    let mut store = fresh();
    let root = digest_key(&digest(3));
    let fully_expired = EXPIRES_AT + GRACE + 1;
    assert_eq!(
        protection(&mut store, fully_expired, true),
        PinProtection::Expired,
        "precondition: the lease rule considers this pin retired"
    );
    assert!(
        store
            .gc_snapshot(fully_expired)
            .expect("snapshot")
            .pinned_roots
            .contains(&root),
        "GC still protects an expired-but-unreleased pin: expiry alone frees nothing"
    );

    // Releasing it is what actually hands the root to GC.
    assert_eq!(
        release_pin_scoped(&mut store, 3, &Releaser::Worker("worker-a".to_owned()))
            .expect("release"),
        ReleaseOutcome::Released
    );
    assert!(
        !store
            .gc_snapshot(fully_expired)
            .expect("snapshot")
            .pinned_roots
            .contains(&root)
    );
}

#[test]
fn t049_a_contradictory_release_from_a_stale_authority_changes_nothing() {
    let mut store = fresh();
    let root = digest_key(&digest(1));
    // A coordinator whose term is behind the active one is a contender,
    // not an authority. Its release must be refused AND must leave the
    // collector's view untouched.
    assert_eq!(
        release_pin_scoped(&mut store, 1, &Releaser::Coordinator(authority(2)))
            .expect("stale release attempt"),
        ReleaseOutcome::RefusedNotActiveAuthority
    );
    assert!(
        store
            .gc_snapshot(1)
            .expect("snapshot")
            .pinned_roots
            .contains(&root),
        "a stale authority's refused release must not unprotect the root"
    );
    assert!(!store.pin_row(1).expect("row").expect("pin 1").released);
}
