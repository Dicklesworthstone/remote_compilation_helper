//! T010: the resource curves a soak is actually for (bead J017 covers
//! the traffic; this covers what the traffic leaves behind).
//!
//! J017's `M8_MULTIDAY_SOAK` runs 1,000 compressed day-cycles of
//! burst → idle → healed reconcile → authority rotation with a stale
//! probe, and gates on `zero lost, zero double-executes`. Those are
//! CORRECTNESS gates and they are not redone here.
//!
//! T010 accepts on something J017 never claims: **flat memory/fd/pin
//! curves**. That is an accumulation question, and accumulation is
//! invisible to a correctness gate — a run can be perfectly correct on
//! every cycle and still be leaking, because each cycle's leak is
//! individually harmless. It only shows up as a curve.
//!
//! What is asserted, and what is deliberately not:
//!
//! - **Pin curve.** Asserted, because it is the one with teeth here:
//!   a pin is what stops GC reclaiming bytes, so a pin that outlives
//!   its owner is disk that never comes back. Measured against
//!   `gc_snapshot`, the collector's own view, rather than against the
//!   lease bookkeeping — those are different code and T049 already
//!   found them disagreeing at one end.
//! - **File-descriptor curve.** Asserted on Linux by counting
//!   `/proc/self/fd`, which is exact rather than a proxy.
//! - **Memory.** NOT asserted. An in-process allocator figure is noise
//!   at this scale — arena growth, allocator caching and the test
//!   harness all move it — so a "flat memory" assertion here would be
//!   either vacuous or flaky, and both are worse than an honest gap.
//!   Memory needs an out-of-process RSS measurement over a real daemon,
//!   which is a different harness than this.
//!
//! Scale: the bead says "millions of action-actor lifecycles". This
//! runs thousands. A linear leak is visible at thousands — the curve's
//! SHAPE is what the assertion reads, not its length — but a leak that
//! only appears after a million cycles would not be caught, and that is
//! a real limit of this test rather than something it papers over.

use rabs_cas::metadata_store::{
    AuthorityRow, RabsMetadataStore, RusqliteEngine, SqlMetadataStore, SqlValue,
};
use rabs_cas::pin_leases::{PUBLICATION_PIN_CLASS, Releaser, release_pin_scoped};
use rabs_cas::publication::authority_digest;
use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

/// Lifecycles per soak. Large enough that a one-row-per-cycle leak is
/// unmistakable against a baseline, small enough to stay a test.
const CYCLES: u128 = 2_000;

fn digest(tag: u128) -> TypedDigest {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&tag.to_be_bytes());
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: "rabs.object.sha256.v1",
        bytes,
    }
}

fn authority() -> CoordinatorAuthority {
    CoordinatorAuthority {
        cluster_id: ClusterId("soak".to_owned()),
        credential_generation: 1,
        term: 1,
        incarnation_id: CoordinatorIncarnationId(1),
    }
}

fn fresh() -> SqlMetadataStore<RusqliteEngine> {
    let mut store =
        SqlMetadataStore::open(RusqliteEngine::open_in_memory().expect("engine")).expect("store");
    store
        .acquire_authority(&AuthorityRow {
            digest: authority_digest(&authority()),
            cluster_id: "soak".to_owned(),
            incarnation: 1,
            term: 1,
            acquired_seq: 1,
        })
        .expect("authority");
    store
}

/// What the COLLECTOR believes it must protect right now.
fn protected_roots(store: &mut SqlMetadataStore<RusqliteEngine>, seq: u64) -> usize {
    store.gc_snapshot(seq).expect("snapshot").pinned_roots.len()
}

/// Total rows in `pins`, live and historical.
fn pin_rows(store: &mut SqlMetadataStore<RusqliteEngine>) -> u64 {
    let rows = store
        .query("SELECT COUNT(*) FROM pins", &[])
        .expect("count pins");
    match rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Int(n)) => u64::try_from(*n).expect("non-negative count"),
        other => panic!("unexpected count shape: {other:?}"),
    }
}

/// Open file descriptors for this process (Linux only; exact, not a proxy).
#[cfg(target_os = "linux")]
fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd")
        .count()
}

/// One full pin lifecycle: take the protection, then give it back.
fn lifecycle(store: &mut SqlMetadataStore<RusqliteEngine>, cycle: u128) {
    let id = cycle + 1;
    store
        .create_pin(
            id,
            &digest(cycle),
            "coordinator",
            PUBLICATION_PIN_CLASS,
            None,
            None,
            true,
            "soak lifecycle",
        )
        .expect("create pin");
    assert_eq!(
        release_pin_scoped(store, id, &Releaser::Coordinator(authority())).expect("release"),
        rabs_cas::pin_leases::ReleaseOutcome::Released,
        "cycle {cycle}: the lifecycle must actually complete"
    );
}

#[test]
fn t010_protected_root_curve_is_flat_across_a_long_soak() {
    // THE pin curve. A pin is what stops GC reclaiming bytes, so a pin
    // that outlives its owner is disk that never comes back. Measured
    // against gc_snapshot — the collector's own view — rather than
    // against the lease bookkeeping, because T049 already found those
    // two disagreeing at one end.
    let mut store = fresh();
    let baseline = protected_roots(&mut store, 1);
    assert_eq!(baseline, 0, "a fresh store protects nothing");

    // Sampled along the way, not only at the end: a curve that rises
    // and then happens to return to baseline is not flat, and an
    // end-state-only assertion cannot tell the difference.
    let checkpoints = [CYCLES / 4, CYCLES / 2, (CYCLES * 3) / 4];
    for cycle in 0..CYCLES {
        lifecycle(&mut store, cycle);
        if checkpoints.contains(&cycle) {
            assert_eq!(
                protected_roots(&mut store, cycle as u64 + 2),
                baseline,
                "cycle {cycle}: a completed lifecycle left protection behind"
            );
        }
    }

    assert_eq!(
        protected_roots(&mut store, CYCLES as u64 + 2),
        baseline,
        "{CYCLES} completed lifecycles must protect exactly what zero did"
    );
}

#[test]
fn t010_an_unreleased_pin_is_the_thing_the_flat_curve_would_catch() {
    // The control, and the reason the test above means something: if
    // protection simply never registered, a flat curve would be
    // vacuous. One lifecycle left UNRELEASED must move the curve by
    // exactly one and keep it there.
    let mut store = fresh();
    assert_eq!(protected_roots(&mut store, 1), 0);

    store
        .create_pin(
            1,
            &digest(0),
            "coordinator",
            PUBLICATION_PIN_CLASS,
            None,
            None,
            true,
            "never released",
        )
        .expect("create pin");
    assert_eq!(
        protected_roots(&mut store, 2),
        1,
        "an unreleased pin MUST show in the curve"
    );

    // And it stays: further completed lifecycles do not mask it.
    for cycle in 1..50 {
        lifecycle(&mut store, cycle);
    }
    assert_eq!(
        protected_roots(&mut store, 100),
        1,
        "the leaked protection persists and is not hidden by later traffic"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn t010_file_descriptor_curve_is_flat_across_a_long_soak() {
    // fds are the other resource a long-lived daemon runs out of, and
    // /proc/self/fd is exact rather than a proxy. The store is opened
    // OUTSIDE the measurement so its own handles are part of the
    // baseline; what is measured is whether the lifecycles add any.
    let mut store = fresh();
    lifecycle(&mut store, 0); // warm any lazily-opened handle
    let baseline = open_fds();

    for cycle in 1..CYCLES {
        lifecycle(&mut store, cycle);
    }

    let after = open_fds();
    assert_eq!(
        after, baseline,
        "{CYCLES} lifecycles changed the open-fd count ({baseline} -> {after})"
    );
}

#[test]
fn t010_the_pins_table_itself_grows_without_bound() {
    // A DOCUMENTED PROPERTY, not a failure — and the one place the
    // "flat pin curve" acceptance needs qualifying.
    //
    // Live PROTECTION is flat (the first test). The pins TABLE is not:
    // a released pin is marked released and kept, and nothing anywhere
    // deletes from `pins` — there is no `DELETE FROM pins` in the store
    // and GC does not touch released rows. So the table grows by one
    // row per lifecycle, forever.
    //
    // The rows are small, so this is not an imminent disk problem. What
    // it does mean is that `gc_snapshot`, which selects the unreleased
    // rows, scans a table whose size is the number of lifecycles the
    // deployment has EVER run. On the "millions of action-actor
    // lifecycles" this bead asks about, GC cost grows linearly with
    // history rather than with live work. Filed separately; pinned here
    // so the next reader meets it as a known property rather than
    // discovering it while wondering why GC got slow.
    let mut store = fresh();
    let baseline = pin_rows(&mut store);
    for cycle in 0..CYCLES {
        lifecycle(&mut store, cycle);
    }
    assert_eq!(
        pin_rows(&mut store),
        baseline + CYCLES as u64,
        "released pins are retained as history: one row per lifecycle, never pruned"
    );
    // Live protection is still flat, so the growth really is history
    // rather than leaked protection.
    assert_eq!(protected_roots(&mut store, CYCLES as u64 + 2), 0);
}

#[test]
fn t010_repeated_release_does_not_move_either_curve() {
    // Soak traffic is not tidy: reconnects replay releases. A duplicate
    // release must be a typed no-op that changes neither the protection
    // curve nor the row count — an idempotent API that appended a row
    // per retry would leak under exactly the reconnect storm this bead
    // is about.
    let mut store = fresh();
    store
        .create_pin(
            1,
            &digest(0),
            "coordinator",
            PUBLICATION_PIN_CLASS,
            None,
            None,
            true,
            "replayed release",
        )
        .expect("create pin");
    release_pin_scoped(&mut store, 1, &Releaser::Coordinator(authority())).expect("release");

    let rows = pin_rows(&mut store);
    let protected = protected_roots(&mut store, 10);
    for _ in 0..200 {
        assert_eq!(
            release_pin_scoped(&mut store, 1, &Releaser::Coordinator(authority()))
                .expect("replayed release"),
            rabs_cas::pin_leases::ReleaseOutcome::AlreadyReleased
        );
    }
    assert_eq!(
        pin_rows(&mut store),
        rows,
        "a replayed release appended rows"
    );
    assert_eq!(
        protected_roots(&mut store, 11),
        protected,
        "a replayed release moved the protection curve"
    );
}
