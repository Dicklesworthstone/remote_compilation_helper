//! T022, the suite-coupling half: order- and setup-coupled tests must
//! never serve per-test hits (bead O014; risk R69). The OUT_DIR replay
//! half (R66) lives in
//! `rabs-protocol/tests/t022_out_dir_replay_and_suite_coupling.rs`.
//!
//! O014 already makes the rule structural — `per_test_serving_allowed()`
//! is true in only the per-test arm of an exhaustive match, so the
//! batch and bypass arms cannot offer per-test serving by construction
//! — and that structural proof is the strongest form this can take.
//! Not redone here.
//!
//! What this adds is the rule exercised through `route`, which is what
//! callers actually reach. The structural property says the ROUTING
//! decides correctly; it says nothing about whether every coupling
//! signal reaches a routing that refuses. A signal newly added to the
//! enum and accidentally left out of the router's matching would pass
//! O014's proof untouched while silently routing its suites back to
//! per-test caching — the exact soundness failure R69 names, since a
//! cached per-test pass was only ever valid in the company of its
//! siblings.

use rabs_key::suite_coupling::{CouplingSignal, SuiteRouting, route};

/// Every coupling signal the enum can express. If a variant is added
/// without being added here, this file still compiles — so the count
/// assertion below is what keeps the list honest.
fn every_coupling_signal() -> Vec<CouplingSignal> {
    vec![
        CouplingSignal::OncePerSuiteInitializer {
            name: "init_tracing".to_owned(),
        },
        CouplingSignal::OrderingDependence {
            witness: ("writes_the_row".to_owned(), "reads_the_row".to_owned()),
        },
        CouplingSignal::SharedDatabase {
            path: "/tmp/fixture.db".to_owned(),
        },
        CouplingSignal::SharedPort { port: 8080 },
        CouplingSignal::SharedTempRoot {
            path: "/tmp/shared-root".to_owned(),
        },
        CouplingSignal::SetupTeardownSideEffect {
            name: "truncates the fixture table".to_owned(),
        },
        CouplingSignal::GlobalExternalState {
            subject: "the staging billing API".to_owned(),
        },
    ]
}

#[test]
fn t022_every_coupling_signal_routes_somewhere_that_refuses_per_test_serving() {
    let signals = every_coupling_signal();
    assert_eq!(
        signals.len(),
        7,
        "the enum has seven wire-stable tags; a new one must be added to this list, \
         or it would be routed without ever being checked here"
    );
    // The tags are wire-stable, so covering 1..=7 is covering the enum.
    let mut tags: Vec<u8> = signals.iter().map(CouplingSignal::tag).collect();
    tags.sort_unstable();
    assert_eq!(
        tags,
        (1..=7).collect::<Vec<u8>>(),
        "every wire tag must be represented exactly once"
    );

    for signal in &signals {
        let routing = route(std::slice::from_ref(signal));
        assert!(
            !routing.per_test_serving_allowed(),
            "{signal:?} routed to {routing:?}, which offers per-test serving — a cached \
             per-test pass would be served for a suite whose tests are coupled (R69)"
        );
    }
}

#[test]
fn t022_coupling_in_combination_never_becomes_serveable_again() {
    // Signals do not cancel out. Every subset that contains at least one
    // coupling signal must still refuse per-test serving, including the
    // full set — a router that took, say, the last signal rather than
    // the strongest would pass the one-at-a-time test above.
    let signals = every_coupling_signal();
    assert!(!route(&signals).per_test_serving_allowed());

    for (index, signal) in signals.iter().enumerate() {
        // Each signal paired with the one after it, in both orders:
        // routing must not depend on the order the detector reported.
        let next = &signals[(index + 1) % signals.len()];
        let forward = route(&[signal.clone(), next.clone()]);
        let backward = route(&[next.clone(), signal.clone()]);
        assert!(!forward.per_test_serving_allowed());
        assert!(!backward.per_test_serving_allowed());
        assert_eq!(
            forward, backward,
            "routing must not depend on the order signals were reported: \
             {signal:?} + {next:?}"
        );
    }
}

#[test]
fn t022_un_keyable_external_state_wins_over_batchable_coupling() {
    // O014's rule that bypass dominates: batching keys the coupled
    // state into the suite key, which is only sound when that state CAN
    // be keyed. Global external state cannot be, so its presence must
    // force bypass however much batchable coupling accompanies it — and
    // bypass, like batch, offers no per-test hit.
    let external = CouplingSignal::GlobalExternalState {
        subject: "the staging billing API".to_owned(),
    };
    let mut mixture = every_coupling_signal();
    mixture.retain(|s| !matches!(s, CouplingSignal::GlobalExternalState { .. }));
    assert!(
        !mixture.is_empty(),
        "the mixture must actually contain batchable coupling"
    );
    let batchable_only = route(&mixture);
    assert!(
        matches!(batchable_only, SuiteRouting::TestBinaryBatch { .. }),
        "batchable coupling alone batches, got {batchable_only:?}"
    );

    mixture.push(external);
    assert!(
        matches!(route(&mixture), SuiteRouting::Bypass { .. }),
        "un-keyable external state must force bypass even among batchable signals"
    );
    assert!(!route(&mixture).per_test_serving_allowed());
}

#[test]
fn t022_an_uncoupled_suite_still_gets_per_test_caching() {
    // The control, and the reason every assertion above means something:
    // a router that refused everything would satisfy them all while
    // destroying the per-test caching this whole mechanism exists to
    // make safe.
    assert_eq!(route(&[]), SuiteRouting::PerTestCaching);
    assert!(route(&[]).per_test_serving_allowed());
}
