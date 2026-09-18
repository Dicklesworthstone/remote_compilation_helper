//! T036 scenarios: partial-transcript crash/fallback and ITERATIVE
//! multi-event subscriber delivery (beads C019/C021/C023/C026; risks
//! R104/R116).
//!
//! The unit suites already crash the delivery engine at *every* boundary
//! of a five-item plan and reconstruct transcript uncertainty at every
//! kill point. What they do not do is run a LONG, mixed stream — the
//! shape T036 names — or put the two lanes together. Both gaps matter
//! for different reasons:
//!
//! - A five-item plan cannot distinguish "the frontier advances by one"
//!   from "the frontier happens to end up right", and it cannot exercise
//!   an ack cadence at all. Length is the point of the iterative
//!   property.
//! - The transcript lane and the stateful lane each track their own
//!   uncertainty, and the fallback decision reads BOTH. A scenario that
//!   exercises one lane at a time can never catch a composition that
//!   authorizes a seamless rerun while the other lane is unresolved —
//!   which is exactly the duplicated-output failure R104/R116 exist to
//!   prevent.
//!
//! These use only the public contract, so they also pin the surface a
//! real edge/wrapper pair would build against.

use rabs_protocol::local_protocol::{
    FallbackAction, FallbackConfig, SubscriberFrontierReport, decide_fallback,
};
use rabs_protocol::stateful_delivery::{
    DeliveryEngine, DeliveryItemKind, DeliveryPlan, RecoveryClass, VisibleWorld,
};
use rabs_protocol::transcript_sequencing::FrameReader;

/// A long, mixed delivery stream: repeating transcript/stateful groups
/// with a single terminal last, the shape a real build produces
/// (diagnostics and metadata interleaved with owned writes).
fn long_mixed_plan(groups: usize) -> DeliveryPlan {
    let mut items = Vec::with_capacity(groups * 4 + 1);
    for _ in 0..groups {
        items.push(DeliveryItemKind::Transcript);
        items.push(DeliveryItemKind::Transcript);
        items.push(DeliveryItemKind::StatefulWrite);
        items.push(DeliveryItemKind::Transcript);
    }
    items.push(DeliveryItemKind::Terminal);
    DeliveryPlan::new(items).expect("a terminal-last plan is valid")
}

/// Drive one item through intent (when stateful), exposure and ack.
fn deliver(engine: &mut DeliveryEngine, world: &mut VisibleWorld, seq: u64, plan: &DeliveryPlan) {
    if plan.kind(seq) == Some(DeliveryItemKind::StatefulWrite) {
        engine.record_intent(seq).expect("intent before exposure");
    }
    engine.begin_expose(seq, world).expect("expose next item");
    engine.ack(seq).expect("ack the item being exposed");
}

#[test]
fn t036_a_long_mixed_stream_acks_strictly_one_item_at_a_time() {
    let plan = long_mixed_plan(30); // 121 items
    let total = plan.len();
    assert_eq!(total, 121);

    let mut engine = DeliveryEngine::new(plan.clone());
    let mut world = VisibleWorld::default();

    for seq in 1..=total {
        // Completion is never reachable before the terminal item, no
        // matter how much of the stream has landed. A stream that
        // reported complete at the frontier's high-water would let a
        // caller stop reading while owned outputs were still coming.
        assert!(
            !engine.delivery_complete(),
            "seq={seq}: complete before the terminal item"
        );
        deliver(&mut engine, &mut world, seq, &plan);
        // ITERATIVE: each ack advances the frontier by exactly one.
        assert_eq!(
            engine.acked_frontier(),
            seq,
            "seq={seq}: the frontier must advance one item per ack"
        );
    }

    assert!(engine.delivery_complete(), "the terminal ack completes");
    assert_eq!(engine.acked_frontier(), engine.terminal_seq());
    // Every item became visible exactly once, in order, across 121
    // items — the property a five-item fixture cannot distinguish from
    // luck.
    assert_eq!(world.exposed.len(), total as usize);
    assert!(world.exposed.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn t036_crashes_across_a_long_stream_never_duplicate_a_stateful_effect() {
    // SAMPLED, not exhaustive, and said so plainly: the unit suite
    // already crashes at every boundary of a small plan, which is the
    // exhaustive argument. This one asks a different question — whether
    // that property survives at length — so it samples kill points
    // across a 121-item stream rather than pretending to enumerate
    // them.
    let plan = long_mixed_plan(30);
    let total = plan.len();

    for kill_after in (0..=total).step_by(7) {
        let mut engine = DeliveryEngine::new(plan.clone());
        let mut world = VisibleWorld::default();
        for seq in 1..=kill_after {
            deliver(&mut engine, &mut world, seq, &plan);
        }

        // Crash: volatile state dies, the durable slice survives.
        let mut recovered = engine.crash();
        // A clean boundary (every started item acked) is never
        // uncertain — uncertainty is for an intent recorded but not
        // acknowledged, and inventing it here would force a needless
        // reconciliation on every restart.
        assert!(
            !matches!(
                recovered.classify(),
                RecoveryClass::DeliveryUncertain { .. }
            ),
            "kill_after={kill_after}: a fully acked prefix is not uncertain"
        );

        for seq in (kill_after + 1)..=total {
            deliver(&mut recovered, &mut world, seq, &plan);
        }
        assert!(
            recovered.delivery_complete(),
            "kill_after={kill_after}: completion must stay reachable after a crash"
        );

        // THE guarantee: a stateful effect lands exactly once even
        // though the stream was interrupted and resumed.
        for seq in 1..=total {
            if plan.kind(seq) == Some(DeliveryItemKind::StatefulWrite) {
                let landed = world.exposed.iter().filter(|s| **s == seq).count();
                assert_eq!(
                    landed, 1,
                    "kill_after={kill_after}: stateful effect {seq} landed {landed} times"
                );
            }
        }
        assert!(
            world.exposed.windows(2).all(|w| w[0] <= w[1]),
            "kill_after={kill_after}: exposure order went backwards"
        );
    }
}

#[test]
fn t036_a_partial_transcript_frame_is_never_exposed_and_reports_uncertainty() {
    // R116: a frame whose write began but never completed is held
    // privately. The user never sees it, and the reconnect report says
    // it MAY be in flight — the honest answer, which is what stops a
    // resume from either duplicating or silently dropping it.
    let mut reader = FrameReader::new(64);
    reader.begin_frame(1, 8).expect("first frame header");
    reader.feed(b"complete").expect("all eight bytes");
    let seq = reader.complete_frame().expect("a whole frame is exposed");
    assert_eq!(seq, 1);
    assert_eq!(reader.exposed(), 1);
    assert_eq!(reader.exposed_payloads(), &[b"complete".to_vec()]);

    // Now a frame that dies mid-write.
    reader.begin_frame(2, 8).expect("second frame header");
    reader.feed(b"half").expect("four of eight bytes");
    assert_eq!(
        reader.exposed(),
        1,
        "a partial frame must not advance the exposed frontier"
    );
    assert_eq!(
        reader.exposed_payloads().len(),
        1,
        "the partial payload must never reach the user"
    );

    let report = reader.resume_report();
    assert_eq!(report.last_fully_exposed_seq, 1);
    assert_eq!(
        report.possibly_in_flight_seq,
        Some(2),
        "the partial frame must be reported as possibly in flight, not forgotten"
    );
}

#[test]
fn t036_neither_lane_alone_may_authorize_a_seamless_rerun() {
    // THE composition T036 names. The fallback decision reads both
    // lanes, so it is checked against both — a scenario exercising one
    // lane at a time cannot catch a rule that ignores the other, and
    // ignoring either is how output gets duplicated.
    let plan = long_mixed_plan(3);
    let engine = DeliveryEngine::new(plan.clone());
    let mut world = VisibleWorld::default();

    // A transcript frame that died mid-write: transcript lane uncertain.
    let mut reader = FrameReader::new(64);
    reader.begin_frame(1, 8).expect("header");
    reader.feed(b"half").expect("partial payload");
    let transcript = reader.resume_report();
    assert!(transcript.possibly_in_flight_seq.is_some());

    for config in [
        FallbackConfig::default(),
        FallbackConfig {
            labeled_transcript_recovery: true,
        },
    ] {
        // Transcript uncertain alone.
        let stateful = engine.frontier_report();
        let combined = SubscriberFrontierReport {
            transcript_uncertain: transcript.possibly_in_flight_seq.is_some(),
            last_fully_delivered_seq: transcript.last_fully_exposed_seq,
            ..stateful
        };
        assert_ne!(
            decide_fallback(&combined, &config, 7),
            FallbackAction::RunOriginalSeamless,
            "an uncertain transcript must forfeit the seamless path \
             (recovery={})",
            config.labeled_transcript_recovery
        );

        // And with the transcript lane clean but the STATEFUL lane
        // mid-item, the seamless path is equally unavailable.
        let mut mid = DeliveryEngine::new(plan.clone());
        // Items 1 and 2 are transcript; item 3 is the stateful write, and
        // an intent may only be recorded for the NEXT item, so the stream
        // has to reach it.
        deliver(&mut mid, &mut world, 1, &plan);
        deliver(&mut mid, &mut world, 2, &plan);
        assert_eq!(plan.kind(3), Some(DeliveryItemKind::StatefulWrite));
        mid.record_intent(3).expect("intent for the stateful item");
        let stateful_pending = SubscriberFrontierReport {
            transcript_uncertain: false,
            ..mid.frontier_report()
        };
        assert_ne!(
            decide_fallback(&stateful_pending, &config, 7),
            FallbackAction::RunOriginalSeamless,
            "a recorded stateful intent must forfeit the seamless path \
             (recovery={})",
            config.labeled_transcript_recovery
        );
    }

    // Sanity floor: a genuinely clean pair of lanes DOES take the
    // seamless path, so the assertions above are discriminating rather
    // than vacuous.
    assert_eq!(
        decide_fallback(
            &SubscriberFrontierReport::default(),
            &FallbackConfig::default(),
            7
        ),
        FallbackAction::RunOriginalSeamless
    );
}
