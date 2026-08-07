//! Cross-crate consistency proof for the delivery frontiers (bead C005):
//! the wire-layer `SubscriberFrontierReport::permitted_fallback` and the
//! state-machine layer `ExposureFrontiers::fallback_class` must agree on
//! every reachable combination — a wrapper deciding from the wire report
//! and an edge deciding from its state machine can never disagree about
//! which fallback band applies (I11/I43/I46; plan §85).

use rabs_action::state_machines::{ExposureFrontiers, FallbackClass};
use rabs_protocol::local_protocol::{FallbackPermission, SubscriberFrontierReport};

fn same_band(a: FallbackClass, b: FallbackPermission) -> bool {
    matches!(
        (a, b),
        (
            FallbackClass::SeamlessNonpublishing,
            FallbackPermission::SeamlessNonpublishing
        ) | (
            FallbackClass::LabeledTranscriptRecoveryOnly,
            FallbackPermission::LabeledTranscriptRecoveryOnly
        ) | (
            FallbackClass::NoUncoordinatedFallback,
            FallbackPermission::NoUncoordinatedFallback
        )
    )
}

#[test]
fn wire_report_and_state_machine_agree_on_every_certain_combination() {
    // The state machine tracks certain exposure; the wire report adds
    // uncertainty flags that CONSERVATIVELY map onto the same bands. For
    // every certain combination the two layers must agree exactly.
    for transcript in [false, true] {
        for stateful in [false, true] {
            let machine = ExposureFrontiers {
                transcript_exposed: transcript,
                stateful_intent_recorded: stateful,
            };
            let wire = SubscriberFrontierReport {
                transcript_exposed: transcript,
                stateful_intent_recorded: stateful,
                ..Default::default()
            };
            assert!(
                same_band(machine.fallback_class(), wire.permitted_fallback()),
                "band disagreement at transcript={transcript} stateful={stateful}: \
                 machine={:?} wire={:?}",
                machine.fallback_class(),
                wire.permitted_fallback()
            );
        }
    }
}

#[test]
fn uncertainty_maps_to_the_certain_band_it_conservatively_equals() {
    // transcript_uncertain must land exactly where transcript_exposed
    // lands; stateful_uncertain exactly where stateful_intent lands —
    // uncertainty is treated AS exposure, no fourth band exists.
    let t_uncertain = SubscriberFrontierReport {
        transcript_uncertain: true,
        ..Default::default()
    };
    let t_certain = SubscriberFrontierReport {
        transcript_exposed: true,
        ..Default::default()
    };
    assert_eq!(
        t_uncertain.permitted_fallback(),
        t_certain.permitted_fallback()
    );
    let s_uncertain = SubscriberFrontierReport {
        stateful_uncertain: true,
        ..Default::default()
    };
    let s_certain = SubscriberFrontierReport {
        stateful_intent_recorded: true,
        ..Default::default()
    };
    assert_eq!(
        s_uncertain.permitted_fallback(),
        s_certain.permitted_fallback()
    );
}
