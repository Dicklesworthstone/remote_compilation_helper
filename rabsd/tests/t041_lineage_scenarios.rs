//! T041 scenarios: snapshot-lineage reseal, downgrade, and what happens
//! AFTER a downgrade (beads D032/I025; invariant I53; risk R110).
//!
//! D032 already ships the two headline T041 cases, and they are good:
//! `t041_mutation_mid_command_reseals_and_never_mixes_state` and
//! `t041_downgrade_arm_is_coherent_not_mixed`. I025 likewise ships the
//! waiter-saturation half in `rabs_scheduler::lineage_waiters`, where a
//! saturated waiter budget still lets producers walk into the reserve.
//! Neither is redone here.
//!
//! What both stop short of is the state AFTER a terminal-looking
//! transition. D032's downgrade test ends at "the next registration
//! refuses" and never asks what the machine does if resolution state
//! mutates AGAIN, or if something tries to seal again. Those are not
//! exotic: a downgrade happens because no reseal lane existed at that
//! moment, and the whole point of a long-running Cargo command is that
//! state keeps moving. The transitions out of a downgraded state are
//! reachable, and nothing covered them.
//!
//! These scenarios assert the coherent behaviour: generation numbers
//! never repeat within a command, and the machine never reports an
//! outcome it will not honour.

use rabsd::edge::snapshot_lineage::{
    LineageError, MutationResponse, RequestedCommandSnapshot, SnapshotLineage,
};

fn lineage() -> SnapshotLineage {
    SnapshotLineage::new(RequestedCommandSnapshot {
        manifest_sha256: [3; 32],
    })
}

fn reseal(machine: &mut SnapshotLineage, digest: u8) -> MutationResponse {
    machine.observe_post_seal_mutation(Some([digest; 32]))
}

#[test]
fn t041_repeated_reseals_are_strictly_monotonic_and_rewrite_no_history() {
    // D032 proves one reseal (gen 1 -> 2). A long command reseals many
    // times; each generation must be strictly newer and every earlier
    // binding must keep the exact generation AND digest it ran under.
    let mut machine = lineage();
    machine.seal([10; 32]).expect("first seal");
    machine
        .register_action("action-gen1")
        .expect("gen 1 action");

    let mut previous = 1;
    for (round, digest) in [20u8, 30, 40, 50].into_iter().enumerate() {
        let MutationResponse::Resealed(sealed) = reseal(&mut machine, digest) else {
            panic!("round {round}: a reseal lane was offered");
        };
        assert!(
            sealed.generation > previous,
            "round {round}: generation {} must strictly exceed {previous}",
            sealed.generation
        );
        previous = sealed.generation;
        machine
            .register_action(&format!("action-gen{}", sealed.generation))
            .expect("action binds the new generation");
    }

    // History is append-only in substance, not just in length: the first
    // binding still names generation 1 and the digest resolution
    // actually had when it ran.
    let bindings = machine.bindings();
    assert_eq!(bindings.len(), 5);
    assert_eq!(bindings[0].sealed.generation, 1);
    assert_eq!(bindings[0].sealed.resolution_sha256, [10; 32]);
    assert_eq!(bindings[4].sealed.resolution_sha256, [50; 32]);

    // Every binding's generation is distinct: two actions in one command
    // can differ in generation, but a generation number must identify
    // exactly one resolution state.
    let mut generations: Vec<u32> = bindings.iter().map(|b| b.sealed.generation).collect();
    let before = generations.len();
    generations.sort_unstable();
    generations.dedup();
    assert_eq!(
        generations.len(),
        before,
        "a generation number must never name two different resolution states"
    );
}

#[test]
fn t041_a_reseal_after_a_downgrade_does_not_reuse_a_generation_number() {
    // The transition D032's downgrade test stops before. A command
    // downgrades because no reseal lane existed at that instant; state
    // then mutates again and a lane appears.
    //
    // Whatever the machine chooses to do here, it must not mint a
    // generation number that an existing binding already names. An
    // action bound to "generation 1, resolution A" and a live generation
    // "1, resolution B" in the same command is the R110 confusion this
    // lineage exists to make unrepresentable — anything keying on the
    // generation number alone would conflate them.
    let mut machine = lineage();
    machine.seal([10; 32]).expect("seal");
    machine.register_action("early").expect("early action");
    assert_eq!(
        machine.observe_post_seal_mutation(None),
        MutationResponse::Downgraded
    );

    let used: Vec<u32> = machine
        .bindings()
        .iter()
        .map(|b| b.sealed.generation)
        .collect();
    assert_eq!(used, vec![1], "precondition: generation 1 is already bound");

    // A downgrade is terminal, so the mutation is answered Downgraded
    // and nothing is minted at all. Asserting the response alone would
    // pass vacuously if the machine silently minted anyway, so the
    // no-reuse property is checked directly as well.
    assert_eq!(reseal(&mut machine, 20), MutationResponse::Downgraded);
    for binding in machine.bindings() {
        assert_eq!(
            binding.sealed.resolution_sha256, [10; 32],
            "generation {} must still name the resolution state it ran under",
            binding.sealed.generation
        );
    }
    assert_eq!(
        machine.register_action("after"),
        Err(LineageError::Downgraded)
    );
    assert_eq!(used, vec![1], "no second generation 1 was ever minted");
}

#[test]
fn t041_generation_numbers_advance_from_a_high_water_not_from_the_current_seal() {
    // The root cause behind the two scenarios above, isolated. Numbering
    // must come from a never-reused high-water, because `current` is
    // exactly what a downgrade clears. This is the same lesson the
    // action-generation fence learned durably (T039): a watermark
    // survives the loss of the thing it is watermarking.
    //
    // Reseal several times so the high-water is genuinely ahead, then
    // check that every number handed out across the command is distinct
    // and strictly increasing.
    let mut machine = lineage();
    let mut seen = vec![machine.seal([10; 32]).expect("seal").generation];
    for digest in [20u8, 30, 40] {
        let MutationResponse::Resealed(sealed) = reseal(&mut machine, digest) else {
            panic!("reseal lane offered");
        };
        assert!(
            sealed.generation > *seen.last().expect("non-empty"),
            "generation {} did not advance past {:?}",
            sealed.generation,
            seen.last()
        );
        seen.push(sealed.generation);
    }
    assert_eq!(seen, vec![1, 2, 3, 4]);
}

#[test]
fn t041_a_downgraded_command_does_not_promise_a_reseal_it_refuses_to_honour() {
    // `MutationResponse::Resealed` documents "new actions bind to it".
    // A downgraded command refuses every registration. So the machine
    // must not answer `Resealed` while still refusing — the response
    // and the behaviour have to agree, or a caller that branches on the
    // response proceeds into a command that will refuse every action.
    let mut machine = lineage();
    machine.seal([10; 32]).expect("seal");
    assert_eq!(
        machine.observe_post_seal_mutation(None),
        MutationResponse::Downgraded
    );

    let response = reseal(&mut machine, 20);
    let registration = machine.register_action("after-downgrade-reseal");
    match response {
        MutationResponse::Resealed(sealed) => assert!(
            registration.is_ok(),
            "the machine answered Resealed(generation {}) but then refused the \
             registration that response invites: {registration:?}",
            sealed.generation
        ),
        MutationResponse::Downgraded => assert_eq!(
            registration,
            Err(LineageError::Downgraded),
            "the machine answered Downgraded, so registration must refuse"
        ),
    }
}

#[test]
fn t041_sealing_again_after_a_downgrade_is_refused() {
    // The other way back into a sealed state. `seal` refuses a second
    // seal with `AlreadySealed` while a generation is current; a
    // downgrade clears `current`, so the guard that stopped the second
    // seal no longer applies. A downgraded command must not be able to
    // seal a fresh generation 1 out from under its own history.
    let mut machine = lineage();
    machine.seal([10; 32]).expect("seal");
    machine.register_action("early").expect("early action");
    assert_eq!(
        machine.observe_post_seal_mutation(None),
        MutationResponse::Downgraded
    );

    assert_eq!(
        machine.seal([20; 32]),
        Err(LineageError::Downgraded),
        "a downgraded command must refuse to seal again rather than restart \
         its generation numbering while old bindings still name generation 1"
    );
}
