//! Deferred proof replay conveyor — end-to-end lifecycle + golden shape
//! (bd-session-history-remediation-ocv9i.5.3).
//!
//! Drives the conveyor state machine through the four mandated recovery
//! scenarios using the real durable store, and pins the agent-facing
//! published-state JSON shape so a renamed field or changed token is caught.
//!
//! Scenarios (from the bead):
//!   1. recovery after disk pressure
//!   2. source changed while queued
//!   3. capability still missing
//!   4. worker becomes eligible after canary rejoin
//!
//! Plus the cross-cutting guarantees: replay never bypasses a safety block,
//! replay never starves interactive work (concurrency cap + FIFO fairness), and
//! terminal states are never resurrected.

use rch_common::disk_pressure_report::ExecFailureClass;
use rch_common::incident::IncidentReasonCode;
use rch_common::proof_intent::{
    ProofIntent, ReplayConstraints, ReplayContext, ReplayDecision, SourceFingerprint,
    StaleSourcePolicy, validate_replay,
};
use rch_common::proof_replay::{
    ConveyorScanItem, ConveyorSignals, ProofReplayRecord, ProofReplayStateStore, ProofState,
    ReplayOutcome, decide, plan_scan, proof_replay_schema_version,
};
use rch_common::readiness::DecisiveBlocker;
use serde_json::{Value, json};

/// A representative intent for a real `cargo test` proof at rev-1.
fn sample_intent() -> ProofIntent {
    ProofIntent::new(
        "blake3:cargo-test-digest",
        "/data/projects/remote_compilation_helper",
        Some("rev-1".to_string()),
        "pooled",
        IncidentReasonCode::ProofRefusal,
        StaleSourcePolicy::RejectIfChanged,
        ReplayConstraints {
            require_same_revision: true,
            require_unchanged_sources: true,
            max_age_secs: Some(86_400),
        },
        1_700_000_000_000,
    )
    .with_source_fingerprints(vec![SourceFingerprint {
        path: "rch-common/src/lib.rs".to_string(),
        blake3: "abc123".to_string(),
    }])
}

fn unchanged_ctx() -> ReplayContext {
    ReplayContext {
        current_revision: Some("rev-1".to_string()),
        current_fingerprints: vec![SourceFingerprint {
            path: "rch-common/src/lib.rs".to_string(),
            blake3: "abc123".to_string(),
        }],
        age_secs: 60,
    }
}

// =============================================================================
// Scenario 1 — recovery after disk pressure
// =============================================================================

#[test]
fn e2e_proof_replay_recovers_after_disk_pressure() {
    let dir = tempfile::tempdir().unwrap();
    let store = ProofReplayStateStore::with_path(dir.path().join("replay.jsonl"));
    let intent = sample_intent();

    // Recorded → queued.
    let rec = ProofReplayRecord::queued(&intent.intent_id, intent.recorded_at_unix_ms);
    store.put(&rec).unwrap();

    // Scan under critical pressure: held queued, NOT replayed.
    let pressured = ConveyorSignals {
        replay: validate_replay(&intent, &unchanged_ctx()),
        blocker: DecisiveBlocker::PressureBlocked,
        replay_capacity_available: true,
    };
    let d1 = decide(rec.state, &pressured);
    let rec = rec.apply(&d1, 1_700_000_100_000);
    store.put(&rec).unwrap();
    assert_eq!(rec.state, ProofState::Queued);
    assert_eq!(rec.last_reason, Some(IncidentReasonCode::CriticalPressure));
    assert_eq!(rec.attempts, 0);

    // Pressure clears → ready with capacity → replays.
    let ready = ConveyorSignals {
        replay: validate_replay(&intent, &unchanged_ctx()),
        blocker: DecisiveBlocker::None,
        replay_capacity_available: true,
    };
    let d2 = decide(rec.state, &ready);
    assert!(d2.attempt_replay);
    let rec = rec.apply(&d2, 1_700_000_200_000);
    store.put(&rec).unwrap();
    assert_eq!(rec.state, ProofState::Replaying);
    assert_eq!(rec.attempts, 1);

    // Replay succeeds → passed (terminal).
    let rec = rec.resolve(ReplayOutcome::Succeeded, 1_700_000_300_000);
    store.put(&rec).unwrap();
    assert_eq!(rec.state, ProofState::Passed);

    // Store reflects exactly one record at its latest (terminal) state.
    let all = store.all();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].state, ProofState::Passed);
    assert_eq!(store.census().get("passed"), Some(&1));
}

// =============================================================================
// Scenario 2 — source changed while queued
// =============================================================================

#[test]
fn e2e_proof_replay_source_changed_while_queued_goes_stale() {
    let intent = sample_intent();
    let rec = ProofReplayRecord::queued(&intent.intent_id, intent.recorded_at_unix_ms);

    // Source mutated since the intent was recorded.
    let changed_ctx = ReplayContext {
        current_revision: Some("rev-1".to_string()),
        current_fingerprints: vec![SourceFingerprint {
            path: "rch-common/src/lib.rs".to_string(),
            blake3: "DIFFERENT".to_string(),
        }],
        age_secs: 60,
    };
    // Even a perfectly healthy fleet with spare capacity must NOT replay.
    let signals = ConveyorSignals {
        replay: validate_replay(&intent, &changed_ctx),
        blocker: DecisiveBlocker::None,
        replay_capacity_available: true,
    };
    let d = decide(rec.state, &signals);
    assert!(!d.attempt_replay, "stale source must never replay");
    let rec = rec.apply(&d, 1_700_000_100_000);
    assert_eq!(rec.state, ProofState::Stale);
    assert!(rec.last_detail.contains("fingerprint") || rec.last_detail.contains("source"));

    // Stale is terminal — a later healthy scan cannot resurrect it.
    let healthy_again = decide(rec.state, &ConveyorSignals::ready());
    let after = rec.apply(&healthy_again, 1_700_000_200_000);
    assert_eq!(after.state, ProofState::Stale, "stale is terminal");
}

// =============================================================================
// Scenario 3 — capability still missing
// =============================================================================

#[test]
fn e2e_proof_replay_capability_still_missing_stays_blocked() {
    let intent = sample_intent();
    let rec = ProofReplayRecord::queued(&intent.intent_id, intent.recorded_at_unix_ms);

    let no_capability = ConveyorSignals {
        replay: validate_replay(&intent, &unchanged_ctx()),
        blocker: DecisiveBlocker::NoCommandCapability,
        replay_capacity_available: true,
    };
    // Repeated scans while the capability gap persists keep it Blocked, never
    // replaying, never counting an attempt.
    let mut rec = rec;
    for tick in 0..3 {
        let d = decide(rec.state, &no_capability);
        assert!(!d.attempt_replay);
        rec = rec.apply(&d, 1_700_000_100_000 + tick);
        assert_eq!(rec.state, ProofState::Blocked);
        assert_eq!(
            rec.last_reason,
            Some(IncidentReasonCode::MissingRuntimeToolchainTarget)
        );
        assert_eq!(rec.attempts, 0);
    }

    // When the capability finally returns, a blocked intent can replay.
    let d = decide(rec.state, &ConveyorSignals::ready());
    assert!(d.attempt_replay);
    let rec = rec.apply(&d, 1_700_000_200_000);
    assert_eq!(rec.state, ProofState::Replaying);
}

// =============================================================================
// Scenario 4 — worker becomes eligible after canary rejoin
// =============================================================================

#[test]
fn e2e_proof_replay_worker_eligible_after_canary_rejoin() {
    let intent = sample_intent();
    let mut rec = ProofReplayRecord::queued(&intent.intent_id, intent.recorded_at_unix_ms);

    // No healthy workers yet (the fleet is down / draining).
    let no_healthy = ConveyorSignals {
        replay: validate_replay(&intent, &unchanged_ctx()),
        blocker: DecisiveBlocker::NoHealthyWorkers,
        replay_capacity_available: true,
    };
    let d = decide(rec.state, &no_healthy);
    rec = rec.apply(&d, 1_700_000_100_000);
    assert_eq!(rec.state, ProofState::Queued);
    assert!(rec.last_detail.contains("canary rejoin"));

    // A canary worker rejoins and becomes admissible for the command.
    let d = decide(rec.state, &ConveyorSignals::ready());
    assert!(d.attempt_replay);
    rec = rec.apply(&d, 1_700_000_200_000);
    assert_eq!(rec.state, ProofState::Replaying);

    // The product itself fails this time → Failed (terminal, not retried).
    let failed = rec.resolve(
        ReplayOutcome::classify(false, ExecFailureClass::ProductCompile),
        1_700_000_300_000,
    );
    assert_eq!(failed.state, ProofState::Failed);
    let revived = decide(failed.state, &ConveyorSignals::ready());
    assert_eq!(
        failed.apply(&revived, 1_700_000_400_000).state,
        ProofState::Failed,
        "a failed product proof is terminal"
    );
}

// =============================================================================
// Cross-cutting — anti-starvation + safety in a multi-intent scan
// =============================================================================

#[test]
fn e2e_proof_replay_scan_is_fair_and_safe_under_mixed_signals() {
    let mk = |id: &str, recorded: u64, blocker: DecisiveBlocker, cap: bool| ConveyorScanItem {
        intent_id: id.to_string(),
        current_state: ProofState::Queued,
        signals: ConveyorSignals {
            replay: ReplayDecision::Replayable,
            blocker,
            replay_capacity_available: cap,
        },
        recorded_at_unix_ms: recorded,
    };

    let items = vec![
        mk("pi-old-ready", 1_000, DecisiveBlocker::None, true),
        mk("pi-mid-ready", 2_000, DecisiveBlocker::None, true),
        mk("pi-new-ready", 3_000, DecisiveBlocker::None, true),
        mk(
            "pi-pressured",
            1_500,
            DecisiveBlocker::PressureBlocked,
            true,
        ),
        mk(
            "pi-no-cap",
            1_800,
            DecisiveBlocker::NoCommandCapability,
            true,
        ),
    ];

    // Capacity for only ONE replay this scan.
    let plan = plan_scan(&items, 1);
    let find = |id: &str| {
        plan.iter()
            .find(|r| r.intent_id == id)
            .unwrap()
            .decision
            .clone()
    };

    // Exactly one replay, and it is the OLDEST ready intent (fairness).
    let replaying: Vec<&str> = plan
        .iter()
        .filter(|r| r.decision.attempt_replay)
        .map(|r| r.intent_id.as_str())
        .collect();
    assert_eq!(replaying, vec!["pi-old-ready"]);

    // The other ready ones are deferred for fairness, not failed.
    assert_eq!(find("pi-mid-ready").next_state, ProofState::Queued);
    assert_eq!(
        find("pi-mid-ready").reason,
        Some(IncidentReasonCode::InsufficientSlots)
    );

    // Safety blocks are honored regardless of capacity.
    assert_eq!(find("pi-pressured").next_state, ProofState::Queued);
    assert_eq!(find("pi-no-cap").next_state, ProofState::Blocked);
}

// =============================================================================
// Golden — pinned published-state JSON shape (what `rch proof status` emits)
// =============================================================================

#[test]
fn e2e_proof_replay_record_json_shape_is_pinned() {
    let intent = sample_intent();
    // Drive: queued -> replaying -> passed, so the record carries an attempt.
    let rec = ProofReplayRecord::queued("pi-fixed", 1_700_000_000_000);
    let replaying = rec.apply(
        &decide(rec.state, &ConveyorSignals::ready()),
        1_700_000_001_000,
    );
    let passed = replaying.resolve(ReplayOutcome::Succeeded, 1_700_000_002_000);
    let _ = &intent;

    let actual: Value = serde_json::to_value(&passed).unwrap();
    let expected = json!({
        "schema_version": proof_replay_schema_version(),
        "intent_id": "pi-fixed",
        "recorded_at_unix_ms": 1_700_000_000_000u64,
        "state": "passed",
        "attempts": 1,
        "last_detail": "replay succeeded remotely; proof passed",
        "updated_at_unix_ms": 1_700_000_002_000u64,
    });
    assert_eq!(
        actual,
        expected,
        "published proof-replay record shape drifted; if intentional, update this golden.\nactual:\n{}",
        serde_json::to_string_pretty(&actual).unwrap()
    );
    // A passed/failed record carries no `last_reason` (no incident).
    assert!(actual.get("last_reason").is_none());
    // Round-trips.
    let back: ProofReplayRecord = serde_json::from_value(actual).unwrap();
    assert_eq!(back, passed);
}

#[test]
fn e2e_proof_replay_blocked_record_carries_reason_code() {
    let mut sig = ConveyorSignals::ready();
    sig.blocker = DecisiveBlocker::NoCommandCapability;
    let rec = ProofReplayRecord::queued("pi-blk", 1_700_000_000_000)
        .apply(&decide(ProofState::Queued, &sig), 1_700_000_001_000);
    let actual: Value = serde_json::to_value(&rec).unwrap();
    assert_eq!(actual["state"], "blocked");
    // The decisive incident reason is the stable RCH-Innn code string.
    assert_eq!(actual["last_reason"], "RCH-I006");
}

#[test]
fn e2e_proof_replay_advance_drives_recovery_through_the_store() {
    use std::collections::BTreeMap;

    let dir = tempfile::tempdir().unwrap();
    let store = ProofReplayStateStore::with_path(dir.path().join("replay.jsonl"));
    let intent = sample_intent();

    // Seed a queued intent.
    store
        .put(&ProofReplayRecord::queued(
            &intent.intent_id,
            intent.recorded_at_unix_ms,
        ))
        .unwrap();

    // Tick 1: fleet is pressured -> stays queued, nothing replays.
    let mut pressured: BTreeMap<String, ConveyorSignals> = BTreeMap::new();
    pressured.insert(
        intent.intent_id.clone(),
        ConveyorSignals {
            replay: validate_replay(&intent, &unchanged_ctx()),
            blocker: DecisiveBlocker::PressureBlocked,
            replay_capacity_available: true,
        },
    );
    let r1 = store.advance(&pressured, 4, 1_700_000_100_000).unwrap();
    assert!(!r1[0].decision.attempt_replay);
    assert_eq!(
        store.get(&intent.intent_id).unwrap().state,
        ProofState::Queued
    );

    // Tick 2: pressure clears -> conveyor replays automatically.
    let mut ready: BTreeMap<String, ConveyorSignals> = BTreeMap::new();
    ready.insert(intent.intent_id.clone(), ConveyorSignals::ready());
    let r2 = store.advance(&ready, 4, 1_700_000_200_000).unwrap();
    assert!(r2[0].decision.attempt_replay);
    let replaying = store.get(&intent.intent_id).unwrap();
    assert_eq!(replaying.state, ProofState::Replaying);
    assert_eq!(replaying.attempts, 1);

    // The product succeeds: resolve to passed and persist.
    let passed = replaying.resolve(ReplayOutcome::Succeeded, 1_700_000_300_000);
    store.put(&passed).unwrap();

    // Tick 3: a terminal intent is never re-evaluated even if offered a signal.
    let r3 = store.advance(&ready, 4, 1_700_000_400_000).unwrap();
    assert!(r3.is_empty(), "terminal intent excluded from the conveyor");
    assert_eq!(store.census().get("passed"), Some(&1));
}

#[test]
fn e2e_proof_replay_all_six_states_have_stable_tokens() {
    let tokens: Vec<&str> = ProofState::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        tokens,
        vec![
            "queued",
            "blocked",
            "replaying",
            "passed",
            "failed",
            "stale"
        ]
    );
}
