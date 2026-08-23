//! The lifecycle shadow comparator (bead J016; plan §102's M7 gate;
//! risk R63/R64).
//!
//! Runs the ATP control plane IN SHADOW alongside the existing RCH
//! control path: the daemon's lifecycle event stream (`build_queued`,
//! `build_started`, `cancellation_requested`, `build_completed`,
//! `build_heartbeat` — the EventBus JSON-line schema) is translated to
//! J012's `RabsMessage` catalog, folded through the pure
//! [`SessionState`] decision function, and each ATP-plane outcome is
//! compared against the outcome RCH semantics require. ANY mismatch is
//! a disagreement row; M7 promotion requires a soak with ZERO rows.
//!
//! ## Where expectations come from
//!
//! The expected outcome for every step encodes documented RCH behavior,
//! which J012 proved maps 1:1 onto the catalog idempotency rules:
//! a build id cannot start twice (re-dispatch joins/returns existing),
//! cancelling an already-cancelled or finished build is a no-op ack,
//! and an authority term ratchet rejects stale messages before any
//! state moves. The comparator therefore fails LOUD on semantic drift
//! in either plane — never silently normalizes it.
use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::durable_ids::{BuildOperationId, DurableWireIdentity};
use rabs_protocol::generation::{ActionGenerationId, AttemptId, ExecutionLeaseId};
use rabs_protocol::messages::{HandlerOutcome, RabsMessage, SessionState};

/// The lifecycle events the comparator understands. Anything else on
/// the bus is ignored (the stream carries ops-domain noise too).
pub const KNOWN_EVENTS: [&str; 5] = [
    "build_queued",
    "build_started",
    "cancellation_requested",
    "build_completed",
    "build_heartbeat",
];

/// One parsed EventBus JSON line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RchLifecycleEvent {
    /// Event name (`build_started`, ...).
    pub name: String,
    /// Build id from the payload (absent for heartbeats without one).
    pub build_id: Option<u64>,
}

/// A parse/translation failure with the offending line number (1-based).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslateError {
    /// 1-based index of the offending line.
    pub line: usize,
    /// What was wrong.
    pub detail: String,
}

/// One translated shadow step: the ATP message plus the outcome RCH
/// semantics REQUIRE at that point in the trace.
#[derive(Debug, Clone)]
pub struct ShadowStep {
    /// Human label tying the step back to its source event.
    pub label: String,
    /// The message handed to the ATP fold.
    pub message: RabsMessage,
    /// Authority term this message travels under.
    pub term: u64,
    /// The required outcome.
    pub expected: HandlerOutcome,
}

/// Build the durable identity tuple for a build id (shadow tier mints
/// generation/attempt/lease deterministically from the id so replays
/// of the same build collide on exactly the same tuple).
#[must_use]
fn identity(build_id: u64) -> DurableWireIdentity {
    let op = u128::from(build_id);
    DurableWireIdentity {
        operation: BuildOperationId(op),
        generation: ActionGenerationId(1),
        attempt: AttemptId(1),
        lease: ExecutionLeaseId(1),
    }
}

fn parse_event(line: &str, line_no: usize) -> Result<Option<RchLifecycleEvent>, TranslateError> {
    let value: serde_json::Value = serde_json::from_str(line).map_err(|e| TranslateError {
        line: line_no,
        detail: format!("not JSON: {e}"),
    })?;
    let name = value
        .get("event")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TranslateError {
            line: line_no,
            detail: "missing event name".to_owned(),
        })?
        .to_owned();
    if !KNOWN_EVENTS.contains(&name.as_str()) {
        return Ok(None);
    }
    let build_id = value
        .pointer("/data/build_id")
        .and_then(serde_json::Value::as_u64);
    Ok(Some(RchLifecycleEvent { name, build_id }))
}

/// Stateful EventBus-stream translator. The seen-id sets persist
/// across calls so a soak (or a live tail) keeps emitting the RIGHT
/// expectation for duplicates however the stream is chunked.
#[derive(Debug, Clone, Default)]
pub struct LifecycleTranslator {
    queued: std::collections::HashSet<u64>,
    started: std::collections::HashSet<u64>,
    cancelled: std::collections::HashSet<u64>,
    /// Authority term stamped on every translated message. Ratches up
    /// as the coordinator's term advances (`set_term`).
    current_term: u64,
}

impl LifecycleTranslator {
    /// Fresh translator with empty seen-id sets under term 1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queued: std::collections::HashSet::new(),
            started: std::collections::HashSet::new(),
            cancelled: std::collections::HashSet::new(),
            current_term: 1,
        }
    }

    /// Ratchet the authority term future messages travel under.
    pub fn set_term(&mut self, term: u64) {
        self.current_term = self.current_term.max(term);
    }

    /// Translate one JSON line at line number `line_no`; `Ok(None)`
    /// for ignored events.
    ///
    /// # Errors
    /// [`TranslateError`] on malformed lines (never silently skipped).
    pub fn translate_line(
        &mut self,
        line_no: usize,
        line: &str,
    ) -> Result<Option<ShadowStep>, TranslateError> {
        let Some(event) = parse_event(line, line_no)? else {
            return Ok(None);
        };
        let Some(build_id) = event.build_id else {
            return Ok(None);
        };
        let label = format!("{}#{}", event.name, build_id);
        let step = match event.name.as_str() {
            "build_queued" => {
                let first = self.queued.insert(build_id);
                ShadowStep {
                    label,
                    message: RabsMessage::SubmitAction {
                        identity: identity(build_id),
                        idempotency_key: u128::from(build_id),
                    },
                    term: self.current_term,
                    expected: if first {
                        HandlerOutcome::Created
                    } else {
                        HandlerOutcome::JoinedExisting
                    },
                }
            }
            "build_started" => {
                let first = self.started.insert(build_id);
                ShadowStep {
                    label,
                    message: RabsMessage::AcceptLease {
                        identity: identity(build_id),
                    },
                    term: self.current_term,
                    expected: if first {
                        HandlerOutcome::Created
                    } else {
                        HandlerOutcome::ReturnedExisting
                    },
                }
            }
            "cancellation_requested" => {
                let first = self.cancelled.insert(build_id);
                ShadowStep {
                    label,
                    message: RabsMessage::CancelAttempt {
                        identity: identity(build_id),
                    },
                    term: self.current_term,
                    expected: if first {
                        HandlerOutcome::Created
                    } else {
                        HandlerOutcome::AlreadyDone
                    },
                }
            }
            "build_completed" => ShadowStep {
                label,
                message: RabsMessage::AttemptEvent {
                    identity: identity(build_id),
                    event_seq: build_id,
                },
                term: self.current_term,
                expected: HandlerOutcome::Created,
            },
            // Heartbeats carry no decision; kept for schema completeness.
            _ => return Ok(None),
        };
        Ok(Some(step))
    }

    /// Translate a whole slice of lines in order.
    ///
    /// # Errors
    /// [`TranslateError`] on malformed lines (never silently skipped).
    pub fn translate_lines(&mut self, lines: &[String]) -> Result<Vec<ShadowStep>, TranslateError> {
        let mut steps = Vec::new();
        for (idx, line) in lines.iter().enumerate() {
            if let Some(step) = self.translate_line(idx + 1, line)? {
                steps.push(step);
            }
        }
        Ok(steps)
    }
}

/// Translate an EventBus JSON-line stream into shadow steps.
///
/// Events without a build id (heartbeats) are skipped — they carry no
/// lifecycle decision. Duplicate queue/start/cancel of the same build
/// id translate to the SAME message again, whose expected outcome
/// flips per the catalog's idempotency rules (that flip IS the shadow
/// comparison for reconnect/replay scenarios).
///
/// # Errors
/// [`TranslateError`] on malformed lines (never silently skipped).
pub fn translate_rch_events(lines: &[String]) -> Result<Vec<ShadowStep>, TranslateError> {
    let mut translator = LifecycleTranslator::new();
    translator.translate_lines(lines)
}

/// One lifecycle disagreement between the planes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisagreementRow {
    /// The step label (source event).
    pub step: String,
    /// Outcome RCH semantics require.
    pub expected: HandlerOutcome,
    /// Outcome the ATP fold produced.
    pub actual: HandlerOutcome,
}

/// The full comparison result for one trace (or a whole soak).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DisagreementReport {
    /// Steps compared.
    pub steps_compared: usize,
    /// Mismatches, in trace order.
    pub rows: Vec<DisagreementRow>,
}

impl DisagreementReport {
    /// M7's gate: zero lifecycle disagreement.
    #[must_use]
    pub const fn zero_disagreement(&self) -> bool {
        self.rows.is_empty()
    }

    /// NDJSON corpus line for each disagreement row
    /// (`rabs.shadow-lifecycle-disagreement` v1).
    #[must_use]
    pub fn to_ndjson(&self) -> Vec<String> {
        self.rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "schema": "rabs.shadow-lifecycle-disagreement",
                    "schema_version": 1,
                    "step": row.step,
                    "expected": format!("{:?}", row.expected),
                    "actual": format!("{:?}", row.actual),
                })
                .to_string()
            })
            .collect()
    }
}

/// Fold the steps through the ATP session state and compare every
/// outcome against the expectation.
#[must_use]
pub fn compare(steps: &[ShadowStep]) -> DisagreementReport {
    let mut state = SessionState::default();
    let mut report = DisagreementReport {
        steps_compared: steps.len(),
        rows: Vec::new(),
    };
    for step in steps {
        let actual = state.handle(&step.message, step.term);
        if actual != step.expected {
            report.rows.push(DisagreementRow {
                step: step.label.clone(),
                expected: step.expected,
                actual,
            });
        }
    }
    report
}

/// Convenience: translate + compare in one call.
///
/// # Errors
/// [`TranslateError`] from the translation pass.
pub fn compare_rch_stream(lines: &[String]) -> Result<DisagreementReport, TranslateError> {
    Ok(compare(&translate_rch_events(lines)?))
}

/// An authority bump injected into a soak scenario (term ratchets up;
/// messages under older terms must then fail closed).
#[derive(Debug, Clone, Copy)]
pub struct AuthorityBump {
    /// New current term.
    pub new_term: u64,
}

/// Extend a step list with an explicit authority update + one stale
/// probe message, encoding the fail-closed contract.
pub fn push_authority_bump(steps: &mut Vec<ShadowStep>, bump: AuthorityBump, probe_build: u64) {
    steps.push(ShadowStep {
        label: format!("authority_update#{}", bump.new_term),
        message: RabsMessage::AuthorityUpdate {
            authority: CoordinatorAuthority {
                cluster_id: ClusterId("shadow-cluster".to_owned()),
                credential_generation: 1,
                term: bump.new_term,
                incarnation_id: CoordinatorIncarnationId(0x5EED),
            },
        },
        term: bump.new_term,
        expected: HandlerOutcome::Created,
    });
    steps.push(ShadowStep {
        label: format!("stale_submit#{probe_build}"),
        message: RabsMessage::SubmitAction {
            identity: identity(probe_build),
            idempotency_key: u128::from(probe_build),
        },
        term: bump.new_term - 1,
        expected: HandlerOutcome::RejectedStaleAuthority,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(event: &str, build_id: u64) -> String {
        serde_json::json!({
            "event": event,
            "data": {"build_id": build_id},
            "timestamp": "2026-08-23T00:00:00Z",
        })
        .to_string()
    }

    #[test]
    fn j016_canonical_lifecycle_has_zero_disagreement() {
        let lines = [
            line("build_queued", 42),
            line("build_started", 42),
            line("build_heartbeat", 42), // no decision
            line("build_completed", 42),
        ];
        let report = compare_rch_stream(&lines).unwrap();
        assert_eq!(report.steps_compared, 3); // heartbeat skipped
        assert!(report.zero_disagreement());
        assert!(report.to_ndjson().is_empty());
    }

    #[test]
    fn j016_requeue_and_redispatch_join_existing_state() {
        let lines = [
            line("build_queued", 7),
            line("build_queued", 7), // replay: JOIN
            line("build_started", 7),
            line("build_started", 7), // re-dispatch: RETURN EXISTING
            line("build_completed", 7),
        ];
        let report = compare_rch_stream(&lines).unwrap();
        assert!(report.zero_disagreement(), "{:?})", report.rows);
    }

    #[test]
    fn j016_double_cancel_is_a_noop_ack_on_both_planes() {
        let lines = [
            line("build_queued", 9),
            line("cancellation_requested", 9),
            line("cancellation_requested", 9), // AlreadyDone
            line("build_started", 9),
            line("build_completed", 9),
        ];
        let report = compare_rch_stream(&lines).unwrap();
        assert!(report.zero_disagreement(), "{:?}", report.rows);
    }

    #[test]
    fn j016_stale_authority_fails_closed_in_shadow() {
        let mut steps = translate_rch_events(&[line("build_queued", 5)]).unwrap();
        push_authority_bump(&mut steps, AuthorityBump { new_term: 3 }, 6);
        let report = compare(&steps);
        assert!(report.zero_disagreement(), "{:?}", report.rows);
        // And the stale submit REALLY did not touch state: resubmitting
        // under the CURRENT term creates fresh (probe id never used).
        let mut steps2 = steps.clone();
        steps2.push(ShadowStep {
            label: "current_term_submit#6".to_owned(),
            message: RabsMessage::SubmitAction {
                identity: identity(6),
                idempotency_key: 6,
            },
            term: 3,
            expected: HandlerOutcome::Created,
        });
        assert!(compare(&steps2).zero_disagreement());
    }

    #[test]
    fn j016_semantic_drift_produces_a_named_disagreement_row() {
        // Simulate drift: claim a duplicate start should be Created.
        let lines = [line("build_started", 11), line("build_started", 11)];
        let mut steps = translate_rch_events(&lines).unwrap();
        steps[1].expected = HandlerOutcome::Created;
        let report = compare(&steps);
        assert!(!report.zero_disagreement());
        assert_eq!(report.rows.len(), 1);
        assert_eq!(report.rows[0].step, "build_started#11");
        assert_eq!(report.rows[0].expected, HandlerOutcome::Created);
        assert_eq!(report.rows[0].actual, HandlerOutcome::ReturnedExisting);
        let ndjson = report.to_ndjson();
        assert_eq!(ndjson.len(), 1);
        assert!(ndjson[0].contains("rabs.shadow-lifecycle-disagreement"));
    }

    #[test]
    fn j016_malformed_lines_are_typed_errors_never_skipped() {
        let err = compare_rch_stream(&["{not json".to_owned()]).unwrap_err();
        assert_eq!(err.line, 1);
        let err = compare_rch_stream(&[
            "{\"event\": \"build_queued\", \"data\": {\"build_id\": 1}}".to_owned(),
            "{\"no_event_name\": true}".to_owned(),
        ])
        .unwrap_err();
        assert_eq!(err.line, 2);
    }

    #[test]
    fn j016_unknown_events_are_ignored_by_schema_contract() {
        let lines = [
            serde_json::json!({"event": "process_triage.pipeline_started", "data": {}}).to_string(),
            line("build_queued", 3),
        ];
        let report = compare_rch_stream(&lines).unwrap();
        assert_eq!(report.steps_compared, 1);
        assert!(report.zero_disagreement());
    }

    #[test]
    fn j016_shadow_soak_zero_disagreement_across_generated_traces() {
        // Deterministic soak: seeded LCG drives interleavings of the
        // full lifecycle vocabulary over many builds, including
        // duplicates, out-of-order starts after cancel, completion
        // tails, and periodic authority bumps with stale probes.
        let mut rng: u64 = 0x5EED_2026_0823;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut translator = LifecycleTranslator::new();
        let mut live_builds: Vec<u64> = Vec::new();
        let mut all_steps: Vec<ShadowStep> = Vec::new();
        let mut next_build = 1_u64;
        let bumps_at: std::collections::HashSet<usize> = [250, 900, 2000].into_iter().collect();
        for step_no in 0..3_000 {
            if bumps_at.contains(&step_no) {
                let new_term = (step_no / 250) as u64 + 1;
                translator.set_term(new_term);
                push_authority_bump(
                    &mut all_steps,
                    AuthorityBump { new_term },
                    100_000 + step_no as u64,
                );
                continue;
            }
            let roll = next() % 100;
            match roll {
                0..=29 => {
                    // Queue a fresh build.
                    let id = 10_000 + next_build;
                    next_build += 1;
                    live_builds.push(id);
                    if let Some(step) = translator
                        .translate_line(step_no, &line("build_queued", id))
                        .unwrap()
                    {
                        all_steps.push(step);
                    }
                }
                30..=54 => {
                    // Start a random queued build (duplicate starts allowed).
                    if let Some(&id) = live_builds.first() {
                        if let Some(step) = translator
                            .translate_line(step_no, &line("build_started", id))
                            .unwrap()
                        {
                            all_steps.push(step);
                        }
                    }
                }
                55..=69 => {
                    // Cancel a random build (possibly already cancelled).
                    if let Some(&id) = live_builds.last() {
                        if let Some(step) = translator
                            .translate_line(step_no, &line("cancellation_requested", id))
                            .unwrap()
                        {
                            all_steps.push(step);
                        }
                    }
                }
                70..=84 => {
                    // Complete + retire a random build.
                    if let Some(id) = live_builds.pop() {
                        if let Some(step) = translator
                            .translate_line(step_no, &line("build_completed", id))
                            .unwrap()
                        {
                            all_steps.push(step);
                        }
                    }
                }
                85..=94 => {
                    // Heartbeat noise: no decision either plane.
                    let id = live_builds.first().copied().unwrap_or(1);
                    assert!(
                        translator
                            .translate_line(step_no, &line("build_heartbeat", id))
                            .unwrap()
                            .is_none()
                    );
                }
                _ => {
                    // Duplicate queue of an existing build (JOIN).
                    if let Some(&id) = live_builds.first() {
                        if let Some(step) = translator
                            .translate_line(step_no, &line("build_queued", id))
                            .unwrap()
                        {
                            all_steps.push(step);
                        }
                    }
                }
            }
        }
        assert!(all_steps.len() > 2_000, "soak generated too few steps");
        let report = compare(&all_steps);
        assert!(
            report.zero_disagreement(),
            "soak disagreements: {:?}",
            report.rows.first()
        );
    }
}
