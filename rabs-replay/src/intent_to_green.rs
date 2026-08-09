//! Intent-to-green reconstruction from agent session timelines (bead
//! B012; feeds the Q002 likely-next-command model).
//!
//! The north-star metric is not "how fast is one build" but "how fast
//! does an AGENT get from wanting a result to having it": an agent
//! loop is edit → check → check → test → GREEN, and the time that
//! matters spans the whole loop. This module stitches B002 corpus
//! records into those loops:
//!
//! - records group by repo (the redacted cwd — one agent loop lives in
//!   one working tree) and order by arrival time;
//! - a LOOP starts at the first invocation after a green state (or the
//!   session's first record) — that invocation is the observable proxy
//!   for "the agent formed an intent";
//! - the loop ends at the first invocation that exits 0 — GREEN — and
//!   intent-to-green is `green.end - loop_start.begin` (wall clock,
//!   from the recorded timestamps);
//! - a session that ends RED leaves an UNRESOLVED loop: counted and
//!   reported, never dropped — a corpus where half the loops never
//!   green is a finding, not noise;
//! - p50/p90/p95 come from the shared exact nearest-rank percentiles.
//!
//! Honest boundary: the full north-star DECOMPOSITION
//! (queueing/capture/key/lookup/transfer/execution/materialization/
//! notification/cancellation/retries) needs per-stage taps that do not
//! exist yet; the whole-loop figure is computable today and the stage
//! breakdown is typed [`MetricGroup::NotInstrumented`] naming the
//! missing source — same discipline as the B008 report.

use crate::ReplaySkip;
use crate::benchmark_report::{MetricGroup, Percentiles, percentiles};

/// One timeline event parsed from a corpus line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEvent {
    /// Repo identity (redacted cwd).
    pub repo: String,
    /// Arrival wall-clock (Unix ms).
    pub recorded_at_unix_ms: u64,
    /// Duration (ms).
    pub duration_ms: u64,
    /// Whether the invocation exited 0 (GREEN).
    pub green: bool,
}

/// Parse the timeline fields from one corpus line.
///
/// # Errors
/// [`ReplaySkip::MalformedRecord`] naming the missing field.
pub fn parse_timeline_event(line: &str) -> Result<TimelineEvent, ReplaySkip> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| ReplaySkip::MalformedRecord {
            detail: e.to_string(),
        })?;
    let repo = value["cwd_redacted"]
        .as_str()
        .ok_or_else(|| ReplaySkip::MalformedRecord {
            detail: "cwd_redacted missing".to_owned(),
        })?
        .to_owned();
    let recorded_at_unix_ms =
        value["recorded_at_unix_ms"]
            .as_u64()
            .ok_or_else(|| ReplaySkip::MalformedRecord {
                detail: "recorded_at_unix_ms missing".to_owned(),
            })?;
    Ok(TimelineEvent {
        repo,
        recorded_at_unix_ms,
        duration_ms: value["duration_ms"].as_u64().unwrap_or(0),
        green: value["outcome_kind"] == "exited" && value["outcome_value"] == 0,
    })
}

/// One reconstructed agent loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLoop {
    /// Repo the loop ran in.
    pub repo: String,
    /// Loop start (first post-green invocation's arrival).
    pub started_at_unix_ms: u64,
    /// Wall-clock intent-to-green (ms).
    pub intent_to_green_ms: u64,
    /// Invocations inside the loop (including the green one).
    pub invocations: usize,
}

/// The reconstruction result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentToGreenReport {
    /// Completed loops, in start order.
    pub loops: Vec<AgentLoop>,
    /// Whole-loop intent-to-green percentiles (None when no loop
    /// completed — never a fabricated zero).
    pub intent_to_green: Option<Percentiles>,
    /// Loops still red when their session's records ran out —
    /// the countermetric; a corpus that rarely greens is a finding.
    pub unresolved_loops: usize,
    /// Malformed lines skipped (counted, never silent).
    pub skipped_malformed: usize,
    /// Per-stage decomposition of the north-star metric: needs the
    /// stage taps (queueing/transfer/materialization/…); typed as
    /// not-instrumented until they exist.
    pub stage_breakdown: MetricGroup<()>,
}

/// Reconstruct agent loops from corpus lines. Lines may arrive in any
/// order; events sort by (repo, arrival).
#[must_use]
pub fn reconstruct(lines: &[&str]) -> IntentToGreenReport {
    let mut events: Vec<TimelineEvent> = Vec::new();
    let mut skipped_malformed = 0;
    for line in lines {
        match parse_timeline_event(line) {
            Ok(event) => events.push(event),
            Err(_) => skipped_malformed += 1,
        }
    }
    events.sort_by(|a, b| {
        (a.repo.as_str(), a.recorded_at_unix_ms).cmp(&(b.repo.as_str(), b.recorded_at_unix_ms))
    });

    let mut loops: Vec<AgentLoop> = Vec::new();
    let mut unresolved_loops = 0;
    let mut index = 0;
    while index < events.len() {
        let repo = events[index].repo.clone();
        // One repo's session slice.
        let mut end = index;
        while end < events.len() && events[end].repo == repo {
            end += 1;
        }
        let session = &events[index..end];
        // Walk loops: start at first record (or first after a green),
        // close at the first green.
        let mut loop_start: Option<(u64, usize)> = None;
        for event in session {
            let (started, count) = loop_start.get_or_insert((event.recorded_at_unix_ms, 0));
            *count += 1;
            if event.green {
                loops.push(AgentLoop {
                    repo: repo.clone(),
                    started_at_unix_ms: *started,
                    intent_to_green_ms: event
                        .recorded_at_unix_ms
                        .saturating_add(event.duration_ms)
                        .saturating_sub(*started),
                    invocations: *count,
                });
                loop_start = None;
            }
        }
        if loop_start.is_some() {
            unresolved_loops += 1;
        }
        index = end;
    }
    loops.sort_by_key(|l| l.started_at_unix_ms);
    let durations: Vec<u64> = loops.iter().map(|l| l.intent_to_green_ms).collect();
    IntentToGreenReport {
        intent_to_green: percentiles(&durations),
        loops,
        unresolved_loops,
        skipped_malformed,
        stage_breakdown: MetricGroup::NotInstrumented {
            needs: "per-stage taps (queueing/capture/key/lookup/transfer/execution/\
                    materialization/notification/cancellation/retries)",
        },
    }
}

/// The machine-readable line (Q002's input format).
#[must_use]
pub fn report_to_ndjson(report: &IntentToGreenReport) -> String {
    let latency = match &report.intent_to_green {
        Some(p) => serde_json::json!({
            "p50_ms": p.p50_ms,
            "p90_ms": p.p90_ms,
            "p95_ms": p.p95_ms,
            "samples": p.samples,
        }),
        None => serde_json::Value::Null,
    };
    let stage = match &report.stage_breakdown {
        MetricGroup::Measured(()) => serde_json::json!({}),
        MetricGroup::NotInstrumented { needs } => {
            serde_json::json!({ "not_instrumented": needs })
        }
    };
    serde_json::json!({
        "schema": "rabs.intent-to-green",
        "schema_version": 1,
        "completed_loops": report.loops.len(),
        "unresolved_loops": report.unresolved_loops,
        "skipped_malformed": report.skipped_malformed,
        "intent_to_green": latency,
        "stage_breakdown": stage,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(repo: &str, at_ms: u64, duration_ms: u64, exit: i64) -> String {
        serde_json::json!({
            "cwd_redacted": repo,
            "recorded_at_unix_ms": at_ms,
            "duration_ms": duration_ms,
            "outcome_kind": "exited",
            "outcome_value": exit,
        })
        .to_string()
    }

    #[test]
    fn b012_loops_reconstruct_edit_check_test_green() {
        // Repo A: red check (t=1000), red check (t=5000), GREEN test
        // (t=9000, 2s) → loop 1: 1000..11000 = 10000ms, 3 invocations.
        // Then red check (t=20000), GREEN check (t=25000, 1s) →
        // loop 2: 20000..26000 = 6000ms, 2 invocations.
        let lines = [
            line("~/a", 1000, 3000, 1),
            line("~/a", 5000, 3000, 1),
            line("~/a", 9000, 2000, 0),
            line("~/a", 20_000, 4000, 1),
            line("~/a", 25_000, 1000, 0),
        ];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let report = reconstruct(&refs);
        assert_eq!(report.loops.len(), 2);
        assert_eq!(report.unresolved_loops, 0);
        assert_eq!(report.loops[0].intent_to_green_ms, 10_000);
        assert_eq!(report.loops[0].invocations, 3);
        assert_eq!(report.loops[1].intent_to_green_ms, 6_000);
        assert_eq!(report.loops[1].invocations, 2);
        // Percentiles over {10000, 6000}.
        let p = report.intent_to_green.unwrap();
        assert_eq!(p.p50_ms, 6_000);
        assert_eq!(p.p95_ms, 10_000);
        assert_eq!(p.samples, 2);
    }

    #[test]
    fn b012_interleaved_repos_reconstruct_independently() {
        // Two agents in two repos, interleaved arrivals: loops must
        // not bleed across repos.
        let lines = [
            line("~/a", 1000, 500, 1),
            line("~/b", 1500, 500, 1),
            line("~/a", 3000, 1000, 0), // A greens: 1000..4000
            line("~/b", 6000, 2000, 0), // B greens: 1500..8000
        ];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let report = reconstruct(&refs);
        assert_eq!(report.loops.len(), 2);
        let a = report.loops.iter().find(|l| l.repo == "~/a").unwrap();
        let b = report.loops.iter().find(|l| l.repo == "~/b").unwrap();
        assert_eq!(a.intent_to_green_ms, 3_000);
        assert_eq!(b.intent_to_green_ms, 6_500);
    }

    #[test]
    fn b012_red_tails_are_unresolved_loops_not_dropped() {
        // Repo greens once, then goes red and the session ends: one
        // completed loop, one UNRESOLVED — visible in the report.
        let lines = [
            line("~/a", 1000, 500, 0),
            line("~/a", 2000, 500, 1),
            line("~/a", 3000, 500, 101),
            "garbage".to_owned(),
        ];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let report = reconstruct(&refs);
        assert_eq!(report.loops.len(), 1);
        assert_eq!(report.unresolved_loops, 1);
        assert_eq!(report.skipped_malformed, 1);
        let ndjson = report_to_ndjson(&report);
        let parsed: serde_json::Value = serde_json::from_str(&ndjson).unwrap();
        assert_eq!(parsed["schema"], "rabs.intent-to-green");
        assert_eq!(parsed["completed_loops"], 1);
        assert_eq!(parsed["unresolved_loops"], 1);
        assert_eq!(parsed["skipped_malformed"], 1);
        assert!(
            parsed["stage_breakdown"]["not_instrumented"].is_string(),
            "stage decomposition is honestly unmeasured until the taps exist"
        );
    }

    #[test]
    fn b012_empty_and_never_green_corpora_never_fabricate_percentiles() {
        let report = reconstruct(&[]);
        assert_eq!(report.intent_to_green, None);
        assert_eq!(report.loops.len(), 0);
        let all_red = [line("~/a", 1000, 500, 1)];
        let refs: Vec<&str> = all_red.iter().map(String::as_str).collect();
        let report = reconstruct(&refs);
        assert_eq!(report.intent_to_green, None, "no green, no percentile");
        assert_eq!(report.unresolved_loops, 1);
        let parsed: serde_json::Value = serde_json::from_str(&report_to_ndjson(&report)).unwrap();
        assert!(parsed["intent_to_green"].is_null());
    }
}
