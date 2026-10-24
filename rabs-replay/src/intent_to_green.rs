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

// ---------------------------------------------------------------------------
// Q002: Likely-next-command model from session corpus + provenance DAG
// ---------------------------------------------------------------------------

use std::collections::{BTreeMap, BTreeSet};

use rabs_protocol::redaction::REDACTED;

/// Provenance dependency DAG mapping crate/package names to their reverse dependents (bead Q002).
///
/// When an agent edits or compiles crate `A`, any crate `B` that depends on `A`
/// (directly or transitively) is part of the impacted provenance closure and is
/// eligible for speculative next-command prediction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProvenanceDag {
    /// Direct reverse dependencies: `dependency -> {dependent_1, dependent_2, ...}`.
    dependents_by_crate: BTreeMap<String, BTreeSet<String>>,
}

impl ProvenanceDag {
    /// Construct an empty provenance DAG.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `dependent` depends on `dependency` (`dependency -> dependent`).
    pub fn add_dependency(&mut self, dependency: impl Into<String>, dependent: impl Into<String>) {
        self.dependents_by_crate
            .entry(dependency.into())
            .or_default()
            .insert(dependent.into());
    }

    /// Direct dependents of `crate_name`.
    #[must_use]
    pub fn direct_dependents(&self, crate_name: &str) -> BTreeSet<String> {
        self.dependents_by_crate
            .get(crate_name)
            .cloned()
            .unwrap_or_default()
    }

    /// Transitive closure of impacted crates starting from `crate_name` (including `crate_name`).
    #[must_use]
    pub fn impacted_crates(&self, crate_name: &str) -> BTreeSet<String> {
        let mut visited = BTreeSet::new();
        let mut stack = vec![crate_name.to_owned()];
        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(children) = self.dependents_by_crate.get(&current) {
                for child in children {
                    if !visited.contains(child) {
                        stack.push(child.clone());
                    }
                }
            }
        }
        visited
    }
}

/// One command-sequence event parsed from a B002 corpus line for Q002 training/evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSequenceEvent {
    /// Repo identity (`cwd_redacted`).
    pub repo: String,
    /// Arrival wall-clock (Unix ms).
    pub recorded_at_unix_ms: u64,
    /// Duration (ms).
    pub duration_ms: u64,
    /// Whether the invocation exited 0 (GREEN).
    pub green: bool,
    /// Normalized build/test command string.
    pub command: String,
    /// Target crate/package extracted from `-p` / `--package` or explicit `"target_crate"`.
    pub target_crate: Option<String>,
}

/// Extract `-p <pkg>` / `--package <pkg>` / `--package=<pkg>` from command tokens.
#[must_use]
pub fn extract_target_crate_from_command(command: &str) -> Option<String> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];
        if (token == "-p" || token == "--package") && i + 1 < tokens.len() {
            return Some(tokens[i + 1].to_owned());
        }
        if let Some(pkg) = token.strip_prefix("--package=")
            && !pkg.is_empty()
        {
            return Some(pkg.to_owned());
        }
        i += 1;
    }
    None
}

/// Parse one B002 corpus line into a [`CommandSequenceEvent`] (bead Q002).
///
/// # Errors
/// Returns [`ReplaySkip::RedactedArgv`] if `argv_redacted` contains a redacted
/// token, or [`ReplaySkip::MalformedRecord`] if required fields are missing.
pub fn parse_command_sequence_event(line: &str) -> Result<CommandSequenceEvent, ReplaySkip> {
    let timeline = parse_timeline_event(line)?;
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| ReplaySkip::MalformedRecord {
            detail: e.to_string(),
        })?;
    let command = if let Some(argv) = value["argv_redacted"].as_array() {
        let mut parts = Vec::with_capacity(argv.len());
        for element in argv {
            let text = element
                .as_str()
                .ok_or_else(|| ReplaySkip::MalformedRecord {
                    detail: "argv element not a string".to_owned(),
                })?;
            if text.contains(REDACTED) {
                return Err(ReplaySkip::RedactedArgv);
            }
            parts.push(text);
        }
        if parts.is_empty() {
            return Err(ReplaySkip::MalformedRecord {
                detail: "argv_redacted empty".to_owned(),
            });
        }
        parts.join(" ")
    } else if let Some(cmd) = value["command"].as_str() {
        if cmd.contains(REDACTED) {
            return Err(ReplaySkip::RedactedArgv);
        }
        cmd.to_owned()
    } else {
        return Err(ReplaySkip::MalformedRecord {
            detail: "argv_redacted or command missing".to_owned(),
        });
    };

    let target_crate = value["target_crate"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| extract_target_crate_from_command(&command));

    Ok(CommandSequenceEvent {
        repo: timeline.repo,
        recorded_at_unix_ms: timeline.recorded_at_unix_ms,
        duration_ms: timeline.duration_ms,
        green: timeline.green,
        command,
        target_crate,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CommandStage {
    Check,
    Test,
    Clippy,
    Build,
    Nextest,
    Other(String),
}

impl CommandStage {
    fn from_command(command: &str) -> Self {
        let tokens: Vec<&str> = command.split_whitespace().collect();
        if tokens.first().copied() == Some("cargo") {
            match tokens.get(1).copied() {
                Some("check" | "c") => Self::Check,
                Some("test" | "t") => Self::Test,
                Some("clippy") => Self::Clippy,
                Some("build" | "b") => Self::Build,
                Some("nextest") => Self::Nextest,
                _ => Self::Other(command.to_owned()),
            }
        } else {
            Self::Other(command.to_owned())
        }
    }

    fn format_for_crate(&self, target_crate: Option<&str>) -> Option<String> {
        let sub = match self {
            Self::Check => "check",
            Self::Test => "test",
            Self::Clippy => "clippy",
            Self::Build => "build",
            Self::Nextest => "nextest run",
            Self::Other(_) => return None,
        };
        Some(match target_crate {
            Some(pkg) => format!("cargo {sub} -p {pkg}"),
            None => format!("cargo {sub} --workspace"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CrateRelation {
    SameCrate,
    DagDependent,
    Workspace,
}

/// One ranked next-command prediction emitted by [`LikelyNextCommandModel`] (bead Q002).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPrediction {
    /// Predicted build/test command.
    pub command: String,
    /// Normalized prediction confidence in permille (`0..=1000`).
    pub probability_permille: u32,
    /// Historical transition support count backing this prediction.
    pub support_count: u64,
    /// Whether the predicted command's target crate lies in the active provenance DAG closure.
    pub provenance_aligned: bool,
}

/// Likely-next-command prediction model trained from B012 session timelines + provenance DAG (bead Q002).
#[derive(Debug, Clone, Default)]
pub struct LikelyNextCommandModel {
    dag: ProvenanceDag,
    /// Exact transitions: `(prev_command, prev_green) -> (next_command -> count)`.
    exact_transitions: BTreeMap<(String, bool), BTreeMap<String, u64>>,
    /// Structural stage+DAG transitions: `(prev_stage, prev_green) -> ((next_stage, relation) -> count)`.
    stage_transitions: BTreeMap<(CommandStage, bool), BTreeMap<(CommandStage, CrateRelation), u64>>,
    /// Global command frequencies for fallback tie-breaking.
    unigram_counts: BTreeMap<String, u64>,
    /// Skipped corpus lines during training.
    pub skipped_training_records: usize,
}

impl LikelyNextCommandModel {
    /// Train a [`LikelyNextCommandModel`] from historical corpus lines and a [`ProvenanceDag`].
    #[must_use]
    pub fn train(corpus_lines: &[&str], dag: &ProvenanceDag) -> Self {
        let mut events = Vec::new();
        let mut skipped_training_records = 0;
        for line in corpus_lines {
            match parse_command_sequence_event(line) {
                Ok(event) => events.push(event),
                Err(_) => skipped_training_records += 1,
            }
        }
        events.sort_by(|a, b| {
            (a.repo.as_str(), a.recorded_at_unix_ms).cmp(&(b.repo.as_str(), b.recorded_at_unix_ms))
        });

        let mut model = Self {
            dag: dag.clone(),
            exact_transitions: BTreeMap::new(),
            stage_transitions: BTreeMap::new(),
            unigram_counts: BTreeMap::new(),
            skipped_training_records,
        };

        let mut idx = 0;
        while idx < events.len() {
            let repo = events[idx].repo.clone();
            let mut end = idx;
            while end < events.len() && events[end].repo == repo {
                end += 1;
            }
            let session = &events[idx..end];
            for event in session {
                *model
                    .unigram_counts
                    .entry(event.command.clone())
                    .or_insert(0) += 1;
            }
            for pair in session.windows(2) {
                let prev = &pair[0];
                let next = &pair[1];
                *model
                    .exact_transitions
                    .entry((prev.command.clone(), prev.green))
                    .or_default()
                    .entry(next.command.clone())
                    .or_insert(0) += 1;

                let prev_stage = CommandStage::from_command(&prev.command);
                let next_stage = CommandStage::from_command(&next.command);
                let relation = match (&prev.target_crate, &next.target_crate) {
                    (Some(p), Some(n)) if p == n => CrateRelation::SameCrate,
                    (Some(p), Some(n)) if dag.impacted_crates(p).contains(n) => {
                        CrateRelation::DagDependent
                    }
                    _ => CrateRelation::Workspace,
                };
                *model
                    .stage_transitions
                    .entry((prev_stage, prev.green))
                    .or_default()
                    .entry((next_stage, relation))
                    .or_insert(0) += 1;
            }
            idx = end;
        }

        model
    }

    /// Predict the top `top_k` likely next build/test commands given the previous
    /// command, whether it exited green (`0`), and any active/edited crates in the
    /// provenance DAG (bead Q002).
    #[must_use]
    pub fn predict_next(
        &self,
        prev_command: &str,
        prev_green: bool,
        edited_crates: &[&str],
        top_k: usize,
    ) -> Vec<CommandPrediction> {
        if top_k == 0 {
            return Vec::new();
        }
        let prev_crate = extract_target_crate_from_command(prev_command);
        let mut impacted = BTreeSet::new();
        for crate_name in edited_crates {
            impacted.extend(self.dag.impacted_crates(crate_name));
        }
        if let Some(ref c) = prev_crate {
            impacted.extend(self.dag.impacted_crates(c));
        }

        // Candidate map: command -> (weighted_score, raw_support, provenance_aligned)
        let mut candidates: BTreeMap<String, (u64, u64, bool)> = BTreeMap::new();

        // 1. Exact historical transitions from `(prev_command, prev_green)`.
        if let Some(next_map) = self
            .exact_transitions
            .get(&(prev_command.to_owned(), prev_green))
        {
            for (cmd, &count) in next_map {
                let cmd_crate = extract_target_crate_from_command(cmd);
                let aligned = cmd_crate.as_deref().is_some_and(|c| impacted.contains(c));
                let weight = if aligned { count * 3 } else { count * 2 };
                let entry = candidates.entry(cmd.clone()).or_insert((0, 0, aligned));
                entry.0 = entry.0.saturating_add(weight);
                entry.1 = entry.1.saturating_add(count);
                entry.2 |= aligned;
            }
        }

        // 2. Structural stage + provenance DAG transitions (enables cross-crate
        //    generalization across the provenance DAG for newly edited crates).
        let prev_stage = CommandStage::from_command(prev_command);
        if let Some(stage_map) = self.stage_transitions.get(&(prev_stage, prev_green)) {
            let primary_crate = edited_crates.first().copied().or(prev_crate.as_deref());
            for ((next_stage, relation), &count) in stage_map {
                match relation {
                    CrateRelation::SameCrate => {
                        if let Some(c) = primary_crate
                            && let Some(synthesized) = next_stage.format_for_crate(Some(c))
                        {
                            let entry = candidates.entry(synthesized).or_insert((0, 0, true));
                            entry.0 = entry.0.saturating_add(count * 2);
                            entry.1 = entry.1.saturating_add(count);
                            entry.2 = true;
                        }
                    }
                    CrateRelation::DagDependent => {
                        if let Some(c) = primary_crate {
                            for dep in self.dag.direct_dependents(c) {
                                if let Some(synthesized) = next_stage.format_for_crate(Some(&dep)) {
                                    let entry =
                                        candidates.entry(synthesized).or_insert((0, 0, true));
                                    entry.0 = entry.0.saturating_add(count * 2);
                                    entry.1 = entry.1.saturating_add(count);
                                    entry.2 = true;
                                }
                            }
                        }
                    }
                    CrateRelation::Workspace => {
                        if let Some(synthesized) = next_stage.format_for_crate(None) {
                            let entry = candidates.entry(synthesized).or_insert((0, 0, false));
                            entry.0 = entry.0.saturating_add(count);
                            entry.1 = entry.1.saturating_add(count);
                        }
                    }
                }
            }
        }

        // 3. Fallback to global unigram frequency if no transition matched.
        if candidates.is_empty() {
            for (cmd, &count) in &self.unigram_counts {
                let cmd_crate = extract_target_crate_from_command(cmd);
                let aligned = cmd_crate.as_deref().is_some_and(|c| impacted.contains(c));
                candidates.insert(cmd.clone(), (count, count, aligned));
            }
        }

        let total_score: u64 = candidates.values().map(|(score, _, _)| *score).sum();
        if total_score == 0 {
            return Vec::new();
        }

        let mut ranked: Vec<(String, u64, u64, bool)> = candidates
            .into_iter()
            .map(|(cmd, (score, support, aligned))| (cmd, score, support, aligned))
            .collect();
        ranked.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| b.3.cmp(&a.3))
                .then_with(|| b.2.cmp(&a.2))
                .then_with(|| a.0.cmp(&b.0))
        });
        ranked.truncate(top_k);

        ranked
            .into_iter()
            .map(|(command, score, support_count, provenance_aligned)| {
                let probability_permille =
                    u32::try_from((score * 1_000).checked_div(total_score).unwrap_or(0))
                        .unwrap_or(0);
                CommandPrediction {
                    command,
                    probability_permille,
                    support_count,
                    provenance_aligned,
                }
            })
            .collect()
    }
}

/// Held-out session precision report for the Q002 likely-next-command model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldOutPrecisionReport {
    /// Total observed command-to-command transitions in the held-out sessions.
    pub total_transitions: u64,
    /// Number of transitions for which the model emitted at least one prediction.
    pub predictions_emitted: u64,
    /// Number of transitions where the top-1 prediction exactly matched the agent's next command.
    pub top1_correct: u64,
    /// Number of transitions where the agent's next command appeared in the top-3 predictions.
    pub top3_correct: u64,
    /// Top-1 prediction precision in permille (`top1_correct * 1000 / predictions_emitted`).
    pub top1_precision_permille: u32,
    /// Top-3 recall/hit-rate in permille (`top3_correct * 1000 / predictions_emitted`).
    pub top3_hit_rate_permille: u32,
    /// Malformed or redacted held-out corpus lines skipped.
    pub skipped_records: usize,
}

/// Measure [`LikelyNextCommandModel`] prediction precision on held-out sessions (bead Q002).
#[must_use]
pub fn evaluate_held_out_sessions(
    model: &LikelyNextCommandModel,
    held_out_lines: &[&str],
) -> HeldOutPrecisionReport {
    let mut events = Vec::new();
    let mut skipped_records = 0;
    for line in held_out_lines {
        match parse_command_sequence_event(line) {
            Ok(event) => events.push(event),
            Err(_) => skipped_records += 1,
        }
    }
    events.sort_by(|a, b| {
        (a.repo.as_str(), a.recorded_at_unix_ms).cmp(&(b.repo.as_str(), b.recorded_at_unix_ms))
    });

    let mut total_transitions = 0_u64;
    let mut predictions_emitted = 0_u64;
    let mut top1_correct = 0_u64;
    let mut top3_correct = 0_u64;

    let mut idx = 0;
    while idx < events.len() {
        let repo = events[idx].repo.clone();
        let mut end = idx;
        while end < events.len() && events[end].repo == repo {
            end += 1;
        }
        let session = &events[idx..end];
        for pair in session.windows(2) {
            let prev = &pair[0];
            let actual_next = &pair[1];
            total_transitions += 1;
            let active_crates: Vec<&str> = prev.target_crate.as_deref().into_iter().collect();
            let preds = model.predict_next(&prev.command, prev.green, &active_crates, 3);
            if !preds.is_empty() {
                predictions_emitted += 1;
                if preds[0].command == actual_next.command {
                    top1_correct += 1;
                }
                if preds.iter().any(|p| p.command == actual_next.command) {
                    top3_correct += 1;
                }
            }
        }
        idx = end;
    }

    let top1_precision_permille = u32::try_from(
        (top1_correct * 1_000)
            .checked_div(predictions_emitted)
            .unwrap_or(0),
    )
    .unwrap_or(0);
    let top3_hit_rate_permille = u32::try_from(
        (top3_correct * 1_000)
            .checked_div(predictions_emitted)
            .unwrap_or(0),
    )
    .unwrap_or(0);

    HeldOutPrecisionReport {
        total_transitions,
        predictions_emitted,
        top1_correct,
        top3_correct,
        top1_precision_permille,
        top3_hit_rate_permille,
        skipped_records,
    }
}

/// Emit the machine-readable NDJSON line for [`HeldOutPrecisionReport`] (bead Q002).
#[must_use]
pub fn held_out_precision_to_ndjson(report: &HeldOutPrecisionReport) -> String {
    serde_json::json!({
        "schema": "rabs.likely-next-command-eval",
        "schema_version": 1,
        "total_transitions": report.total_transitions,
        "predictions_emitted": report.predictions_emitted,
        "top1_correct": report.top1_correct,
        "top3_correct": report.top3_correct,
        "top1_precision_permille": report.top1_precision_permille,
        "top3_hit_rate_permille": report.top3_hit_rate_permille,
        "skipped_records": report.skipped_records,
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

    fn cmd_line(repo: &str, at_ms: u64, duration_ms: u64, exit: i64, argv: &[&str]) -> String {
        serde_json::json!({
            "cwd_redacted": repo,
            "recorded_at_unix_ms": at_ms,
            "duration_ms": duration_ms,
            "outcome_kind": "exited",
            "outcome_value": exit,
            "argv_redacted": argv,
        })
        .to_string()
    }

    #[test]
    fn q002_likely_next_command_model_predicts_and_measures_held_out_precision() {
        let mut dag = ProvenanceDag::new();
        dag.add_dependency("rabs-protocol", "rabs-cas");
        dag.add_dependency("rabs-cas", "rabsd");
        dag.add_dependency("rabs-protocol", "rabs-key");

        let impacted = dag.impacted_crates("rabs-protocol");
        assert!(impacted.contains("rabs-protocol"));
        assert!(impacted.contains("rabs-cas"));
        assert!(impacted.contains("rabsd"));
        assert!(impacted.contains("rabs-key"));

        // Historical training sessions:
        // Agent pattern:
        // 1. Red `cargo check -p <crate>` -> re-runs `cargo check -p <crate>`
        // 2. Green `cargo check -p <crate>` -> runs `cargo test -p <crate>`
        // 3. Green `cargo test -p <crate>` -> runs `cargo test -p <dependent>`
        let training = [
            // Session 1 in repo ~/train-a
            cmd_line(
                "~/train-a",
                1_000,
                500,
                1,
                &["cargo", "check", "-p", "rabs-protocol"],
            ),
            cmd_line(
                "~/train-a",
                2_000,
                500,
                0,
                &["cargo", "check", "-p", "rabs-protocol"],
            ),
            cmd_line(
                "~/train-a",
                3_000,
                900,
                0,
                &["cargo", "test", "-p", "rabs-protocol"],
            ),
            cmd_line(
                "~/train-a",
                4_500,
                1_100,
                0,
                &["cargo", "test", "-p", "rabs-cas"],
            ),
            // Session 2 in repo ~/train-b
            cmd_line(
                "~/train-b",
                10_000,
                400,
                1,
                &["cargo", "check", "-p", "rabs-cas"],
            ),
            cmd_line(
                "~/train-b",
                11_000,
                400,
                0,
                &["cargo", "check", "-p", "rabs-cas"],
            ),
            cmd_line(
                "~/train-b",
                12_000,
                800,
                0,
                &["cargo", "test", "-p", "rabs-cas"],
            ),
            cmd_line(
                "~/train-b",
                13_500,
                1_200,
                0,
                &["cargo", "test", "-p", "rabsd"],
            ),
        ];
        let train_refs: Vec<&str> = training.iter().map(String::as_str).collect();
        let model = LikelyNextCommandModel::train(&train_refs, &dag);
        assert_eq!(model.skipped_training_records, 0);

        // After RED `cargo check -p rabs-protocol`, top-1 is `cargo check -p rabs-protocol`.
        let after_red =
            model.predict_next("cargo check -p rabs-protocol", false, &["rabs-protocol"], 3);
        assert_eq!(after_red[0].command, "cargo check -p rabs-protocol");
        assert!(after_red[0].provenance_aligned);

        // After GREEN `cargo check -p rabs-protocol`, top-1 is `cargo test -p rabs-protocol`.
        let after_green =
            model.predict_next("cargo check -p rabs-protocol", true, &["rabs-protocol"], 3);
        assert_eq!(after_green[0].command, "cargo test -p rabs-protocol");
        assert!(after_green[0].provenance_aligned);

        // Held-out evaluation on unseen sessions (including structural generalization to `rabs-key`):
        let held_out = [
            cmd_line(
                "~/held-out-1",
                50_000,
                400,
                1,
                &["cargo", "check", "-p", "rabs-protocol"],
            ),
            cmd_line(
                "~/held-out-1",
                51_000,
                400,
                0,
                &["cargo", "check", "-p", "rabs-protocol"],
            ),
            cmd_line(
                "~/held-out-1",
                52_000,
                800,
                0,
                &["cargo", "test", "-p", "rabs-protocol"],
            ),
            // Structural DAG generalization on `rabs-key` (never seen in training argv, only in DAG):
            cmd_line(
                "~/held-out-2",
                60_000,
                300,
                1,
                &["cargo", "check", "-p", "rabs-key"],
            ),
            cmd_line(
                "~/held-out-2",
                61_000,
                300,
                0,
                &["cargo", "check", "-p", "rabs-key"],
            ),
            cmd_line(
                "~/held-out-2",
                62_000,
                700,
                0,
                &["cargo", "test", "-p", "rabs-key"],
            ),
            // Redacted record must be skipped and counted, never silently replayed.
            cmd_line("~/held-out-2", 63_000, 100, 0, &["cargo", "test", REDACTED]),
        ];
        let held_out_refs: Vec<&str> = held_out.iter().map(String::as_str).collect();
        let eval = evaluate_held_out_sessions(&model, &held_out_refs);
        assert_eq!(eval.skipped_records, 1);
        assert_eq!(eval.total_transitions, 4);
        assert_eq!(eval.predictions_emitted, 4);
        assert_eq!(eval.top1_correct, 4);
        assert_eq!(eval.top3_correct, 4);
        assert_eq!(eval.top1_precision_permille, 1_000);
        assert_eq!(eval.top3_hit_rate_permille, 1_000);

        let ndjson = held_out_precision_to_ndjson(&eval);
        let parsed: serde_json::Value = serde_json::from_str(&ndjson).unwrap();
        assert_eq!(parsed["schema"], "rabs.likely-next-command-eval");
        assert_eq!(parsed["top1_precision_permille"], 1_000);
        assert_eq!(parsed["top3_hit_rate_permille"], 1_000);
        assert_eq!(parsed["skipped_records"], 1);
    }
}
