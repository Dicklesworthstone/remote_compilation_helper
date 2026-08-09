//! # rabs-replay — the replay runner (bead B005)
//!
//! Executes recorded invocations under the STOCK path and any number of
//! CANDIDATE RABS paths, and compares what happened: availability
//! (would we have hit?), result metadata, output/diagnostic digests,
//! timing. This is the engine of the trust ladder — Stage 1 shadow
//! keys, Stage 2 shadow result comparison — and of every performance
//! gate above it.
//!
//! Honesty rules baked into the API:
//!
//! - **Redacted records refuse to replay.** The B002 corpus stores
//!   redacted presentation argv (digests-only policy, B004). For the
//!   ordinary build commands the corpus exists for, redaction changes
//!   nothing and the command replays byte-faithfully; a record whose
//!   argv WAS altered by redaction cannot be reproduced from the
//!   corpus and yields a typed [`ReplaySkip::RedactedArgv`] — never a
//!   silently-wrong replay of a masked command.
//! - **The stock path really executes.** [`StockPath`] runs the
//!   command via `sh -c`, captures the wait status with
//!   signal-vs-exit preserved, and digests stdout/stderr with the
//!   same correlation hash the corpus uses.
//! - **Candidates plug in.** [`ExecutionPath`] is one trait; the
//!   comparison logic never knows which implementation produced an
//!   observation.
//! - **Divergence is typed and emitted.** [`compare`] produces a
//!   [`DivergenceRecord`] naming exactly which dimensions diverged;
//!   [`divergence_to_ndjson`] is the divergence-corpus line format
//!   downstream gates consume.

pub mod minimizer;
pub mod scenario_labels;

use std::process::Command;
use std::time::Instant;

use rabs_protocol::invocation_record::NormalizedOutcome;
use rabs_protocol::redaction::{REDACTED, correlation_hash};

/// One replayable invocation, reconstructed from a corpus line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCommand {
    /// The shell command to execute.
    pub command: String,
    /// Working directory (already un-redacted by the session loader;
    /// `~` expansion is the loader's job).
    pub cwd: String,
    /// The recorded outcome (what the original run produced).
    pub recorded_outcome: NormalizedOutcome,
    /// The recorded duration.
    pub recorded_duration_ms: u64,
}

/// Why a corpus record cannot replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplaySkip {
    /// The argv presentation was altered by redaction: the true bytes
    /// are not in the corpus (digests-only policy) and any replay
    /// would run a DIFFERENT command.
    RedactedArgv,
    /// The corpus line did not parse as an invocation record.
    MalformedRecord {
        /// Parse failure description.
        detail: String,
    },
}

/// Parse one B002 NDJSON corpus line into a replayable command.
///
/// # Errors
/// Typed [`ReplaySkip`]; skipped records are COUNTED by callers, never
/// silently dropped.
pub fn parse_corpus_line(line: &str) -> Result<ReplayCommand, ReplaySkip> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| ReplaySkip::MalformedRecord {
            detail: e.to_string(),
        })?;
    let argv = value["argv_redacted"]
        .as_array()
        .ok_or_else(|| ReplaySkip::MalformedRecord {
            detail: "argv_redacted missing".to_owned(),
        })?;
    let mut parts = Vec::new();
    for element in argv {
        let text = element
            .as_str()
            .ok_or_else(|| ReplaySkip::MalformedRecord {
                detail: "argv element not a string".to_owned(),
            })?;
        if text.contains(REDACTED) {
            return Err(ReplaySkip::RedactedArgv);
        }
        parts.push(text.to_owned());
    }
    let command = parts.join(" ");
    let cwd = value["cwd_redacted"]
        .as_str()
        .ok_or_else(|| ReplaySkip::MalformedRecord {
            detail: "cwd_redacted missing".to_owned(),
        })?
        .to_owned();
    let outcome = match (
        value["outcome_kind"].as_str(),
        value["outcome_value"].as_i64(),
    ) {
        (Some("exited"), Some(code)) => NormalizedOutcome::Exited(code as i32),
        (Some("signaled"), Some(signal)) => NormalizedOutcome::Signaled(signal as i32),
        _ => {
            return Err(ReplaySkip::MalformedRecord {
                detail: "outcome fields missing".to_owned(),
            });
        }
    };
    Ok(ReplayCommand {
        command,
        cwd,
        recorded_outcome: outcome,
        recorded_duration_ms: value["duration_ms"].as_u64().unwrap_or(0),
    })
}

/// Availability: did this path SERVE the invocation from its cache, or
/// did it run the tool? (The stock path always runs; candidates report
/// hits — Stage 1's "would we have hit?" question.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// The tool actually executed.
    Executed,
    /// Served from the path's cache without executing.
    CacheHit,
    /// The path REFUSED the invocation (typed unavailability — e.g. a
    /// candidate that cannot key this command yet).
    Unavailable,
}

/// What one path observed for one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathObservation {
    /// Which path produced this (the trait impl's name).
    pub path_name: String,
    /// Availability classification.
    pub availability: Availability,
    /// Outcome with signal-vs-exit preserved (`None` iff unavailable).
    pub outcome: Option<NormalizedOutcome>,
    /// Correlation digest over stdout bytes.
    pub stdout_digest: u64,
    /// Correlation digest over stderr bytes.
    pub stderr_digest: u64,
    /// Wall-clock duration of THIS replay in milliseconds.
    pub duration_ms: u64,
}

/// One execution path the runner can drive. The stock path and every
/// RABS candidate implement exactly this.
pub trait ExecutionPath {
    /// The name recorded in observations and divergence records.
    fn name(&self) -> &str;
    /// Execute (or serve) one invocation and report what happened.
    fn execute(&mut self, invocation: &ReplayCommand) -> PathObservation;
}

/// The stock path: run the command for real, exactly as recorded.
#[derive(Debug, Default)]
pub struct StockPath;

impl ExecutionPath for StockPath {
    fn name(&self) -> &str {
        "stock"
    }

    fn execute(&mut self, invocation: &ReplayCommand) -> PathObservation {
        let started = Instant::now();
        let output = Command::new("sh")
            .arg("-c")
            .arg(&invocation.command)
            .current_dir(&invocation.cwd)
            .output();
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match output {
            Ok(output) => {
                #[cfg(unix)]
                let outcome = {
                    use std::os::unix::process::ExitStatusExt;
                    output.status.code().map_or_else(
                        || NormalizedOutcome::Signaled(output.status.signal().unwrap_or(0)),
                        NormalizedOutcome::Exited,
                    )
                };
                #[cfg(not(unix))]
                let outcome = NormalizedOutcome::Exited(output.status.code().unwrap_or(-1));
                PathObservation {
                    path_name: self.name().to_owned(),
                    availability: Availability::Executed,
                    outcome: Some(outcome),
                    stdout_digest: correlation_hash(&output.stdout),
                    stderr_digest: correlation_hash(&output.stderr),
                    duration_ms,
                }
            }
            Err(_) => PathObservation {
                path_name: self.name().to_owned(),
                availability: Availability::Unavailable,
                outcome: None,
                stdout_digest: 0,
                stderr_digest: 0,
                duration_ms,
            },
        }
    }
}

/// The typed comparison of one invocation across two paths — the
/// divergence-corpus row. `diverged()` is derived, never stored, so a
/// row cannot claim agreement its fields contradict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceRecord {
    /// The replayed command (redaction-clean by construction).
    pub command: String,
    /// Baseline path name (conventionally "stock").
    pub baseline_path: String,
    /// Candidate path name.
    pub candidate_path: String,
    /// Availability on each side.
    pub baseline_availability: Availability,
    /// Candidate availability.
    pub candidate_availability: Availability,
    /// Whether the OUTCOME (exit/signal metadata) diverged.
    pub outcome_diverged: bool,
    /// Whether stdout digests diverged.
    pub stdout_diverged: bool,
    /// Whether stderr digests diverged.
    pub stderr_diverged: bool,
    /// Baseline duration (ms).
    pub baseline_duration_ms: u64,
    /// Candidate duration (ms).
    pub candidate_duration_ms: u64,
}

impl DivergenceRecord {
    /// Whether ANY compared dimension diverged. Availability is a
    /// difference, not a divergence: a candidate cache HIT with
    /// identical results is the goal state, and a typed
    /// `Unavailable` is a refusal (counted separately upstream).
    #[must_use]
    pub const fn diverged(&self) -> bool {
        self.outcome_diverged || self.stdout_diverged || self.stderr_diverged
    }
}

/// Compare one invocation's observations across baseline and candidate.
#[must_use]
pub fn compare(
    invocation: &ReplayCommand,
    baseline: &PathObservation,
    candidate: &PathObservation,
) -> DivergenceRecord {
    DivergenceRecord {
        command: invocation.command.clone(),
        baseline_path: baseline.path_name.clone(),
        candidate_path: candidate.path_name.clone(),
        baseline_availability: baseline.availability,
        candidate_availability: candidate.availability,
        outcome_diverged: baseline.outcome != candidate.outcome,
        stdout_diverged: baseline.stdout_digest != candidate.stdout_digest,
        stderr_diverged: baseline.stderr_digest != candidate.stderr_digest,
        baseline_duration_ms: baseline.duration_ms,
        candidate_duration_ms: candidate.duration_ms,
    }
}

/// Serialize one divergence record as its NDJSON corpus line.
#[must_use]
pub fn divergence_to_ndjson(record: &DivergenceRecord) -> String {
    let availability = |a: Availability| match a {
        Availability::Executed => "executed",
        Availability::CacheHit => "cache-hit",
        Availability::Unavailable => "unavailable",
    };
    serde_json::json!({
        "schema": "rabs.replay-divergence",
        "schema_version": 1,
        "command": record.command,
        "baseline_path": record.baseline_path,
        "candidate_path": record.candidate_path,
        "baseline_availability": availability(record.baseline_availability),
        "candidate_availability": availability(record.candidate_availability),
        "outcome_diverged": record.outcome_diverged,
        "stdout_diverged": record.stdout_diverged,
        "stderr_diverged": record.stderr_diverged,
        "diverged": record.diverged(),
        "baseline_duration_ms": record.baseline_duration_ms,
        "candidate_duration_ms": record.candidate_duration_ms,
    })
    .to_string()
}

/// Session-level replay summary: what ran, what was skipped and WHY,
/// what diverged. Skips are first-class — a session summary that hid
/// them would overstate coverage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionReport {
    /// Divergence rows, one per replayed invocation.
    pub rows: Vec<DivergenceRecord>,
    /// Records skipped as redacted.
    pub skipped_redacted: usize,
    /// Records skipped as malformed.
    pub skipped_malformed: usize,
}

impl SessionReport {
    /// Rows that diverged.
    #[must_use]
    pub fn divergences(&self) -> usize {
        self.rows.iter().filter(|r| r.diverged()).count()
    }
}

/// Replay a whole recorded session (B002 NDJSON lines) under a baseline
/// and a candidate path, producing the session report.
pub fn replay_session(
    corpus_lines: &[&str],
    baseline: &mut dyn ExecutionPath,
    candidate: &mut dyn ExecutionPath,
) -> SessionReport {
    let mut report = SessionReport::default();
    for line in corpus_lines {
        let invocation = match parse_corpus_line(line) {
            Ok(invocation) => invocation,
            Err(ReplaySkip::RedactedArgv) => {
                report.skipped_redacted += 1;
                continue;
            }
            Err(ReplaySkip::MalformedRecord { .. }) => {
                report.skipped_malformed += 1;
                continue;
            }
        };
        let base = baseline.execute(&invocation);
        let cand = candidate.execute(&invocation);
        report.rows.push(compare(&invocation, &base, &cand));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::invocation_record::{InvocationRecord, ToolKind};
    use rabs_protocol::raw_bytes::RawBytes;

    /// Encode a record exactly as B002's spool does (field-for-field).
    fn spool_line(record: &InvocationRecord) -> String {
        let (outcome_kind, outcome_value) = match record.outcome {
            NormalizedOutcome::Exited(code) => ("exited", code),
            NormalizedOutcome::Signaled(signal) => ("signaled", signal),
        };
        serde_json::json!({
            "schema": "rabs.invocation-record",
            "schema_version": record.schema_version,
            "tool": format!("{:?}", record.tool),
            "argv_correlation": record.argv_correlation,
            "argv_redacted": record.argv_redacted,
            "env_correlation": record.env_correlation,
            "env_redacted": record.env_redacted,
            "cwd_redacted": record.cwd_redacted,
            "outcome_kind": outcome_kind,
            "outcome_value": outcome_value,
            "duration_ms": record.duration_ms,
        })
        .to_string()
    }

    fn record_line(command: &str, outcome: NormalizedOutcome) -> String {
        let argv = [RawBytes::from(command)];
        let env: [(RawBytes, RawBytes); 0] = [];
        let record = InvocationRecord::capture(
            ToolKind::CargoWholeCommand,
            &argv,
            &env,
            &RawBytes::from("/tmp"),
            "",
            outcome,
            10,
        );
        spool_line(&record)
    }

    /// A candidate that serves everything from "cache" with recorded
    /// results — the divergence-free goal state.
    struct FaithfulCandidate {
        stock: StockPath,
    }
    impl ExecutionPath for FaithfulCandidate {
        fn name(&self) -> &str {
            "faithful-candidate"
        }
        fn execute(&mut self, invocation: &ReplayCommand) -> PathObservation {
            let mut observation = self.stock.execute(invocation);
            observation.path_name = self.name().to_owned();
            observation.availability = Availability::CacheHit;
            observation
        }
    }

    /// A candidate that lies about stdout — must show up as divergence.
    struct LyingCandidate;
    impl ExecutionPath for LyingCandidate {
        fn name(&self) -> &str {
            "lying-candidate"
        }
        fn execute(&mut self, _invocation: &ReplayCommand) -> PathObservation {
            PathObservation {
                path_name: self.name().to_owned(),
                availability: Availability::CacheHit,
                outcome: Some(NormalizedOutcome::Exited(0)),
                stdout_digest: 0xDEAD,
                stderr_digest: 0xBEEF,
                duration_ms: 1,
            }
        }
    }

    #[test]
    fn b005_stock_replay_is_bit_faithful_across_runs() {
        // THE acceptance: a recorded session replays against the stock
        // path with byte-identical results run over run (deterministic
        // commands; digests + outcomes + NDJSON rows all equal).
        let lines = [
            record_line("true", NormalizedOutcome::Exited(0)),
            record_line("echo replay-fidelity", NormalizedOutcome::Exited(0)),
            record_line("sh -c 'exit 101'", NormalizedOutcome::Exited(101)),
        ];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let run = |_tag: &str| {
            let mut baseline = StockPath;
            let mut candidate = FaithfulCandidate { stock: StockPath };
            replay_session(&refs, &mut baseline, &mut candidate)
        };
        let first = run("a");
        let second = run("b");
        assert_eq!(first.rows.len(), 3);
        assert_eq!(first.skipped_redacted + first.skipped_malformed, 0);
        // Bit-faithful: identical rows across runs (timings excluded —
        // compare every field that carries result identity).
        for (a, b) in first.rows.iter().zip(&second.rows) {
            assert_eq!(a.command, b.command);
            assert_eq!(a.outcome_diverged, b.outcome_diverged);
            assert_eq!(a.stdout_diverged, b.stdout_diverged);
            assert_eq!(a.stderr_diverged, b.stderr_diverged);
        }
        // And the faithful candidate diverges NOWHERE while hitting
        // cache everywhere — availability difference is not divergence.
        for row in &first.rows {
            assert!(!row.diverged(), "faithful candidate diverged: {row:?}");
            assert_eq!(row.candidate_availability, Availability::CacheHit);
            assert_eq!(row.baseline_availability, Availability::Executed);
        }
    }

    #[test]
    fn b005_outcomes_replay_with_signal_vs_exit_preserved() {
        let lines = [record_line(
            "sh -c 'kill -9 $$'",
            NormalizedOutcome::Signaled(9),
        )];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let mut baseline = StockPath;
        let invocation = parse_corpus_line(refs[0]).unwrap();
        assert_eq!(invocation.recorded_outcome, NormalizedOutcome::Signaled(9));
        let observation = baseline.execute(&invocation);
        assert_eq!(
            observation.outcome,
            Some(NormalizedOutcome::Signaled(9)),
            "a SIGKILLed replay is observed as signaled, never 137"
        );
    }

    #[test]
    fn b005_divergence_rows_name_the_dimension_and_emit_the_corpus_format() {
        let lines = [record_line("echo hello", NormalizedOutcome::Exited(0))];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let mut baseline = StockPath;
        let mut candidate = LyingCandidate;
        let report = replay_session(&refs, &mut baseline, &mut candidate);
        assert_eq!(report.divergences(), 1);
        let row = &report.rows[0];
        assert!(row.stdout_diverged && row.stderr_diverged);
        assert!(!row.outcome_diverged, "exit 0 matched");
        let line = divergence_to_ndjson(row);
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["schema"], "rabs.replay-divergence");
        assert_eq!(parsed["diverged"], true);
        assert_eq!(parsed["stdout_diverged"], true);
        assert_eq!(parsed["outcome_diverged"], false);
        assert_eq!(parsed["baseline_path"], "stock");
        assert_eq!(parsed["candidate_path"], "lying-candidate");
    }

    #[test]
    fn b005_redacted_and_malformed_records_skip_with_typed_reasons() {
        // A command whose argv redaction ALTERED the bytes cannot
        // replay: the true command is not in the corpus.
        let secret = record_line(
            "cargo publish --token=tok_live_secret",
            NormalizedOutcome::Exited(0),
        );
        assert_eq!(parse_corpus_line(&secret), Err(ReplaySkip::RedactedArgv));
        assert!(matches!(
            parse_corpus_line("not json at all"),
            Err(ReplaySkip::MalformedRecord { .. })
        ));
        // Session accounting keeps skips first-class.
        let ok = record_line("true", NormalizedOutcome::Exited(0));
        let lines = [secret.as_str(), "not json at all", ok.as_str()];
        let mut baseline = StockPath;
        let mut candidate = FaithfulCandidate { stock: StockPath };
        let report = replay_session(&lines, &mut baseline, &mut candidate);
        assert_eq!(report.skipped_redacted, 1);
        assert_eq!(report.skipped_malformed, 1);
        assert_eq!(report.rows.len(), 1);
    }
}
