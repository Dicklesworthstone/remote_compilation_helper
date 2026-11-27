//! Runnable CLI for inspecting, stratifying, and running paired benchmarks
//! over B002 RABS invocation corpora (`rabs-replay`, bead W2/B013).
//!
//! Stays strictly within A012's 2-dependency budget (`rabs-protocol` +
//! `serde_json`, zero extra crates) and `#![forbid(unsafe_code)]`.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rabs_protocol::invocation_record::NormalizedOutcome;
use rabs_protocol::redaction::{REDACTED, correlation_hash};

use crate::benchmark_report::{BenchmarkReport, Percentiles, percentiles};
use crate::intent_to_green::{self, IntentToGreenReport};
use crate::scenario_labels::{SessionRecord, parse_session_record, peak_overlap};
use crate::stratified_selection::{
    MultiRepoCorpusAudit, StratifiedSample, audit_multi_repo_corpus, select_stratified,
};
use crate::{Availability, PathObservation, ReplayCommand, SessionReport, compare};

const INSPECT_SCHEMA: &str = "rabs.replay-inspect.v1";
const STRATIFY_SCHEMA: &str = "rabs.replay-stratify.v1";
const PAIR_SCHEMA: &str = "rabs.replay-pair.v1";

/// Markers that should never appear verbatim in redacted presentation fields.
const SECRET_MARKERS: &[&str] = &[
    "ghp_",
    "gho_",
    "AKIA",
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "tok_live_",
];

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Parsed CLI command for `rabs-replay`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayCliCommand {
    /// Inspect a B002 NDJSONL invocation corpus.
    Inspect {
        /// Path to the B002 `invocations.ndjsonl` file.
        path: PathBuf,
        /// Emit machine-readable JSON instead of human text.
        json: bool,
        /// Number of top repositories to display.
        top: usize,
    },
    /// Run B010 stratified selection and B003 multi-repo coverage audit.
    Stratify {
        /// Path to the B002 `invocations.ndjsonl` file.
        path: PathBuf,
        /// Maximum records selected per stratum.
        per_stratum: usize,
        /// Emit machine-readable JSON instead of human text.
        json: bool,
    },
    /// Run paired interleaved stock-vs-candidate (or A/A) benchmark iterations.
    Pair {
        /// Working directory in which commands execute.
        workdir: PathBuf,
        /// Optional path to `rabs-wrap` (sets `RUSTC_WRAPPER` on candidate runs).
        rabs_wrap: Option<PathBuf>,
        /// Optional daemon socket path (sets `RABS_SOCKET` on candidate runs).
        rabs_socket: Option<PathBuf>,
        /// Number of paired iterations (1..=50).
        iterations: usize,
        /// Run stock on both arms to measure the A/A noise floor.
        aa_check: bool,
        /// Emit machine-readable JSON instead of human text.
        json: bool,
        /// Command + arguments to run.
        command: Vec<String>,
    },
    /// Print CLI help text.
    Help,
}

/// Top repository entry in an `inspect` report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoInspectRow {
    /// Redacted working directory recorded in the corpus.
    pub repo: String,
    /// Total parsed records for this working directory.
    pub records: u64,
    /// Cumulative recorded wall time in milliseconds.
    pub total_duration_ms: u64,
    /// Records that exited with code 0.
    pub exited_zero: u64,
}

/// Full inspection summary over a B002 NDJSONL invocation spool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusInspectReport {
    /// Path that was inspected.
    pub path: String,
    /// Total non-empty lines read from the file.
    pub non_empty_lines: usize,
    /// Records successfully parsed.
    pub parsed_records: usize,
    /// Malformed lines skipped (counted, never silent).
    pub malformed_lines: usize,
    /// Records whose `argv_redacted` contains `<REDACTED>`.
    pub redacted_argv_records: usize,
    /// Count of parsed records containing known unredacted secret markers.
    pub raw_secret_marker_hits: usize,
    /// Tool-kind distribution.
    pub tool_counts: BTreeMap<String, u64>,
    /// Records with `exited` and code 0.
    pub exited_zero: u64,
    /// Records with `exited` and code != 0.
    pub exited_nonzero: u64,
    /// Records terminated by a signal.
    pub signaled: u64,
    /// Exact exit-code distribution.
    pub exit_codes: BTreeMap<i32, u64>,
    /// Exact signal distribution.
    pub signals: BTreeMap<i32, u64>,
    /// Records with `ci_env == true`.
    pub ci_records: u64,
    /// Records with `ci_env == false`.
    pub non_ci_records: u64,
    /// Earliest recorded Unix timestamp (ms).
    pub earliest_unix_ms: Option<u64>,
    /// Latest recorded Unix timestamp (ms).
    pub latest_unix_ms: Option<u64>,
    /// Minimum recorded duration (ms).
    pub min_duration_ms: Option<u64>,
    /// Maximum recorded duration (ms).
    pub max_duration_ms: Option<u64>,
    /// Sum of recorded durations (ms).
    pub total_duration_ms: u64,
    /// Exact nearest-rank p50/p90/p95 durations.
    pub duration_percentiles: Option<Percentiles>,
    /// Exact nearest-rank p99 duration (ms).
    pub p99_duration_ms: Option<u64>,
    /// Peak simultaneous interval overlap across records.
    pub peak_overlap: u32,
    /// Count of records whose execution interval overlapped at least one other record.
    pub overlapping_records: usize,
    /// Reconstructed agent intent-to-green loops.
    pub intent_to_green: IntentToGreenReport,
    /// B003 multi-repo / 10-context coverage audit.
    pub b003_audit: MultiRepoCorpusAudit,
    /// Top repositories ordered by record count descending.
    pub top_repos: Vec<RepoInspectRow>,
}

/// Output of `rabs-replay stratify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusStratifyReport {
    /// Corpus path.
    pub path: String,
    /// Requested cap per stratum.
    pub per_stratum: usize,
    /// Total non-empty lines read.
    pub total_lines: usize,
    /// B010 stratified sample.
    pub sample: StratifiedSample,
    /// B003 multi-repo / 10-context coverage audit.
    pub b003_audit: MultiRepoCorpusAudit,
    /// Baseline recorded latency percentiles over selected records.
    pub selected_recorded_latency: Option<Percentiles>,
    /// Honest B008 benchmark report shell (candidate unmeasured; 8 stage groups `NotInstrumented`).
    pub benchmark_report: BenchmarkReport,
}

/// One paired iteration's measurements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairIterationRow {
    /// 1-based iteration number.
    pub iteration: usize,
    /// Execution order (`"stock-first"` or `"candidate-first"`).
    pub order: &'static str,
    /// Baseline (stock) wall time (ms).
    pub baseline_duration_ms: u64,
    /// Candidate wall time (ms).
    pub candidate_duration_ms: u64,
    /// Whether exit/signal, stdout digest, or stderr digest diverged.
    pub diverged: bool,
    /// Baseline exit/signal description.
    pub baseline_outcome: String,
    /// Candidate exit/signal description.
    pub candidate_outcome: String,
}

/// Output of `rabs-replay pair`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairBenchmarkReport {
    /// Working directory.
    pub workdir: String,
    /// Command executed.
    pub command: String,
    /// Whether this was an A/A noise-floor check (stock vs stock).
    pub aa_mode: bool,
    /// Wrapper binary used for candidate arm, if any.
    pub rabs_wrap: Option<String>,
    /// Socket path passed to candidate arm, if any.
    pub rabs_socket: Option<String>,
    /// Paired iterations executed.
    pub iterations: Vec<PairIterationRow>,
    /// Baseline latency percentiles.
    pub baseline_latency: Option<Percentiles>,
    /// Candidate latency percentiles.
    pub candidate_latency: Option<Percentiles>,
    /// Baseline spread percentage `((max - min) * 100) / max(1, min)`.
    pub baseline_spread_pct: u64,
    /// Candidate spread percentage `((max - min) * 100) / max(1, min)`.
    pub candidate_spread_pct: u64,
    /// True when baseline or candidate spread exceeds 30% (invalidates perf claims per gate ledger).
    pub noise_floor_invalidated: bool,
    /// Signed candidate-vs-baseline median delta in ms (negative = speedup, positive = regression).
    pub median_delta_ms: i64,
    /// Ratio `baseline_p50_ms * 1000 / candidate_p50_ms` (>1000 = faster, <1000 = slower).
    pub speedup_permille: Option<u64>,
    /// Total iterations with any outcome/stdout/stderr divergence.
    pub divergences: usize,
    /// B008 benchmark report JSON string for downstream gate consumers.
    pub b008_report_ndjson: String,
}

/// Usage text for `rabs-replay`.
#[must_use]
pub const fn usage() -> &'static str {
    "Usage:\n  rabs-replay inspect <invocations.ndjsonl> [--top N] [--json]\n  rabs-replay stratify <invocations.ndjsonl> [--per-stratum N] [--json]\n  rabs-replay pair --workdir <DIR> [--rabs-wrap <PATH>] [--rabs-socket <PATH>] [--iterations N] [--aa-check] [--json] -- <cmd...>\n"
}

/// Parse command-line arguments (excluding argv[0]).
///
/// # Errors
/// Invalid subcommand, missing required flags, or out-of-range numeric arguments.
pub fn parse_args(args: &[String]) -> Result<ReplayCliCommand, String> {
    let Some(first) = args.first().map(String::as_str) else {
        return Ok(ReplayCliCommand::Help);
    };
    match first {
        "-h" | "--help" | "help" => Ok(ReplayCliCommand::Help),
        "inspect" => parse_inspect_args(&args[1..]),
        "stratify" => parse_stratify_args(&args[1..]),
        "pair" => parse_pair_args(&args[1..]),
        other => Err(format!("unknown subcommand `{other}`\n{}", usage())),
    }
}

fn parse_inspect_args(args: &[String]) -> Result<ReplayCliCommand, String> {
    let mut path: Option<PathBuf> = None;
    let mut json = false;
    let mut top: usize = 10;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--top" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--top requires a positive integer".to_owned())?;
                top = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --top `{value}`"))?;
                if top == 0 {
                    return Err("--top must be >= 1".to_owned());
                }
            }
            "-h" | "--help" => return Ok(ReplayCliCommand::Help),
            flag if flag.starts_with('-') => {
                return Err(format!("unknown option `{flag}` for `inspect`"));
            }
            positional => {
                if path.is_some() {
                    return Err(format!("unexpected extra argument `{positional}`"));
                }
                path = Some(PathBuf::from(positional));
            }
        }
        i += 1;
    }
    let path = path.ok_or_else(|| "inspect requires <invocations.ndjsonl>".to_owned())?;
    Ok(ReplayCliCommand::Inspect { path, json, top })
}

fn parse_stratify_args(args: &[String]) -> Result<ReplayCliCommand, String> {
    let mut path: Option<PathBuf> = None;
    let mut per_stratum: usize = 3;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--per-stratum" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--per-stratum requires a positive integer".to_owned())?;
                per_stratum = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --per-stratum `{value}`"))?;
                if per_stratum == 0 {
                    return Err("--per-stratum must be >= 1".to_owned());
                }
            }
            "-h" | "--help" => return Ok(ReplayCliCommand::Help),
            flag if flag.starts_with('-') => {
                return Err(format!("unknown option `{flag}` for `stratify`"));
            }
            positional => {
                if path.is_some() {
                    return Err(format!("unexpected extra argument `{positional}`"));
                }
                path = Some(PathBuf::from(positional));
            }
        }
        i += 1;
    }
    let path = path.ok_or_else(|| "stratify requires <invocations.ndjsonl>".to_owned())?;
    Ok(ReplayCliCommand::Stratify {
        path,
        per_stratum,
        json,
    })
}

fn parse_pair_args(args: &[String]) -> Result<ReplayCliCommand, String> {
    let mut workdir: Option<PathBuf> = None;
    let mut rabs_wrap: Option<PathBuf> = None;
    let mut rabs_socket: Option<PathBuf> = None;
    let mut iterations: usize = 3;
    let mut aa_check = false;
    let mut json = false;
    let mut command: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                command = args[i + 1..].to_vec();
                break;
            }
            "--workdir" => {
                i += 1;
                workdir =
                    Some(PathBuf::from(args.get(i).ok_or_else(|| {
                        "--workdir requires a directory path".to_owned()
                    })?));
            }
            "--rabs-wrap" => {
                i += 1;
                rabs_wrap =
                    Some(PathBuf::from(args.get(i).ok_or_else(|| {
                        "--rabs-wrap requires a binary path".to_owned()
                    })?));
            }
            "--rabs-socket" => {
                i += 1;
                rabs_socket =
                    Some(PathBuf::from(args.get(i).ok_or_else(|| {
                        "--rabs-socket requires a socket path".to_owned()
                    })?));
            }
            "--iterations" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--iterations requires an integer 1..=50".to_owned())?;
                iterations = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --iterations `{value}`"))?;
                if !(1..=50).contains(&iterations) {
                    return Err("--iterations must be between 1 and 50".to_owned());
                }
            }
            "--aa-check" => aa_check = true,
            "--json" => json = true,
            "-h" | "--help" => return Ok(ReplayCliCommand::Help),
            other => return Err(format!("unknown option `{other}` for `pair`")),
        }
        i += 1;
    }
    let workdir = workdir.ok_or_else(|| "pair requires --workdir <DIR>".to_owned())?;
    if command.is_empty() {
        return Err("pair requires `-- <cmd...>`".to_owned());
    }
    Ok(ReplayCliCommand::Pair {
        workdir,
        rabs_wrap,
        rabs_socket,
        iterations,
        aa_check,
        json,
        command,
    })
}

fn read_non_empty_lines(path: &Path) -> Result<Vec<String>, String> {
    let file = File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            lines.push(trimmed.to_owned());
        }
    }
    Ok(lines)
}

fn exact_percentile(durations: &[u64], percent: u64) -> Option<u64> {
    if durations.is_empty() {
        return None;
    }
    let mut sorted = durations.to_vec();
    sorted.sort_unstable();
    let n = sorted.len() as u64;
    let position = (percent * n).div_ceil(100).max(1);
    Some(sorted[usize::try_from(position - 1).unwrap_or(0)])
}

/// Count how many records overlapped in time with at least one other record.
fn count_overlapping_records(records: &[SessionRecord]) -> usize {
    if records.len() < 2 {
        return 0;
    }
    let mut intervals: Vec<(u64, u64, usize)> = records
        .iter()
        .enumerate()
        .map(|(idx, r)| {
            let start = r.recorded_at_unix_ms;
            let end = start.saturating_add(r.duration_ms.max(1));
            (start, end, idx)
        })
        .collect();
    intervals.sort_by_key(|&(start, end, idx)| (start, end, idx));
    let mut overlapped = vec![false; records.len()];
    let mut max_end = intervals[0].1;
    let mut max_end_owner = intervals[0].2;
    for &(start, end, idx) in intervals.iter().skip(1) {
        if start < max_end {
            overlapped[idx] = true;
            overlapped[max_end_owner] = true;
        }
        if end > max_end {
            max_end = end;
            max_end_owner = idx;
        }
    }
    overlapped.into_iter().filter(|&flag| flag).count()
}

fn contains_secret_marker(value: &serde_json::Value) -> bool {
    let check_str = |s: &str| SECRET_MARKERS.iter().any(|marker| s.contains(marker));
    if value
        .get("cwd_redacted")
        .and_then(serde_json::Value::as_str)
        .is_some_and(check_str)
    {
        return true;
    }
    for key in ["argv_redacted", "env_redacted"] {
        if let Some(items) = value.get(key).and_then(serde_json::Value::as_array)
            && items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(check_str)
        {
            return true;
        }
    }
    false
}

/// Inspect a B002 NDJSONL invocation corpus file.
///
/// # Errors
/// File open/read errors.
#[allow(clippy::too_many_lines)]
pub fn inspect_corpus(path: &Path, top: usize) -> Result<CorpusInspectReport, String> {
    let lines = read_non_empty_lines(path)?;
    let line_refs: Vec<&str> = lines.iter().map(String::as_str).collect();

    let mut parsed_records = 0_usize;
    let mut malformed_lines = 0_usize;
    let mut redacted_argv_records = 0_usize;
    let mut raw_secret_marker_hits = 0_usize;
    let mut tool_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut exited_zero = 0_u64;
    let mut exited_nonzero = 0_u64;
    let mut signaled = 0_u64;
    let mut exit_codes: BTreeMap<i32, u64> = BTreeMap::new();
    let mut signals: BTreeMap<i32, u64> = BTreeMap::new();
    let mut ci_records = 0_u64;
    let mut non_ci_records = 0_u64;
    let mut earliest_unix_ms: Option<u64> = None;
    let mut latest_unix_ms: Option<u64> = None;
    let mut durations: Vec<u64> = Vec::new();
    let mut total_duration_ms = 0_u64;
    let mut session_records: Vec<SessionRecord> = Vec::new();
    let mut per_repo: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();

    for line in &lines {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            malformed_lines += 1;
            continue;
        };
        let (Some(tool), Some(cwd), Some(outcome_kind), Some(outcome_value), Some(argv)) = (
            value.get("tool").and_then(serde_json::Value::as_str),
            value
                .get("cwd_redacted")
                .and_then(serde_json::Value::as_str),
            value
                .get("outcome_kind")
                .and_then(serde_json::Value::as_str),
            value
                .get("outcome_value")
                .and_then(serde_json::Value::as_i64),
            value
                .get("argv_redacted")
                .and_then(serde_json::Value::as_array),
        ) else {
            malformed_lines += 1;
            continue;
        };
        let Ok(code_i32) = i32::try_from(outcome_value) else {
            malformed_lines += 1;
            continue;
        };
        let is_zero = match outcome_kind {
            "exited" => {
                *exit_codes.entry(code_i32).or_insert(0) += 1;
                if code_i32 == 0 {
                    exited_zero += 1;
                    true
                } else {
                    exited_nonzero += 1;
                    false
                }
            }
            "signaled" => {
                signaled += 1;
                *signals.entry(code_i32).or_insert(0) += 1;
                false
            }
            _ => {
                malformed_lines += 1;
                continue;
            }
        };
        parsed_records += 1;
        *tool_counts.entry(tool.to_owned()).or_insert(0) += 1;
        if argv
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|part| part.contains(REDACTED))
        {
            redacted_argv_records += 1;
        }
        if contains_secret_marker(&value) {
            raw_secret_marker_hits += 1;
        }
        if value
            .get("ci_env")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            ci_records += 1;
        } else {
            non_ci_records += 1;
        }
        let duration_ms = value
            .get("duration_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        durations.push(duration_ms);
        total_duration_ms = total_duration_ms.saturating_add(duration_ms);
        if let Some(ts) = value
            .get("recorded_at_unix_ms")
            .and_then(serde_json::Value::as_u64)
        {
            earliest_unix_ms = Some(earliest_unix_ms.map_or(ts, |prev| prev.min(ts)));
            latest_unix_ms = Some(latest_unix_ms.map_or(ts, |prev| prev.max(ts)));
        }
        if let Ok(rec) = parse_session_record(line) {
            session_records.push(rec);
        }
        let repo_entry = per_repo.entry(cwd.to_owned()).or_insert((0, 0, 0));
        repo_entry.0 += 1;
        repo_entry.1 = repo_entry.1.saturating_add(duration_ms);
        if is_zero {
            repo_entry.2 += 1;
        }
    }

    let min_duration_ms = durations.iter().copied().min();
    let max_duration_ms = durations.iter().copied().max();
    let duration_percentiles = percentiles(&durations);
    let p99_duration_ms = exact_percentile(&durations, 99);
    let peak = peak_overlap(&session_records);
    let overlapping_records = count_overlapping_records(&session_records);
    let intent_to_green = intent_to_green::reconstruct(&line_refs);
    let b003_audit = audit_multi_repo_corpus(&line_refs);

    let mut top_repos: Vec<RepoInspectRow> = per_repo
        .into_iter()
        .map(
            |(repo, (records, repo_duration_ms, repo_exited_zero))| RepoInspectRow {
                repo,
                records,
                total_duration_ms: repo_duration_ms,
                exited_zero: repo_exited_zero,
            },
        )
        .collect();
    top_repos.sort_by(|a, b| {
        b.records
            .cmp(&a.records)
            .then_with(|| b.total_duration_ms.cmp(&a.total_duration_ms))
            .then_with(|| a.repo.cmp(&b.repo))
    });
    top_repos.truncate(top);

    Ok(CorpusInspectReport {
        path: path.display().to_string(),
        non_empty_lines: lines.len(),
        parsed_records,
        malformed_lines,
        redacted_argv_records,
        raw_secret_marker_hits,
        tool_counts,
        exited_zero,
        exited_nonzero,
        signaled,
        exit_codes,
        signals,
        ci_records,
        non_ci_records,
        earliest_unix_ms,
        latest_unix_ms,
        min_duration_ms,
        max_duration_ms,
        total_duration_ms,
        duration_percentiles,
        p99_duration_ms,
        peak_overlap: peak,
        overlapping_records,
        intent_to_green,
        b003_audit,
        top_repos,
    })
}

/// Serialize a [`CorpusInspectReport`] to structured JSON.
#[must_use]
pub fn inspect_to_json(report: &CorpusInspectReport) -> serde_json::Value {
    let pct = |p: &Option<Percentiles>| match p {
        Some(p) => serde_json::json!({
            "p50_ms": p.p50_ms,
            "p90_ms": p.p90_ms,
            "p95_ms": p.p95_ms,
            "samples": p.samples,
        }),
        None => serde_json::Value::Null,
    };
    let top_repos: Vec<serde_json::Value> = report
        .top_repos
        .iter()
        .map(|row| {
            serde_json::json!({
                "repo": row.repo,
                "records": row.records,
                "total_duration_ms": row.total_duration_ms,
                "exited_zero": row.exited_zero,
            })
        })
        .collect();
    let tools_present: Vec<String> = report
        .b003_audit
        .tools_present
        .iter()
        .map(|tk| format!("{tk:?}"))
        .collect();
    let missing_tools: Vec<String> = report
        .b003_audit
        .missing_tools
        .iter()
        .map(|tk| format!("{tk:?}"))
        .collect();
    let exit_codes: serde_json::Map<String, serde_json::Value> = report
        .exit_codes
        .iter()
        .map(|(code, count)| (code.to_string(), serde_json::json!(count)))
        .collect();
    let signals: serde_json::Map<String, serde_json::Value> = report
        .signals
        .iter()
        .map(|(sig, count)| (sig.to_string(), serde_json::json!(count)))
        .collect();

    serde_json::json!({
        "schema": INSPECT_SCHEMA,
        "path": report.path,
        "non_empty_lines": report.non_empty_lines,
        "parsed_records": report.parsed_records,
        "malformed_lines": report.malformed_lines,
        "redacted_argv_records": report.redacted_argv_records,
        "raw_secret_marker_hits": report.raw_secret_marker_hits,
        "tool_counts": report.tool_counts,
        "outcomes": {
            "exited_zero": report.exited_zero,
            "exited_nonzero": report.exited_nonzero,
            "signaled": report.signaled,
            "exit_codes": exit_codes,
            "signals": signals,
        },
        "ci_env": {
            "ci_records": report.ci_records,
            "non_ci_records": report.non_ci_records,
        },
        "time_span_unix_ms": {
            "earliest": report.earliest_unix_ms,
            "latest": report.latest_unix_ms,
        },
        "durations_ms": {
            "min": report.min_duration_ms,
            "max": report.max_duration_ms,
            "total": report.total_duration_ms,
            "percentiles": pct(&report.duration_percentiles),
            "p99_ms": report.p99_duration_ms,
        },
        "concurrency": {
            "peak_overlap": report.peak_overlap,
            "overlapping_records": report.overlapping_records,
            "storm_ge_2": report.peak_overlap >= 2,
            "storm_ge_4": report.peak_overlap >= 4,
            "storm_ge_15": report.peak_overlap >= 15,
        },
        "intent_to_green": {
            "completed_loops": report.intent_to_green.loops.len(),
            "unresolved_loops": report.intent_to_green.unresolved_loops,
            "percentiles": pct(&report.intent_to_green.intent_to_green),
        },
        "b003_coverage": {
            "distinct_repos": report.b003_audit.repos.len(),
            "tools_present": tools_present,
            "missing_tools": missing_tools,
            "satisfies_two_repo_all_contexts": report.b003_audit.satisfies_b003(2),
        },
        "top_repos": top_repos,
    })
}

/// Format a [`CorpusInspectReport`] for terminal output.
#[must_use]
pub fn format_inspect(report: &CorpusInspectReport) -> String {
    let mut lines = vec![
        format!("rabs-replay inspect: {}", report.path),
        format!(
            "  records: {} parsed, {} malformed, {} redacted-argv, {} secret-marker-hits",
            report.parsed_records,
            report.malformed_lines,
            report.redacted_argv_records,
            report.raw_secret_marker_hits
        ),
        format!(
            "  outcomes: {} exited(0), {} exited(!=0), {} signaled",
            report.exited_zero, report.exited_nonzero, report.signaled
        ),
    ];
    if let Some(p) = &report.duration_percentiles {
        lines.push(format!(
            "  duration_ms: p50={} p90={} p95={} p99={} max={} (samples={}, total={}ms)",
            p.p50_ms,
            p.p90_ms,
            p.p95_ms,
            report.p99_duration_ms.unwrap_or(0),
            report.max_duration_ms.unwrap_or(0),
            p.samples,
            report.total_duration_ms
        ));
    }
    lines.push(format!(
        "  concurrency: peak_overlap={}, overlapping_records={}",
        report.peak_overlap, report.overlapping_records
    ));
    if let Some(itg) = &report.intent_to_green.intent_to_green {
        lines.push(format!(
            "  intent_to_green: {} completed loops (p50={}ms p90={}ms p95={}ms), {} unresolved",
            report.intent_to_green.loops.len(),
            itg.p50_ms,
            itg.p90_ms,
            itg.p95_ms,
            report.intent_to_green.unresolved_loops
        ));
    }
    lines.push(format!(
        "  b003 coverage: {} repos, {}/{} tool contexts present",
        report.b003_audit.repos.len(),
        report.b003_audit.tools_present.len(),
        rabs_protocol::invocation_record::ToolKind::ALL.len()
    ));
    for (tool, count) in &report.tool_counts {
        lines.push(format!("  tool {tool}: {count}"));
    }
    if !report.top_repos.is_empty() {
        lines.push("  top repos:".to_owned());
        for row in &report.top_repos {
            lines.push(format!(
                "    {} — {} records ({} green, {}ms total)",
                row.repo, row.records, row.exited_zero, row.total_duration_ms
            ));
        }
    }
    lines.join("\n")
}

/// Stratify a B002 corpus using B010 anti-recency stratified selection and emit
/// an honest B008 benchmark report shell.
///
/// # Errors
/// File open/read errors.
pub fn stratify_corpus(path: &Path, per_stratum: usize) -> Result<CorpusStratifyReport, String> {
    let lines = read_non_empty_lines(path)?;
    let line_refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let sample = select_stratified(&line_refs, per_stratum);
    let b003_audit = audit_multi_repo_corpus(&line_refs);

    let mut selected_durations = Vec::with_capacity(sample.selected_indexes.len());
    for &idx in &sample.selected_indexes {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&lines[idx])
            && let Some(dur) = value.get("duration_ms").and_then(serde_json::Value::as_u64)
        {
            selected_durations.push(dur);
        }
    }
    let selected_recorded_latency = percentiles(&selected_durations);
    let mut benchmark_report = BenchmarkReport::from_session(&SessionReport::default());
    benchmark_report.baseline_latency = selected_recorded_latency;
    benchmark_report.divergence.skipped = sample.skipped_malformed;

    Ok(CorpusStratifyReport {
        path: path.display().to_string(),
        per_stratum,
        total_lines: lines.len(),
        sample,
        b003_audit,
        selected_recorded_latency,
        benchmark_report,
    })
}

/// Serialize [`CorpusStratifyReport`] to JSON.
#[must_use]
pub fn stratify_to_json(report: &CorpusStratifyReport) -> serde_json::Value {
    let coverage_json: serde_json::Value = serde_json::from_str(
        &crate::stratified_selection::coverage_to_ndjson(&report.sample),
    )
    .unwrap_or(serde_json::Value::Null);
    let benchmark_json: serde_json::Value =
        serde_json::from_str(&report.benchmark_report.to_ndjson())
            .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "schema": STRATIFY_SCHEMA,
        "path": report.path,
        "per_stratum": report.per_stratum,
        "total_lines": report.total_lines,
        "strata_count": report.sample.coverage.len(),
        "selected_count": report.sample.selected_indexes.len(),
        "skipped_malformed": report.sample.skipped_malformed,
        "b003_repos": report.b003_audit.repos.len(),
        "b003_tools_present": report.b003_audit.tools_present.len(),
        "coverage": coverage_json,
        "benchmark_report": benchmark_json,
    })
}

/// Format [`CorpusStratifyReport`] for terminal output.
#[must_use]
pub fn format_stratify(report: &CorpusStratifyReport) -> String {
    let mut lines = vec![
        format!("rabs-replay stratify: {}", report.path),
        format!(
            "  {} lines -> {} strata -> {} selected (cap {}/stratum, {} malformed)",
            report.total_lines,
            report.sample.coverage.len(),
            report.sample.selected_indexes.len(),
            report.per_stratum,
            report.sample.skipped_malformed
        ),
    ];
    if let Some(p) = &report.selected_recorded_latency {
        lines.push(format!(
            "  selected baseline recorded latency: p50={}ms p90={}ms p95={}ms (samples={})",
            p.p50_ms, p.p90_ms, p.p95_ms, p.samples
        ));
    }
    for stratum in report.sample.coverage.iter().take(20) {
        lines.push(format!(
            "  stratum [{} | {} | {} | tc={}]: {}/{}",
            stratum.key.tool,
            stratum.key.duration.name(),
            stratum.key.repo,
            stratum.key.toolchain.as_deref().unwrap_or("none"),
            stratum.selected,
            stratum.population
        ));
    }
    if report.sample.coverage.len() > 20 {
        lines.push(format!(
            "  ... {} additional strata omitted in text view (use --json for all)",
            report.sample.coverage.len() - 20
        ));
    }
    lines.join("\n")
}

struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn create(label: &str) -> Result<Self, String> {
        let pid = std::process::id();
        let seq = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!("rabs-replay-{label}-{pid}-{nanos}-{seq}"));
        fs::create_dir_all(&path)
            .map_err(|e| format!("cannot create scratch dir {}: {e}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn outcome_label(outcome: Option<NormalizedOutcome>) -> String {
    match outcome {
        Some(NormalizedOutcome::Exited(code)) => format!("exited({code})"),
        Some(NormalizedOutcome::Signaled(sig)) => format!("signaled({sig})"),
        None => "unavailable".to_owned(),
    }
}

fn run_one_arm(
    path_name: &str,
    workdir: &Path,
    command: &[String],
    target_dir: &Path,
    rabs_wrap: Option<&Path>,
    rabs_socket: Option<&Path>,
) -> PathObservation {
    let started = Instant::now();
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .current_dir(workdir)
        .env("CARGO_TARGET_DIR", target_dir)
        .env("CARGO_INCREMENTAL", "0");
    if let Some(wrap) = rabs_wrap {
        cmd.env("RUSTC_WRAPPER", wrap);
    } else {
        cmd.env_remove("RUSTC_WRAPPER");
    }
    if let Some(socket) = rabs_socket {
        cmd.env("RABS_SOCKET", socket);
    } else {
        cmd.env_remove("RABS_SOCKET");
    }
    let output = cmd.output();
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
                path_name: path_name.to_owned(),
                availability: Availability::Executed,
                outcome: Some(outcome),
                stdout_digest: correlation_hash(&output.stdout),
                stderr_digest: correlation_hash(&output.stderr),
                duration_ms,
            }
        }
        Err(_) => PathObservation {
            path_name: path_name.to_owned(),
            availability: Availability::Unavailable,
            outcome: None,
            stdout_digest: 0,
            stderr_digest: 0,
            duration_ms,
        },
    }
}

fn spread_pct(durations: &[u64]) -> u64 {
    let (Some(min), Some(max)) = (
        durations.iter().copied().min(),
        durations.iter().copied().max(),
    ) else {
        return 0;
    };
    max.saturating_sub(min).saturating_mul(100) / min.max(1)
}

/// Run interleaved paired stock-vs-candidate (or A/A) iterations with isolated
/// per-iteration target directories and parity/noise-floor verification.
///
/// # Errors
/// Invalid workdir, missing command, or scratch directory creation failures.
pub fn run_pair_benchmark(
    workdir: &Path,
    rabs_wrap: Option<&Path>,
    rabs_socket: Option<&Path>,
    iterations: usize,
    aa_check: bool,
    command: &[String],
) -> Result<PairBenchmarkReport, String> {
    if !workdir.is_dir() {
        return Err(format!("workdir does not exist: {}", workdir.display()));
    }
    if command.is_empty() {
        return Err("command must not be empty".to_owned());
    }
    let effective_aa = aa_check || rabs_wrap.is_none();
    let cand_wrap = if effective_aa { None } else { rabs_wrap };
    let cand_socket = if effective_aa { None } else { rabs_socket };
    let cand_name = if effective_aa {
        "stock-aa"
    } else {
        "rabs-candidate"
    };
    let command_joined = command.join(" ");

    let mut session = SessionReport::default();
    let mut rows = Vec::with_capacity(iterations);
    let mut baseline_durations = Vec::with_capacity(iterations);
    let mut candidate_durations = Vec::with_capacity(iterations);

    for idx in 0..iterations {
        let base_scratch = ScratchDir::create("stock")?;
        let cand_scratch = ScratchDir::create("cand")?;
        let stock_first = idx.is_multiple_of(2);
        let (base_obs, cand_obs) = if stock_first {
            let base = run_one_arm("stock", workdir, command, &base_scratch.path, None, None);
            let cand = run_one_arm(
                cand_name,
                workdir,
                command,
                &cand_scratch.path,
                cand_wrap,
                cand_socket,
            );
            (base, cand)
        } else {
            let cand = run_one_arm(
                cand_name,
                workdir,
                command,
                &cand_scratch.path,
                cand_wrap,
                cand_socket,
            );
            let base = run_one_arm("stock", workdir, command, &base_scratch.path, None, None);
            (base, cand)
        };
        let invocation = ReplayCommand {
            command: command_joined.clone(),
            cwd: workdir.display().to_string(),
            recorded_outcome: base_obs.outcome.unwrap_or(NormalizedOutcome::Exited(-1)),
            recorded_duration_ms: base_obs.duration_ms,
        };
        let diff = compare(&invocation, &base_obs, &cand_obs);
        let diverged = diff.diverged();
        baseline_durations.push(base_obs.duration_ms);
        candidate_durations.push(cand_obs.duration_ms);
        rows.push(PairIterationRow {
            iteration: idx + 1,
            order: if stock_first {
                "stock-first"
            } else {
                "candidate-first"
            },
            baseline_duration_ms: base_obs.duration_ms,
            candidate_duration_ms: cand_obs.duration_ms,
            diverged,
            baseline_outcome: outcome_label(base_obs.outcome),
            candidate_outcome: outcome_label(cand_obs.outcome),
        });
        session.rows.push(diff);
    }

    let b008 = BenchmarkReport::from_session(&session);
    let baseline_spread_pct = spread_pct(&baseline_durations);
    let candidate_spread_pct = spread_pct(&candidate_durations);
    let noise_floor_invalidated =
        iterations >= 2 && (baseline_spread_pct > 30 || candidate_spread_pct > 30);

    let (median_delta_ms, speedup_permille) =
        match (&b008.baseline_latency, &b008.candidate_latency) {
            (Some(base), Some(cand)) => {
                let delta = i64::try_from(cand.p50_ms).unwrap_or(i64::MAX)
                    - i64::try_from(base.p50_ms).unwrap_or(i64::MAX);
                let speedup =
                    (cand.p50_ms > 0).then(|| base.p50_ms.saturating_mul(1_000) / cand.p50_ms);
                (delta, speedup)
            }
            _ => (0, None),
        };

    Ok(PairBenchmarkReport {
        workdir: workdir.display().to_string(),
        command: command_joined,
        aa_mode: effective_aa,
        rabs_wrap: cand_wrap.map(|p| p.display().to_string()),
        rabs_socket: cand_socket.map(|p| p.display().to_string()),
        iterations: rows,
        baseline_latency: b008.baseline_latency,
        candidate_latency: b008.candidate_latency,
        baseline_spread_pct,
        candidate_spread_pct,
        noise_floor_invalidated,
        median_delta_ms,
        speedup_permille,
        divergences: session.divergences(),
        b008_report_ndjson: b008.to_ndjson(),
    })
}

/// Serialize [`PairBenchmarkReport`] to JSON.
#[must_use]
pub fn pair_to_json(report: &PairBenchmarkReport) -> serde_json::Value {
    let pct = |p: &Option<Percentiles>| match p {
        Some(p) => serde_json::json!({
            "p50_ms": p.p50_ms,
            "p90_ms": p.p90_ms,
            "p95_ms": p.p95_ms,
            "samples": p.samples,
        }),
        None => serde_json::Value::Null,
    };
    let iterations: Vec<serde_json::Value> = report
        .iterations
        .iter()
        .map(|row| {
            serde_json::json!({
                "iteration": row.iteration,
                "order": row.order,
                "baseline_duration_ms": row.baseline_duration_ms,
                "candidate_duration_ms": row.candidate_duration_ms,
                "diverged": row.diverged,
                "baseline_outcome": row.baseline_outcome,
                "candidate_outcome": row.candidate_outcome,
            })
        })
        .collect();
    let b008: serde_json::Value =
        serde_json::from_str(&report.b008_report_ndjson).unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "schema": PAIR_SCHEMA,
        "workdir": report.workdir,
        "command": report.command,
        "aa_mode": report.aa_mode,
        "rabs_wrap": report.rabs_wrap,
        "rabs_socket": report.rabs_socket,
        "iterations": iterations,
        "baseline_latency": pct(&report.baseline_latency),
        "candidate_latency": pct(&report.candidate_latency),
        "baseline_spread_pct": report.baseline_spread_pct,
        "candidate_spread_pct": report.candidate_spread_pct,
        "noise_floor_invalidated": report.noise_floor_invalidated,
        "median_delta_ms": report.median_delta_ms,
        "speedup_permille": report.speedup_permille,
        "divergences": report.divergences,
        "b008_report": b008,
    })
}

/// Format [`PairBenchmarkReport`] for terminal output.
#[must_use]
pub fn format_pair(report: &PairBenchmarkReport) -> String {
    let mut lines = vec![
        format!(
            "rabs-replay pair ({}): `{}` in {}",
            if report.aa_mode {
                "A/A stock noise check"
            } else {
                "stock vs rabs-candidate"
            },
            report.command,
            report.workdir
        ),
        format!(
            "  iterations: {}, divergences: {}, spread: baseline={}% candidate={}%{}",
            report.iterations.len(),
            report.divergences,
            report.baseline_spread_pct,
            report.candidate_spread_pct,
            if report.noise_floor_invalidated {
                " [NOISE FLOOR INVALIDATED >30%]"
            } else {
                ""
            }
        ),
    ];
    if let (Some(base), Some(cand)) = (&report.baseline_latency, &report.candidate_latency) {
        let ratio = report.speedup_permille.map_or_else(
            || "n/a".to_owned(),
            |pm| format!("{}.{:02}x", pm / 1_000, (pm % 1_000) / 10),
        );
        lines.push(format!(
            "  p50: baseline={}ms candidate={}ms delta={:+}ms speedup={ratio}",
            base.p50_ms, cand.p50_ms, report.median_delta_ms
        ));
    }
    for row in &report.iterations {
        lines.push(format!(
            "  iter {} ({}): base={}ms [{}] cand={}ms [{}] diverged={}",
            row.iteration,
            row.order,
            row.baseline_duration_ms,
            row.baseline_outcome,
            row.candidate_duration_ms,
            row.candidate_outcome,
            row.diverged
        ));
    }
    lines.join("\n")
}

/// Execute `rabs-replay` from CLI arguments (excluding argv[0]), returning
/// stdout text on success or an error message on failure.
///
/// # Errors
/// Argument errors, I/O errors, or invalid workdir/command errors.
pub fn run_from_args(args: &[String]) -> Result<String, String> {
    match parse_args(args)? {
        ReplayCliCommand::Help => Ok(usage().to_owned()),
        ReplayCliCommand::Inspect { path, json, top } => {
            let report = inspect_corpus(&path, top)?;
            if json {
                serde_json::to_string_pretty(&inspect_to_json(&report))
                    .map_err(|e| format!("json encode failed: {e}"))
            } else {
                Ok(format_inspect(&report))
            }
        }
        ReplayCliCommand::Stratify {
            path,
            per_stratum,
            json,
        } => {
            let report = stratify_corpus(&path, per_stratum)?;
            if json {
                serde_json::to_string_pretty(&stratify_to_json(&report))
                    .map_err(|e| format!("json encode failed: {e}"))
            } else {
                Ok(format_stratify(&report))
            }
        }
        ReplayCliCommand::Pair {
            workdir,
            rabs_wrap,
            rabs_socket,
            iterations,
            aa_check,
            json,
            command,
        } => {
            let report = run_pair_benchmark(
                &workdir,
                rabs_wrap.as_deref(),
                rabs_socket.as_deref(),
                iterations,
                aa_check,
                &command,
            )?;
            if json {
                serde_json::to_string_pretty(&pair_to_json(&report))
                    .map_err(|e| format!("json encode failed: {e}"))
            } else {
                Ok(format_pair(&report))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_sample_corpus(dir: &Path) -> PathBuf {
        let path = dir.join("invocations.ndjsonl");
        let lines = [
            serde_json::json!({
                "schema": "rabs.invocation-record",
                "schema_version": 1,
                "tool": "CargoWholeCommand",
                "argv_correlation": 100_u64,
                "argv_redacted": ["cargo check --workspace"],
                "env_correlation": 1_u64,
                "env_redacted": ["RUSTUP_TOOLCHAIN=nightly-2026-08-31"],
                "cwd_redacted": "/work/repo_a",
                "outcome_kind": "exited",
                "outcome_value": 101,
                "duration_ms": 5_000_u64,
                "recorded_at_unix_ms": 1_000_u64,
                "ci_env": false,
            })
            .to_string(),
            serde_json::json!({
                "schema": "rabs.invocation-record",
                "schema_version": 1,
                "tool": "CargoWholeCommand",
                "argv_correlation": 101_u64,
                "argv_redacted": ["cargo check --workspace"],
                "env_correlation": 1_u64,
                "env_redacted": ["RUSTUP_TOOLCHAIN=nightly-2026-08-31"],
                "cwd_redacted": "/work/repo_a",
                "outcome_kind": "exited",
                "outcome_value": 0,
                "duration_ms": 2_000_u64,
                "recorded_at_unix_ms": 3_000_u64,
                "ci_env": false,
            })
            .to_string(),
            serde_json::json!({
                "schema": "rabs.invocation-record",
                "schema_version": 1,
                "tool": "Nextest",
                "argv_correlation": 102_u64,
                "argv_redacted": [format!("cargo nextest run --token={REDACTED}")],
                "env_correlation": 2_u64,
                "env_redacted": [],
                "cwd_redacted": "/work/repo_b",
                "outcome_kind": "signaled",
                "outcome_value": 9,
                "duration_ms": 15_000_u64,
                "recorded_at_unix_ms": 4_000_u64,
                "ci_env": true,
            })
            .to_string(),
            "not valid json".to_owned(),
        ];
        fs::write(&path, lines.join("\n")).unwrap();
        path
    }

    #[test]
    fn inspect_and_stratify_compute_exact_counts_overlap_and_malformed_lines() {
        let scratch = ScratchDir::create("cli-test").unwrap();
        let corpus = write_sample_corpus(&scratch.path);

        let inspected = inspect_corpus(&corpus, 5).unwrap();
        assert_eq!(inspected.non_empty_lines, 4);
        assert_eq!(inspected.parsed_records, 3);
        assert_eq!(inspected.malformed_lines, 1);
        assert_eq!(inspected.redacted_argv_records, 1);
        assert_eq!(inspected.raw_secret_marker_hits, 0);
        assert_eq!(inspected.exited_zero, 1);
        assert_eq!(inspected.exited_nonzero, 1);
        assert_eq!(inspected.signaled, 1);
        assert_eq!(inspected.ci_records, 1);
        assert_eq!(inspected.non_ci_records, 2);
        // Records overlap: [1000,6000), [3000,5000), [4000,19000) -> peak 3!
        assert_eq!(inspected.peak_overlap, 3);
        assert_eq!(inspected.overlapping_records, 3);
        assert_eq!(inspected.intent_to_green.loops.len(), 1);
        assert_eq!(inspected.intent_to_green.unresolved_loops, 1);
        assert_eq!(inspected.top_repos[0].repo, "/work/repo_a");
        assert_eq!(inspected.top_repos[0].records, 2);
        let json = inspect_to_json(&inspected);
        assert_eq!(json["schema"], INSPECT_SCHEMA);
        assert_eq!(json["concurrency"]["peak_overlap"], 3);

        let stratified = stratify_corpus(&corpus, 2).unwrap();
        assert_eq!(stratified.total_lines, 4);
        assert_eq!(stratified.sample.skipped_malformed, 1);
        assert_eq!(stratified.sample.selected_indexes.len(), 3);
        let strat_json = stratify_to_json(&stratified);
        assert_eq!(strat_json["schema"], STRATIFY_SCHEMA);
        assert!(
            strat_json["benchmark_report"]["first_diagnostic_latency"]["not_instrumented"]
                .is_string()
        );

        // Regression: unknown outcome_kind must not pollute tool/redaction/secret counts.
        let dirty_path = scratch.path.join("dirty.ndjsonl");
        let dirty_line = serde_json::json!({
            "schema": "rabs.invocation-record",
            "schema_version": 1,
            "tool": "BogusTool",
            "argv_redacted": [format!("cmd ghp_secret {REDACTED}")],
            "cwd_redacted": "/work/dirty",
            "outcome_kind": "unknown-kind",
            "outcome_value": 1,
            "duration_ms": 100_u64,
            "recorded_at_unix_ms": 1_000_u64,
            "ci_env": false,
        })
        .to_string();
        fs::write(&dirty_path, dirty_line).unwrap();
        let dirty = inspect_corpus(&dirty_path, 5).unwrap();
        assert_eq!(dirty.parsed_records, 0);
        assert_eq!(dirty.malformed_lines, 1);
        assert!(dirty.tool_counts.is_empty());
        assert_eq!(dirty.redacted_argv_records, 0);
        assert_eq!(dirty.raw_secret_marker_hits, 0);
        assert_eq!(spread_pct(&[0, 5]), 500);
        assert_eq!(spread_pct(&[0, 0]), 0);
    }

    #[test]
    fn pair_benchmark_runs_interleaved_aa_with_zero_divergences() {
        let scratch = ScratchDir::create("pair-test").unwrap();
        let report = run_pair_benchmark(
            &scratch.path,
            None,
            None,
            2,
            true,
            &[
                "sh".to_owned(),
                "-c".to_owned(),
                "printf parity-ok".to_owned(),
            ],
        )
        .unwrap();
        assert!(report.aa_mode);
        assert_eq!(report.iterations.len(), 2);
        assert_eq!(report.iterations[0].order, "stock-first");
        assert_eq!(report.iterations[1].order, "candidate-first");
        assert_eq!(report.divergences, 0);
        let json = pair_to_json(&report);
        assert_eq!(json["schema"], PAIR_SCHEMA);
        assert_eq!(json["divergences"], 0);
        assert!(format_pair(&report).contains("divergences: 0"));
    }

    #[test]
    fn cli_argument_parser_validates_all_subcommands() {
        let inspect = parse_args(&[
            "inspect".to_owned(),
            "corpus.ndjsonl".to_owned(),
            "--top".to_owned(),
            "5".to_owned(),
            "--json".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            inspect,
            ReplayCliCommand::Inspect {
                path: PathBuf::from("corpus.ndjsonl"),
                json: true,
                top: 5,
            }
        );
        let pair = parse_args(&[
            "pair".to_owned(),
            "--workdir".to_owned(),
            "/tmp".to_owned(),
            "--iterations".to_owned(),
            "4".to_owned(),
            "--aa-check".to_owned(),
            "--".to_owned(),
            "true".to_owned(),
        ])
        .unwrap();
        assert!(matches!(
            pair,
            ReplayCliCommand::Pair {
                iterations: 4,
                aa_check: true,
                ..
            }
        ));
        assert!(
            parse_args(&["pair".to_owned(), "--workdir".to_owned(), "/tmp".to_owned()]).is_err()
        );
        assert!(
            parse_args(&[
                "inspect".to_owned(),
                "x".to_owned(),
                "--top".to_owned(),
                "0".to_owned()
            ])
            .is_err()
        );
    }
}
