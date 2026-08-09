//! Stratified automatic replay selection (bead B010; consumed by the
//! B013 CI regression gate).
//!
//! Shadow and regression runs must cover the DISTRIBUTION of recorded
//! work, not whatever happened recently: a corpus dominated by
//! yesterday's sub-second `cargo check` storm would otherwise starve
//! the rare-but-critical strata (long nextest runs, cross-toolchain
//! builds) out of every gate run. Selection here:
//!
//! - stratifies by the four B010 axes — action class (the recorded
//!   tool), duration bucket (documented boundaries below), repo (the
//!   redacted cwd), and toolchain (the recorded `RUSTUP_TOOLCHAIN`
//!   env line when present, `None` otherwise — absence is a stratum,
//!   not a guess);
//! - takes up to `per_stratum` records from EVERY stratum; strata
//!   smaller than the cap are included whole;
//! - picks by even spacing across the stratum's arrival order —
//!   deterministic (same corpus → same sample, no seed to lose) and
//!   explicitly anti-recency: the earliest and latest records of a
//!   stratum are always eligible;
//! - documents coverage: the emitted report lists every stratum with
//!   population and selected counts, so "the gate ran the corpus" is
//!   checkable per stratum, never a vibe.

use crate::ReplaySkip;

/// Documented duration buckets (whole-command wall time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DurationBucket {
    /// `< 1s` — classification/no-op territory.
    SubSecond,
    /// `1s ..< 10s` — small incremental builds.
    Seconds,
    /// `10s ..< 60s` — medium builds and test runs.
    TensOfSeconds,
    /// `>= 60s` — long builds, full test suites.
    Minutes,
}

impl DurationBucket {
    /// Bucket a duration.
    #[must_use]
    pub const fn of(duration_ms: u64) -> Self {
        match duration_ms {
            0..=999 => Self::SubSecond,
            1000..=9_999 => Self::Seconds,
            10_000..=59_999 => Self::TensOfSeconds,
            _ => Self::Minutes,
        }
    }

    /// Stable name for coverage reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SubSecond => "sub-second",
            Self::Seconds => "seconds",
            Self::TensOfSeconds => "tens-of-seconds",
            Self::Minutes => "minutes",
        }
    }
}

/// One stratum identity across the four B010 axes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StratumKey {
    /// Recorded tool (action class).
    pub tool: String,
    /// Duration bucket.
    pub duration: DurationBucket,
    /// Redacted repo path (cwd).
    pub repo: String,
    /// Recorded toolchain, when the corpus captured one.
    pub toolchain: Option<String>,
}

/// Parse the stratification axes from one corpus line.
///
/// # Errors
/// [`ReplaySkip::MalformedRecord`] naming the missing field.
pub fn stratum_of(line: &str) -> Result<StratumKey, ReplaySkip> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| ReplaySkip::MalformedRecord {
            detail: e.to_string(),
        })?;
    let text = |name: &str| {
        value[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| ReplaySkip::MalformedRecord {
                detail: format!("{name} missing"),
            })
    };
    let toolchain = value["env_redacted"].as_array().and_then(|lines| {
        lines.iter().find_map(|l| {
            l.as_str()
                .and_then(|s| s.strip_prefix("RUSTUP_TOOLCHAIN="))
                .map(str::to_owned)
        })
    });
    Ok(StratumKey {
        tool: text("tool")?,
        duration: DurationBucket::of(value["duration_ms"].as_u64().unwrap_or(0)),
        repo: text("cwd_redacted")?,
        toolchain,
    })
}

/// Per-stratum coverage in the selection report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StratumCoverage {
    /// The stratum.
    pub key: StratumKey,
    /// Records in the corpus belonging to this stratum.
    pub population: usize,
    /// Records selected from it.
    pub selected: usize,
}

/// The stratified sample: selected line indexes + documented coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StratifiedSample {
    /// Indexes into the input line slice, ascending.
    pub selected_indexes: Vec<usize>,
    /// Coverage per stratum, sorted by key.
    pub coverage: Vec<StratumCoverage>,
    /// Lines that failed to parse (counted, never silently dropped).
    pub skipped_malformed: usize,
}

/// Select up to `per_stratum` records from every stratum, evenly
/// spaced across each stratum's arrival order. Deterministic.
#[must_use]
pub fn select_stratified(lines: &[&str], per_stratum: usize) -> StratifiedSample {
    let mut strata: Vec<(StratumKey, Vec<usize>)> = Vec::new();
    let mut skipped_malformed = 0;
    for (index, line) in lines.iter().enumerate() {
        match stratum_of(line) {
            Ok(key) => {
                if let Some((_, members)) = strata.iter_mut().find(|(k, _)| *k == key) {
                    members.push(index);
                } else {
                    strata.push((key, vec![index]));
                }
            }
            Err(_) => skipped_malformed += 1,
        }
    }
    strata.sort_by(|(a, _), (b, _)| a.cmp(b));
    let mut selected_indexes = Vec::new();
    let mut coverage = Vec::new();
    for (key, members) in strata {
        let take = per_stratum.min(members.len());
        // Even spacing across arrival order: for k picks over n
        // members, pick positions floor(i*n/k) — the first record is
        // always eligible and picks span the whole time range (the
        // anti-recency property).
        let mut picked = Vec::with_capacity(take);
        for i in 0..take {
            picked.push(members[i * members.len() / take]);
        }
        picked.dedup();
        coverage.push(StratumCoverage {
            key,
            population: members.len(),
            selected: picked.len(),
        });
        selected_indexes.extend(picked);
    }
    selected_indexes.sort_unstable();
    StratifiedSample {
        selected_indexes,
        coverage,
        skipped_malformed,
    }
}

/// The documented-coverage NDJSON the CI gate stores next to its run.
#[must_use]
pub fn coverage_to_ndjson(sample: &StratifiedSample) -> String {
    let strata: Vec<serde_json::Value> = sample
        .coverage
        .iter()
        .map(|c| {
            serde_json::json!({
                "tool": c.key.tool,
                "duration_bucket": c.key.duration.name(),
                "repo": c.key.repo,
                "toolchain": c.key.toolchain,
                "population": c.population,
                "selected": c.selected,
            })
        })
        .collect();
    serde_json::json!({
        "schema": "rabs.replay-selection-coverage",
        "schema_version": 1,
        "total_selected": sample.selected_indexes.len(),
        "skipped_malformed": sample.skipped_malformed,
        "strata": strata,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(tool: &str, duration_ms: u64, repo: &str, toolchain: Option<&str>) -> String {
        let env: Vec<String> = toolchain
            .map(|t| vec![format!("RUSTUP_TOOLCHAIN={t}")])
            .unwrap_or_default();
        serde_json::json!({
            "tool": tool,
            "duration_ms": duration_ms,
            "cwd_redacted": repo,
            "env_redacted": env,
        })
        .to_string()
    }

    #[test]
    fn b010_selection_covers_the_distribution_not_the_majority_class() {
        // A skewed corpus: 100 recent sub-second checks in repo-a
        // dominating 3 long nextest runs in repo-b and 5 nightly rustc
        // builds. Recency/majority sampling would take checks only;
        // stratified selection covers ALL strata.
        let mut lines: Vec<String> = Vec::new();
        for _ in 0..100 {
            lines.push(line("CargoWholeCommand", 500, "~/repo-a", None));
        }
        for _ in 0..3 {
            lines.push(line("Nextest", 120_000, "~/repo-b", None));
        }
        for _ in 0..5 {
            lines.push(line("Rustc", 5_000, "~/repo-a", Some("nightly")));
        }
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let sample = select_stratified(&refs, 10);
        assert_eq!(sample.coverage.len(), 3, "three strata, all covered");
        for c in &sample.coverage {
            assert!(c.selected > 0, "stratum {:?} starved", c.key);
        }
        // The cap binds the big stratum; small strata are whole.
        let big = sample
            .coverage
            .iter()
            .find(|c| c.population == 100)
            .unwrap();
        assert_eq!(big.selected, 10);
        let nextest = sample.coverage.iter().find(|c| c.population == 3).unwrap();
        assert_eq!(nextest.selected, 3, "small strata are included whole");
        // Toolchain is an axis: the nightly stratum is distinct.
        assert!(
            sample
                .coverage
                .iter()
                .any(|c| c.key.toolchain.as_deref() == Some("nightly"))
        );
        // Determinism: same corpus, same sample.
        assert_eq!(select_stratified(&refs, 10), sample);
    }

    #[test]
    fn b010_even_spacing_defeats_recency_bias() {
        // One stratum of 90 records in arrival order; 9 picks must
        // span the whole range — first third, middle, last third all
        // represented — never the last 9.
        let lines: Vec<String> = (0..90)
            .map(|_| line("CargoWholeCommand", 500, "~/r", None))
            .collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let sample = select_stratified(&refs, 9);
        assert_eq!(sample.selected_indexes.len(), 9);
        assert!(sample.selected_indexes.iter().any(|i| *i < 30));
        assert!(sample.selected_indexes.iter().any(|i| (30..60).contains(i)));
        assert!(sample.selected_indexes.iter().any(|i| *i >= 60));
        assert_eq!(sample.selected_indexes[0], 0, "earliest record eligible");
    }

    #[test]
    fn b010_duration_buckets_have_documented_boundaries() {
        assert_eq!(DurationBucket::of(0), DurationBucket::SubSecond);
        assert_eq!(DurationBucket::of(999), DurationBucket::SubSecond);
        assert_eq!(DurationBucket::of(1000), DurationBucket::Seconds);
        assert_eq!(DurationBucket::of(9_999), DurationBucket::Seconds);
        assert_eq!(DurationBucket::of(10_000), DurationBucket::TensOfSeconds);
        assert_eq!(DurationBucket::of(59_999), DurationBucket::TensOfSeconds);
        assert_eq!(DurationBucket::of(60_000), DurationBucket::Minutes);
    }

    #[test]
    fn b010_coverage_report_documents_every_stratum_and_the_skips() {
        let lines = [
            line("Rustc", 100, "~/r", None),
            "not json".to_owned(),
            line("Rustc", 100_000, "~/r", None),
        ];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let sample = select_stratified(&refs, 5);
        assert_eq!(sample.skipped_malformed, 1);
        let ndjson = coverage_to_ndjson(&sample);
        let parsed: serde_json::Value = serde_json::from_str(&ndjson).unwrap();
        assert_eq!(parsed["schema"], "rabs.replay-selection-coverage");
        assert_eq!(parsed["skipped_malformed"], 1);
        assert_eq!(parsed["total_selected"], 2);
        let strata = parsed["strata"].as_array().unwrap();
        assert_eq!(strata.len(), 2);
        assert_eq!(strata[0]["population"], 1);
        assert_eq!(strata[0]["selected"], 1);
        assert!(
            strata.iter().any(|s| s["duration_bucket"] == "sub-second")
                && strata.iter().any(|s| s["duration_bucket"] == "minutes")
        );
    }
}
