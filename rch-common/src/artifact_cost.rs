//! File-count-aware artifact retrieval cost model and manifest advice
//! (bd-session-history-remediation-ocv9i.9.2).
//!
//! Artifact retrieval that expands a broad recursive glob (`target/**/*`) can
//! match *tens of thousands* of files — most of them intermediate build cruft —
//! turning a quick build into a multi-minute rsync. This module measures the
//! retrieval ([`ArtifactCostReport`]: file count, bytes, files/sec, bytes/sec,
//! and per-phase wall-clock timings) and, before the transfer, advises whether
//! a glob is too broad ([`assess_glob_expansion`]) — recommending a manifest or
//! explicit artifact list when one would suffice. All pure + deterministic.

use serde::{Deserialize, Serialize};

/// File count at/above which a broad recursive glob earns a warning.
pub const GLOB_WARN_THRESHOLD: u64 = 10_000;
/// File count at/above which a broad recursive glob is refused in favor of a
/// manifest / explicit list.
pub const GLOB_REFUSE_THRESHOLD: u64 = 50_000;

/// Per-phase wall-clock timings for an artifact retrieval, in milliseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactPhaseTimings {
    pub collection_ms: u64,
    pub compression_ms: u64,
    pub transfer_ms: u64,
    pub extract_ms: u64,
}

impl ArtifactPhaseTimings {
    /// Total wall-clock across all phases.
    #[must_use]
    pub const fn total_ms(&self) -> u64 {
        self.collection_ms
            .saturating_add(self.compression_ms)
            .saturating_add(self.transfer_ms)
            .saturating_add(self.extract_ms)
    }
}

/// How retrieval should be performed, given the cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalMode {
    /// A glob is fine at this scale.
    Glob,
    /// Prefer a manifest of exact files.
    Manifest,
}

/// Advice on whether a glob expansion is acceptable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "advice")]
pub enum GlobAdvice {
    /// Proceed with the glob.
    Proceed,
    /// Proceed, but the expansion is large — a manifest would be cheaper.
    Warn {
        file_count: u64,
        threshold: u64,
        suggestion: String,
    },
    /// Refuse the glob — far too broad; require a manifest / explicit list.
    Refuse {
        file_count: u64,
        hard_cap: u64,
        suggestion: String,
    },
}

impl GlobAdvice {
    /// Whether retrieval should not proceed as a glob.
    #[must_use]
    pub const fn is_refused(&self) -> bool {
        matches!(self, Self::Refuse { .. })
    }

    /// The recommended retrieval mode.
    #[must_use]
    pub const fn recommended_mode(&self) -> RetrievalMode {
        match self {
            Self::Proceed => RetrievalMode::Glob,
            Self::Warn { .. } | Self::Refuse { .. } => RetrievalMode::Manifest,
        }
    }
}

/// Heuristic: is this pattern a broad recursive glob (`**` anywhere, or a bare
/// directory wildcard like `target/*`)? Such patterns are the ones that blow up
/// to tens of thousands of files.
#[must_use]
pub fn is_broad_recursive_glob(pattern: &str) -> bool {
    pattern.contains("**") || pattern.ends_with("/*") || pattern.ends_with('/')
}

/// Assess whether a glob's expansion (`file_count`) is acceptable. Only *broad
/// recursive* globs are warned/refused — an explicit pattern matching many
/// files is the operator's deliberate choice.
#[must_use]
pub fn assess_glob_expansion(pattern: &str, file_count: u64) -> GlobAdvice {
    if !is_broad_recursive_glob(pattern) {
        return GlobAdvice::Proceed;
    }
    if file_count >= GLOB_REFUSE_THRESHOLD {
        return GlobAdvice::Refuse {
            file_count,
            hard_cap: GLOB_REFUSE_THRESHOLD,
            suggestion:
                "use a manifest or explicit artifact list instead of a broad recursive glob"
                    .to_string(),
        };
    }
    if file_count >= GLOB_WARN_THRESHOLD {
        return GlobAdvice::Warn {
            file_count,
            threshold: GLOB_WARN_THRESHOLD,
            suggestion: "a manifest of exact artifacts would transfer far fewer files".to_string(),
        };
    }
    GlobAdvice::Proceed
}

/// A measured artifact-retrieval cost report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactCostReport {
    pub file_count: u64,
    pub total_bytes: u64,
    pub files_per_sec: f64,
    pub bytes_per_sec: f64,
    pub timings: ArtifactPhaseTimings,
    pub wall_clock_ms: u64,
}

impl ArtifactCostReport {
    /// Human-readable cost summary.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "artifact retrieval cost: {} files, {} bytes in {} ms \
             ({:.0} files/s, {:.0} bytes/s) \
             [collect {}ms, compress {}ms, transfer {}ms, extract {}ms]",
            self.file_count,
            self.total_bytes,
            self.wall_clock_ms,
            self.files_per_sec,
            self.bytes_per_sec,
            self.timings.collection_ms,
            self.timings.compression_ms,
            self.timings.transfer_ms,
            self.timings.extract_ms,
        )
    }
}

/// Compute the cost report from a measured retrieval. Rates are 0.0 when no
/// time elapsed (avoids a divide-by-zero / infinity).
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn compute_artifact_cost(
    file_count: u64,
    total_bytes: u64,
    timings: ArtifactPhaseTimings,
) -> ArtifactCostReport {
    let wall_clock_ms = timings.total_ms();
    let secs = wall_clock_ms as f64 / 1000.0;
    let (files_per_sec, bytes_per_sec) = if secs > 0.0 {
        (file_count as f64 / secs, total_bytes as f64 / secs)
    } else {
        (0.0, 0.0)
    };
    ArtifactCostReport {
        file_count,
        total_bytes,
        files_per_sec,
        bytes_per_sec,
        timings,
        wall_clock_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timings_total_is_sum_of_phases() {
        let t = ArtifactPhaseTimings {
            collection_ms: 100,
            compression_ms: 200,
            transfer_ms: 300,
            extract_ms: 50,
        };
        assert_eq!(t.total_ms(), 650);
    }

    #[test]
    fn cost_rates_computed_from_timings() {
        let t = ArtifactPhaseTimings {
            collection_ms: 0,
            compression_ms: 0,
            transfer_ms: 2000,
            extract_ms: 0,
        };
        // 1000 files, 2_000_000 bytes in 2 s -> 500 files/s, 1_000_000 bytes/s.
        let r = compute_artifact_cost(1000, 2_000_000, t);
        assert_eq!(r.wall_clock_ms, 2000);
        assert!((r.files_per_sec - 500.0).abs() < 1e-6);
        assert!((r.bytes_per_sec - 1_000_000.0).abs() < 1e-6);
    }

    #[test]
    fn zero_time_yields_zero_rates_not_infinity() {
        let r = compute_artifact_cost(5, 100, ArtifactPhaseTimings::default());
        assert_eq!(r.wall_clock_ms, 0);
        assert_eq!(r.files_per_sec, 0.0);
        assert_eq!(r.bytes_per_sec, 0.0);
        assert!(r.files_per_sec.is_finite());
    }

    #[test]
    fn broad_recursive_glob_detection() {
        assert!(is_broad_recursive_glob("target/**/*.rlib"));
        assert!(is_broad_recursive_glob("target/debug/*"));
        assert!(is_broad_recursive_glob("target/debug/"));
        assert!(!is_broad_recursive_glob("target/debug/app"));
        assert!(!is_broad_recursive_glob(".rch-target/debug/libfoo.rlib"));
    }

    #[test]
    fn many_small_files_under_broad_glob_warns() {
        // The classic case: a target dir with ~15k intermediate files.
        let advice = assess_glob_expansion("target/**/*", 15_000);
        match advice {
            GlobAdvice::Warn {
                file_count,
                threshold,
                ..
            } => {
                assert_eq!(file_count, 15_000);
                assert_eq!(threshold, GLOB_WARN_THRESHOLD);
            }
            other => panic!("expected warn, got {other:?}"),
        }
        assert_eq!(advice.recommended_mode(), RetrievalMode::Manifest);
        assert!(!advice.is_refused());
    }

    #[test]
    fn enormous_broad_glob_is_refused() {
        let advice = assess_glob_expansion("target/**/*", 80_000);
        assert!(advice.is_refused());
        assert_eq!(advice.recommended_mode(), RetrievalMode::Manifest);
        if let GlobAdvice::Refuse { hard_cap, .. } = advice {
            assert_eq!(hard_cap, GLOB_REFUSE_THRESHOLD);
        } else {
            panic!("expected refuse");
        }
    }

    #[test]
    fn explicit_pattern_never_warns_even_with_many_files() {
        // A non-recursive, explicit pattern is the operator's deliberate choice.
        let advice = assess_glob_expansion("target/debug/app", 99_999);
        assert_eq!(advice, GlobAdvice::Proceed);
        assert_eq!(advice.recommended_mode(), RetrievalMode::Glob);
    }

    #[test]
    fn small_broad_glob_proceeds() {
        assert_eq!(
            assess_glob_expansion("target/**/*.rlib", 200),
            GlobAdvice::Proceed
        );
    }

    #[test]
    fn report_render_and_serde_are_stable() {
        let r = compute_artifact_cost(
            1000,
            2_000_000,
            ArtifactPhaseTimings {
                collection_ms: 10,
                compression_ms: 20,
                transfer_ms: 1970,
                extract_ms: 0,
            },
        );
        let text = r.render();
        assert!(text.contains("1000 files"));
        assert!(text.contains("transfer 1970ms"));
        // Stable JSON diagnostics (field-name freeze).
        let v = serde_json::to_value(&r).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "bytes_per_sec",
                "file_count",
                "files_per_sec",
                "timings",
                "total_bytes",
                "wall_clock_ms",
            ]
        );
        let back: ArtifactCostReport = serde_json::from_value(v).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn glob_advice_serializes_with_tagged_variant() {
        let v = serde_json::to_value(assess_glob_expansion("target/**/*", 15_000)).unwrap();
        assert_eq!(v["advice"], "warn");
        assert_eq!(v["file_count"], 15_000);
    }
}
