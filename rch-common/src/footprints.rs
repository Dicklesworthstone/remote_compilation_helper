//! Operator-visible learned build disk footprints.
//!
//! These summaries describe estimation evidence, not live disk reservations.
//! Forgetting evidence changes future estimates only; active build ownership,
//! worker floors, and growth enforcement are separate contracts.

use serde::{Deserialize, Serialize};

/// Validate a deliberately narrow operator selection. Project whitespace is
/// part of its identity; command whitespace is normalized by the footprint key.
pub fn validate_selection(project: &str, command: Option<&str>) -> Result<(), &'static str> {
    if project.trim().is_empty() {
        return Err("project must not be empty");
    }
    if project.len() > 4096 {
        return Err("project exceeds 4096 bytes");
    }
    if project.chars().any(char::is_control) {
        return Err("project must not contain control characters");
    }
    if let Some(command) = command {
        if command.trim().is_empty() {
            return Err("command must not be empty");
        }
        if command.len() > 16384 {
            return Err("command exceeds 16384 bytes");
        }
        if command.chars().any(char::is_control) {
            return Err("command must not contain control characters");
        }
    }
    Ok(())
}

/// The measurement namespace that contributed a footprint record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FootprintSource {
    /// Attributed allocation for one exact command; retired v2 rows may contain
    /// whole-pool totals that cannot establish a current estimate.
    Exact,
    /// Allocation evidence shared by a compilation kind and optional scope.
    Family,
    /// Older filesystem-free-space observations, with no exact command.
    Legacy,
    /// Conditional additional allocation for an exact command and endpoint.
    Warm,
}

/// Cargo workload scope used by the shared cold-budget policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FootprintScope {
    Narrow,
    Wide,
}

/// One recognized footprint key, with stale samples visible in the total count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FootprintRecord {
    pub source: FootprintSource,
    pub version: u32,
    /// Historical exact v2 and scoped-family v3 rows are retained for inspection
    /// and reset, but never contribute to current admission estimates.
    pub retired: bool,
    pub kind: Option<String>,
    pub scope: Option<FootprintScope>,
    pub command: Option<String>,
    /// Show the endpoint host without exposing SSH identity-file paths.
    pub endpoint_host: Option<String>,
    pub sample_count: usize,
    pub valid_sample_count: usize,
    pub complete_sample_count: usize,
    pub high_water_gib: Option<f64>,
    /// Latest timestamp among valid samples, not a future or expired timestamp.
    pub latest_observed_unix: Option<i64>,
    pub pool_count: usize,
    /// Fresh, anchored pools with complete valid samples. Actual warm admission
    /// still requires the worker to verify an exact retained-pool proof.
    pub qualified_pool_count: usize,
}

/// A read-only view scoped to one normalized project and optional exact command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FootprintSnapshot {
    pub project: String,
    pub command: Option<String>,
    pub observed_unix: i64,
    pub persistence_enabled: bool,
    pub cold_prior_gib: Option<f64>,
    pub learned_gib: Option<f64>,
    pub growth_budget_gib: Option<u32>,
    pub records: Vec<FootprintRecord>,
}

/// Counts of evidence removed by an explicit, scoped operator reset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FootprintReset {
    pub project: String,
    pub command: Option<String>,
    pub removed_entries: usize,
    pub removed_pools: usize,
    pub removed_samples: usize,
    /// True only when the candidate book was persisted before publishing it
    /// in memory. Explicitly in-memory histories return false.
    pub persisted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footprint_selection_keeps_literal_project_identity_and_bounds_inputs() {
        for project in ["engine", " engine ", "engine[1]*", "équipe"] {
            assert_eq!(validate_selection(project, Some(" cargo test ")), Ok(()));
        }
        assert_eq!(validate_selection(&"p".repeat(4096), None), Ok(()));
        assert_eq!(
            validate_selection("engine", Some(&"c".repeat(16384))),
            Ok(())
        );
        for project in ["", " ", "engine\n", "engine\t", "engine\0", "engine\u{85}"] {
            assert!(validate_selection(project, None).is_err(), "{project:?}");
        }
        assert!(validate_selection(&"p".repeat(4097), None).is_err());
        assert!(validate_selection(&"é".repeat(2049), None).is_err());
        for command in ["", "  ", "cargo\ntest", "cargo test\t", "cargo test\0"] {
            assert!(validate_selection("engine", Some(command)).is_err());
        }
        assert!(validate_selection("engine", Some(&"c".repeat(16385))).is_err());
    }
}
