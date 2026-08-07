//! Key-fragmentation analyzer with costed convergence
//! recommendations (bead Q011; plan §104; consumes the F018
//! histograms).
//!
//! The F018 aggregator says WHICH component fragments; this analyzer
//! says WHAT IT COSTS and what to do about it:
//!
//! - eleven fragmentation categories (closed registry, pinned);
//! - the cost model is deterministic integer arithmetic: a logical
//!   action compiled under `v` distinct variants did `v` compiles
//!   where one would have served — waste is
//!   `(v - 1) × logical_actions × mean_action_cost_ms`;
//! - the report emits one COSTED recommendation per fragmented
//!   category, sorted by waste (largest first), each naming its
//!   remediation — and a CONVERGED category (one variant) emits NO
//!   row: the analyzer prices problems, it does not scold.

/// The eleven fragmentation categories (closed registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum FragmentationCategory {
    DependencyVersionSpread,
    FeatureDrift,
    LockfileInconsistency,
    ToolchainDrift,
    RustflagsProfileDivergence,
    TargetCpuDrift,
    PathPolicyDrift,
    CommandPaletteDrift,
    BuildScriptVolatility,
    PlatformFragmentation,
    DuplicateSnapshots,
}

/// Every category, in registry order (count pinned by test).
pub const ALL_CATEGORIES: [FragmentationCategory; 11] = [
    FragmentationCategory::DependencyVersionSpread,
    FragmentationCategory::FeatureDrift,
    FragmentationCategory::LockfileInconsistency,
    FragmentationCategory::ToolchainDrift,
    FragmentationCategory::RustflagsProfileDivergence,
    FragmentationCategory::TargetCpuDrift,
    FragmentationCategory::PathPolicyDrift,
    FragmentationCategory::CommandPaletteDrift,
    FragmentationCategory::BuildScriptVolatility,
    FragmentationCategory::PlatformFragmentation,
    FragmentationCategory::DuplicateSnapshots,
];

impl FragmentationCategory {
    /// The convergence remediation for this category.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::DependencyVersionSpread => {
                "converge duplicate dependency versions (cargo update -p / workspace deps table)"
            }
            Self::FeatureDrift => {
                "unify feature sets across the workspace (cargo-hakari workspace-hack crate)"
            }
            Self::LockfileInconsistency => "commit one lockfile and build with --locked everywhere",
            Self::ToolchainDrift => "pin one toolchain in rust-toolchain.toml fleet-wide",
            Self::RustflagsProfileDivergence => {
                "centralize RUSTFLAGS/profiles in workspace config; forbid ad-hoc env flags"
            }
            Self::TargetCpuDrift => {
                "build for the shared CPU baseline cohort (F008), not per-host native"
            }
            Self::PathPolicyDrift => {
                "move families to one canonical path policy (D030) instead of mixed lanes"
            }
            Self::CommandPaletteDrift => {
                "standardize the invocation palette (B014 configuration pack)"
            }
            Self::BuildScriptVolatility => {
                "declare build-script inputs (E015) so reruns stop forking keys"
            }
            Self::PlatformFragmentation => {
                "consolidate on supported platform classes; retire one-off targets"
            }
            Self::DuplicateSnapshots => {
                "deduplicate equivalent snapshots via ancestry (P004) before keying"
            }
        }
    }
}

/// One category's observed fragmentation over the fleet corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedFragmentation {
    /// The category.
    pub category: FragmentationCategory,
    /// Distinct variants observed (from the F018 histograms).
    pub distinct_variants: u32,
    /// Logical actions affected.
    pub logical_actions: u64,
    /// Mean cost of one such action (ms).
    pub mean_action_cost_ms: u64,
}

impl ObservedFragmentation {
    /// Compiler-ms lost: every variant beyond the first recompiled
    /// each logical action once.
    #[must_use]
    pub const fn wasted_ms(&self) -> u64 {
        (self.distinct_variants.saturating_sub(1) as u64)
            .saturating_mul(self.logical_actions)
            .saturating_mul(self.mean_action_cost_ms)
    }
}

/// One costed recommendation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostedRecommendation {
    /// The fragmented category.
    pub category: FragmentationCategory,
    /// Quantified waste (compiler-ms).
    pub wasted_ms: u64,
    /// Distinct variants observed.
    pub distinct_variants: u32,
    /// The remediation.
    pub remediation: &'static str,
}

/// The analyzer report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerReport {
    /// Costed recommendations, largest waste first (ties by registry
    /// order for determinism).
    pub recommendations: Vec<CostedRecommendation>,
    /// Total quantified waste (compiler-ms).
    pub total_wasted_ms: u64,
}

/// Analyze a fleet corpus of per-category observations.
#[must_use]
pub fn analyze(observations: &[ObservedFragmentation]) -> AnalyzerReport {
    let mut recommendations: Vec<CostedRecommendation> = observations
        .iter()
        .filter(|o| o.distinct_variants > 1) // converged: no row
        .map(|o| CostedRecommendation {
            category: o.category,
            wasted_ms: o.wasted_ms(),
            distinct_variants: o.distinct_variants,
            remediation: o.category.remediation(),
        })
        .collect();
    let registry_index = |c: FragmentationCategory| {
        ALL_CATEGORIES
            .iter()
            .position(|x| *x == c)
            .expect("closed registry")
    };
    recommendations.sort_by(|a, b| {
        b.wasted_ms
            .cmp(&a.wasted_ms)
            .then_with(|| registry_index(a.category).cmp(&registry_index(b.category)))
    });
    let total_wasted_ms = recommendations.iter().map(|r| r.wasted_ms).sum();
    AnalyzerReport {
        recommendations,
        total_wasted_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fleet corpus fixture: mixed fragmentation.
    fn corpus() -> Vec<ObservedFragmentation> {
        vec![
            ObservedFragmentation {
                category: FragmentationCategory::ToolchainDrift,
                distinct_variants: 3, // three nightlies in the fleet
                logical_actions: 400,
                mean_action_cost_ms: 900,
            },
            ObservedFragmentation {
                category: FragmentationCategory::FeatureDrift,
                distinct_variants: 5,
                logical_actions: 120,
                mean_action_cost_ms: 700,
            },
            ObservedFragmentation {
                category: FragmentationCategory::LockfileInconsistency,
                distinct_variants: 1, // CONVERGED
                logical_actions: 500,
                mean_action_cost_ms: 800,
            },
            ObservedFragmentation {
                category: FragmentationCategory::TargetCpuDrift,
                distinct_variants: 2,
                logical_actions: 50,
                mean_action_cost_ms: 1_000,
            },
        ]
    }

    #[test]
    fn the_registry_is_closed_with_a_remediation_per_category() {
        assert_eq!(ALL_CATEGORIES.len(), 11, "eleven categories, pinned");
        for category in ALL_CATEGORIES {
            assert!(
                !category.remediation().is_empty(),
                "{category:?} must name its convergence remediation"
            );
        }
    }

    #[test]
    fn the_fleet_corpus_report_quantifies_and_ranks() {
        // THE acceptance: quantified costs on the corpus, ranked.
        let report = analyze(&corpus());
        // Toolchain: (3-1) * 400 * 900 = 720000 ms.
        // Features:  (5-1) * 120 * 700 = 336000 ms.
        // Target CPU:(2-1) *  50 * 1000 = 50000 ms.
        let rows: Vec<(FragmentationCategory, u64)> = report
            .recommendations
            .iter()
            .map(|r| (r.category, r.wasted_ms))
            .collect();
        assert_eq!(
            rows,
            vec![
                (FragmentationCategory::ToolchainDrift, 720_000),
                (FragmentationCategory::FeatureDrift, 336_000),
                (FragmentationCategory::TargetCpuDrift, 50_000),
            ]
        );
        assert_eq!(report.total_wasted_ms, 1_106_000);
        // Each row carries its remediation.
        assert!(
            report.recommendations[0]
                .remediation
                .contains("rust-toolchain.toml")
        );
        assert!(report.recommendations[1].remediation.contains("hakari"));
    }

    #[test]
    fn converged_categories_emit_no_row() {
        // The analyzer prices problems; it does not scold the
        // converged lockfile (1 variant, 0 waste, NO row).
        let report = analyze(&corpus());
        assert!(
            !report
                .recommendations
                .iter()
                .any(|r| r.category == FragmentationCategory::LockfileInconsistency),
            "a converged category must not appear"
        );
        // And an all-converged fleet reports empty at zero cost.
        let converged: Vec<ObservedFragmentation> = ALL_CATEGORIES
            .map(|category| ObservedFragmentation {
                category,
                distinct_variants: 1,
                logical_actions: 1_000,
                mean_action_cost_ms: 1_000,
            })
            .to_vec();
        let clean = analyze(&converged);
        assert!(clean.recommendations.is_empty());
        assert_eq!(clean.total_wasted_ms, 0);
    }

    #[test]
    fn the_cost_model_is_monotonic_in_variants() {
        let observed = |v: u32| ObservedFragmentation {
            category: FragmentationCategory::DependencyVersionSpread,
            distinct_variants: v,
            logical_actions: 10,
            mean_action_cost_ms: 100,
        };
        assert_eq!(observed(1).wasted_ms(), 0, "one variant wastes nothing");
        assert_eq!(observed(2).wasted_ms(), 1_000);
        assert_eq!(observed(4).wasted_ms(), 3_000);
        assert!(observed(4).wasted_ms() > observed(3).wasted_ms());
    }
}
