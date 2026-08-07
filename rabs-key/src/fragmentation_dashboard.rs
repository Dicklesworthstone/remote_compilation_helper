//! Fragmentation dashboard + convergence trend (bead R010; plan
//! §105; renders the Q011 analyzer output).
//!
//! Two surfaces:
//!
//! - RENDER: schema-stable `key=value` lines over the Q011 report —
//!   every row carries the quantified waste AND its actionable
//!   remediation (an operator can act from the line alone);
//! - TREND: the fleet convergence view — two analyzer windows
//!   compared per category, each delta classified (improving,
//!   worsening, flat, newly fragmented, resolved) so convergence
//!   work shows up as movement, not vibes.

use crate::fragmentation_analyzer::{AnalyzerReport, FragmentationCategory};

/// Render the analyzer report as schema-stable lines.
#[must_use]
pub fn render(report: &AnalyzerReport) -> Vec<String> {
    let mut lines = vec![
        format!("frag.total_wasted_ms={}", report.total_wasted_ms),
        format!("frag.recommendations={}", report.recommendations.len()),
    ];
    for (rank, rec) in report.recommendations.iter().enumerate() {
        lines.push(format!("frag.rec.{rank}.category={:?}", rec.category));
        lines.push(format!("frag.rec.{rank}.wasted_ms={}", rec.wasted_ms));
        lines.push(format!(
            "frag.rec.{rank}.variants={}",
            rec.distinct_variants
        ));
        lines.push(format!("frag.rec.{rank}.action={}", rec.remediation));
    }
    lines
}

/// Direction of one category between two windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trend {
    /// Waste fell (convergence working).
    Improving,
    /// Waste rose.
    Worsening,
    /// Unchanged.
    Flat,
    /// Fragmented now, was converged before.
    NewlyFragmented,
    /// Converged now, was fragmented before.
    Resolved,
}

/// One trend row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrendRow {
    /// The category.
    pub category: FragmentationCategory,
    /// Waste in the previous window (ms).
    pub previous_ms: u64,
    /// Waste in the current window (ms).
    pub current_ms: u64,
    /// The classified direction.
    pub direction: Trend,
}

/// The convergence view: per-category movement between two windows.
#[must_use]
pub fn trend(previous: &AnalyzerReport, current: &AnalyzerReport) -> Vec<TrendRow> {
    let waste_of = |report: &AnalyzerReport, category: FragmentationCategory| {
        report
            .recommendations
            .iter()
            .find(|r| r.category == category)
            .map(|r| r.wasted_ms)
    };
    let mut categories: Vec<FragmentationCategory> = Vec::new();
    for rec in previous
        .recommendations
        .iter()
        .chain(current.recommendations.iter())
    {
        if !categories.contains(&rec.category) {
            categories.push(rec.category);
        }
    }
    categories
        .into_iter()
        .map(|category| {
            let prev = waste_of(previous, category);
            let curr = waste_of(current, category);
            let direction = match (prev, curr) {
                (None, Some(_)) => Trend::NewlyFragmented,
                (Some(_), None) => Trend::Resolved,
                (Some(p), Some(c)) if c < p => Trend::Improving,
                (Some(p), Some(c)) if c > p => Trend::Worsening,
                _ => Trend::Flat,
            };
            TrendRow {
                category,
                previous_ms: prev.unwrap_or(0),
                current_ms: curr.unwrap_or(0),
                direction,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragmentation_analyzer::{ObservedFragmentation, analyze};

    fn window(toolchain_variants: u32, feature_variants: u32) -> AnalyzerReport {
        analyze(&[
            ObservedFragmentation {
                category: FragmentationCategory::ToolchainDrift,
                distinct_variants: toolchain_variants,
                logical_actions: 400,
                mean_action_cost_ms: 900,
            },
            ObservedFragmentation {
                category: FragmentationCategory::FeatureDrift,
                distinct_variants: feature_variants,
                logical_actions: 120,
                mean_action_cost_ms: 700,
            },
        ])
    }

    #[test]
    fn the_dashboard_renders_the_analyzer_report_actionably() {
        // THE acceptance: each rendered row carries waste AND the
        // remediation — actionable from the line alone.
        let lines = render(&window(3, 1));
        assert_eq!(
            lines,
            vec![
                "frag.total_wasted_ms=720000",
                "frag.recommendations=1",
                "frag.rec.0.category=ToolchainDrift",
                "frag.rec.0.wasted_ms=720000",
                "frag.rec.0.variants=3",
                "frag.rec.0.action=pin one toolchain in rust-toolchain.toml fleet-wide",
            ]
        );
        // A fully converged fleet renders the clean summary.
        assert_eq!(
            render(&window(1, 1)),
            vec!["frag.total_wasted_ms=0", "frag.recommendations=0"]
        );
    }

    #[test]
    fn the_trend_view_classifies_every_movement() {
        // Previous window: toolchain 3 variants, features converged.
        // Current window: toolchain converged (Resolved), features
        // fragmented to 5 (NewlyFragmented).
        let rows = trend(&window(3, 1), &window(1, 5));
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            TrendRow {
                category: FragmentationCategory::ToolchainDrift,
                previous_ms: 720_000,
                current_ms: 0,
                direction: Trend::Resolved,
            }
        );
        assert_eq!(rows[1].direction, Trend::NewlyFragmented);
        // Improving / worsening / flat.
        let improving = trend(&window(3, 1), &window(2, 1));
        assert_eq!(improving[0].direction, Trend::Improving);
        let worsening = trend(&window(2, 1), &window(3, 1));
        assert_eq!(worsening[0].direction, Trend::Worsening);
        let flat = trend(&window(3, 1), &window(3, 1));
        assert_eq!(flat[0].direction, Trend::Flat);
    }
}
