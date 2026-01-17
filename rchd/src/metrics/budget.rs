//! Budget status tracking for AGENTS.md performance requirements.
//!
//! This module provides utilities for checking and reporting compliance
//! with the performance budgets defined in AGENTS.md.

// Allow dead code for budget types not yet fully integrated
#![allow(dead_code)]

use serde::Serialize;

use super::DECISION_BUDGET_VIOLATIONS;
use super::latency::{
    COMPILATION_BUDGET_MS, COMPILATION_PANIC_MS, NON_COMPILATION_BUDGET_MS,
    NON_COMPILATION_PANIC_MS, WORKER_SELECTION_BUDGET_MS, WORKER_SELECTION_PANIC_MS,
};

/// Overall budget compliance status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    /// All budgets are being met.
    Passing,
    /// Some budgets have violations but within panic threshold.
    Warning,
    /// Critical violations exceeding panic thresholds.
    Failing,
}

impl std::fmt::Display for BudgetStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetStatus::Passing => write!(f, "passing"),
            BudgetStatus::Warning => write!(f, "warning"),
            BudgetStatus::Failing => write!(f, "failing"),
        }
    }
}

/// Budget information for a specific decision type.
#[derive(Debug, Clone, Serialize)]
pub struct BudgetInfo {
    /// Budget threshold in milliseconds.
    pub budget_ms: f64,
    /// Panic threshold in milliseconds.
    pub panic_threshold_ms: f64,
    /// Total number of budget violations.
    pub violations: u64,
    /// Violation rate (violations / total observations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violation_rate: Option<f64>,
}

/// Complete budget status response.
#[derive(Debug, Clone, Serialize)]
pub struct BudgetStatusResponse {
    /// Overall status.
    pub status: BudgetStatus,
    /// Per-decision-type budget info.
    pub budgets: BudgetBreakdown,
    /// Timestamp when this status was computed (ISO 8601).
    pub computed_at: String,
}

/// Breakdown of budgets by decision type.
#[derive(Debug, Clone, Serialize)]
pub struct BudgetBreakdown {
    /// Non-compilation decision budget.
    pub non_compilation: BudgetInfo,
    /// Compilation decision budget.
    pub compilation: BudgetInfo,
    /// Worker selection budget.
    pub worker_selection: BudgetInfo,
}

/// Get the current budget status.
pub fn get_budget_status() -> BudgetStatusResponse {
    let non_compilation_violations = get_violations("non_compilation");
    let compilation_violations = get_violations("compilation");
    let worker_selection_violations = get_violations("worker_selection");

    // Determine overall status
    let total_violations =
        non_compilation_violations + compilation_violations + worker_selection_violations;
    let status = if total_violations == 0 {
        BudgetStatus::Passing
    } else {
        // In a real implementation, we'd check if violations exceed a threshold
        // For now, any violation is a warning
        BudgetStatus::Warning
    };

    // Get current timestamp
    let computed_at = chrono::Utc::now().to_rfc3339();

    BudgetStatusResponse {
        status,
        budgets: BudgetBreakdown {
            non_compilation: BudgetInfo {
                budget_ms: NON_COMPILATION_BUDGET_MS,
                panic_threshold_ms: NON_COMPILATION_PANIC_MS,
                violations: non_compilation_violations,
                violation_rate: None, // Would need total observations to compute
            },
            compilation: BudgetInfo {
                budget_ms: COMPILATION_BUDGET_MS,
                panic_threshold_ms: COMPILATION_PANIC_MS,
                violations: compilation_violations,
                violation_rate: None,
            },
            worker_selection: BudgetInfo {
                budget_ms: WORKER_SELECTION_BUDGET_MS,
                panic_threshold_ms: WORKER_SELECTION_PANIC_MS,
                violations: worker_selection_violations,
                violation_rate: None,
            },
        },
        computed_at,
    }
}

/// Get the number of violations for a decision type.
fn get_violations(decision_type: &str) -> u64 {
    DECISION_BUDGET_VIOLATIONS
        .with_label_values(&[decision_type])
        .get() as u64
}

/// Check if all budgets are passing.
pub fn is_passing() -> bool {
    get_budget_status().status == BudgetStatus::Passing
}

/// Check if there are any critical violations.
pub fn has_critical_violations() -> bool {
    get_budget_status().status == BudgetStatus::Failing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_status_display() {
        assert_eq!(BudgetStatus::Passing.to_string(), "passing");
        assert_eq!(BudgetStatus::Warning.to_string(), "warning");
        assert_eq!(BudgetStatus::Failing.to_string(), "failing");
    }

    #[test]
    fn test_get_budget_status() {
        let status = get_budget_status();

        // Verify structure
        assert!(status.budgets.non_compilation.budget_ms > 0.0);
        assert!(status.budgets.compilation.budget_ms > 0.0);
        assert!(status.budgets.worker_selection.budget_ms > 0.0);

        // Verify panic thresholds are higher than budgets
        assert!(
            status.budgets.non_compilation.panic_threshold_ms
                > status.budgets.non_compilation.budget_ms
        );
        assert!(
            status.budgets.compilation.panic_threshold_ms > status.budgets.compilation.budget_ms
        );
        assert!(
            status.budgets.worker_selection.panic_threshold_ms
                > status.budgets.worker_selection.budget_ms
        );
    }

    #[test]
    fn test_budget_info_serialization() {
        let info = BudgetInfo {
            budget_ms: 1.0,
            panic_threshold_ms: 5.0,
            violations: 0,
            violation_rate: None,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("budget_ms"));
        assert!(json.contains("violations"));
        // violation_rate should be skipped when None
        assert!(!json.contains("violation_rate"));
    }

    #[test]
    fn test_budget_breakdown() {
        let breakdown = BudgetBreakdown {
            non_compilation: BudgetInfo {
                budget_ms: NON_COMPILATION_BUDGET_MS,
                panic_threshold_ms: NON_COMPILATION_PANIC_MS,
                violations: 0,
                violation_rate: None,
            },
            compilation: BudgetInfo {
                budget_ms: COMPILATION_BUDGET_MS,
                panic_threshold_ms: COMPILATION_PANIC_MS,
                violations: 2,
                violation_rate: Some(0.01),
            },
            worker_selection: BudgetInfo {
                budget_ms: WORKER_SELECTION_BUDGET_MS,
                panic_threshold_ms: WORKER_SELECTION_PANIC_MS,
                violations: 0,
                violation_rate: None,
            },
        };

        let json = serde_json::to_string_pretty(&breakdown).unwrap();
        assert!(json.contains("non_compilation"));
        assert!(json.contains("compilation"));
        assert!(json.contains("worker_selection"));
    }
}
