//! Decision latency tracking for AGENTS.md compliance.
//!
//! Performance budgets from AGENTS.md:
//! - Non-compilation decision: < 1ms (95th percentile)
//! - Compilation decision: < 5ms (95th percentile)
//! - Worker selection: < 10ms
//! - Full pipeline: < 15% overhead

// Allow dead code for latency tracking types not yet integrated
#![allow(dead_code)]

use std::time::{Duration, Instant};
use tracing::warn;

use super::{
    CLASSIFICATION_TIER_LATENCY, CLASSIFICATION_TIER_TOTAL, DECISION_BUDGET_VIOLATIONS,
    DECISION_LATENCY, DECISION_PANIC_THRESHOLD_VIOLATIONS,
};

/// Performance budget for non-compilation decisions (milliseconds).
/// From AGENTS.md: "Hook decision (non-compilation) | <1ms | 5ms"
pub const NON_COMPILATION_BUDGET_MS: f64 = 1.0;

/// Performance budget for compilation decisions (milliseconds).
/// From AGENTS.md: "Hook decision (compilation) | <5ms | 10ms"
pub const COMPILATION_BUDGET_MS: f64 = 5.0;

/// Performance budget for worker selection (milliseconds).
/// From AGENTS.md: "Worker selection | <10ms | 50ms"
pub const WORKER_SELECTION_BUDGET_MS: f64 = 10.0;

/// Panic threshold for non-compilation decisions (milliseconds).
pub const NON_COMPILATION_PANIC_MS: f64 = 5.0;

/// Panic threshold for compilation decisions (milliseconds).
pub const COMPILATION_PANIC_MS: f64 = 10.0;

/// Panic threshold for worker selection (milliseconds).
pub const WORKER_SELECTION_PANIC_MS: f64 = 50.0;

/// Decision type for latency tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionType {
    /// Non-compilation command (must complete < 1ms).
    NonCompilation,
    /// Compilation command (must complete < 5ms).
    Compilation,
    /// Worker selection (must complete < 10ms).
    WorkerSelection,
}

impl DecisionType {
    /// Get the budget in milliseconds for this decision type.
    pub fn budget_ms(self) -> f64 {
        match self {
            DecisionType::NonCompilation => NON_COMPILATION_BUDGET_MS,
            DecisionType::Compilation => COMPILATION_BUDGET_MS,
            DecisionType::WorkerSelection => WORKER_SELECTION_BUDGET_MS,
        }
    }

    /// Get the panic threshold in milliseconds for this decision type.
    pub fn panic_threshold_ms(self) -> f64 {
        match self {
            DecisionType::NonCompilation => NON_COMPILATION_PANIC_MS,
            DecisionType::Compilation => COMPILATION_PANIC_MS,
            DecisionType::WorkerSelection => WORKER_SELECTION_PANIC_MS,
        }
    }

    fn index(self) -> usize {
        match self {
            DecisionType::NonCompilation => 0,
            DecisionType::Compilation => 1,
            DecisionType::WorkerSelection => 2,
        }
    }

    /// Get the label for Prometheus metrics.
    pub fn label(self) -> &'static str {
        match self {
            DecisionType::NonCompilation => "non_compilation",
            DecisionType::Compilation => "compilation",
            DecisionType::WorkerSelection => "worker_selection",
        }
    }
}

/// A busy dispatcher exceeds these budgets on most selections (css logged ~10
/// "CRITICAL" lines a minute on 2026-10-14), burying real errors. The
/// counters stay exact; each decision type and severity logs at most once
/// per interval, with the number of lines suppressed since the last one.
const VIOLATION_LOG_INTERVAL_MS: u64 = 60_000;
// Slots: decision index * 2 + (0 budget, 1 panic); slot 6 is the unit test's.
static VIOLATION_LAST_LOG_MS: [std::sync::atomic::AtomicU64; 7] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 7];
static VIOLATION_SUPPRESSED: [std::sync::atomic::AtomicU64; 7] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 7];

/// `Some(suppressed)` when this slot may log now, else counts a suppression.
fn violation_log_gate(slot: usize, now_ms: u64) -> Option<u64> {
    use std::sync::atomic::Ordering::Relaxed;
    let last = VIOLATION_LAST_LOG_MS[slot].load(Relaxed);
    if last != 0 && now_ms.saturating_sub(last) < VIOLATION_LOG_INTERVAL_MS
        || VIOLATION_LAST_LOG_MS[slot]
            .compare_exchange(last, now_ms.max(1), Relaxed, Relaxed)
            .is_err()
    {
        VIOLATION_SUPPRESSED[slot].fetch_add(1, Relaxed);
        return None;
    }
    Some(VIOLATION_SUPPRESSED[slot].swap(0, Relaxed))
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// Record decision latency and check budget compliance.
///
/// Returns the duration for further processing.
///
/// # Arguments
/// * `decision_type` - The type of decision being timed.
/// * `start` - The instant when the decision started.
///
/// # Returns
/// The duration of the decision.
pub fn record_decision_latency(decision_type: DecisionType, start: Instant) -> Duration {
    let duration = start.elapsed();
    let duration_secs = duration.as_secs_f64();
    let duration_ms = duration_secs * 1000.0;

    // Record histogram observation
    DECISION_LATENCY
        .with_label_values(&[decision_type.label()])
        .observe(duration_secs);

    // Check budget violations
    let budget_ms = decision_type.budget_ms();

    if duration_ms > budget_ms {
        DECISION_BUDGET_VIOLATIONS
            .with_label_values(&[decision_type.label()])
            .inc();

        if let Some(suppressed) = violation_log_gate(decision_type.index() * 2, unix_now_ms()) {
            warn!(
                decision_type = decision_type.label(),
                duration_ms = format!("{:.3}", duration_ms),
                budget_ms = budget_ms,
                suppressed,
                "Decision latency budget violation"
            );
        }
    }

    // Log panic threshold violations at error level
    let panic_ms = decision_type.panic_threshold_ms();
    if duration_ms > panic_ms {
        DECISION_PANIC_THRESHOLD_VIOLATIONS
            .with_label_values(&[decision_type.label()])
            .inc();

        if let Some(suppressed) = violation_log_gate(decision_type.index() * 2 + 1, unix_now_ms()) {
            tracing::error!(
                decision_type = decision_type.label(),
                duration_ms = format!("{:.3}", duration_ms),
                panic_threshold_ms = panic_ms,
                suppressed,
                "CRITICAL: Decision latency exceeded panic threshold"
            );
        }
    }

    duration
}

/// Record classification tier metrics.
///
/// # Arguments
/// * `tier` - The classification tier (0-4).
/// * `duration` - The time spent in this tier.
pub fn record_classification_tier(tier: u8, duration: Duration) {
    let tier_str = tier.to_string();

    // Increment tier counter
    CLASSIFICATION_TIER_TOTAL
        .with_label_values(&[&tier_str])
        .inc();

    // Record tier latency
    CLASSIFICATION_TIER_LATENCY
        .with_label_values(&[&tier_str])
        .observe(duration.as_secs_f64());
}

/// A RAII guard for timing decisions.
///
/// Automatically records latency when dropped.
pub struct DecisionTimer {
    decision_type: DecisionType,
    start: Option<Instant>,
}

impl DecisionTimer {
    /// Create a new decision timer.
    pub fn new(decision_type: DecisionType) -> Self {
        Self {
            decision_type,
            start: Some(Instant::now()),
        }
    }

    /// Get the elapsed time without stopping the timer.
    pub fn elapsed(&self) -> Duration {
        self.start.map(|start| start.elapsed()).unwrap_or_default()
    }

    /// Stop the timer and record the latency.
    ///
    /// This consumes the timer, so it will not record again on drop.
    pub fn stop(mut self) -> Duration {
        self.start
            .take()
            .map(|start| record_decision_latency(self.decision_type, start))
            .unwrap_or_default()
    }
}

impl Drop for DecisionTimer {
    fn drop(&mut self) {
        if let Some(start) = self.start.take() {
            let _ = record_decision_latency(self.decision_type, start);
        }
    }
}

/// A RAII guard for timing classification tiers.
pub struct TierTimer {
    tier: u8,
    start: Instant,
}

impl TierTimer {
    /// Create a new tier timer.
    pub fn new(tier: u8) -> Self {
        Self {
            tier,
            start: Instant::now(),
        }
    }

    /// Stop the timer and record the tier latency.
    pub fn stop(self) {
        record_classification_tier(self.tier, self.start.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;
    use std::thread;

    #[test]
    fn test_decision_type_budget() {
        let _guard = test_guard!();
        assert_eq!(DecisionType::NonCompilation.budget_ms(), 1.0);
        assert_eq!(DecisionType::Compilation.budget_ms(), 5.0);
        assert_eq!(DecisionType::WorkerSelection.budget_ms(), 10.0);
    }

    #[test]
    fn test_decision_type_label() {
        let _guard = test_guard!();
        assert_eq!(DecisionType::NonCompilation.label(), "non_compilation");
        assert_eq!(DecisionType::Compilation.label(), "compilation");
        assert_eq!(DecisionType::WorkerSelection.label(), "worker_selection");
    }

    #[test]
    fn test_record_decision_latency() {
        let _guard = test_guard!();
        let start = Instant::now();
        // Simulate some work
        thread::sleep(Duration::from_micros(100));

        let duration = record_decision_latency(DecisionType::NonCompilation, start);

        // Duration should be at least 100µs
        assert!(duration.as_micros() >= 100);
    }

    #[test]
    fn test_decision_timer() {
        let _guard = test_guard!();
        let timer = DecisionTimer::new(DecisionType::Compilation);
        thread::sleep(Duration::from_micros(50));

        let elapsed = timer.elapsed();
        assert!(elapsed.as_micros() >= 50);

        // Note: stop() would be called, but timer moved
        // In practice, either call stop() or let drop handle it
    }

    #[test]
    fn test_decision_timer_stop_records_once() {
        let _guard = test_guard!();
        let histogram = DECISION_LATENCY.with_label_values(&["worker_selection"]);
        let before = histogram.get_sample_count();

        let timer = DecisionTimer::new(DecisionType::WorkerSelection);
        let _elapsed = timer.stop();

        assert_eq!(histogram.get_sample_count(), before + 1);
    }

    #[test]
    fn test_tier_timer() {
        let _guard = test_guard!();
        let timer = TierTimer::new(2);
        thread::sleep(Duration::from_micros(10));
        timer.stop();

        // Metric should have been recorded (verified by prometheus)
    }

    #[test]
    fn violation_logs_are_gated_per_slot_and_report_suppressions() {
        // The reserved test slot, with synthetic clocks.
        let base = 1_000_000_000;
        assert_eq!(violation_log_gate(6, base), Some(0));
        assert_eq!(violation_log_gate(6, base + 1), None);
        assert_eq!(
            violation_log_gate(6, base + VIOLATION_LOG_INTERVAL_MS - 1),
            None
        );
        assert_eq!(
            violation_log_gate(6, base + VIOLATION_LOG_INTERVAL_MS),
            Some(2)
        );
        assert_eq!(
            violation_log_gate(6, base + VIOLATION_LOG_INTERVAL_MS + 5),
            None
        );
    }

    #[test]
    fn test_panic_thresholds() {
        let _guard = test_guard!();
        assert!(
            DecisionType::NonCompilation.panic_threshold_ms()
                > DecisionType::NonCompilation.budget_ms()
        );
        assert!(
            DecisionType::Compilation.panic_threshold_ms() > DecisionType::Compilation.budget_ms()
        );
        assert!(
            DecisionType::WorkerSelection.panic_threshold_ms()
                > DecisionType::WorkerSelection.budget_ms()
        );
    }
}
