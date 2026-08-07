//! SLO brownout for speculation (bead I012; plan §84; the
//! `speculation_browns_out_before_foreground` core scenario).
//!
//! Speculation is the first casualty of pressure and foreground never
//! is. Two thresholds:
//!
//! - **soft**: new speculation stops ADMITTING (running speculation
//!   finishes);
//! - **hard**: low-value running speculation CANCELS and the pool
//!   drains — while cleanup and object-integrity work remain
//!   REQUIRED at every level (they are not optional work; refusing
//!   them under pressure is how storage corrupts);
//! - provenance: every brownout decision records wasted (cancelled
//!   mid-flight) versus saved (completed before pressure) speculative
//!   work so the speculation policy can be judged on numbers.

/// Pressure bands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(missing_docs)]
pub enum PressureBand {
    Normal,
    Soft,
    Hard,
}

/// Classify pressure permille into a band.
#[must_use]
pub const fn band(
    pressure_permille: u16,
    soft_threshold: u16,
    hard_threshold: u16,
) -> PressureBand {
    if pressure_permille >= hard_threshold {
        PressureBand::Hard
    } else if pressure_permille >= soft_threshold {
        PressureBand::Soft
    } else {
        PressureBand::Normal
    }
}

/// Work categories the brownout gate judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum WorkCategory {
    Foreground,
    NewSpeculation,
    RunningLowValueSpeculation,
    Cleanup,
    ObjectIntegrity,
}

/// The gate's decision for one category under one band.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrownoutDecision {
    /// Admit / keep running.
    Admit,
    /// Stop admitting new items (running ones finish).
    StopAdmitting,
    /// Cancel and drain.
    CancelAndDrain,
}

/// The brownout table.
#[must_use]
pub const fn decide(category: WorkCategory, pressure: PressureBand) -> BrownoutDecision {
    match (category, pressure) {
        // Foreground is NEVER browned out.
        (WorkCategory::Foreground, _) => BrownoutDecision::Admit,
        // Cleanup and object integrity remain REQUIRED at every band.
        (WorkCategory::Cleanup | WorkCategory::ObjectIntegrity, _) => BrownoutDecision::Admit,
        // New speculation stops at soft, everything above.
        (WorkCategory::NewSpeculation, PressureBand::Normal) => BrownoutDecision::Admit,
        (WorkCategory::NewSpeculation, PressureBand::Soft | PressureBand::Hard) => {
            BrownoutDecision::StopAdmitting
        }
        // Running low-value speculation survives soft, cancels at hard.
        (WorkCategory::RunningLowValueSpeculation, PressureBand::Normal | PressureBand::Soft) => {
            BrownoutDecision::Admit
        }
        (WorkCategory::RunningLowValueSpeculation, PressureBand::Hard) => {
            BrownoutDecision::CancelAndDrain
        }
    }
}

/// Provenance accounting for speculation under brownout.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpeculationProvenance {
    /// Speculative work cancelled mid-flight (wasted).
    pub wasted_cancelled: u64,
    /// Speculative work that completed before pressure (saved).
    pub saved_completed: u64,
    /// Admissions refused at the soft threshold.
    pub admissions_refused: u64,
}

impl SpeculationProvenance {
    /// Record one brownout decision's effect.
    pub fn record(&mut self, decision: BrownoutDecision, was_running: bool) {
        match decision {
            BrownoutDecision::CancelAndDrain if was_running => self.wasted_cancelled += 1,
            BrownoutDecision::StopAdmitting => self.admissions_refused += 1,
            BrownoutDecision::Admit | BrownoutDecision::CancelAndDrain => {}
        }
    }

    /// Record a speculation that completed before pressure hit.
    pub fn record_completed(&mut self) {
        self.saved_completed += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use PressureBand as P;
    use WorkCategory as W;

    #[test]
    fn speculation_browns_out_before_foreground() {
        // THE core scenario: walk the pressure ladder — speculation
        // degrades in two steps while foreground admits at EVERY band.
        for pressure in [P::Normal, P::Soft, P::Hard] {
            assert_eq!(
                decide(W::Foreground, pressure),
                BrownoutDecision::Admit,
                "foreground is never browned out ({pressure:?})"
            );
        }
        // Normal: everything runs.
        assert_eq!(
            decide(W::NewSpeculation, P::Normal),
            BrownoutDecision::Admit
        );
        // Soft: new speculation stops; running speculation finishes.
        assert_eq!(
            decide(W::NewSpeculation, P::Soft),
            BrownoutDecision::StopAdmitting
        );
        assert_eq!(
            decide(W::RunningLowValueSpeculation, P::Soft),
            BrownoutDecision::Admit
        );
        // Hard: low-value running speculation cancels and drains.
        assert_eq!(
            decide(W::RunningLowValueSpeculation, P::Hard),
            BrownoutDecision::CancelAndDrain
        );
    }

    #[test]
    fn cleanup_and_integrity_work_remain_required_at_every_band() {
        for pressure in [P::Normal, P::Soft, P::Hard] {
            assert_eq!(decide(W::Cleanup, pressure), BrownoutDecision::Admit);
            assert_eq!(
                decide(W::ObjectIntegrity, pressure),
                BrownoutDecision::Admit,
                "refusing integrity work under pressure is how storage corrupts"
            );
        }
    }

    #[test]
    fn thresholds_classify_bands() {
        assert_eq!(band(100, 600, 850), PressureBand::Normal);
        assert_eq!(band(600, 600, 850), PressureBand::Soft);
        assert_eq!(band(700, 600, 850), PressureBand::Soft);
        assert_eq!(band(850, 600, 850), PressureBand::Hard);
        assert_eq!(band(1000, 600, 850), PressureBand::Hard);
    }

    #[test]
    fn provenance_records_wasted_vs_saved() {
        // The accounting the speculation policy is judged on.
        let mut provenance = SpeculationProvenance::default();
        // Two speculations complete before pressure: saved.
        provenance.record_completed();
        provenance.record_completed();
        // Soft threshold refuses three admissions.
        for _ in 0..3 {
            provenance.record(decide(W::NewSpeculation, P::Soft), false);
        }
        // Hard threshold cancels one running speculation: wasted.
        provenance.record(decide(W::RunningLowValueSpeculation, P::Hard), true);
        assert_eq!(
            provenance,
            SpeculationProvenance {
                wasted_cancelled: 1,
                saved_completed: 2,
                admissions_refused: 3,
            }
        );
    }
}
