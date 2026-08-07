//! Action resource-envelope schema + estimator (bead I005; plan §84;
//! risk R66).
//!
//! Every schedulable action carries a resource envelope — the
//! scheduler's picture of what running it will cost. Envelopes are
//! ESTIMATES from historical observations keyed by (action class,
//! toolchain, crate family), updated after every completion; the
//! `uncertainty_permille` field keeps the estimator honest: a fresh
//! key admits it knows nothing (maximum uncertainty) and confidence is
//! EARNED by observations, never asserted.
//!
//! Pure math, deterministic: exponential moving averages with integer
//! arithmetic — no floats, no clocks (durations arrive as observed
//! values; this module never reads time).

/// Coarse memory-peak behavior class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum MemoryPeakClass {
    /// Flat usage near the mean.
    Steady,
    /// Pronounced single peak (typical rustc codegen).
    SinglePeak,
    /// Sawtooth/multi-peak (incremental, LTO merges).
    MultiPeak,
}

/// Heaviness classes for link/LTO phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(missing_docs)]
pub enum Heaviness {
    None,
    Light,
    Moderate,
    Heavy,
}

/// The resource envelope (estimate or observation — one shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceEnvelope {
    /// CPU threads the action will use concurrently.
    pub cpu_threads: u32,
    /// Working-set memory bytes.
    pub memory_bytes: u64,
    /// Peak behavior class.
    pub memory_peak_class: MemoryPeakClass,
    /// Bytes read from disk.
    pub disk_read_bytes: u64,
    /// Bytes written to disk.
    pub disk_write_bytes: u64,
    /// Temporary space required.
    pub temp_space_bytes: u64,
    /// Network bytes in (object fetches).
    pub network_in_bytes: u64,
    /// Network bytes out (result offers).
    pub network_out_bytes: u64,
    /// Link-phase heaviness.
    pub linker_heaviness: Heaviness,
    /// LTO-phase heaviness.
    pub lto_heaviness: Heaviness,
    /// Processes spawned.
    pub process_count: u32,
    /// Expected duration in milliseconds.
    pub expected_duration_ms: u64,
    /// Estimator uncertainty, 0 (certain) to 1000 (knows nothing).
    pub uncertainty_permille: u16,
}

impl ResourceEnvelope {
    /// The know-nothing prior for a never-observed key: conservative
    /// middle-of-road resources at MAXIMUM uncertainty.
    #[must_use]
    pub const fn unobserved_prior() -> Self {
        Self {
            cpu_threads: 1,
            memory_bytes: 1 << 30, // 1 GiB conservative default
            memory_peak_class: MemoryPeakClass::SinglePeak,
            disk_read_bytes: 64 << 20,
            disk_write_bytes: 64 << 20,
            temp_space_bytes: 256 << 20,
            network_in_bytes: 32 << 20,
            network_out_bytes: 32 << 20,
            linker_heaviness: Heaviness::Light,
            lto_heaviness: Heaviness::None,
            process_count: 1,
            expected_duration_ms: 10_000,
            uncertainty_permille: 1000,
        }
    }
}

/// EMA weight: observation gets 1/4, history 3/4 (integer arithmetic).
fn ema(history: u64, observed: u64) -> u64 {
    (history * 3 + observed) / 4
}

/// One estimator cell: the current estimate plus observation count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeEstimator {
    /// Current estimate.
    pub estimate: ResourceEnvelope,
    /// Completed observations folded in.
    pub observations: u64,
}

impl Default for EnvelopeEstimator {
    fn default() -> Self {
        Self {
            estimate: ResourceEnvelope::unobserved_prior(),
            observations: 0,
        }
    }
}

impl EnvelopeEstimator {
    /// Fold one completed action's OBSERVED envelope into the estimate
    /// (the update loop). Uncertainty decays with each observation:
    /// `1000 / (observations + 1)`, floored at 50 — confidence is
    /// earned, and never reaches zero (the world changes).
    pub fn observe(&mut self, observed: &ResourceEnvelope) {
        let e = &mut self.estimate;
        if self.observations == 0 {
            // First observation replaces the prior outright (the prior
            // was an admission of ignorance, not data).
            *e = observed.clone();
        } else {
            e.cpu_threads = u32::try_from(ema(
                u64::from(e.cpu_threads),
                u64::from(observed.cpu_threads),
            ))
            .unwrap_or(u32::MAX);
            e.memory_bytes = ema(e.memory_bytes, observed.memory_bytes);
            e.disk_read_bytes = ema(e.disk_read_bytes, observed.disk_read_bytes);
            e.disk_write_bytes = ema(e.disk_write_bytes, observed.disk_write_bytes);
            e.temp_space_bytes = ema(e.temp_space_bytes, observed.temp_space_bytes);
            e.network_in_bytes = ema(e.network_in_bytes, observed.network_in_bytes);
            e.network_out_bytes = ema(e.network_out_bytes, observed.network_out_bytes);
            e.process_count = u32::try_from(ema(
                u64::from(e.process_count),
                u64::from(observed.process_count),
            ))
            .unwrap_or(u32::MAX);
            e.expected_duration_ms = ema(e.expected_duration_ms, observed.expected_duration_ms);
            // Classes take the latest observation (they are modes, not
            // averages).
            e.memory_peak_class = observed.memory_peak_class;
            e.linker_heaviness = observed.linker_heaviness;
            e.lto_heaviness = observed.lto_heaviness;
        }
        self.observations += 1;
        let decayed = 1000 / (self.observations + 1);
        e.uncertainty_permille = u16::try_from(decayed.max(50)).unwrap_or(1000);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(memory: u64, duration: u64) -> ResourceEnvelope {
        ResourceEnvelope {
            cpu_threads: 4,
            memory_bytes: memory,
            memory_peak_class: MemoryPeakClass::SinglePeak,
            disk_read_bytes: 10 << 20,
            disk_write_bytes: 20 << 20,
            temp_space_bytes: 30 << 20,
            network_in_bytes: 5 << 20,
            network_out_bytes: 6 << 20,
            linker_heaviness: Heaviness::None,
            lto_heaviness: Heaviness::None,
            process_count: 2,
            expected_duration_ms: duration,
            uncertainty_permille: 0, // observations are facts
        }
    }

    #[test]
    fn unobserved_keys_admit_maximum_uncertainty() {
        let est = EnvelopeEstimator::default();
        assert_eq!(est.estimate.uncertainty_permille, 1000);
        assert_eq!(est.observations, 0);
    }

    #[test]
    fn first_observation_replaces_the_prior_and_uncertainty_decays() {
        let mut est = EnvelopeEstimator::default();
        est.observe(&observed(2 << 30, 42_000));
        assert_eq!(est.estimate.memory_bytes, 2 << 30, "prior replaced");
        assert_eq!(est.estimate.expected_duration_ms, 42_000);
        assert!(est.estimate.uncertainty_permille < 1000);
        // Uncertainty keeps decaying but floors at 50 (never certain).
        for _ in 0..100 {
            est.observe(&observed(2 << 30, 42_000));
        }
        assert_eq!(est.estimate.uncertainty_permille, 50);
    }

    #[test]
    fn update_loop_converges_toward_recent_observations() {
        let mut est = EnvelopeEstimator::default();
        est.observe(&observed(1 << 30, 10_000));
        // The crate got heavier: durations move toward the new regime.
        for _ in 0..10 {
            est.observe(&observed(4 << 30, 40_000));
        }
        assert!(
            est.estimate.memory_bytes > 3 << 30,
            "EMA must approach the new regime, got {}",
            est.estimate.memory_bytes
        );
        assert!(est.estimate.expected_duration_ms > 30_000);
        // And it is stable when observations are stable.
        let before = est.estimate.clone();
        est.observe(&observed(4 << 30, 40_000));
        assert!(
            est.estimate.memory_bytes >= before.memory_bytes,
            "no drift away from a stable regime"
        );
    }

    #[test]
    fn envelope_schema_carries_every_bead_field() {
        // Exhaustive destructure — the schema completeness check
        // against the bead's field list.
        let ResourceEnvelope {
            cpu_threads: _,
            memory_bytes: _,
            memory_peak_class: _,
            disk_read_bytes: _,
            disk_write_bytes: _,
            temp_space_bytes: _,
            network_in_bytes: _,
            network_out_bytes: _,
            linker_heaviness: _,
            lto_heaviness: _,
            process_count: _,
            expected_duration_ms: _,
            uncertainty_permille: _,
        } = ResourceEnvelope::unobserved_prior();
    }
}
