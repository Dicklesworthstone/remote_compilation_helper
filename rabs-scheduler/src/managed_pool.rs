//! Managed pool sizing behind opt-in + replay gate (bead I017; plan
//! §99; couples to the I013 sizing model).
//!
//! Automatic pool resizing is DANGEROUS-BY-DEFAULT machinery: a bad
//! resize degrades every tenant at once. So a resize APPLIES only
//! through a gate with no bypass arm:
//!
//! - explicit operator OPT-IN (config fact, default off);
//! - a minimum count of STABLE observation windows (an unstable
//!   window contributes nothing);
//! - a minimum total evidence count across those windows;
//! - REPLAY VALIDATION: the proposed size must have beaten the
//!   current size on the replay corpus (the I015 simulation);
//! - HYSTERESIS: the proposed delta must be large enough to matter
//!   AND enough windows must have passed since the last resize;
//! - every refusal is TYPED and names the failed condition.
//!
//! After an applied resize the controller watches tail latency
//! against the pre-resize baseline: a regression beyond the bound
//! ROLLS BACK to the previous size automatically and records why.
//!
//! Deterministic integer math; time is counted in observation
//! windows, never wall clocks.

/// Gate constants.
pub const MIN_STABLE_WINDOWS: u32 = 6;
/// Minimum total samples across the stable windows.
pub const MIN_EVIDENCE_SAMPLES: u64 = 500;
/// Minimum size delta (workers) worth acting on.
pub const MIN_RESIZE_DELTA: u32 = 2;
/// Minimum windows between resizes (hysteresis cooldown).
pub const MIN_WINDOWS_BETWEEN_RESIZES: u32 = 12;
/// Tail-latency regression bound (permille over baseline) that
/// triggers rollback.
pub const ROLLBACK_REGRESSION_PERMILLE: u64 = 150;

/// One observation window's summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationWindow {
    /// Samples observed in the window.
    pub samples: u64,
    /// Observed tail (p95) latency in the window (ms).
    pub tail_latency_ms: u64,
    /// Whether the window was STABLE (no brownout, no worker churn,
    /// no pressure collapse during it).
    pub stable: bool,
}

/// A resize proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResizeProposal {
    /// Proposed pool size (workers).
    pub new_size: u32,
    /// Replay validation verdict: the proposed size beat the current
    /// size on the replay corpus (the I015 simulation, run by the
    /// proposer; false = not run or did not beat).
    pub replay_validated: bool,
}

/// Typed refusal: which gate condition failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeRefusal {
    /// Operator has not opted in: the gate's outermost condition.
    NotOptedIn,
    /// Fewer stable windows than required (count included).
    InsufficientStableWindows(u32),
    /// Total evidence below the minimum (count included).
    InsufficientEvidence(u64),
    /// Replay validation missing or the proposal did not win.
    ReplayNotValidated,
    /// Delta below the hysteresis threshold.
    DeltaTooSmall(u32),
    /// Too soon after the last resize (windows since, included).
    CooldownActive(u32),
}

/// A rollback record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rollback {
    /// Size rolled back from.
    pub from: u32,
    /// Size restored.
    pub to: u32,
    /// The observed regression (permille over baseline), capped at `u64::MAX`
    /// for reporting only. The rollback decision uses the uncapped value.
    pub regression_permille: u64,
}

/// The managed pool controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolController {
    /// Operator opt-in (config fact; default off).
    pub opted_in: bool,
    /// Current pool size.
    pub current_size: u32,
    /// Previous size (rollback target after a resize).
    pub previous_size: u32,
    /// Pre-resize baseline tail latency (ms).
    pub baseline_tail_ms: u64,
    /// Windows elapsed since the last applied resize.
    pub windows_since_resize: u32,
}

impl PoolController {
    /// A controller that has never resized.
    #[must_use]
    pub const fn new(opted_in: bool, size: u32, baseline_tail_ms: u64) -> Self {
        Self {
            opted_in,
            current_size: size,
            previous_size: size,
            baseline_tail_ms,
            // A fresh controller is past cooldown by construction.
            windows_since_resize: MIN_WINDOWS_BETWEEN_RESIZES,
        }
    }

    /// Evaluate a proposal against the gate; apply if every condition
    /// holds.
    ///
    /// # Errors
    /// The FIRST failed condition, typed. Order: opt-in, windows,
    /// evidence, replay, delta, cooldown — the cheap config facts
    /// before the expensive evidence questions.
    pub fn propose(
        &mut self,
        windows: &[ObservationWindow],
        proposal: ResizeProposal,
    ) -> Result<u32, ResizeRefusal> {
        if !self.opted_in {
            return Err(ResizeRefusal::NotOptedIn);
        }
        // Widen BEFORE accumulating. Individually valid u64 windows can
        // overflow either total even though their mean fits in u64 (#73).
        // A slice can hold at most usize::MAX windows, so these u128 totals
        // are exact on the supported 32/64-bit targets. Count the same windows
        // used by both sums; a capped diagnostic count is not a denominator.
        let (stable_count, evidence, tail_sum) = windows.iter().filter(|w| w.stable).fold(
            (0_u128, 0_u128, 0_u128),
            |(count, samples, tails), window| {
                (
                    count + 1,
                    samples + u128::from(window.samples),
                    tails + u128::from(window.tail_latency_ms),
                )
            },
        );
        if stable_count < u128::from(MIN_STABLE_WINDOWS) {
            return Err(ResizeRefusal::InsufficientStableWindows(
                u32::try_from(stable_count).expect("count below the u32 gate fits in u32"),
            ));
        }
        if evidence < u128::from(MIN_EVIDENCE_SAMPLES) {
            return Err(ResizeRefusal::InsufficientEvidence(
                u64::try_from(evidence).expect("evidence below the u64 gate fits in u64"),
            ));
        }
        if !proposal.replay_validated {
            return Err(ResizeRefusal::ReplayNotValidated);
        }
        let delta = self.current_size.abs_diff(proposal.new_size);
        if delta < MIN_RESIZE_DELTA {
            return Err(ResizeRefusal::DeltaTooSmall(delta));
        }
        if self.windows_since_resize < MIN_WINDOWS_BETWEEN_RESIZES {
            return Err(ResizeRefusal::CooldownActive(self.windows_since_resize));
        }
        // Applied: baseline is the stable-window tail going in.
        self.baseline_tail_ms =
            u64::try_from(tail_sum / stable_count).expect("the mean of u64 latencies fits in u64");
        self.previous_size = self.current_size;
        self.current_size = proposal.new_size;
        self.windows_since_resize = 0;
        Ok(self.current_size)
    }

    /// Observe one post-resize window. A tail regression beyond the
    /// bound rolls back to the previous size and says so.
    pub fn observe(&mut self, window: ObservationWindow) -> Option<Rollback> {
        self.windows_since_resize = self.windows_since_resize.saturating_add(1);
        if self.current_size == self.previous_size || self.baseline_tail_ms == 0 {
            return None; // nothing to roll back to
        }
        // Saturating the scaled numerator before division can turn a 100%
        // regression into 1.8%, suppressing rollback (#73). Keep the existing
        // integer-permille threshold, but decide in u128 and narrow only the
        // reported value. Even the largest possible delta times 1000 fits.
        let regression_permille =
            u128::from(window.tail_latency_ms.saturating_sub(self.baseline_tail_ms)) * 1_000
                / u128::from(self.baseline_tail_ms);
        if regression_permille > u128::from(ROLLBACK_REGRESSION_PERMILLE) {
            let rollback = Rollback {
                from: self.current_size,
                to: self.previous_size,
                regression_permille: u64::try_from(regression_permille).unwrap_or(u64::MAX),
            };
            self.current_size = self.previous_size;
            self.windows_since_resize = 0;
            return Some(rollback);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stable_windows(n: usize, samples: u64, tail: u64) -> Vec<ObservationWindow> {
        vec![
            ObservationWindow {
                samples,
                tail_latency_ms: tail,
                stable: true,
            };
            n
        ]
    }

    fn good_proposal() -> ResizeProposal {
        ResizeProposal {
            new_size: 12,
            replay_validated: true,
        }
    }

    #[test]
    fn the_gate_refuses_each_missing_condition_by_name() {
        // THE planted negatives: every condition, individually absent,
        // produces ITS refusal — not a generic no.
        let windows = stable_windows(6, 100, 800);
        // No opt-in: outermost.
        let mut c = PoolController::new(false, 8, 800);
        assert_eq!(
            c.propose(&windows, good_proposal()),
            Err(ResizeRefusal::NotOptedIn)
        );
        // Too few stable windows (unstable ones do not count).
        let mut c = PoolController::new(true, 8, 800);
        let mut mixed = stable_windows(5, 100, 800);
        mixed.push(ObservationWindow {
            samples: 100,
            tail_latency_ms: 800,
            stable: false, // brownout during the window
        });
        assert_eq!(
            c.propose(&mixed, good_proposal()),
            Err(ResizeRefusal::InsufficientStableWindows(5)),
            "an unstable window contributes nothing"
        );
        // Thin evidence.
        let mut c = PoolController::new(true, 8, 800);
        assert_eq!(
            c.propose(&stable_windows(6, 10, 800), good_proposal()),
            Err(ResizeRefusal::InsufficientEvidence(60))
        );
        // Replay not validated.
        let mut c = PoolController::new(true, 8, 800);
        assert_eq!(
            c.propose(
                &windows,
                ResizeProposal {
                    new_size: 12,
                    replay_validated: false
                }
            ),
            Err(ResizeRefusal::ReplayNotValidated)
        );
        // Hysteresis: delta of one worker is noise.
        let mut c = PoolController::new(true, 8, 800);
        assert_eq!(
            c.propose(
                &windows,
                ResizeProposal {
                    new_size: 9,
                    replay_validated: true
                }
            ),
            Err(ResizeRefusal::DeltaTooSmall(1))
        );
        // Cooldown: a second resize right after the first refuses.
        let mut c = PoolController::new(true, 8, 800);
        assert_eq!(c.propose(&windows, good_proposal()), Ok(12));
        assert_eq!(
            c.propose(
                &windows,
                ResizeProposal {
                    new_size: 16,
                    replay_validated: true
                }
            ),
            Err(ResizeRefusal::CooldownActive(0))
        );
    }

    #[test]
    fn a_fully_evidenced_opted_in_proposal_applies() {
        let mut c = PoolController::new(true, 8, 900);
        let applied = c.propose(&stable_windows(6, 100, 800), good_proposal());
        assert_eq!(applied, Ok(12));
        assert_eq!(c.current_size, 12);
        assert_eq!(c.previous_size, 8, "rollback target retained");
        assert_eq!(c.baseline_tail_ms, 800, "baseline from the windows");
    }

    #[test]
    fn induced_regression_rolls_back_automatically() {
        // THE acceptance: resize applies, then an INDUCED tail
        // regression (past the bound) rolls back to the previous size
        // with the regression recorded.
        let mut c = PoolController::new(true, 8, 800);
        assert_eq!(
            c.propose(&stable_windows(6, 100, 800), good_proposal()),
            Ok(12)
        );
        // First post-resize window: mild wobble inside the bound.
        assert_eq!(
            c.observe(ObservationWindow {
                samples: 100,
                tail_latency_ms: 880, // +10%: inside 15% bound
                stable: true,
            }),
            None
        );
        assert_eq!(c.current_size, 12, "no rollback inside the bound");
        // Induced regression: tail blows out 50% over baseline.
        let rollback = c.observe(ObservationWindow {
            samples: 100,
            tail_latency_ms: 1_200,
            stable: true,
        });
        assert_eq!(
            rollback,
            Some(Rollback {
                from: 12,
                to: 8,
                regression_permille: 500,
            })
        );
        assert_eq!(c.current_size, 8, "rolled back to the previous size");
        // After rollback there is nothing further to roll back to.
        assert_eq!(
            c.observe(ObservationWindow {
                samples: 100,
                tail_latency_ms: 2_000,
                stable: true,
            }),
            None
        );
    }

    #[test]
    fn healthy_post_resize_windows_keep_the_new_size() {
        let mut c = PoolController::new(true, 8, 800);
        assert_eq!(
            c.propose(&stable_windows(6, 100, 800), good_proposal()),
            Ok(12)
        );
        for _ in 0..20 {
            assert_eq!(
                c.observe(ObservationWindow {
                    samples: 100,
                    tail_latency_ms: 700, // improved
                    stable: true,
                }),
                None
            );
        }
        assert_eq!(c.current_size, 12);
        // And the cooldown has elapsed: a further resize may propose.
        assert!(c.windows_since_resize >= MIN_WINDOWS_BETWEEN_RESIZES);
    }

    #[test]
    fn overflowing_evidence_does_not_panic_or_wrap_below_the_gate() {
        let mut windows = stable_windows(6, 0, 800);
        windows[0].samples = u64::MAX;
        windows[1].samples = 1; // wraps to zero in the old u64 accumulator
        let mut c = PoolController::new(true, 8, 900);
        assert_eq!(c.propose(&windows, good_proposal()), Ok(12));
        assert_eq!(c.baseline_tail_ms, 800);
        assert_eq!(c.previous_size, 8);
    }

    #[test]
    fn overflowing_latency_totals_keep_the_exact_representable_mean() {
        let mut c = PoolController::new(true, 8, 800);
        assert_eq!(
            c.propose(&stable_windows(6, 100, u64::MAX), good_proposal()),
            Ok(12)
        );
        assert_eq!(c.baseline_tail_ms, u64::MAX);

        let mut windows = stable_windows(6, 100, 0);
        for window in &mut windows[..3] {
            window.tail_latency_ms = u64::MAX;
        }
        // Unstable windows must not enter either sum or the denominator.
        windows.push(ObservationWindow {
            samples: u64::MAX,
            tail_latency_ms: u64::MAX,
            stable: false,
        });
        let mut c = PoolController::new(true, 8, 800);
        assert_eq!(c.propose(&windows, good_proposal()), Ok(12));
        assert_eq!(c.baseline_tail_ms, u64::MAX / 2);
    }

    #[test]
    fn large_evidence_still_requires_replay_delta_and_cooldown() {
        let windows = stable_windows(6, u64::MAX, u64::MAX);
        for (proposal, elapsed, refusal) in [
            (
                ResizeProposal {
                    new_size: 12,
                    replay_validated: false,
                },
                MIN_WINDOWS_BETWEEN_RESIZES,
                ResizeRefusal::ReplayNotValidated,
            ),
            (
                ResizeProposal {
                    new_size: 9,
                    replay_validated: true,
                },
                MIN_WINDOWS_BETWEEN_RESIZES,
                ResizeRefusal::DeltaTooSmall(1),
            ),
            (good_proposal(), 1, ResizeRefusal::CooldownActive(1)),
        ] {
            let mut c = PoolController::new(true, 8, 800);
            c.windows_since_resize = elapsed;
            let before = c.clone();
            assert_eq!(c.propose(&windows, proposal), Err(refusal));
            assert_eq!(c, before, "a refused proposal must not change state");
        }
    }

    #[test]
    fn sample_gate_counts_only_stable_evidence_at_the_exact_boundary() {
        let mut windows = stable_windows(6, 0, 800);
        windows[0].samples = MIN_EVIDENCE_SAMPLES - 1;
        windows.push(ObservationWindow {
            samples: u64::MAX,
            tail_latency_ms: u64::MAX,
            stable: false,
        });
        let mut c = PoolController::new(true, 8, 900);
        let before = c.clone();
        assert_eq!(
            c.propose(&windows, good_proposal()),
            Err(ResizeRefusal::InsufficientEvidence(499))
        );
        assert_eq!(c, before);
        windows[0].samples += 1;
        assert_eq!(c.propose(&windows, good_proposal()), Ok(12));
        assert_eq!(c.baseline_tail_ms, 800);
    }

    #[test]
    fn doubled_large_tail_rolls_back_instead_of_reporting_eighteen_permille() {
        let baseline = 1_000_000_000_000_000_000;
        let mut c = PoolController::new(true, 8, baseline);
        assert_eq!(
            c.propose(&stable_windows(6, 100, baseline), good_proposal()),
            Ok(12)
        );
        assert_eq!(
            c.observe(ObservationWindow {
                samples: 100,
                tail_latency_ms: 2_000_000_000_000_000_000,
                stable: true,
            }),
            Some(Rollback {
                from: 12,
                to: 8,
                regression_permille: 1_000,
            })
        );
        assert_eq!(c.current_size, 8);
        assert_eq!(c.windows_since_resize, 0);
    }

    #[test]
    fn rollback_keeps_the_strict_integer_permille_threshold_at_every_scale() {
        for scale in [1, 1_000_000_000_000_000_u64] {
            for (tail, expected) in [(1_149, None), (1_150, None), (1_151, Some(151))] {
                let mut c = PoolController::new(true, 8, 1_000 * scale);
                c.current_size = 12;
                let rollback = c.observe(ObservationWindow {
                    samples: 100,
                    tail_latency_ms: tail * scale,
                    stable: true,
                });
                assert_eq!(rollback.map(|r| r.regression_permille), expected);
                assert_eq!(c.current_size, if expected.is_some() { 8 } else { 12 });
            }
        }
    }

    #[test]
    fn only_the_report_saturates_for_an_unrepresentable_regression() {
        let mut c = PoolController::new(true, 8, 1);
        c.current_size = 12;
        assert_eq!(
            c.observe(ObservationWindow {
                samples: 100,
                tail_latency_ms: u64::MAX,
                stable: true,
            }),
            Some(Rollback {
                from: 12,
                to: 8,
                regression_permille: u64::MAX,
            })
        );
        assert_eq!(c.current_size, 8);
    }

    #[test]
    fn rollback_matches_quotient_remainder_oracle_over_u64_extremes() {
        let values = [
            0,
            1,
            999,
            1_000,
            1_151,
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ];
        for baseline in values {
            for tail in values {
                let mut c = PoolController::new(true, 8, baseline);
                c.current_size = 12;
                let observed = c.observe(ObservationWindow {
                    samples: 100,
                    tail_latency_ms: tail,
                    stable: true,
                });
                // An independent decomposition avoids scaling the original
                // numerator, the operation that overflowed in the defect.
                let expected = if baseline == 0 || tail <= baseline {
                    None
                } else {
                    let delta = tail - baseline;
                    let ratio = u128::from(delta / baseline) * 1_000
                        + u128::from(delta % baseline) * 1_000 / u128::from(baseline);
                    (ratio > u128::from(ROLLBACK_REGRESSION_PERMILLE))
                        .then(|| u64::try_from(ratio).unwrap_or(u64::MAX))
                };
                assert_eq!(
                    observed.map(|r| r.regression_permille),
                    expected,
                    "baseline={baseline}, tail={tail}"
                );
                assert_eq!(c.current_size, if expected.is_some() { 8 } else { 12 });
            }
        }
    }

    #[test]
    fn the_gate_has_no_bypass_arm() {
        // Structural: the controller's fields are the opt-in, sizes,
        // baseline, and window counter — no force/override flag
        // exists to skip the gate.
        let PoolController {
            opted_in: _,
            current_size: _,
            previous_size: _,
            baseline_tail_ms: _,
            windows_since_resize: _,
        } = PoolController::new(false, 8, 800);
    }
}
