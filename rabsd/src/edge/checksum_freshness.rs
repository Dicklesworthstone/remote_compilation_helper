//! Checksum-freshness opt-in lane (bead D015; plan §28).
//!
//! Nightly Cargo can judge freshness by CONTENT CHECKSUM
//! (`-Zchecksum-freshness`) instead of mtimes — which dissolves the
//! whole D009/D010 mtime-choreography problem class for toolchains
//! that support it. But an unvalidated freshness semantic is worse
//! than the devil we choreograph, so the lane is triple-gated:
//!
//! - **supported**: the toolchain is nightly (capability detection,
//!   same rule as trim-paths — never assumed);
//! - **opted in**: the profile explicitly selects checksum freshness;
//! - **validated**: the differential suite passed FOR THIS TOOLCHAIN
//!   and the validation is recorded by toolchain version — D010's
//!   serving decision accepts the checksum lane only from a validated
//!   record, so skew handling can never route through an unproven
//!   semantic.
//!
//! Materialization absorbs checksum freshness without changing CAS
//! semantics by construction: CAS objects are already content-addressed
//! and immutable; the only thing the lane changes is whether Cargo
//! consults mtimes at all (the D009 floor becomes advisory).

/// The explicit freshness profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FreshnessProfile {
    /// Mtime-based freshness with D009/D010 choreography (default).
    #[default]
    Mtime,
    /// Opt-in checksum freshness (requires support + validation).
    ChecksumOptIn,
}

/// A recorded validation of the checksum lane for one toolchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneValidation {
    /// The toolchain's verbose version the differential suite ran on.
    pub toolchain_verbose_version: String,
}

/// The resolved checksum-freshness lane state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumFreshnessLane {
    /// Toolchain supports `-Zchecksum-freshness` (nightly).
    pub supported: bool,
    /// The profile opted in.
    pub opted_in: bool,
    /// The recorded validation, if the differential suite passed for
    /// this exact toolchain.
    pub validation: Option<LaneValidation>,
}

impl ChecksumFreshnessLane {
    /// Resolve the lane from toolchain capability + profile +
    /// validation records. Support detection uses the release channel
    /// from `rustc -vV` (nightly-only Cargo flag — never assumed).
    #[must_use]
    pub fn resolve(
        rustc_verbose_version: &str,
        profile: FreshnessProfile,
        recorded_validation: Option<&LaneValidation>,
    ) -> Self {
        let release = rustc_verbose_version
            .lines()
            .find_map(|line| line.strip_prefix("release: "))
            .unwrap_or_default();
        let supported = release.contains("-nightly") || release.contains("-dev");
        // A validation recorded for a DIFFERENT toolchain does not
        // stand — the record must name this exact version report.
        let validation = recorded_validation
            .filter(|record| {
                rustc_verbose_version.contains(&record.toolchain_verbose_version)
                    || record.toolchain_verbose_version == rustc_verbose_version
            })
            .cloned();
        Self {
            supported,
            opted_in: profile == FreshnessProfile::ChecksumOptIn,
            validation,
        }
    }

    /// Whether the lane is ACTIVE (all three gates open).
    #[must_use]
    pub fn active(&self) -> bool {
        self.supported && self.opted_in && self.validation.is_some()
    }

    /// The extra Cargo argv when active (empty otherwise — an inactive
    /// lane changes nothing).
    #[must_use]
    pub fn cargo_args(&self) -> Vec<String> {
        if self.active() {
            vec!["-Zchecksum-freshness".to_string()]
        } else {
            Vec::new()
        }
    }

    /// The D010 serving-decision input: the checksum lane is offered to
    /// skew handling ONLY when active — an unvalidated lane can never
    /// absorb a skew bypass.
    #[must_use]
    pub fn validated_for_serving(&self) -> bool {
        self.active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::mtime_choreography::{MtimeCoherence, ServingDecision, serving_decision};

    const NIGHTLY: &str = "rustc 1.99.0-nightly (09ee43b2d 2026-07-27)\nrelease: 1.99.0-nightly\n";
    const STABLE: &str = "rustc 1.85.0\nrelease: 1.85.0\n";

    fn validation() -> LaneValidation {
        LaneValidation {
            toolchain_verbose_version: "1.99.0-nightly (09ee43b2d 2026-07-27)".to_string(),
        }
    }

    #[test]
    fn all_three_gates_must_open() {
        // supported + opted-in + validated => active.
        let active = ChecksumFreshnessLane::resolve(
            NIGHTLY,
            FreshnessProfile::ChecksumOptIn,
            Some(&validation()),
        );
        assert!(active.active());
        assert_eq!(active.cargo_args(), vec!["-Zchecksum-freshness"]);

        // Stable toolchain: unsupported regardless of the rest.
        let unsupported = ChecksumFreshnessLane::resolve(
            STABLE,
            FreshnessProfile::ChecksumOptIn,
            Some(&validation()),
        );
        assert!(!unsupported.active());
        assert!(unsupported.cargo_args().is_empty());

        // No opt-in: inactive.
        let not_opted =
            ChecksumFreshnessLane::resolve(NIGHTLY, FreshnessProfile::Mtime, Some(&validation()));
        assert!(!not_opted.active());

        // No validation record: inactive.
        let unvalidated =
            ChecksumFreshnessLane::resolve(NIGHTLY, FreshnessProfile::ChecksumOptIn, None);
        assert!(!unvalidated.active());
    }

    #[test]
    fn a_validation_for_a_different_toolchain_does_not_stand() {
        let stale_record = LaneValidation {
            toolchain_verbose_version: "1.98.0-nightly (11aa22b3c 2026-06-01)".to_string(),
        };
        let lane = ChecksumFreshnessLane::resolve(
            NIGHTLY,
            FreshnessProfile::ChecksumOptIn,
            Some(&stale_record),
        );
        assert!(
            lane.validation.is_none(),
            "cross-toolchain validation laundering"
        );
        assert!(!lane.active());
    }

    #[test]
    fn skew_routes_through_checksum_lane_only_when_validated() {
        // The D010 coupling: an unvalidated lane can never absorb skew.
        let skew = MtimeCoherence::SkewedFuture {
            skewed: vec![("x.rs".to_string(), u128::MAX)],
        };
        let unvalidated =
            ChecksumFreshnessLane::resolve(NIGHTLY, FreshnessProfile::ChecksumOptIn, None);
        assert!(matches!(
            serving_decision(skew.clone(), unvalidated.validated_for_serving()),
            ServingDecision::Bypass { .. }
        ));
        let validated = ChecksumFreshnessLane::resolve(
            NIGHTLY,
            FreshnessProfile::ChecksumOptIn,
            Some(&validation()),
        );
        assert_eq!(
            serving_decision(skew, validated.validated_for_serving()),
            ServingDecision::ServeWithChecksumFreshness
        );
    }
}
