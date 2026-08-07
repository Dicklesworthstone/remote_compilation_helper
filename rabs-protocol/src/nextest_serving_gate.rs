//! Nextest interception semantics-proof gate (bead O011; plan §102;
//! the serving flag COUPLED to the proof matrix).
//!
//! Test-result serving is EARNED per nextest version by a
//! shadow-first semantics proof across five dimensions — cwd, env,
//! signal handling, retry transparency, output fidelity. The gate:
//!
//! - a version serves test results ONLY when every dimension is
//!   proven (the flag is DERIVED from the matrix row, not stored —
//!   there is no field to set without the proofs);
//! - a version failing ANY dimension keeps test execution UNCACHED
//!   while compile actions still benefit (the degraded mode is
//!   explicit, not a silent downgrade);
//! - unknown versions have no row and never serve.

use crate::nextest_runner::may_intercept;

/// The five proof dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ProofDimension {
    Cwd,
    Env,
    Signals,
    RetryTransparency,
    OutputFidelity,
}

/// One version's semantics-proof row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticsProofRow {
    /// The nextest version this row covers.
    pub version: String,
    /// Dimensions proven by shadow integration.
    pub proven: Vec<ProofDimension>,
}

impl SemanticsProofRow {
    /// Whether ALL five dimensions are proven.
    #[must_use]
    pub fn fully_proven(&self) -> bool {
        [
            ProofDimension::Cwd,
            ProofDimension::Env,
            ProofDimension::Signals,
            ProofDimension::RetryTransparency,
            ProofDimension::OutputFidelity,
        ]
        .iter()
        .all(|d| self.proven.contains(d))
    }
}

/// The serving decision for test actions under one nextest version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestServingMode {
    /// Full test-result caching/serving.
    ServeTestResults,
    /// Tests run UNCACHED; compile actions still benefit.
    TestsUncachedCompilesBenefit,
}

/// Derive the serving mode: version interceptable AND fully proven.
/// The flag is DERIVED — no stored boolean exists to flip without
/// the proofs.
#[must_use]
pub fn serving_mode(version: &str, proof_matrix: &[SemanticsProofRow]) -> TestServingMode {
    let proven = proof_matrix
        .iter()
        .find(|row| row.version == version)
        .is_some_and(SemanticsProofRow::fully_proven);
    if may_intercept(version) && proven {
        TestServingMode::ServeTestResults
    } else {
        TestServingMode::TestsUncachedCompilesBenefit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ProofDimension as D;

    fn full_row(version: &str) -> SemanticsProofRow {
        SemanticsProofRow {
            version: version.into(),
            proven: vec![
                D::Cwd,
                D::Env,
                D::Signals,
                D::RetryTransparency,
                D::OutputFidelity,
            ],
        }
    }

    #[test]
    fn serving_requires_the_full_proof_matrix_row() {
        // THE acceptance: the serving flag is COUPLED to the matrix.
        let matrix = vec![full_row("0.9.85")];
        assert_eq!(
            serving_mode("0.9.85", &matrix),
            TestServingMode::ServeTestResults
        );
        // ONE missing dimension (signals unproven): tests uncached,
        // compiles still benefit.
        let partial = vec![SemanticsProofRow {
            version: "0.9.86".into(),
            proven: vec![D::Cwd, D::Env, D::RetryTransparency, D::OutputFidelity],
        }];
        assert_eq!(
            serving_mode("0.9.86", &partial),
            TestServingMode::TestsUncachedCompilesBenefit
        );
    }

    #[test]
    fn unknown_or_uninterceptable_versions_never_serve() {
        // No matrix row: never serve.
        assert_eq!(
            serving_mode("0.9.85", &[]),
            TestServingMode::TestsUncachedCompilesBenefit
        );
        // Fully proven row for a version OUTSIDE the interception
        // range: still refuses (both gates must pass).
        let matrix = vec![full_row("0.10.0")];
        assert_eq!(
            serving_mode("0.10.0", &matrix),
            TestServingMode::TestsUncachedCompilesBenefit
        );
    }

    #[test]
    fn the_flag_is_derived_never_stored() {
        // Structural: TestServingMode is an output of serving_mode
        // only; SemanticsProofRow has no serve boolean to flip — the
        // exhaustive destructure pins the row's shape.
        let SemanticsProofRow {
            version: _,
            proven: _,
        } = full_row("0.9.85");
        // And the degraded mode is explicit, not an absence.
        match serving_mode("garbage", &[]) {
            TestServingMode::ServeTestResults | TestServingMode::TestsUncachedCompilesBenefit => {}
        }
    }
}
