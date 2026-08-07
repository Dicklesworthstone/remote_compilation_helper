//! The nextest runner protocol (bead O001; plan §102; Epic O's seam).
//!
//! RABS intercepts test launches through nextest's TARGET-RUNNER seam:
//! nextest resolves a target runner (env `CARGO_TARGET_<T>_RUNNER` /
//! `target.'cfg'.runner` config) and invokes it as
//! `runner <test-binary> <args...>` for enumeration (`--list`) and for
//! per-case execution (`--exact <case> --nocapture ...`). The protocol
//! model here versions that seam:
//!
//! - [`TestLaunch`] captures everything nextest hands the runner —
//!   binary, args, env, cwd — plus the phase (enumeration vs
//!   execution) RABS classifies from the args;
//! - the runner contract fixes signal forwarding (TERM/INT forwarded
//!   to the case; KILL after the grace window), retry transparency
//!   (nextest owns retries — the runner NEVER retries internally,
//!   which would corrupt nextest's flaky-test accounting), and
//!   complete stdout/stderr pass-through;
//! - [`NEXTEST_VERSION_MATRIX`] records the supported releases and
//!   their seam behavior; an unlisted version refuses interception
//!   (the wrapper steps aside and the stock runner runs).

/// The phase a launch belongs to (classified from argv).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchPhase {
    /// Test enumeration (`--list` present).
    Enumeration,
    /// One test case (`--exact` present).
    PerCaseExecution,
    /// Whole-binary run (no case filter — batch mode).
    WholeBinary,
}

/// One intercepted test launch (the seam's data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestLaunch {
    /// The test binary path as nextest resolved it.
    pub binary: String,
    /// Arguments after the binary.
    pub args: Vec<String>,
    /// Environment nextest set for the case.
    pub env: Vec<(String, String)>,
    /// Working directory nextest chose.
    pub cwd: String,
}

impl TestLaunch {
    /// Classify the launch phase from the args.
    #[must_use]
    pub fn phase(&self) -> LaunchPhase {
        if self.args.iter().any(|a| a == "--list") {
            LaunchPhase::Enumeration
        } else if self.args.iter().any(|a| a == "--exact") {
            LaunchPhase::PerCaseExecution
        } else {
            LaunchPhase::WholeBinary
        }
    }

    /// The exact case name for per-case launches.
    #[must_use]
    pub fn case_name(&self) -> Option<&str> {
        let pos = self.args.iter().position(|a| a == "--exact")?;
        self.args.get(pos + 1).map(String::as_str)
    }
}

/// The runner contract RABS's adapter must honor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerContract {
    /// Signals forwarded to the case (TERM/INT).
    pub forwards_term_and_int: bool,
    /// KILL escalation grace window (ms).
    pub kill_grace_ms: u64,
    /// The runner NEVER retries internally: nextest owns retries, and
    /// an internal retry would corrupt its flaky-test accounting.
    pub internal_retries_forbidden: bool,
    /// stdout/stderr pass through completely (nextest parses them).
    pub complete_output_passthrough: bool,
}

/// The one contract (constants, not configuration).
pub const RUNNER_CONTRACT: RunnerContract = RunnerContract {
    forwards_term_and_int: true,
    kill_grace_ms: 10_000,
    internal_retries_forbidden: true,
    complete_output_passthrough: true,
};

/// One row of the version matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextestVersionRow {
    /// Version range this row covers (inclusive minor range).
    pub versions: &'static str,
    /// Whether the target-runner seam behaves as modeled.
    pub seam_verified: bool,
    /// Notes on seam differences.
    pub notes: &'static str,
}

/// The supported-version matrix (started per the acceptance; rows are
/// appended as releases are verified).
pub const NEXTEST_VERSION_MATRIX: [NextestVersionRow; 2] = [
    NextestVersionRow {
        versions: "0.9.70-0.9.99",
        seam_verified: true,
        notes: "target-runner env + config forms both resolve; --list/--exact stable",
    },
    NextestVersionRow {
        versions: "0.9.x-future",
        seam_verified: false,
        notes: "unverified: interception refuses; stock runner runs",
    },
];

/// Whether RABS may intercept launches for a nextest version string.
/// Unlisted/unverified versions refuse — the wrapper steps aside.
#[must_use]
pub fn may_intercept(version: &str) -> bool {
    // Verified range today: 0.9.70..=0.9.99 (parsed minimally).
    let Some(patch) = version.strip_prefix("0.9.") else {
        return false;
    };
    patch
        .parse::<u32>()
        .is_ok_and(|patch| (70..=99).contains(&patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch(args: &[&str]) -> TestLaunch {
        TestLaunch {
            binary: "/target/debug/deps/mytest-abc".into(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            env: vec![("NEXTEST".into(), "1".into())],
            cwd: "/w".into(),
        }
    }

    #[test]
    fn phases_classify_from_argv() {
        assert_eq!(
            launch(&["--list", "--format", "terse"]).phase(),
            LaunchPhase::Enumeration
        );
        let per_case = launch(&["--exact", "parser::tests::round_trip", "--nocapture"]);
        assert_eq!(per_case.phase(), LaunchPhase::PerCaseExecution);
        assert_eq!(per_case.case_name(), Some("parser::tests::round_trip"));
        assert_eq!(launch(&["--nocapture"]).phase(), LaunchPhase::WholeBinary);
        assert_eq!(launch(&["--nocapture"]).case_name(), None);
    }

    #[test]
    fn the_runner_contract_is_fixed() {
        // The contract is constants: signal forwarding on, retries
        // forbidden (nextest owns flaky accounting), full passthrough.
        // (black_box launders the const so the pin is a real runtime
        // comparison, not a compile-time tautology.)
        let contract = std::hint::black_box(RUNNER_CONTRACT);
        assert_eq!(
            contract,
            RunnerContract {
                forwards_term_and_int: true,
                kill_grace_ms: 10_000,
                internal_retries_forbidden: true,
                complete_output_passthrough: true,
            }
        );
    }

    #[test]
    fn unlisted_versions_refuse_interception() {
        // Verified range intercepts.
        assert!(may_intercept("0.9.70"));
        assert!(may_intercept("0.9.85"));
        assert!(may_intercept("0.9.99"));
        // Everything else steps aside (the stock runner runs).
        assert!(!may_intercept("0.9.69"));
        assert!(!may_intercept("0.10.0"));
        assert!(!may_intercept("1.0.0"));
        assert!(!may_intercept("garbage"));
        // The matrix documents both states.
        assert!(NEXTEST_VERSION_MATRIX[0].seam_verified);
        assert!(!NEXTEST_VERSION_MATRIX[1].seam_verified);
    }

    #[test]
    fn the_launch_captures_the_full_seam() {
        // Schema completeness: binary, args, env, cwd — everything
        // nextest hands the runner.
        let TestLaunch {
            binary: _,
            args: _,
            env: _,
            cwd: _,
        } = launch(&[]);
    }
}
