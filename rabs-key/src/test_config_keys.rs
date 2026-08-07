//! Nextest config keying + retry-pass flaky classification (bead
//! O015; plan §102; risk R91; extends the O002 test keys).
//!
//! Three rules:
//!
//! - the RUNNER PROFILE and its retry/timeout/fail-fast policy are
//!   KEY INPUTS: a profile change invalidates cached results (a test
//!   that passed under retries=2/timeout=60s proves nothing about
//!   retries=0/timeout=5s);
//! - setup scripts / archive state / once-per-run fixtures are BATCH
//!   PREREQUISITES: they key the batch and run before per-test
//!   serving — a per-test cache hit never skips them (there is no
//!   serve path that bypasses the prerequisite digest);
//! - a test that passes ONLY AFTER RETRY is FLAKY — never a stable
//!   authoritative pass. Flaky results are observations to report,
//!   not results to serve.

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for the runner-profile key component.
pub const DOMAIN_RUNNER_PROFILE: &str = "rabs.test-runner-profile.v1";

/// The keyed runner profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerProfileKey {
    /// Profile name (`default`, `ci`, ...).
    pub profile_name: String,
    /// Retry count policy.
    pub retries: u32,
    /// Per-test timeout (ms).
    pub timeout_ms: u64,
    /// Fail-fast enabled.
    pub fail_fast: bool,
    /// Setup-script/archive/once-per-run prerequisite digest (the
    /// batch prerequisite — content of the scripts + fixture state).
    pub batch_prerequisites: TypedDigest,
}

impl RunnerProfileKey {
    /// The profile's key component digest.
    #[must_use]
    pub fn profile_digest(&self) -> TypedDigest {
        let mut enc = CanonicalEncoder::new();
        enc.str(&self.profile_name)
            .u32(self.retries)
            .u64(self.timeout_ms)
            .bool(self.fail_fast)
            .str(self.batch_prerequisites.domain)
            .bytes(&self.batch_prerequisites.bytes);
        compute(DOMAIN_RUNNER_PROFILE, &enc.finish())
    }
}

/// One test case's execution history within a nextest run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionHistory {
    /// Per-execution pass/fail in order (nextest-ordered retries).
    pub executions: Vec<bool>,
}

/// The result classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestResultClass {
    /// Passed on the first execution: a stable, serveable pass.
    StablePass,
    /// Passed only after retries: FLAKY — reported, never served.
    FlakyRetryPass,
    /// Failed every execution.
    Fail,
}

/// Classify an execution history (R91).
#[must_use]
pub fn classify_result(history: &ExecutionHistory) -> TestResultClass {
    match history.executions.as_slice() {
        [] => TestResultClass::Fail, // never ran = no pass to serve
        [first, rest @ ..] => {
            if *first {
                TestResultClass::StablePass
            } else if rest.contains(&true) {
                TestResultClass::FlakyRetryPass
            } else {
                TestResultClass::Fail
            }
        }
    }
}

/// Whether a classification may be SERVED as an authoritative pass.
#[must_use]
pub const fn serveable(class: TestResultClass) -> bool {
    matches!(class, TestResultClass::StablePass)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        }
    }

    fn profile() -> RunnerProfileKey {
        RunnerProfileKey {
            profile_name: "ci".into(),
            retries: 2,
            timeout_ms: 60_000,
            fail_fast: false,
            batch_prerequisites: d(1),
        }
    }

    #[test]
    fn profile_change_invalidates() {
        // THE acceptance: every profile dimension forks the digest.
        let base = profile().profile_digest();
        let mut m = profile();
        m.profile_name = "default".into();
        assert_ne!(base, m.profile_digest());
        let mut m = profile();
        m.retries = 0;
        assert_ne!(base, m.profile_digest(), "retry policy is a key input");
        let mut m = profile();
        m.timeout_ms = 5_000;
        assert_ne!(base, m.profile_digest());
        let mut m = profile();
        m.fail_fast = true;
        assert_ne!(base, m.profile_digest());
        // Setup scripts / fixture state: a changed prerequisite forks —
        // and because the digest RIDES the profile key, no per-test
        // serve path exists that bypasses it.
        let mut m = profile();
        m.batch_prerequisites = d(9);
        assert_ne!(base, m.profile_digest());
    }

    #[test]
    fn retry_pass_is_flaky_never_authoritative() {
        // THE R91 acceptance fixture: FAIL then PASS = flaky.
        let retry_pass = ExecutionHistory {
            executions: vec![false, true],
        };
        assert_eq!(
            classify_result(&retry_pass),
            TestResultClass::FlakyRetryPass
        );
        assert!(!serveable(TestResultClass::FlakyRetryPass));
        // First-execution pass: stable, serveable.
        let stable = ExecutionHistory {
            executions: vec![true],
        };
        assert_eq!(classify_result(&stable), TestResultClass::StablePass);
        assert!(serveable(TestResultClass::StablePass));
        // All failures: fail; empty history serves nothing.
        assert_eq!(
            classify_result(&ExecutionHistory {
                executions: vec![false, false, false]
            }),
            TestResultClass::Fail
        );
        assert_eq!(
            classify_result(&ExecutionHistory { executions: vec![] }),
            TestResultClass::Fail
        );
    }

    #[test]
    fn a_pass_after_many_retries_is_still_flaky() {
        let eventually = ExecutionHistory {
            executions: vec![false, false, true],
        };
        assert_eq!(
            classify_result(&eventually),
            TestResultClass::FlakyRetryPass,
            "retry count does not launder flakiness"
        );
    }
}
