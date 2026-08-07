//! Side-effecting/setup/fixture-generation cache-ineligibility (bead
//! O012; plan §102; judges the O003 observation record).
//!
//! A test whose run CHANGES THE WORLD cannot serve from cache — the
//! world would silently stop changing. Four denial patterns, each
//! detected from the observation and denied with its own reason:
//!
//! - DATABASE MUTATION: writes to database files (`.db`/`.sqlite*`)
//!   anywhere, declared or not — a cached pass would skip the
//!   mutation the next consumer expects;
//! - FIXTURE GENERATION: writes INTO the source fixture tree
//!   (`tests/`, `fixtures/`, `golden` paths) — the test manufactures
//!   inputs, so serving it would freeze them;
//! - SHARED-STATE WRITE: any write outside the declared output/state
//!   dirs — undeclared mutation is ineligible, full stop;
//! - EXTERNAL SERVICE: network access observed (the O003 volatile
//!   record) — the pass depended on a service the cache cannot
//!   vouch for.
//!
//! Writes INSIDE declared output/state dirs are the eligible
//! control: declared effects are the action's own business. Every
//! violation is reported (never first-only), each naming its path or
//! endpoint.

use crate::test_observation::{DeclaredSideEffect, TestObservation, VolatileAccess};

/// One typed cache denial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheDenial {
    /// Stable reason code.
    pub reason_code: &'static str,
    /// The offending path or endpoint.
    pub subject: String,
}

/// Reason codes (wire-stable).
pub const DENIED_DATABASE_MUTATION: &str = "TEST_CACHE_DENIED_DATABASE_MUTATION";
/// Fixture generation into the source tree.
pub const DENIED_FIXTURE_GENERATION: &str = "TEST_CACHE_DENIED_FIXTURE_GENERATION";
/// Undeclared shared-state write.
pub const DENIED_SHARED_STATE_WRITE: &str = "TEST_CACHE_DENIED_SHARED_STATE_WRITE";
/// External service dependency.
pub const DENIED_EXTERNAL_SERVICE: &str = "TEST_CACHE_DENIED_EXTERNAL_SERVICE";

fn is_database_path(path: &str) -> bool {
    path.ends_with(".db") || path.contains(".sqlite")
}

fn is_fixture_tree_path(path: &str) -> bool {
    path.contains("/tests/") || path.contains("/fixtures/") || path.contains("/golden/")
}

/// Judge cache eligibility from the observation plus the writes the
/// supervised run actually performed.
///
/// # Errors
/// Every [`CacheDenial`] found (all violations, never first-only).
pub fn cache_eligibility(
    observation: &TestObservation,
    observed_writes: &[String],
) -> Result<(), Vec<CacheDenial>> {
    let mut denials = Vec::new();
    let declared: Vec<&str> = observation
        .side_effects
        .iter()
        .map(|effect| match effect {
            DeclaredSideEffect::OutputDir { path } | DeclaredSideEffect::StateDir { path } => {
                path.as_str()
            }
        })
        .collect();
    let inside_declared = |path: &str| {
        declared
            .iter()
            .any(|dir| path.starts_with(&format!("{dir}/")))
    };
    for write in observed_writes {
        // Database mutation denies even inside declared dirs: the
        // NEXT run needs the mutation to actually happen.
        if is_database_path(write) {
            denials.push(CacheDenial {
                reason_code: DENIED_DATABASE_MUTATION,
                subject: write.clone(),
            });
        } else if inside_declared(write) {
            // Declared effect: the action's own business.
        } else if is_fixture_tree_path(write) {
            denials.push(CacheDenial {
                reason_code: DENIED_FIXTURE_GENERATION,
                subject: write.clone(),
            });
        } else {
            denials.push(CacheDenial {
                reason_code: DENIED_SHARED_STATE_WRITE,
                subject: write.clone(),
            });
        }
    }
    for access in &observation.volatile {
        if let VolatileAccess::Network { endpoint } = access {
            denials.push(CacheDenial {
                reason_code: DENIED_EXTERNAL_SERVICE,
                subject: endpoint.clone(),
            });
        }
    }
    if denials.is_empty() {
        Ok(())
    } else {
        Err(denials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_observation::TestObservation;

    fn observation_with(side_effects: Vec<DeclaredSideEffect>) -> TestObservation {
        TestObservation {
            inputs: vec![],
            volatile: vec![],
            side_effects,
        }
    }

    #[test]
    fn the_corpus_covers_each_denial_pattern() {
        // THE acceptance corpus: one fixture per pattern, each denied
        // with ITS reason and the offending subject named.
        // (1) Database mutation.
        let denials = cache_eligibility(
            &observation_with(vec![]),
            &["/__rabs/state/app.sqlite3".to_owned()],
        )
        .expect_err("db mutation denies");
        assert_eq!(denials[0].reason_code, DENIED_DATABASE_MUTATION);
        assert!(denials[0].subject.contains("sqlite"));
        // (2) Fixture generation into the source tree.
        let denials = cache_eligibility(
            &observation_with(vec![]),
            &["/__rabs/workspace/tests/golden/new_case.json".to_owned()],
        )
        .expect_err("fixture generation denies");
        assert_eq!(denials[0].reason_code, DENIED_FIXTURE_GENERATION);
        // (3) Undeclared shared-state write.
        let denials = cache_eligibility(
            &observation_with(vec![]),
            &["/__rabs/shared/counters.txt".to_owned()],
        )
        .expect_err("shared state denies");
        assert_eq!(denials[0].reason_code, DENIED_SHARED_STATE_WRITE);
        // (4) External service dependency.
        let mut obs = observation_with(vec![]);
        obs.volatile.push(VolatileAccess::Network {
            endpoint: "postgres.internal:5432".into(),
        });
        let denials = cache_eligibility(&obs, &[]).expect_err("external service denies");
        assert_eq!(denials[0].reason_code, DENIED_EXTERNAL_SERVICE);
        assert_eq!(denials[0].subject, "postgres.internal:5432");
    }

    #[test]
    fn declared_effects_are_the_eligible_control() {
        // The same write, DECLARED: eligible — declared effects are
        // the action's own business.
        let obs = observation_with(vec![DeclaredSideEffect::OutputDir {
            path: "/__rabs/outputs/test-artifacts".into(),
        }]);
        assert_eq!(
            cache_eligibility(
                &obs,
                &["/__rabs/outputs/test-artifacts/report.xml".to_owned()]
            ),
            Ok(())
        );
        // And a fully clean test is eligible.
        assert_eq!(cache_eligibility(&observation_with(vec![]), &[]), Ok(()));
    }

    #[test]
    fn database_mutation_denies_even_when_declared() {
        // A declared state dir does NOT launder a database write: the
        // next consumer needs the mutation to happen.
        let obs = observation_with(vec![DeclaredSideEffect::StateDir {
            path: "/__rabs/state".into(),
        }]);
        let denials = cache_eligibility(&obs, &["/__rabs/state/app.db".to_owned()])
            .expect_err("db mutation denies regardless of declaration");
        assert_eq!(denials[0].reason_code, DENIED_DATABASE_MUTATION);
    }

    #[test]
    fn every_violation_is_reported_not_just_the_first() {
        let mut obs = observation_with(vec![]);
        obs.volatile.push(VolatileAccess::Network {
            endpoint: "redis:6379".into(),
        });
        let denials = cache_eligibility(
            &obs,
            &[
                "/__rabs/state/app.db".to_owned(),
                "/__rabs/workspace/tests/golden/x.json".to_owned(),
                "/__rabs/shared/y.txt".to_owned(),
            ],
        )
        .expect_err("all four deny");
        let codes: Vec<&str> = denials.iter().map(|d| d.reason_code).collect();
        assert_eq!(
            codes,
            vec![
                DENIED_DATABASE_MUTATION,
                DENIED_FIXTURE_GENERATION,
                DENIED_SHARED_STATE_WRITE,
                DENIED_EXTERNAL_SERVICE,
            ],
            "the full picture, never first-only"
        );
    }
}
