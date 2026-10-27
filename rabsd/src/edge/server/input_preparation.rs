//! Start independent input observations in the same live request.
//!
//! A pending package used to return before dependency observation began, so
//! cold builds paid for source and dependency hashing serially (plus another
//! wrapper backoff). Both observers already own bounded, generation-fenced
//! singleflight work. Start them together, but do not retain an action, a
//! waiter, or output ownership while either input set is incomplete.

use crate::coord::live_dependency::canonical::CanonicalPaths;
use crate::edge::live_facts::{DependencyFacts, FactsMiss, LiveFacts, PackageFacts};
use rabs_key::live_dependency::DependencyActionPlan;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub(super) enum InputMiss {
    Package(FactsMiss),
    Dependencies(FactsMiss),
    PackageAndDependenciesPending,
}

pub(super) fn observe(
    facts: &Arc<LiveFacts>,
    logical: &DependencyActionPlan,
    physical: &DependencyActionPlan,
    canonical: Option<&CanonicalPaths>,
    may_wait: bool,
) -> Result<(Arc<PackageFacts>, Arc<DependencyFacts>), InputMiss> {
    let package = match canonical {
        Some(paths) => {
            let generated = paths
                .generated_root(logical, physical)
                .map_err(|reason| InputMiss::Package(FactsMiss::Refused(reason)))?;
            facts.package_canonical(physical, generated.as_ref())
        }
        None => {
            if logical.canonical_cargo || physical.canonical_cargo {
                return Err(InputMiss::Package(FactsMiss::Refused(
                    "canonical package observation lacks its retained driver mapping".into(),
                )));
            }
            facts.package(
                Path::new(&physical.source_root),
                physical.source_kind,
                physical.generated_root.as_deref().map(Path::new),
            )
        }
    };
    join_observations(package, || facts.dependencies(physical), may_wait)
}

/// A refusal is terminal, whereas Pending is only readiness. In particular,
/// a permanently refused dependency must not hide behind a warming package.
/// Legacy non-waiting callers keep their early, healthy fallback and do not
/// schedule speculative work once their package observation has missed.
fn join_observations<P, D>(
    package: Result<P, FactsMiss>,
    observe_dependencies: impl FnOnce() -> Result<D, FactsMiss>,
    may_wait: bool,
) -> Result<(P, D), InputMiss> {
    let package = match package {
        Ok(package) => Ok(package),
        Err(FactsMiss::Pending) if may_wait => Err(FactsMiss::Pending),
        Err(miss) => return Err(InputMiss::Package(miss)),
    };
    // This call must happen before returning a pending package. It grants
    // observation authority only; the caller still validates generated
    // inputs, binds the captured build-script environment, keys, and asks
    // the coordinator for execution/reuse after BOTH observations are ready.
    let dependencies = observe_dependencies();
    match (package, dependencies) {
        (_, Err(miss @ FactsMiss::Refused(_))) => Err(InputMiss::Dependencies(miss)),
        (Err(FactsMiss::Pending), Err(FactsMiss::Pending)) => {
            Err(InputMiss::PackageAndDependenciesPending)
        }
        (Err(miss), _) => Err(InputMiss::Package(miss)),
        (Ok(_), Err(miss)) => Err(InputMiss::Dependencies(miss)),
        (Ok(package), Ok(dependencies)) => Ok((package, dependencies)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn cold_package_starts_dependencies_before_returning_preparing() {
        let calls = Cell::new(0);
        let result = join_observations::<(), ()>(
            Err(FactsMiss::Pending),
            || {
                calls.set(calls.get() + 1);
                Err(FactsMiss::Pending)
            },
            true,
        );
        assert_eq!(calls.get(), 1);
        assert!(matches!(
            result,
            Err(InputMiss::PackageAndDependenciesPending)
        ));
    }

    #[test]
    fn a_ready_dependency_cannot_admit_a_pending_package() {
        let calls = Cell::new(0);
        let result = join_observations::<(), _>(
            Err(FactsMiss::Pending),
            || {
                calls.set(calls.get() + 1);
                Ok("observed dependency generation")
            },
            true,
        );
        assert_eq!(calls.get(), 1);
        assert!(matches!(
            result,
            Err(InputMiss::Package(FactsMiss::Pending))
        ));
    }

    #[test]
    fn dependency_refusal_wins_over_a_pending_package() {
        let result = join_observations::<(), ()>(
            Err(FactsMiss::Pending),
            || Err(FactsMiss::Refused("dependency aliases an output".into())),
            true,
        );
        assert!(matches!(
            result,
            Err(InputMiss::Dependencies(FactsMiss::Refused(reason)))
                if reason == "dependency aliases an output"
        ));
    }

    #[test]
    fn terminal_package_refusal_never_schedules_dependencies() {
        for may_wait in [false, true] {
            let result = join_observations::<(), ()>(
                Err(FactsMiss::Refused("source root is a symlink".into())),
                || panic!("refused sources must not occupy another warmer"),
                may_wait,
            );
            assert!(matches!(
                result,
                Err(InputMiss::Package(FactsMiss::Refused(reason)))
                    if reason == "source root is a symlink"
            ));
        }
    }

    #[test]
    fn legacy_package_miss_preserves_non_speculative_fallback() {
        let result = join_observations::<(), ()>(
            Err(FactsMiss::Pending),
            || panic!("a legacy caller has already declined waiting"),
            false,
        );
        assert!(matches!(
            result,
            Err(InputMiss::Package(FactsMiss::Pending))
        ));
    }

    #[test]
    fn ready_package_still_waits_for_dependencies_and_propagates_refusals() {
        for may_wait in [false, true] {
            let pending =
                join_observations::<_, ()>(Ok("package"), || Err(FactsMiss::Pending), may_wait);
            assert!(matches!(
                pending,
                Err(InputMiss::Dependencies(FactsMiss::Pending))
            ));
            let refused = join_observations::<_, ()>(
                Ok("package"),
                || Err(FactsMiss::Refused("changed dependency generation".into())),
                may_wait,
            );
            assert!(matches!(
                refused,
                Err(InputMiss::Dependencies(FactsMiss::Refused(reason)))
                    if reason == "changed dependency generation"
            ));
        }
    }

    #[test]
    fn both_ready_returns_the_exact_observation_owners_once() {
        let package = Arc::new("package generation");
        let dependencies = Arc::new("dependency generation");
        let calls = Cell::new(0);
        let (p, d) = join_observations(
            Ok(Arc::clone(&package)),
            || {
                calls.set(calls.get() + 1);
                Ok(Arc::clone(&dependencies))
            },
            true,
        )
        .unwrap();
        assert!(Arc::ptr_eq(&p, &package));
        assert!(Arc::ptr_eq(&d, &dependencies));
        assert_eq!(calls.get(), 1);
    }
}
