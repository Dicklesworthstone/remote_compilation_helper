//! N/N-1 rolling-upgrade rules + the upgrade matrix suite (bead
//! T009; plan §107; composes J002 negotiation, the R009 doctor, and
//! its own drain/rollback/migration/canary gates).
//!
//! The rules a rolling upgrade must obey:
//!
//! - every layer (wrapper contract, ATP transport, RABS application)
//!   upgrades INDEPENDENTLY, and every intermediate fleet state must
//!   either negotiate (N/N-1) or refuse typed — never misbehave;
//! - a worker replacement whose new version cannot negotiate with
//!   the version its in-flight clients speak requires DRAIN first
//!   (typed refusal carrying the in-flight count); a compatible
//!   replacement may go live immediately;
//! - rollback is admissible only to a version the current
//!   coordinator still speaks — rolling back PAST the compatibility
//!   floor is refused, not attempted;
//! - a DB migration applies only with a backup taken AND a clean
//!   differential check (each absence is its own typed refusal);
//! - canaries gate promotion: the required success count with ZERO
//!   failures promotes; any failure rolls back regardless of how
//!   many successes accumulated.
//!
//! Key/projection epochs are SEPARATE from all of this: no type in
//! this module (or the doctor's `NodeReport`) carries an epoch — an
//! application upgrade cannot invalidate cache keys by construction;
//! epochs move only by explicit F002 epoch bumps.

use crate::version_negotiation::{Negotiation, VersionHello, VersionRange, negotiate};

/// Replacement admission for a worker upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replacement {
    /// Old and new overlap: clients keep working mid-replacement.
    LiveReplace,
    /// The worker was already drained: replace freely.
    ReplaceAfterDrain,
}

/// Typed upgrade refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeRefusal {
    /// Incompatible replacement with jobs still in flight.
    DrainRequired {
        /// Jobs that must finish or migrate first.
        in_flight: u32,
    },
    /// Rollback target is below the coordinator's floor.
    RollbackPastCompatibilityFloor {
        /// The refused target version.
        target: u32,
        /// The coordinator's minimum.
        floor: u32,
    },
    /// Migration without a backup.
    MigrationBackupMissing,
    /// Migration without a clean differential check.
    MigrationDifferentialNotClean,
}

/// Admit a worker replacement.
///
/// # Errors
/// [`UpgradeRefusal::DrainRequired`] when the new version cannot
/// negotiate with what in-flight clients speak and jobs remain.
pub fn admit_replacement(
    old: &VersionHello,
    new: &VersionHello,
    in_flight: u32,
) -> Result<Replacement, UpgradeRefusal> {
    match negotiate(old, new) {
        Negotiation::Agreed { .. } => Ok(Replacement::LiveReplace),
        Negotiation::Refused(_) => {
            if in_flight > 0 {
                Err(UpgradeRefusal::DrainRequired { in_flight })
            } else {
                Ok(Replacement::ReplaceAfterDrain)
            }
        }
    }
}

/// Admit a rollback to `target` under a coordinator's range.
///
/// # Errors
/// [`UpgradeRefusal::RollbackPastCompatibilityFloor`] when the
/// target is below what the coordinator still speaks.
pub const fn admit_rollback(target: u32, coordinator: VersionRange) -> Result<u32, UpgradeRefusal> {
    if target < coordinator.minimum_compatible {
        return Err(UpgradeRefusal::RollbackPastCompatibilityFloor {
            target,
            floor: coordinator.minimum_compatible,
        });
    }
    Ok(target)
}

/// Admit a DB migration.
///
/// # Errors
/// A typed refusal for a missing backup or an unclean differential.
pub const fn admit_migration(
    backup_taken: bool,
    differential_clean: bool,
) -> Result<(), UpgradeRefusal> {
    if !backup_taken {
        return Err(UpgradeRefusal::MigrationBackupMissing);
    }
    if !differential_clean {
        return Err(UpgradeRefusal::MigrationDifferentialNotClean);
    }
    Ok(())
}

/// Canary verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryDecision {
    /// Enough clean canaries: promote the upgrade fleet-wide.
    Promote,
    /// A canary failed (or too few ran): roll back.
    RollBack,
}

/// Judge canary results: `required` successes, ZERO failures.
#[must_use]
pub fn canary_verdict(results: &[bool], required: u32) -> CanaryDecision {
    let successes = u32::try_from(results.iter().filter(|r| **r).count()).unwrap_or(u32::MAX);
    let any_failure = results.iter().any(|r| !*r);
    if any_failure || successes < required {
        CanaryDecision::RollBack
    } else {
        CanaryDecision::Promote
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat_doctor::{NodeReport, diagnose};

    /// Hello at application version `v` (N-1 floor), transport 2.
    fn hello(v: u32) -> VersionHello {
        VersionHello {
            transport: VersionRange {
                minimum_compatible: 1,
                current: 2,
            },
            application: VersionRange {
                minimum_compatible: v.saturating_sub(1).max(1),
                current: v,
            },
        }
    }

    fn node(node_id: u64, app: u32) -> NodeReport {
        NodeReport {
            node_id,
            hello: hello(app),
            schema_fingerprint: 0xFEED,
            wrapper_contract: 4,
        }
    }

    #[test]
    fn the_upgrade_matrix_is_green_through_every_intermediate_state() {
        // THE acceptance matrix: coordinator/edge/worker at every
        // N/N-1 combination of application v5/v6 — all nine
        // intermediate fleet states negotiate and diagnose healthy;
        // any node at N-2 (v4) refuses or flags.
        for coordinator_v in [5, 6] {
            for edge_v in [5, 6] {
                for worker_v in [5, 6] {
                    let coordinator = node(0, coordinator_v);
                    let fleet = [node(1, edge_v), node(2, worker_v)];
                    let report = diagnose(&coordinator, &fleet);
                    assert!(
                        report.healthy(),
                        "N/N-1 state ({coordinator_v},{edge_v},{worker_v}) must be green: \
                         {:?}",
                        report.findings
                    );
                }
            }
        }
        // N-2 in the mix: the doctor flags it (matrix edge).
        let report = diagnose(&node(0, 6), &[node(1, 4)]);
        assert!(!report.healthy(), "v6 coordinator + v4 node is not green");
    }

    #[test]
    fn incompatible_worker_replacement_requires_drain() {
        // Old worker speaks 4..=5; the replacement dropped v5 support
        // entirely (7..=8): in-flight clients would strand.
        let old = hello(5);
        let incompatible = VersionHello {
            transport: old.transport,
            application: VersionRange {
                minimum_compatible: 7,
                current: 8,
            },
        };
        assert_eq!(
            admit_replacement(&old, &incompatible, 12),
            Err(UpgradeRefusal::DrainRequired { in_flight: 12 })
        );
        // Drained: replacement admissible.
        assert_eq!(
            admit_replacement(&old, &incompatible, 0),
            Ok(Replacement::ReplaceAfterDrain)
        );
        // A compatible N/N-1 replacement goes live with jobs in
        // flight — live wrappers survive the upgrade.
        assert_eq!(
            admit_replacement(&hello(5), &hello(6), 12),
            Ok(Replacement::LiveReplace)
        );
    }

    #[test]
    fn rollback_stops_at_the_compatibility_floor() {
        let coordinator = VersionRange {
            minimum_compatible: 5,
            current: 6,
        };
        assert_eq!(admit_rollback(5, coordinator), Ok(5), "N-1 rollback fine");
        assert_eq!(
            admit_rollback(4, coordinator),
            Err(UpgradeRefusal::RollbackPastCompatibilityFloor {
                target: 4,
                floor: 5
            })
        );
    }

    #[test]
    fn migrations_require_backup_and_clean_differential() {
        assert_eq!(
            admit_migration(false, true),
            Err(UpgradeRefusal::MigrationBackupMissing)
        );
        assert_eq!(
            admit_migration(true, false),
            Err(UpgradeRefusal::MigrationDifferentialNotClean)
        );
        assert_eq!(admit_migration(true, true), Ok(()));
    }

    #[test]
    fn canaries_promote_only_clean_and_sufficient() {
        assert_eq!(
            canary_verdict(&[true, true, true], 3),
            CanaryDecision::Promote
        );
        // One failure rolls back regardless of successes.
        assert_eq!(
            canary_verdict(&[true, true, true, false], 3),
            CanaryDecision::RollBack
        );
        // Too few canaries is not promotion.
        assert_eq!(canary_verdict(&[true, true], 3), CanaryDecision::RollBack);
        assert_eq!(canary_verdict(&[], 1), CanaryDecision::RollBack);
    }

    #[test]
    fn key_and_projection_epochs_are_separate_from_upgrades() {
        // Structural: NO type in the upgrade path carries an epoch —
        // NodeReport's exhaustive destructure proves an application
        // upgrade has no epoch field to touch. Epochs move only by
        // explicit F002 bumps in the descriptor.
        let NodeReport {
            node_id: _,
            hello: _,
            schema_fingerprint: _,
            wrapper_contract: _,
        } = node(1, 6); // a new field lands here for review first
    }
}
