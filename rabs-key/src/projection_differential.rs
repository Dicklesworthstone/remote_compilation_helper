//! Exact-vs-projected differential + automatic rollback (bead F022;
//! plan §62; risk R49's runtime enforcement arm).
//!
//! F010 admits a projection; this framework keeps it honest IN
//! PRODUCTION: every projected hit is shadow-compared against the
//! conservative exact path, and the FIRST divergence:
//!
//! 1. **disables the projection epoch automatically** — no operator in
//!    the loop, no grace period: the epoch that produced the divergent
//!    hit is dead for new keying from that observation on;
//! 2. **quarantines affected serving** — every serving record produced
//!    under the disabled epoch is listed for the F032 quarantine
//!    transition (an incident ID per record, never a prose reason);
//! 3. keeps the evidence: the differential record ties projected and
//!    exact digests to the action for the divergence incident.
//!
//! The framework also quantifies benefit honestly: hits-avoided-by-
//! projection is reported NEXT TO the divergence count — a projection
//! with any divergence has negative worth regardless of hit gains, and
//! the report structure makes that unhideable.

use rabs_protocol::result_identity::TypedDigest;

/// One shadow comparison of a projected hit against the exact path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DifferentialObservation {
    /// The action key (projected namespace) that hit.
    pub action_key: TypedDigest,
    /// Semantic result digest served via the projection.
    pub projected_result: TypedDigest,
    /// Semantic result digest the exact path produced in shadow.
    pub exact_result: TypedDigest,
    /// Serving-record revision that served the projected hit (for
    /// quarantine addressing).
    pub serving_record_revision: u64,
}

impl DifferentialObservation {
    /// Whether this observation diverges.
    #[must_use]
    pub fn diverges(&self) -> bool {
        self.projected_result != self.exact_result
    }
}

/// The state of one projection epoch under differential watch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochStanding {
    /// No divergence observed so far, with the count of clean
    /// shadow-verified hits (the benefit numerator).
    CleanSoFar {
        /// Shadow-verified projected hits.
        verified_hits: u64,
    },
    /// Divergence observed: epoch auto-disabled.
    Disabled {
        /// The observation that killed it.
        first_divergence: DifferentialObservation,
        /// Serving-record revisions to quarantine (every record served
        /// under this epoch up to disablement).
        quarantine_revisions: Vec<u64>,
    },
}

/// Differential watch for one projection epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionWatch {
    /// The watched projection epoch.
    pub projection_epoch: u32,
    /// Standing.
    pub standing: EpochStanding,
    /// All revisions served under this epoch (quarantine addressing).
    served_revisions: Vec<u64>,
}

impl ProjectionWatch {
    /// New watch for an epoch.
    #[must_use]
    pub const fn new(projection_epoch: u32) -> Self {
        Self {
            projection_epoch,
            standing: EpochStanding::CleanSoFar { verified_hits: 0 },
            served_revisions: Vec::new(),
        }
    }

    /// Whether new keying may use this epoch.
    #[must_use]
    pub const fn epoch_enabled(&self) -> bool {
        matches!(self.standing, EpochStanding::CleanSoFar { .. })
    }

    /// Record a shadow observation. Divergence disables the epoch and
    /// lists every served revision for quarantine; further observations
    /// on a disabled epoch are ignored (it is already dead).
    pub fn observe(&mut self, obs: &DifferentialObservation) {
        let EpochStanding::CleanSoFar { verified_hits } = &mut self.standing else {
            return; // Already disabled; nothing can re-enable it here.
        };
        self.served_revisions.push(obs.serving_record_revision);
        if obs.diverges() {
            self.standing = EpochStanding::Disabled {
                first_divergence: obs.clone(),
                quarantine_revisions: self.served_revisions.clone(),
            };
        } else {
            *verified_hits += 1;
        }
    }
}

/// The honest benefit report: gains and divergences side by side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionBenefitReport {
    /// The epoch reported on.
    pub projection_epoch: u32,
    /// Shadow-verified hits the projection served (the benefit).
    pub verified_hits: u64,
    /// Divergences observed (any nonzero value voids the benefit).
    pub divergences: u64,
    /// Whether the epoch remains enabled.
    pub enabled: bool,
}

/// Produce the benefit report for a watch.
#[must_use]
pub fn benefit_report(watch: &ProjectionWatch) -> ProjectionBenefitReport {
    match &watch.standing {
        EpochStanding::CleanSoFar { verified_hits } => ProjectionBenefitReport {
            projection_epoch: watch.projection_epoch,
            verified_hits: *verified_hits,
            divergences: 0,
            enabled: true,
        },
        EpochStanding::Disabled {
            quarantine_revisions,
            ..
        } => ProjectionBenefitReport {
            projection_epoch: watch.projection_epoch,
            // Verified count BEFORE the divergence — reported, but the
            // divergences field sits beside it: negative worth is
            // unhideable.
            verified_hits: (quarantine_revisions.len() as u64).saturating_sub(1),
            divergences: 1,
            enabled: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.semantic-result.v1",
            bytes: [tag; 32],
        }
    }

    fn key(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.action-key.sha256.v1",
            bytes: [tag; 32],
        }
    }

    fn clean(revision: u64) -> DifferentialObservation {
        DifferentialObservation {
            action_key: key(1),
            projected_result: d(5),
            exact_result: d(5),
            serving_record_revision: revision,
        }
    }

    #[test]
    fn seeded_projection_bug_triggers_auto_rollback() {
        // THE acceptance case: a projection serves clean hits, then a
        // seeded bug makes projected != exact once — the epoch disables
        // by itself and every served revision lands on the quarantine
        // list.
        let mut watch = ProjectionWatch::new(2);
        watch.observe(&clean(10));
        watch.observe(&clean(11));
        assert!(watch.epoch_enabled());
        let seeded_bug = DifferentialObservation {
            action_key: key(1),
            projected_result: d(5),
            exact_result: d(6), // the exact path disagrees
            serving_record_revision: 12,
        };
        watch.observe(&seeded_bug);
        assert!(!watch.epoch_enabled(), "epoch must auto-disable");
        let EpochStanding::Disabled {
            first_divergence,
            quarantine_revisions,
        } = &watch.standing
        else {
            panic!("expected disabled standing");
        };
        assert_eq!(first_divergence, &seeded_bug);
        assert_eq!(
            quarantine_revisions,
            &vec![10, 11, 12],
            "EVERY revision served under the epoch is quarantined, not just the divergent one"
        );
    }

    #[test]
    fn disabled_epochs_never_re_enable_from_observations() {
        let mut watch = ProjectionWatch::new(2);
        let bug = DifferentialObservation {
            action_key: key(1),
            projected_result: d(5),
            exact_result: d(6),
            serving_record_revision: 1,
        };
        watch.observe(&bug);
        assert!(!watch.epoch_enabled());
        // A stream of clean observations afterwards changes nothing.
        watch.observe(&clean(2));
        watch.observe(&clean(3));
        assert!(!watch.epoch_enabled(), "no observation re-enables");
    }

    #[test]
    fn benefit_report_quantifies_and_cannot_hide_divergence() {
        let mut watch = ProjectionWatch::new(2);
        watch.observe(&clean(1));
        watch.observe(&clean(2));
        let healthy = benefit_report(&watch);
        assert_eq!(healthy.verified_hits, 2);
        assert_eq!(healthy.divergences, 0);
        assert!(healthy.enabled);
        let bug = DifferentialObservation {
            action_key: key(1),
            projected_result: d(5),
            exact_result: d(6),
            serving_record_revision: 3,
        };
        watch.observe(&bug);
        let after = benefit_report(&watch);
        assert_eq!(after.divergences, 1, "divergence sits beside the benefit");
        assert_eq!(after.verified_hits, 2, "pre-divergence gains reported");
        assert!(!after.enabled);
    }
}
