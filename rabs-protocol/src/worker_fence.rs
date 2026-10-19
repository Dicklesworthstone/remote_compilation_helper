//! Worker boot-generation and process-incarnation fencing (bead F029;
//! invariants I47/I54; risks R106/R114).
//!
//! Every worker start increments a **durable boot generation** and mints a
//! **fresh random process-incarnation ID**. The coordinator admits ONE
//! active incarnation per worker identity/boot-generation and rejects
//! stale, duplicate, or non-increasing sessions. Two truths held apart:
//!
//! - incarnation fencing **detects** duplicate/overlapping sessions
//!   (a cloned disk image, a restored VM, two daemons racing);
//! - it does **not prove which clone is legitimate** (I54). Ambiguity
//!   fails closed — `RejectCloneAmbiguity` — until hardware-bound
//!   enrollment or an operator re-enrollment proof resolves it. The plan
//!   makes no anti-cloning claim without that evidence.

use crate::generation::{WorkerBootGeneration, WorkerIncarnationId};
use crate::provenance_receipt::NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING;
use crate::result_identity::TypedDigest;
use crate::wire_time::PeerId;

/// The coordinator's durable fence row for one worker identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerIncarnationFenceRecord {
    /// The worker's durable peer identity.
    pub worker_peer_id: PeerId,
    /// Highest boot generation ever admitted.
    pub highest_boot_generation: WorkerBootGeneration,
    /// The active incarnation for that generation, if a session is live.
    pub active_incarnation: Option<WorkerIncarnationId>,
    /// A same-generation competing incarnation was observed. While set,
    /// neither contender is authoritative: sessions and execution leases
    /// fail closed until a fresh operator re-enrollment proof or a strictly
    /// newer boot generation selects one lineage.
    pub clone_ambiguous: bool,
    /// Highest operator re-enrollment generation consumed.
    pub operator_reenrollment_generation: u64,
}

/// A worker session offer at admission time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSessionOffer {
    /// Claimed worker identity.
    pub worker_peer_id: PeerId,
    /// Claimed durable boot generation.
    pub boot_generation: WorkerBootGeneration,
    /// Fresh process incarnation.
    pub incarnation: WorkerIncarnationId,
    /// Operator re-enrollment proof generation, if presented
    /// (signature-verified at the transport layer).
    pub reenrollment_proof: Option<u64>,
}

/// Session admission outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerAdmission {
    /// Strictly newer boot generation: admit; every lease from prior
    /// incarnations is invalid from this point.
    AdmitNewGeneration,
    /// Same generation, same incarnation as the live session: an ordinary
    /// reconnect of the admitted process.
    AdmitReconnect,
    /// Same generation, no live incarnation (coordinator restarted or the
    /// session dropped): admit this incarnation as the one active.
    AdmitResume,
    /// Fresh operator re-enrollment proof consumed at or above the
    /// durable boot-generation high-water: admit and record it.
    AdmitViaReenrollment,
    /// Boot generation lower than the high-water mark: a stale or
    /// restored daemon; reject.
    RejectStaleBootGeneration,
    /// Same generation but a DIFFERENT incarnation while one is active:
    /// duplicate/overlapping session. Detection, not legitimacy — fails
    /// closed pending re-enrollment (I54; R106/R114).
    RejectCloneAmbiguity,
    /// The offer names a different worker identity than this record.
    RejectIdentityMismatch,
}

/// Why a worker-bound execution lease is not current at a durable fence.
///
/// This decision is deliberately independent of lease sequence/state: it
/// answers only whether the worker tuple that owns an attempt is the one
/// unambiguously active tuple NOW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerLeaseBindingRejection {
    /// The lease names another durable worker identity.
    IdentityMismatch,
    /// The lease's boot generation is not the fence's current high-water.
    BootGenerationMismatch,
    /// The worker has no active session.
    NoActiveIncarnation,
    /// The lease belongs to a different process incarnation.
    IncarnationMismatch,
    /// A same-generation clone conflict is unresolved; neither contender
    /// may continue using leases.
    CloneAmbiguous,
}

impl WorkerIncarnationFenceRecord {
    /// Evaluate a session offer against this fence row.
    #[must_use]
    pub fn evaluate(&self, offer: &WorkerSessionOffer) -> WorkerAdmission {
        if offer.worker_peer_id != self.worker_peer_id {
            return WorkerAdmission::RejectIdentityMismatch;
        }
        // No proof may lower the durable high-water: otherwise a clone
        // from the old lineage could later present that old high-water
        // and look strictly newer than the operator-selected worker.
        if offer.boot_generation < self.highest_boot_generation {
            return WorkerAdmission::RejectStaleBootGeneration;
        }
        // A FRESH re-enrollment proof resolves same-generation clone
        // ambiguity (or accompanies a newer generation) by operator
        // decision; a stale/replayed proof does not.
        if let Some(proof) = offer.reenrollment_proof
            && proof > self.operator_reenrollment_generation
        {
            return WorkerAdmission::AdmitViaReenrollment;
        }
        if self.clone_ambiguous {
            return WorkerAdmission::RejectCloneAmbiguity;
        }
        if offer.boot_generation > self.highest_boot_generation {
            return WorkerAdmission::AdmitNewGeneration;
        }
        // Equal generation: exactly one active incarnation may exist.
        match self.active_incarnation {
            None => WorkerAdmission::AdmitResume,
            Some(active) if active == offer.incarnation => WorkerAdmission::AdmitReconnect,
            Some(_) => WorkerAdmission::RejectCloneAmbiguity,
        }
    }

    /// Check whether an attempt/lease's worker tuple is the exact active,
    /// unambiguous owner of this fence.
    ///
    /// # Errors
    /// A typed reason when the binding is stale, inactive, or ambiguous.
    pub fn validate_lease_binding(
        &self,
        worker: &PeerId,
        boot_generation: WorkerBootGeneration,
        incarnation: WorkerIncarnationId,
    ) -> Result<(), WorkerLeaseBindingRejection> {
        if worker != &self.worker_peer_id {
            return Err(WorkerLeaseBindingRejection::IdentityMismatch);
        }
        if boot_generation != self.highest_boot_generation {
            return Err(WorkerLeaseBindingRejection::BootGenerationMismatch);
        }
        if self.clone_ambiguous {
            return Err(WorkerLeaseBindingRejection::CloneAmbiguous);
        }
        match self.active_incarnation {
            None => Err(WorkerLeaseBindingRejection::NoActiveIncarnation),
            Some(active) if active == incarnation => Ok(()),
            Some(_) => Err(WorkerLeaseBindingRejection::IncarnationMismatch),
        }
    }

    /// Observe a worker session offer and apply the durable fence state transition
    /// (beads S022/S023; invariants I47/I54; risks R106/R114).
    ///
    /// When a competing incarnation arrives at the current boot generation,
    /// `clone_ambiguous` flips to `true`, immediately fencing BOTH the newcomer
    /// and the incumbent until hardware-bound enrollment or a fresh operator
    /// re-enrollment resolves legitimacy.
    pub fn observe_session_offer(&mut self, offer: &WorkerSessionOffer) -> WorkerAdmission {
        let decision = self.evaluate(offer);
        match decision {
            WorkerAdmission::AdmitNewGeneration => {
                self.highest_boot_generation = offer.boot_generation;
                self.active_incarnation = Some(offer.incarnation);
                self.clone_ambiguous = false;
            }
            WorkerAdmission::AdmitReconnect => {}
            WorkerAdmission::AdmitResume => {
                self.active_incarnation = Some(offer.incarnation);
            }
            WorkerAdmission::AdmitViaReenrollment => {
                if let Some(proof) = offer.reenrollment_proof {
                    self.operator_reenrollment_generation = proof;
                }
                self.highest_boot_generation = offer.boot_generation;
                self.active_incarnation = Some(offer.incarnation);
                self.clone_ambiguous = false;
            }
            WorkerAdmission::RejectCloneAmbiguity => {
                // Both contenders are now ambiguous; neither may exercise authority.
                self.clone_ambiguous = true;
            }
            WorkerAdmission::RejectStaleBootGeneration
            | WorkerAdmission::RejectIdentityMismatch => {}
        }
        decision
    }
}

/// Domain separator for hardware-bound worker enrollment attestations (bead S023; I54; R114).
pub const HARDWARE_ENROLLMENT_KEY_DOMAIN: &str = "rabs.hardware-enrollment-key.sha256.v1";
/// Domain separator for hardware platform quote digests (bead S023; I54; R114).
pub const HARDWARE_PLATFORM_QUOTE_DOMAIN: &str = "rabs.hardware-platform-quote.sha256.v1";

/// Enrollment posture presented by a worker identity (bead S023; I54; R114).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerEnrollmentPosture {
    /// Software-only identity: incarnation fencing detects duplicate sessions,
    /// but makes NO anti-cloning legitimacy claim (`NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING`).
    SoftwareOnlyIdentity,
    /// Hardware-bound key enrollment (e.g. TPM / Secure Enclave quote bound to
    /// the worker identity, boot generation, and process incarnation).
    HardwareBoundEnrollment {
        /// Digest of the hardware-bound non-exportable public key.
        hardware_key_fingerprint: TypedDigest,
        /// Digest of the verified platform attestation quote.
        platform_quote_digest: TypedDigest,
        /// Monotonic hardware enrollment generation (> `operator_reenrollment_generation`).
        enrollment_generation: u64,
    },
    /// Explicit operator re-enrollment selecting the legitimate worker incarnation.
    OperatorReenrollment {
        /// Monotonic operator re-enrollment generation (> `operator_reenrollment_generation`).
        reenrollment_generation: u64,
    },
}

/// Policy governing whether clone legitimacy proof is required (bead S023; I54; R114).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneLegitimacyPolicy {
    /// Software-only identities are admitted while unambiguous (carrying
    /// `NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING`), and fail closed on any clone race.
    AllowSoftwareIdentityWhenUnambiguous,
    /// Legitimacy matters: require hardware-bound enrollment or operator re-enrollment
    /// even before a clone conflict is observed.
    RequireHardwareOrOperatorEnrollment,
}

/// Outcome of evaluating a worker session under S023 enrollment + clone-legitimacy policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloneLegitimacyDecision {
    /// Software-only worker admitted with the explicit `NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING`
    /// non-claim recorded.
    AdmittedSoftwareIdentityWithNonClaim {
        /// Admission kind.
        admission: WorkerAdmission,
        /// Required explicit non-claim code (`NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING`).
        non_claim: &'static str,
    },
    /// Hardware-bound enrollment verified; resolves any prior clone ambiguity and binds the active incarnation.
    AdmittedHardwareBound {
        /// Verified hardware key fingerprint.
        hardware_key_fingerprint: TypedDigest,
        /// Consumed enrollment generation.
        enrollment_generation: u64,
    },
    /// Operator re-enrollment verified; resolves any prior clone ambiguity and binds the active incarnation.
    AdmittedOperatorReenrolled {
        /// Consumed re-enrollment generation.
        reenrollment_generation: u64,
        /// Explicit non-claim code for software key material after operator selection.
        non_claim: &'static str,
    },
}

/// Typed fail-closed refusal under S023 clone-race and enrollment evaluation (I54; R114).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloneLegitimacyRefusal {
    ///Underlying session admission failed (stale boot generation or identity mismatch).
    SessionRejected(WorkerAdmission),
    /// Competing incarnations detected at the same boot generation: both clones fail closed
    /// pending hardware-bound enrollment or operator re-enrollment.
    CloneAmbiguityFailsClosedPendingEnrollment {
        /// Explicit non-claim code explaining why software fencing cannot pick a winner.
        non_claim: &'static str,
    },
    /// Policy requires hardware-bound or operator enrollment, but only a software identity was presented.
    HardwareOrOperatorEnrollmentRequired {
        /// Explicit non-claim code for software-only identity.
        non_claim: &'static str,
    },
    /// Hardware enrollment key or platform quote digest had an invalid domain.
    MalformedHardwareEnrollmentEvidence,
    /// Hardware or operator enrollment generation is stale/replayed (`<= operator_reenrollment_generation`).
    StaleEnrollmentGeneration {
        /// Presented generation.
        presented: u64,
        /// Durable high-water mark.
        high_water: u64,
    },
}

/// Evaluate a worker session offer and enrollment posture against the durable
/// [`WorkerIncarnationFenceRecord`] (bead S023; I54; R114).
///
/// Updates `fence` in place: a clone race marks `fence.clone_ambiguous = true` and
/// fails closed (`CloneAmbiguityFailsClosedPendingEnrollment`) for BOTH clones until
/// hardware-bound enrollment or operator re-enrollment with a strictly newer
/// generation resolves legitimacy.
///
/// # Errors
/// [`CloneLegitimacyRefusal`] when a clone race is unresolved, when policy requires
/// hardware/operator enrollment, or when presented enrollment evidence is stale or malformed.
pub fn evaluate_clone_legitimacy_and_enrollment(
    fence: &mut WorkerIncarnationFenceRecord,
    offer: &WorkerSessionOffer,
    posture: &WorkerEnrollmentPosture,
    policy: CloneLegitimacyPolicy,
) -> Result<CloneLegitimacyDecision, CloneLegitimacyRefusal> {
    if offer.worker_peer_id != fence.worker_peer_id {
        return Err(CloneLegitimacyRefusal::SessionRejected(
            WorkerAdmission::RejectIdentityMismatch,
        ));
    }
    if offer.boot_generation < fence.highest_boot_generation {
        return Err(CloneLegitimacyRefusal::SessionRejected(
            WorkerAdmission::RejectStaleBootGeneration,
        ));
    }

    match posture {
        WorkerEnrollmentPosture::SoftwareOnlyIdentity => {
            let mut software_offer = offer.clone();
            software_offer.reenrollment_proof = None;
            let admission = fence.observe_session_offer(&software_offer);
            if admission == WorkerAdmission::RejectCloneAmbiguity {
                return Err(
                    CloneLegitimacyRefusal::CloneAmbiguityFailsClosedPendingEnrollment {
                        non_claim: NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING,
                    },
                );
            }
            if matches!(
                policy,
                CloneLegitimacyPolicy::RequireHardwareOrOperatorEnrollment
            ) {
                return Err(
                    CloneLegitimacyRefusal::HardwareOrOperatorEnrollmentRequired {
                        non_claim: NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING,
                    },
                );
            }
            Ok(
                CloneLegitimacyDecision::AdmittedSoftwareIdentityWithNonClaim {
                    admission,
                    non_claim: NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING,
                },
            )
        }
        WorkerEnrollmentPosture::HardwareBoundEnrollment {
            hardware_key_fingerprint,
            platform_quote_digest,
            enrollment_generation,
        } => {
            if hardware_key_fingerprint.domain != HARDWARE_ENROLLMENT_KEY_DOMAIN
                || platform_quote_digest.domain != HARDWARE_PLATFORM_QUOTE_DOMAIN
            {
                return Err(CloneLegitimacyRefusal::MalformedHardwareEnrollmentEvidence);
            }
            if *enrollment_generation <= fence.operator_reenrollment_generation {
                return Err(CloneLegitimacyRefusal::StaleEnrollmentGeneration {
                    presented: *enrollment_generation,
                    high_water: fence.operator_reenrollment_generation,
                });
            }
            let mut hw_offer = offer.clone();
            hw_offer.reenrollment_proof = Some(*enrollment_generation);
            let _ = fence.observe_session_offer(&hw_offer);
            Ok(CloneLegitimacyDecision::AdmittedHardwareBound {
                hardware_key_fingerprint: hardware_key_fingerprint.clone(),
                enrollment_generation: *enrollment_generation,
            })
        }
        WorkerEnrollmentPosture::OperatorReenrollment {
            reenrollment_generation,
        } => {
            if *reenrollment_generation <= fence.operator_reenrollment_generation {
                return Err(CloneLegitimacyRefusal::StaleEnrollmentGeneration {
                    presented: *reenrollment_generation,
                    high_water: fence.operator_reenrollment_generation,
                });
            }
            let mut op_offer = offer.clone();
            op_offer.reenrollment_proof = Some(*reenrollment_generation);
            let _ = fence.observe_session_offer(&op_offer);
            Ok(CloneLegitimacyDecision::AdmittedOperatorReenrolled {
                reenrollment_generation: *reenrollment_generation,
                non_claim: NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::DigestAlgorithm;

    fn record(generation: u64, active: Option<u128>) -> WorkerIncarnationFenceRecord {
        WorkerIncarnationFenceRecord {
            worker_peer_id: PeerId("wkr-1".into()),
            highest_boot_generation: WorkerBootGeneration(generation),
            active_incarnation: active.map(WorkerIncarnationId),
            clone_ambiguous: false,
            operator_reenrollment_generation: 0,
        }
    }

    fn offer(generation: u64, incarnation: u128) -> WorkerSessionOffer {
        WorkerSessionOffer {
            worker_peer_id: PeerId("wkr-1".into()),
            boot_generation: WorkerBootGeneration(generation),
            incarnation: WorkerIncarnationId(incarnation),
            reenrollment_proof: None,
        }
    }

    #[test]
    fn restart_with_higher_generation_admits_and_fences_the_past() {
        let r = record(3, Some(11));
        assert_eq!(
            r.evaluate(&offer(4, 99)),
            WorkerAdmission::AdmitNewGeneration
        );
    }

    #[test]
    fn stale_and_restored_daemons_are_rejected() {
        let r = record(3, None);
        assert_eq!(
            r.evaluate(&offer(2, 99)),
            WorkerAdmission::RejectStaleBootGeneration,
            "a restored disk image presents an old boot generation"
        );
    }

    #[test]
    fn one_active_incarnation_per_generation() {
        let r = record(3, Some(11));
        // The admitted process reconnecting: fine.
        assert_eq!(r.evaluate(&offer(3, 11)), WorkerAdmission::AdmitReconnect);
        // A DIFFERENT incarnation at the same generation while one is
        // active: the clone/overlap case — fails closed (R106).
        assert_eq!(
            r.evaluate(&offer(3, 22)),
            WorkerAdmission::RejectCloneAmbiguity
        );
        // No live session: the incarnation may resume the generation.
        let idle = record(3, None);
        assert_eq!(idle.evaluate(&offer(3, 22)), WorkerAdmission::AdmitResume);
    }

    #[test]
    fn reenrollment_resolves_ambiguity_but_replays_do_not() {
        let r = record(3, Some(11));
        let mut o = offer(3, 22);
        o.reenrollment_proof = Some(1);
        assert_eq!(
            r.evaluate(&o),
            WorkerAdmission::AdmitViaReenrollment,
            "a FRESH operator proof is the sanctioned clone resolution (I54)"
        );
        // Replayed proof at or below the consumed generation: no effect.
        let mut consumed = record(3, Some(11));
        consumed.operator_reenrollment_generation = 1;
        assert_eq!(
            consumed.evaluate(&o),
            WorkerAdmission::RejectCloneAmbiguity,
            "a replayed proof must not resolve ambiguity"
        );
    }

    #[test]
    fn durable_ambiguity_fences_incumbent_sessions_and_leases() {
        let mut r = record(3, Some(11));
        r.clone_ambiguous = true;
        assert_eq!(
            r.evaluate(&offer(3, 11)),
            WorkerAdmission::RejectCloneAmbiguity,
            "the incumbent is not privileged once two clones are visible"
        );
        assert_eq!(
            r.validate_lease_binding(
                &PeerId("wkr-1".into()),
                WorkerBootGeneration(3),
                WorkerIncarnationId(11),
            ),
            Err(WorkerLeaseBindingRejection::CloneAmbiguous)
        );

        let mut selected = offer(3, 22);
        selected.reenrollment_proof = Some(1);
        assert_eq!(r.evaluate(&selected), WorkerAdmission::AdmitViaReenrollment);
        assert_eq!(
            r.evaluate(&offer(4, 33)),
            WorkerAdmission::RejectCloneAmbiguity,
            "a self-reported boot increment cannot adjudicate which clone is legitimate"
        );
    }

    #[test]
    fn reenrollment_never_lowers_the_global_boot_high_water() {
        let r = record(5, Some(11));
        let mut restored = offer(1, 22);
        restored.reenrollment_proof = Some(1);
        assert_eq!(
            r.evaluate(&restored),
            WorkerAdmission::RejectStaleBootGeneration,
            "operator recovery must first advance the durable boot generation"
        );
    }

    #[test]
    fn identity_mismatch_rejects_outright() {
        let r = record(3, None);
        let mut o = offer(3, 22);
        o.worker_peer_id = PeerId("wkr-2".into());
        assert_eq!(r.evaluate(&o), WorkerAdmission::RejectIdentityMismatch);
    }

    #[test]
    fn s023_clone_race_scenario_fails_closed_pending_enrollment_and_documents_non_claim() {
        const TRUST_DOC: &str = include_str!("../../docs/rabs-trust-model-v1.md");
        assert!(
            TRUST_DOC.contains(NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING),
            "docs/rabs-trust-model-v1.md must document NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING"
        );

        let mut fence = record(3, None);
        // 1. First software-only worker incarnation connects and is admitted with the explicit non-claim.
        let decision = evaluate_clone_legitimacy_and_enrollment(
            &mut fence,
            &offer(3, 101),
            &WorkerEnrollmentPosture::SoftwareOnlyIdentity,
            CloneLegitimacyPolicy::AllowSoftwareIdentityWhenUnambiguous,
        )
        .unwrap();
        assert_eq!(
            decision,
            CloneLegitimacyDecision::AdmittedSoftwareIdentityWithNonClaim {
                admission: WorkerAdmission::AdmitResume,
                non_claim: NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING,
            }
        );

        // 2. A cloned VM starts a competing incarnation (202) at the same boot generation (3).
        // The clone race fails closed AND flips fence.clone_ambiguous = true.
        assert_eq!(
            evaluate_clone_legitimacy_and_enrollment(
                &mut fence,
                &offer(3, 202),
                &WorkerEnrollmentPosture::SoftwareOnlyIdentity,
                CloneLegitimacyPolicy::AllowSoftwareIdentityWhenUnambiguous,
            ),
            Err(
                CloneLegitimacyRefusal::CloneAmbiguityFailsClosedPendingEnrollment {
                    non_claim: NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING,
                }
            )
        );
        assert!(fence.clone_ambiguous);

        // 3. The incumbent incarnation (101) AND a self-reported higher boot generation (4, 303)
        // also fail closed while ambiguity is unresolved; active leases are rejected.
        assert_eq!(
            evaluate_clone_legitimacy_and_enrollment(
                &mut fence,
                &offer(3, 101),
                &WorkerEnrollmentPosture::SoftwareOnlyIdentity,
                CloneLegitimacyPolicy::AllowSoftwareIdentityWhenUnambiguous,
            ),
            Err(
                CloneLegitimacyRefusal::CloneAmbiguityFailsClosedPendingEnrollment {
                    non_claim: NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING,
                }
            )
        );
        assert_eq!(
            fence.validate_lease_binding(
                &PeerId("wkr-1".into()),
                WorkerBootGeneration(3),
                WorkerIncarnationId(101),
            ),
            Err(WorkerLeaseBindingRejection::CloneAmbiguous)
        );
        assert_eq!(
            evaluate_clone_legitimacy_and_enrollment(
                &mut fence,
                &offer(4, 303),
                &WorkerEnrollmentPosture::SoftwareOnlyIdentity,
                CloneLegitimacyPolicy::AllowSoftwareIdentityWhenUnambiguous,
            ),
            Err(
                CloneLegitimacyRefusal::CloneAmbiguityFailsClosedPendingEnrollment {
                    non_claim: NO_CLAIM_SOFTWARE_IDENTITY_ANTI_CLONING,
                }
            )
        );

        // 4. Hardware-bound enrollment resolves the clone race and binds incarnation 202.
        let hw_key = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: HARDWARE_ENROLLMENT_KEY_DOMAIN,
            bytes: [0xA1; 32],
        };
        let hw_quote = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: HARDWARE_PLATFORM_QUOTE_DOMAIN,
            bytes: [0xB2; 32],
        };
        let hw_decision = evaluate_clone_legitimacy_and_enrollment(
            &mut fence,
            &offer(4, 202),
            &WorkerEnrollmentPosture::HardwareBoundEnrollment {
                hardware_key_fingerprint: hw_key.clone(),
                platform_quote_digest: hw_quote.clone(),
                enrollment_generation: 1,
            },
            CloneLegitimacyPolicy::RequireHardwareOrOperatorEnrollment,
        )
        .unwrap();
        assert_eq!(
            hw_decision,
            CloneLegitimacyDecision::AdmittedHardwareBound {
                hardware_key_fingerprint: hw_key.clone(),
                enrollment_generation: 1,
            }
        );
        assert!(!fence.clone_ambiguous);
        assert_eq!(fence.active_incarnation, Some(WorkerIncarnationId(202)));
        assert_eq!(
            fence.validate_lease_binding(
                &PeerId("wkr-1".into()),
                WorkerBootGeneration(4),
                WorkerIncarnationId(202),
            ),
            Ok(())
        );

        // 5. Replaying the same enrollment generation (1) is refused as StaleEnrollmentGeneration.
        assert_eq!(
            evaluate_clone_legitimacy_and_enrollment(
                &mut fence,
                &offer(4, 202),
                &WorkerEnrollmentPosture::HardwareBoundEnrollment {
                    hardware_key_fingerprint: hw_key,
                    platform_quote_digest: hw_quote,
                    enrollment_generation: 1,
                },
                CloneLegitimacyPolicy::RequireHardwareOrOperatorEnrollment,
            ),
            Err(CloneLegitimacyRefusal::StaleEnrollmentGeneration {
                presented: 1,
                high_water: 1,
            })
        );
    }
}
