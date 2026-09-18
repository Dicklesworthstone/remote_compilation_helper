//! The serving sample gate + instant divergence quarantine (bead K008;
//! trust-ladder Stage 3; risk R28/R99).
//!
//! Stage 2 (the shadow comparison itself) lives in `rabs-replay`; this
//! module is the coordinator-side policy that decides, per action,
//! whether a request is eligible for sampled cache serving or must
//! execute PRIVATELY as fresh shadow evidence:
//!
//! - only LOW-RISK registry classes are ever sampled;
//! - a published action must have an eligible serving disposition and
//!   no durable quarantine or named blocking references;
//! - evidence counts independent, attributable attempts of THIS action,
//!   not repeated observations or invented worker identities;
//! - rates are validated basis points and zero evidence always refuses,
//!   including when the configured minimum is zero;
//! - eligible keys are sampled deterministically from their action-key
//!   digest, without shared mutable state.
//!
//! Sampling eligibility is NOT final delivery authorization: callers
//! must still pass the clock/TTL-aware serving gate and validate the
//! materializable closure before exposing cached output.
//!
//! A served result that diverges from authoritative stock is a
//! soundness incident handled by [`quarantine_served_divergence`].
//! Quarantine is persisted FIRST, then the incident is appended and the
//! serving record is demoted, preserving all existing named blockers.
//! An interrupted demotion remains blocked by the durable serving gate.
//!
//! State-machine refusals reuse [`RevalidationError`] verbatim.

use sha2::{Digest, Sha256};

use rabs_protocol::result_identity::TypedDigest;

use crate::metadata_store::{
    DivergenceIncidentRow, QuarantineScope, RabsMetadataStore, StoreError, digest_key,
};
use crate::serving_state::{RevalidationError, SERVABLE_DISPOSITION, action_quarantine_present};
use crate::trust_evidence::{
    DISPOSITION_QUARANTINED, require_active_authority, verification_evidence,
};

/// Quarantine reason recorded for a served result that diverged from
/// authoritative stock during sampled serving.
pub const SERVING_SAMPLE_QUARANTINE_REASON: &str = "k008-served-divergence";

/// Risk tier of an action CLASS (plan §113). Only low-risk registry
/// classes are eligible for sampled serving at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClassRisk {
    /// Registry/git dependency actions (first served class, M4).
    LowRiskRegistry,
    /// Anything else: workspace outputs, tool-generated code, unknown
    /// classes. Never sampled.
    Elevated,
}

/// Sampling policy knobs. All rates are basis points (0..=10_000) so
/// decisions are exact integer arithmetic — a float threshold could
/// disagree between processes compiling with different codegen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplingPolicy {
    /// Minimum independent attributable verification attempts. At least
    /// one actual attempt is always required, even when this is zero.
    pub min_samples: u32,
    /// Required fraction of PASSED independent attempts, in basis
    /// points (9_900 = 99%). A failed observation dominates other
    /// observations of the same attempt.
    pub min_pass_rate_basis_points: u32,
    /// Share of eligible keys served from cache, in basis points
    /// (1_000 = 10% sampled serving).
    pub sample_rate_basis_points: u32,
}

impl SamplingPolicy {
    /// Policy that samples every eligible key (used by tests and by
    /// operators who want full serving after shadow evidence).
    #[must_use]
    pub const fn sample_all(min_samples: u32, min_pass_rate_basis_points: u32) -> Self {
        Self {
            min_samples,
            min_pass_rate_basis_points,
            sample_rate_basis_points: 10_000,
        }
    }
}

/// Why the gate refused to serve and demands private execution instead.
/// Private execution produces fresh shadow evidence for the trust ladder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateExecutionReason {
    /// The action class is not a sampled class.
    ElevatedClassRisk,
    /// A basis-point rate was outside the supported closed interval.
    InvalidPolicy,
    /// No committed publication or corresponding serving record exists.
    NoPublishedResult,
    /// A durable action quarantine or named blocker forbids reuse.
    Quarantined,
    /// The mutable serving disposition does not permit reuse.
    ServingNotEligible {
        /// The stored disposition.
        disposition: String,
    },
    /// Not enough independent verification attempts recorded yet.
    InsufficientVerificationSamples {
        /// Attributable attempts recorded (passed + failed).
        observed: u32,
        /// Policy minimum, with a hard lower bound of one.
        required: u32,
    },
    /// Pass rate below policy.
    VerificationRateBelowPolicy {
        /// Observed pass rate in basis points.
        observed_basis_points: u32,
        /// [`SamplingPolicy::min_pass_rate_basis_points`].
        required_basis_points: u32,
    },
    /// Eligible, but this key's deterministic share says run privately.
    NotSampledThisEpoch {
        /// The key's bucket in basis points (stable per key).
        key_bucket_basis_points: u32,
    },
}

/// The sampling gate's decision for one action. A positive decision
/// still requires the full serving/closure checks before delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SampleGateDecision {
    /// Eligible for sampled serving from the published cache.
    ServeFromCache,
    /// Execute privately (typed reason), recording fresh evidence.
    ExecutePrivately(PrivateExecutionReason),
}

/// Deterministic per-key sampling bucket in `[0, 10_000)` basis
/// points, derived ONLY from the canonical key string — two processes
/// with the same key compute the same bucket with no shared state.
#[must_use]
pub fn key_bucket_basis_points(action: &TypedDigest) -> u32 {
    let digest = Sha256::digest(digest_key(action).as_bytes());
    let window = u32::from(digest[0]) << 24
        | u32::from(digest[1]) << 16
        | u32::from(digest[2]) << 8
        | u32::from(digest[3]);
    ((window >> 16).saturating_mul(10_000)) >> 16
}

/// Decide whether ONE action is eligible for sampled cache serving or
/// must execute privately. Checks run strictest-first; this never writes
/// metadata or repairs a quarantine.
///
/// # Errors
/// [`StoreError`] from reading publication, serving, or evidence state.
pub fn serving_sample_decision(
    store: &mut dyn RabsMetadataStore,
    action: &TypedDigest,
    risk: ActionClassRisk,
    policy: &SamplingPolicy,
) -> Result<SampleGateDecision, StoreError> {
    if risk == ActionClassRisk::Elevated {
        return Ok(SampleGateDecision::ExecutePrivately(
            PrivateExecutionReason::ElevatedClassRisk,
        ));
    }
    if policy.min_pass_rate_basis_points > 10_000 || policy.sample_rate_basis_points > 10_000 {
        return Ok(SampleGateDecision::ExecutePrivately(
            PrivateExecutionReason::InvalidPolicy,
        ));
    }
    if !store.has_publication(action)? {
        return Ok(SampleGateDecision::ExecutePrivately(
            PrivateExecutionReason::NoPublishedResult,
        ));
    }
    let action_key = digest_key(action);
    let Some(record) = store.serving_record(&action_key)? else {
        return Ok(SampleGateDecision::ExecutePrivately(
            PrivateExecutionReason::NoPublishedResult,
        ));
    };
    if !record.blocking.is_empty() || action_quarantine_present(store, &action_key)? {
        return Ok(SampleGateDecision::ExecutePrivately(
            PrivateExecutionReason::Quarantined,
        ));
    }
    if record.disposition != SERVABLE_DISPOSITION {
        return Ok(SampleGateDecision::ExecutePrivately(
            PrivateExecutionReason::ServingNotEligible {
                disposition: record.disposition,
            },
        ));
    }
    let evidence = verification_evidence(store, action)?;
    let observed = u32::try_from(evidence.attempts).unwrap_or(u32::MAX);
    let required = policy.min_samples.max(1);
    if observed < required {
        return Ok(SampleGateDecision::ExecutePrivately(
            PrivateExecutionReason::InsufficientVerificationSamples { observed, required },
        ));
    }
    // The minimum above guarantees a nonzero denominator. Widen BEFORE
    // multiplication, and divide by the full count rather than the
    // u32-saturated diagnostic count. The quotient is always <= 10_000.
    let pass_rate_basis_points = u32::try_from(
        u128::from(evidence.passed_attempts) * 10_000 / u128::from(evidence.attempts),
    )
    .unwrap_or(0);
    if pass_rate_basis_points < policy.min_pass_rate_basis_points {
        return Ok(SampleGateDecision::ExecutePrivately(
            PrivateExecutionReason::VerificationRateBelowPolicy {
                observed_basis_points: pass_rate_basis_points,
                required_basis_points: policy.min_pass_rate_basis_points,
            },
        ));
    }
    let bucket = key_bucket_basis_points(action);
    if bucket >= policy.sample_rate_basis_points {
        return Ok(SampleGateDecision::ExecutePrivately(
            PrivateExecutionReason::NotSampledThisEpoch {
                key_bucket_basis_points: bucket,
            },
        ));
    }
    Ok(SampleGateDecision::ServeFromCache)
}

/// Instant-quarantine reaction to a SERVED result diverging from
/// authoritative stock. Persists an action-entry quarantine FIRST,
/// appends a `"serving-sample-divergence"` incident, and demotes serving
/// at `expected_revision + 1` while preserving earlier blocking refs.
/// Returns the new serving revision.
///
/// Incident numbering advances past the highest EXISTING sequence,
/// not the row count: other incident producers may leave sparse values.
///
/// # Errors
/// [`RevalidationError`] for missing/stale records, exhausted sequences,
/// or store errors. An admitted divergence stays quarantined even if a
/// later append or disposition update fails.
pub fn quarantine_served_divergence(
    store: &mut dyn RabsMetadataStore,
    authority: &TypedDigest,
    action_key_str: &str,
    expected_revision: u64,
    generation: u128,
    attempt: u128,
    detail: &str,
) -> Result<u64, RevalidationError> {
    let record = store
        .serving_record(action_key_str)
        .map_err(|e| RevalidationError::Store(format!("{e:?}")))?
        .ok_or(RevalidationError::NoServingRecord)?;
    if record.state_revision != expected_revision {
        return Err(RevalidationError::StaleRevision {
            stored: record.state_revision,
        });
    }
    require_active_authority(store, authority)
        .map_err(|e| RevalidationError::Store(format!("{e:?}")))?;
    let new_revision = expected_revision
        .checked_add(1)
        .ok_or(RevalidationError::RevisionExhausted)?;
    if !action_quarantine_present(store, action_key_str)
        .map_err(|e| RevalidationError::Store(format!("{e:?}")))?
    {
        store
            .add_quarantine(
                QuarantineScope::ActionEntry,
                action_key_str,
                SERVING_SAMPLE_QUARANTINE_REASON,
            )
            .map_err(|e| RevalidationError::Store(format!("{e:?}")))?;
    }
    let incidents = store
        .list_divergence_incidents(action_key_str)
        .map_err(|e| RevalidationError::Store(format!("{e:?}")))?;
    let seq = incidents
        .iter()
        .map(|incident| incident.seq)
        .max()
        .map_or(Some(0), |seq| seq.checked_add(1))
        .ok_or_else(|| {
            RevalidationError::Store("divergence incident sequence exhausted".to_owned())
        })?;
    store
        .record_divergence_incident(
            authority,
            &DivergenceIncidentRow {
                action_key: action_key_str.to_owned(),
                seq,
                class: "serving-sample-divergence".to_owned(),
                committed_manifest_key: String::new(),
                candidate_manifest_key: String::new(),
                candidate_evidence_key: String::new(),
                candidate_pin_hex: String::new(),
                generation_hex: format!("{generation:x}"),
                attempt_hex: format!("{attempt:x}"),
                detail: detail.to_owned(),
            },
        )
        .map_err(|e| RevalidationError::Store(format!("{e:?}")))?;

    let mut blocking = Vec::new();
    for (scope, subject) in &record.blocking {
        let scope = match scope.as_str() {
            "location" => QuarantineScope::Location,
            "logical-object" => QuarantineScope::LogicalObject,
            "action-entry" => QuarantineScope::ActionEntry,
            _ => {
                return Err(RevalidationError::Store(format!(
                    "unknown blocking quarantine scope: {scope}"
                )));
            }
        };
        blocking.push((scope, subject.clone()));
    }
    if !blocking.iter().any(|(scope, subject)| {
        scope == &QuarantineScope::ActionEntry && subject == action_key_str
    }) {
        blocking.push((QuarantineScope::ActionEntry, action_key_str.to_owned()));
    }
    store
        .put_serving_record(
            authority,
            action_key_str,
            DISPOSITION_QUARANTINED,
            new_revision,
            &record.validity,
            &blocking,
        )
        .map_err(|e| RevalidationError::Store(format!("{e:?}")))?;
    Ok(new_revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{
        ActionEntryRow, AuthorityRow, CommitOutcome, FsqliteEngine, PublicationRow, ResultKindTag,
        RusqliteEngine, SqlMetadataStore,
    };
    use crate::serving_state::{ServeDecision, serving_gate};
    use rabs_protocol::result_identity::DigestAlgorithm;
    use rabs_protocol::serving::ServingValidity;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_path(tag: &str) -> std::path::PathBuf {
        let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("rabs-k008-{tag}-{}-{n}.db", std::process::id()))
    }

    fn digest(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn action(tag: u8) -> TypedDigest {
        digest("rabs.action-key.sha256.v1", tag)
    }

    fn authority_row(tag: u8) -> AuthorityRow {
        AuthorityRow {
            digest: digest("rabs.authority.sha256.v1", tag),
            cluster_id: "cluster-a".to_owned(),
            incarnation: u128::from(tag),
            term: u64::from(tag),
            acquired_seq: 1,
        }
    }

    /// Publish action `tag` at generation `generation` and return its
    /// canonical key string. Generations must strictly increase (the
    /// store enforces a high-water mark).
    fn published(store: &mut dyn RabsMetadataStore, tag: u8, generation: u128) -> String {
        let active = digest("rabs.authority.sha256.v1", 1);
        store.acquire_authority(&authority_row(1)).unwrap();
        let entry = ActionEntryRow {
            action_key: action(tag),
            key_epoch: 0,
            projection_epoch: 0,
        };
        store.upsert_action_entry(&entry).unwrap();
        store
            .create_generation(&active, generation, &entry.action_key)
            .unwrap();
        let attempt = generation * 10 + 1;
        store
            .record_attempt(attempt, generation, "worker-a", 5)
            .unwrap();
        let row = PublicationRow {
            action_key: entry.action_key.clone(),
            descriptor_digest: digest("rabs.descriptor.sha256.v1", 1),
            manifest_digest: digest("rabs.result-manifest.sha256.v1", 1),
            evidence_digest: digest("rabs.evidence-bundle.sha256.v1", 1),
            winner_generation: generation,
            winner_attempt: attempt,
            result_kind: ResultKindTag::Success,
            pin_id: generation * 10 + 2,
            pin_owner: "coordinator".to_owned(),
            provisional_ancestors: Vec::new(),
        };
        assert_eq!(
            store.commit_publication(&active, None, &row).unwrap(),
            CommitOutcome::Committed
        );
        digest_key(&entry.action_key)
    }

    /// Append independent attempts, never overwrite earlier failed
    /// samples to manufacture a healthy pass rate.
    fn samples(
        store: &mut dyn RabsMetadataStore,
        tag: u8,
        generation: u128,
        passes: u32,
        fails: u32,
    ) {
        let mut seq = store.list_verification_samples(&action(tag)).unwrap().len() as u64 + 1;
        for passed in std::iter::repeat_n(true, passes as usize)
            .chain(std::iter::repeat_n(false, fails as usize))
        {
            let attempt = generation * 1_000 + u128::from(seq);
            store.record_attempt(attempt, generation, "worker-sampler", seq).unwrap();
            store
                .record_verification_sample(&action(tag), attempt, passed, seq)
                .unwrap();
            seq += 1;
        }
    }

    /// All decision scenarios on one backend; returns the final
    /// snapshot for differential comparison.
    fn k008_scenarios(store: &mut dyn RabsMetadataStore) -> Vec<String> {
        let active = digest("rabs.authority.sha256.v1", 1);
        let strict = SamplingPolicy {
            min_samples: 4,
            min_pass_rate_basis_points: 9_900,
            sample_rate_basis_points: 10_000,
        };

        // Elevated classes NEVER sample, regardless of evidence.
        assert_eq!(
            serving_sample_decision(
                store,
                &action(1),
                ActionClassRisk::Elevated,
                &SamplingPolicy::sample_all(0, 0),
            )
            .unwrap(),
            SampleGateDecision::ExecutePrivately(PrivateExecutionReason::ElevatedClassRisk)
        );
        assert_eq!(
            serving_sample_decision(store, &action(99), ActionClassRisk::LowRiskRegistry, &strict)
                .unwrap(),
            SampleGateDecision::ExecutePrivately(PrivateExecutionReason::NoPublishedResult)
        );
        let key_one = published(store, 1, 10);

        // Zero minimum with no evidence used to divide by zero.
        assert_eq!(
            serving_sample_decision(
                store,
                &action(1),
                ActionClassRisk::LowRiskRegistry,
                &SamplingPolicy::sample_all(0, 0),
            )
            .unwrap(),
            SampleGateDecision::ExecutePrivately(
                PrivateExecutionReason::InsufficientVerificationSamples {
                    observed: 0,
                    required: 1,
                }
            )
        );
        for invalid in [
            SamplingPolicy { min_pass_rate_basis_points: 10_001, ..strict },
            SamplingPolicy { sample_rate_basis_points: 10_001, ..strict },
        ] {
            assert_eq!(
                serving_sample_decision(store, &action(1), ActionClassRisk::LowRiskRegistry, &invalid)
                    .unwrap(),
                SampleGateDecision::ExecutePrivately(PrivateExecutionReason::InvalidPolicy)
            );
        }

        // Insufficient samples refuse with counts.
        assert_eq!(
            serving_sample_decision(store, &action(1), ActionClassRisk::LowRiskRegistry, &strict)
                .unwrap(),
            SampleGateDecision::ExecutePrivately(
                PrivateExecutionReason::InsufficientVerificationSamples {
                    observed: 0,
                    required: 4,
                }
            )
        );

        samples(store, 1, 10, 3, 1);
        assert_eq!(
            serving_sample_decision(store, &action(1), ActionClassRisk::LowRiskRegistry, &strict)
                .unwrap(),
            SampleGateDecision::ExecutePrivately(
                PrivateExecutionReason::VerificationRateBelowPolicy {
                    observed_basis_points: 7_500,
                    required_basis_points: 9_900,
                }
            )
        );
        samples(store, 1, 10, 5, 0);
        assert_eq!(
            serving_sample_decision(store, &action(1), ActionClassRisk::LowRiskRegistry, &strict)
                .unwrap(),
            SampleGateDecision::ExecutePrivately(
                PrivateExecutionReason::VerificationRateBelowPolicy {
                    observed_basis_points: 8_888,
                    required_basis_points: 9_900,
                }
            )
        );

        // A healthy independent evidence set can still serve.
        let key_two = published(store, 2, 11);
        samples(store, 2, 11, 4, 0);
        let none = SamplingPolicy {
            sample_rate_basis_points: 0,
            ..strict
        };
        match serving_sample_decision(store, &action(2), ActionClassRisk::LowRiskRegistry, &none)
            .unwrap()
        {
            SampleGateDecision::ExecutePrivately(PrivateExecutionReason::NotSampledThisEpoch {
                key_bucket_basis_points: observed_bucket,
            }) => {
                assert_eq!(observed_bucket, key_bucket_basis_points(&action(2)));
                assert!(observed_bucket < 10_000);
            }
            other => panic!("zero-rate policy served anyway: {other:?}"),
        }
        assert_eq!(
            serving_sample_decision(
                store,
                &action(2),
                ActionClassRisk::LowRiskRegistry,
                &SamplingPolicy::sample_all(4, 9_900),
            )
            .unwrap(),
            SampleGateDecision::ServeFromCache
        );
        assert_eq!(
            key_bucket_basis_points(&action(2)),
            key_bucket_basis_points(&action(2))
        );

        // Repeated observations and unknown attempts do not satisfy a
        // stronger independent-execution requirement.
        store.record_verification_sample(&action(2), 11_001, true, 500).unwrap();
        store.record_verification_sample(&action(2), 99_999, true, 501).unwrap();
        assert_eq!(
            serving_sample_decision(
                store,
                &action(2),
                ActionClassRisk::LowRiskRegistry,
                &SamplingPolicy::sample_all(5, 9_900),
            )
            .unwrap(),
            SampleGateDecision::ExecutePrivately(
                PrivateExecutionReason::InsufficientVerificationSamples {
                    observed: 4,
                    required: 5,
                }
            )
        );

        store.set_serving_disposition_key(&key_two, "evidence-pending").unwrap();
        assert_eq!(
            serving_sample_decision(store, &action(2), ActionClassRisk::LowRiskRegistry, &strict)
                .unwrap(),
            SampleGateDecision::ExecutePrivately(PrivateExecutionReason::ServingNotEligible {
                disposition: "evidence-pending".to_owned(),
            })
        );
        store.set_serving_disposition_key(&key_two, SERVABLE_DISPOSITION).unwrap();
        store.add_quarantine(QuarantineScope::ActionEntry, &key_two, "corrupt closure").unwrap();
        assert!(store.serving_record(&key_two).unwrap().unwrap().blocking.is_empty());
        assert_eq!(
            serving_sample_decision(store, &action(2), ActionClassRisk::LowRiskRegistry, &strict)
                .unwrap(),
            SampleGateDecision::ExecutePrivately(PrivateExecutionReason::Quarantined)
        );

        // ---- Instant divergence quarantine, preserving prior blockers ----
        store.add_quarantine(QuarantineScope::LogicalObject, "object:damaged", "bad bytes").unwrap();
        store
            .put_serving_record(
                &active,
                &key_one,
                SERVABLE_DISPOSITION,
                7,
                &ServingValidity {
                    evaluated_at_unix_micros: 1_000,
                    maximum_age_micros: None,
                    clock_uncertainty_micros: 0,
                    coordinator_clock_epoch: 1,
                },
                &[(QuarantineScope::LogicalObject, "object:damaged".to_owned())],
            )
            .unwrap();
        assert_eq!(
            serving_sample_decision(store, &action(1), ActionClassRisk::LowRiskRegistry, &strict)
                .unwrap(),
            SampleGateDecision::ExecutePrivately(PrivateExecutionReason::Quarantined)
        );
        let before = store.differential_snapshot().unwrap();
        assert_eq!(
            quarantine_served_divergence(store, &active, &key_one, 6, 11, 22, "mismatch"),
            Err(RevalidationError::StaleRevision { stored: 7 })
        );
        let wrong = digest("rabs.authority.sha256.v1", 2);
        assert_eq!(
            quarantine_served_divergence(store, &wrong, &key_one, 7, 11, 22, "mismatch"),
            Err(RevalidationError::Store(format!("{:?}", StoreError::NotActiveAuthority)))
        );
        assert_eq!(store.differential_snapshot().unwrap(), before);

        // Sparse existing incident sequences must not collide with the
        // sample gate's next incident or be mistaken for a row count.
        store
            .record_divergence_incident(
                &active,
                &DivergenceIncidentRow {
                    action_key: key_one.clone(),
                    seq: 40,
                    class: "prior-incident".to_owned(),
                    committed_manifest_key: String::new(),
                    candidate_manifest_key: String::new(),
                    candidate_evidence_key: String::new(),
                    candidate_pin_hex: String::new(),
                    generation_hex: "a".to_owned(),
                    attempt_hex: "14".to_owned(),
                    detail: "preexisting sparse sequence".to_owned(),
                },
            )
            .unwrap();
        let new_revision = quarantine_served_divergence(
            store, &active, &key_one, 7, 11, 22, "stdout digest mismatch",
        )
        .unwrap();
        assert_eq!(new_revision, 8);
        let incidents = store.list_divergence_incidents(&key_one).unwrap();
        assert_eq!(incidents.len(), 2);
        assert_eq!(incidents[0].seq, 40);
        assert_eq!(incidents[1].seq, 41);
        assert_eq!(incidents[1].class, "serving-sample-divergence");
        assert_eq!(incidents[1].detail, "stdout digest mismatch");
        let record = store.serving_record(&key_one).unwrap().unwrap();
        assert_eq!(record.disposition, DISPOSITION_QUARANTINED);
        assert_eq!(
            record.blocking,
            vec![
                ("action-entry".to_owned(), key_one.clone()),
                ("logical-object".to_owned(), "object:damaged".to_owned()),
            ]
        );
        assert_eq!(
            serving_gate(store, &key_one, 2_000, 1).unwrap(),
            ServeDecision::NotServable {
                disposition: DISPOSITION_QUARANTINED.to_owned(),
            }
        );
        assert_eq!(
            quarantine_served_divergence(store, &active, &key_one, 7, 11, 23, "again"),
            Err(RevalidationError::StaleRevision { stored: 8 })
        );
        assert_eq!(
            quarantine_served_divergence(store, &active, &key_one, 8, 11, 23, "next"),
            Ok(9)
        );
        let incidents = store.list_divergence_incidents(&key_one).unwrap();
        assert_eq!(incidents.iter().map(|incident| incident.seq).collect::<Vec<_>>(), vec![40, 41, 42]);
        assert_eq!(store.serving_record(&key_one).unwrap().unwrap().blocking, record.blocking);
        assert_eq!(
            quarantine_served_divergence(store, &active, "missing:key", 1, 1, 1, "x"),
            Err(RevalidationError::NoServingRecord)
        );
        store.differential_snapshot().unwrap()
    }

    #[test]
    fn k008_reference_backend() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        k008_scenarios(&mut store);
    }

    #[test]
    fn k008_differential_reference_vs_frankensqlite() {
        let reference_engine = RusqliteEngine::open(&fresh_path("ref")).unwrap();
        let mut reference = SqlMetadataStore::open(reference_engine).unwrap();
        let candidate_engine = FsqliteEngine::open(&fresh_path("fsq")).unwrap();
        let mut candidate = SqlMetadataStore::open(candidate_engine).unwrap();
        assert_eq!(
            k008_scenarios(&mut reference),
            k008_scenarios(&mut candidate)
        );
    }
}
