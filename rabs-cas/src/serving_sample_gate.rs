//! The serving sample gate + instant divergence quarantine (bead K008;
//! trust-ladder Stage 3; risk R28/R99).
//!
//! Stage 2 (the shadow comparison itself) lives in `rabs-replay`; this
//! module is the coordinator-side policy that decides, per action,
//! whether a request is SERVED from the published cache or executed
//! PRIVATELY as fresh shadow evidence:
//!
//! - only LOW-RISK registry classes are ever sampled — an elevated
//!   class always executes privately;
//! - a class serves only with ENOUGH verification samples (H033 rows)
//!   and a pass rate at or above policy (basis points; no floats);
//! - even an eligible key serves only when its DETERMINISTIC share of
//!   the sampling epoch is up: the bucket is derived from the action
//!   key digest itself (`SHA-256` over the canonical key string), so
//!   every process and every store agrees on the decision without
//!   shared mutable state.
//!
//! Every refusal to serve is a TYPED reason, never a silent downgrade:
//! private execution still produces shadow evidence for the ladder.
//!
//! A served result that diverges from authoritative stock is a
//! soundness incident handled by [`quarantine_served_divergence`]:
//! divergence incident appended (H026), scoped quarantine row added,
//! serving disposition flipped to `"quarantined"` at one revision past
//! the served record's revision — mirroring K007's revalidation branch,
//! with the same crash-ordering property (quarantine row before the
//! disposition write, so a crash leaves blocked-but-unlabeled, never
//! serving-while-quarantined).
//!
//! State-machine refusals reuse [`RevalidationError`] verbatim: "no
//! record" and "revision moved" mean exactly the same things here.

use sha2::{Digest, Sha256};

use rabs_protocol::result_identity::TypedDigest;

use crate::metadata_store::{
    DivergenceIncidentRow, QuarantineScope, RabsMetadataStore, StoreError, digest_key,
};
use crate::serving_state::RevalidationError;
use crate::trust_evidence::DISPOSITION_QUARANTINED;

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
    /// Fewer recorded verification samples than this: never serve.
    pub min_samples: u32,
    /// Required fraction of PASSED verification samples, in basis
    /// points (9_900 = 99%).
    pub min_pass_rate_basis_points: u32,
    /// Share of eligible keys served from cache per epoch, in basis
    /// points (1_000 = 10% sampled serving).
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
/// Private execution is NOT a punishment: it produces the fresh shadow
/// evidence the trust ladder consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateExecutionReason {
    /// The action class is not a sampled class.
    ElevatedClassRisk,
    /// Not enough verification samples recorded yet.
    InsufficientVerificationSamples {
        /// Samples recorded (passed + failed).
        observed: u32,
        /// [`SamplingPolicy::min_samples`].
        required: u32,
    },
    /// Pass rate below policy.
    VerificationRateBelowPolicy {
        /// Observed pass rate in basis points.
        observed_basis_points: u32,
        /// [`SamplingPolicy::min_pass_rate_basis_points`].
        required_basis_points: u32,
    },
    /// Eligible, but this key's deterministic epoch share says run it
    /// privately this time.
    NotSampledThisEpoch {
        /// The key's bucket in basis points (stable per key).
        key_bucket_basis_points: u32,
    },
}

/// The gate's whole decision for one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SampleGateDecision {
    /// Serve from the published cache.
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

/// Decide whether ONE action request is served from cache or executed
/// privately under `policy`. Checks run strictest-first.
///
/// # Errors
/// [`StoreError`] from reading verification samples.
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
    let samples = store.list_verification_samples(action)?;
    let observed = u32::try_from(samples.len()).unwrap_or(u32::MAX);
    if observed < policy.min_samples {
        return Ok(SampleGateDecision::ExecutePrivately(
            PrivateExecutionReason::InsufficientVerificationSamples {
                observed,
                required: policy.min_samples,
            },
        ));
    }
    let passed = samples.iter().filter(|sample| sample.passed).count();
    // Integer-exact rate; `passed <= observed` keeps this within u32.
    let pass_rate_basis_points =
        u32::try_from(passed * 10_000 / usize::try_from(observed).unwrap_or(1)).unwrap_or(0);
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
/// authoritative stock: divergence incident appended (class
/// `"serving-sample-divergence"`), action-entry quarantine row added,
/// serving disposition flipped to quarantined at
/// `expected_revision + 1` with the blocking reference NAMED. Returns
/// the new serving revision.
///
/// The sequence of the appended incident is the store's existing
/// append-only count for the key, so repeated incidents never collide.
///
/// # Errors
/// [`RevalidationError`] — nothing to revalidate, or the stored
/// revision moved past `expected_revision` (another authority acted;
/// retry against fresh state, never clobber).
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
    let new_revision = expected_revision + 1;
    let seq = u64::try_from(
        store
            .list_divergence_incidents(action_key_str)
            .map_err(|e| RevalidationError::Store(format!("{e:?}")))?
            .len(),
    )
    .unwrap_or(u64::MAX);
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
    store
        .add_quarantine(
            QuarantineScope::ActionEntry,
            action_key_str,
            SERVING_SAMPLE_QUARANTINE_REASON,
        )
        .map_err(|e| RevalidationError::Store(format!("{e:?}")))?;
    store
        .put_serving_record(
            authority,
            action_key_str,
            DISPOSITION_QUARANTINED,
            new_revision,
            &record.validity,
            &[(QuarantineScope::ActionEntry, action_key_str.to_owned())],
        )
        .map_err(|e| RevalidationError::Store(format!("{e:?}")))?;
    Ok(new_revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{
        ActionEntryRow, AuthorityRow, CommitOutcome, FsqliteEngine, PublicationPermit,
        PublicationRow, ResultKindTag, RusqliteEngine, SqlMetadataStore,
    };
    use crate::serving_state::{SERVABLE_DISPOSITION, ServeDecision, serving_gate};
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
            store
                .commit_publication(PublicationPermit::for_fixture(&active), &row)
                .unwrap(),
            CommitOutcome::Committed
        );
        digest_key(&entry.action_key)
    }

    /// Record `passes` passed then `fails` failed verification samples.
    fn samples(store: &mut dyn RabsMetadataStore, tag: u8, passes: u32, fails: u32) {
        let mut seq = 1_u64;
        for _ in 0..passes {
            store
                .record_verification_sample(&action(tag), u128::from(seq), true, seq)
                .unwrap();
            seq += 1;
        }
        for _ in 0..fails {
            store
                .record_verification_sample(&action(tag), u128::from(seq), false, seq)
                .unwrap();
            seq += 1;
        }
    }

    /// All decision scenarios on one backend; returns the final
    /// snapshot for differential comparison.
    fn k008_scenarios(store: &mut dyn RabsMetadataStore) -> Vec<String> {
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

        let key_one = published(store, 1, 10);

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

        // A weak pass rate refuses with the measured rate.
        samples(store, 1, 3, 1); // now 75% < 99%
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
        samples(store, 1, 5, 0); // now 100%
        assert_eq!(
            serving_sample_decision(store, &action(1), ActionClassRisk::LowRiskRegistry, &strict)
                .unwrap(),
            SampleGateDecision::ServeFromCache
        );

        // The zero-rate switch sends every eligible key to private
        // execution with its stable bucket named; the full-rate switch
        // never does.
        let _key_two = published(store, 2, 11);
        samples(store, 2, 4, 0);
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

        // Buckets are pure functions of the key: stable across calls
        // and independent of store contents.
        assert_eq!(
            key_bucket_basis_points(&action(2)),
            key_bucket_basis_points(&action(2))
        );

        // ---- Instant divergence quarantine ----
        store
            .put_serving_record(
                &digest("rabs.authority.sha256.v1", 1),
                &key_one,
                SERVABLE_DISPOSITION,
                7,
                &ServingValidity {
                    evaluated_at_unix_micros: 1_000,
                    maximum_age_micros: None,
                    clock_uncertainty_micros: 0,
                    coordinator_clock_epoch: 1,
                },
                &[],
            )
            .unwrap();

        // Wrong expected revision refuses without writing anything.
        assert_eq!(
            quarantine_served_divergence(
                store,
                &digest("rabs.authority.sha256.v1", 1),
                &key_one,
                6,
                11,
                22,
                "stdout digest mismatch",
            ),
            Err(RevalidationError::StaleRevision { stored: 7 })
        );

        let new_revision = quarantine_served_divergence(
            store,
            &digest("rabs.authority.sha256.v1", 1),
            &key_one,
            7,
            11,
            22,
            "stdout digest mismatch",
        )
        .unwrap();
        assert_eq!(new_revision, 8);

        let incidents = store.list_divergence_incidents(&key_one).unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].class, "serving-sample-divergence");
        assert_eq!(incidents[0].detail, "stdout digest mismatch");
        let record = store.serving_record(&key_one).unwrap().unwrap();
        assert_eq!(record.disposition, DISPOSITION_QUARANTINED);
        assert_eq!(
            record.blocking,
            vec![("action-entry".to_owned(), key_one.clone())]
        );
        assert_eq!(
            serving_gate(store, &key_one, 2_000, 1).unwrap(),
            ServeDecision::NotServable {
                disposition: DISPOSITION_QUARANTINED.to_owned(),
            }
        );

        // Re-quarantining against the moved revision is a typed
        // stale-revision refusal; an unknown key is a typed no-record.
        assert_eq!(
            quarantine_served_divergence(
                store,
                &digest("rabs.authority.sha256.v1", 1),
                &key_one,
                7,
                11,
                23,
                "again",
            ),
            Err(RevalidationError::StaleRevision { stored: 8 })
        );
        assert_eq!(
            quarantine_served_divergence(
                store,
                &digest("rabs.authority.sha256.v1", 1),
                "missing:key",
                1,
                1,
                1,
                "x",
            ),
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
