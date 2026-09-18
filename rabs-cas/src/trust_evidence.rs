//! Append-only evidence indexing and versioned trust promotion/demotion
//! (bead H033; invariant I42; risk R99).
//!
//! A committed publication is history: promotion, demotion, policy
//! change, and post-publication compromise NEVER rewrite its canonical
//! bytes. Everything that moves lives in three places the store already
//! separates —
//!
//! - the **evidence index** (`action_evidence_index`, H011): append-only,
//!   idempotent per digest; its canonically sorted + deduplicated ID set
//!   names the evidence state via [`evidence_set_digest`] (the same
//!   canonicalization law as `rabs_protocol::serving::
//!   evidence_set_digest_input` — insertion order and duplicates can
//!   never rename a set);
//! - the **trust-evaluation ledger** (`action_trust_evaluations`, H038):
//!   append-only, strictly versioned, authority-gated;
//! - the **mutable serving disposition** (`action_serving_states`).
//!
//! [`reevaluate_action`] recomputes serving from the CURRENT evidence
//! under the LATEST NON-REVOKED policy. Only distinct, attributable
//! attempts belonging to this action derive a positive observed tier.
//! Failed samples remain adverse evidence. Neither positive evidence nor
//! a weaker policy releases existing quarantine or named blockers: that
//! requires the explicit repair flow, not ordinary reevaluation.
//!
//! With no active policy an ordinary evaluation leaves state untouched.
//! A compromise report is different: durable quarantine is written
//! BEFORE appending the report or evaluating policy, so a missing policy
//! or interrupted evaluation cannot leave the compromised result usable.
//!
//! Write ordering inside one evaluation (each store call is its own
//! transaction): quarantine first, ledger second, disposition LAST — a
//! crash between steps can leave a stricter-than-necessary state, never
//! a more permissive one. The serving gate independently checks durable
//! quarantine, including when the disposition update has not landed.

use std::collections::BTreeSet;

use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use rabs_protocol::serving::TrustEvidenceTier;
use sha2::{Digest, Sha256};

use crate::metadata_store::{
    QuarantineScope, RabsMetadataStore, SqlValue, StoreError, TrustEvaluationRow, digest_key,
};
use crate::serving_state::action_quarantine_present;

/// Domain separator for the canonical evidence-set digest.
pub const EVIDENCE_SET_DOMAIN: &str = "rabs.evidence-set.sha256.v1";
/// Digest domain that MARKS an evidence bundle as a post-publication
/// compromise report. The domain is the class authority (R121); no
/// reason-string parsing decides quarantine.
pub const COMPROMISE_REPORT_DOMAIN: &str = "rabs.compromise-report.sha256.v1";

/// Serving disposition written when the evaluated tier satisfies policy.
pub const DISPOSITION_SERVABLE: &str = "servable";
/// Serving disposition while required evidence is still missing.
pub const DISPOSITION_EVIDENCE_PENDING: &str = "evidence-pending";
/// Serving disposition under adverse evidence or compromise.
pub const DISPOSITION_QUARANTINED: &str = "quarantined";

/// One versioned, revocable trust policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustPolicy {
    /// Policy version (higher supersedes).
    pub version: u32,
    /// A revoked policy is never evaluated against.
    pub revoked: bool,
    /// Minimum evidence tier required for serving eligibility.
    pub required_tier: TrustEvidenceTier,
}

/// The latest non-revoked policy, if any (the ONLY policy evaluations
/// may use).
#[must_use]
pub fn latest_nonrevoked_policy(policies: &[TrustPolicy]) -> Option<&TrustPolicy> {
    policies
        .iter()
        .filter(|policy| !policy.revoked)
        .max_by_key(|policy| policy.version)
}

/// Typed H033 errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustEvidenceError {
    /// Underlying store error.
    Store(StoreError),
    /// Every supplied policy is revoked (or none were supplied).
    /// Ordinary reevaluation leaves state untouched; a compromise
    /// report remains durably quarantined even when evaluation fails.
    NoActivePolicy,
    /// The append-only ledger cannot advance without overflowing.
    LedgerVersionExhausted,
    /// The action has no committed publication to evaluate.
    NotPublished,
    /// A compromise report must carry [`COMPROMISE_REPORT_DOMAIN`]; any
    /// other domain is refused, never silently reclassified.
    NotACompromiseReport {
        /// The domain that was presented.
        presented: String,
    },
}

impl From<StoreError> for TrustEvidenceError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Reject an already-stale caller before the non-authority-gated
/// evidence/quarantine writes. The ledger write still performs its own
/// transactional authority check; this is not a replacement for it.
fn require_active_authority(
    store: &mut dyn RabsMetadataStore,
    authority: &TypedDigest,
) -> Result<(), StoreError> {
    match store.read_authority()? {
        Some(current) if &current.digest == authority => Ok(()),
        _ => Err(StoreError::NotActiveAuthority),
    }
}

/// Length-delimited canonical framing (the F034 pattern): every field is
/// `len(u64 be) || bytes`, so no concatenation ambiguity exists.
struct Framing(Sha256);

impl Framing {
    fn new(domain: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain.as_bytes());
        Self(hasher)
    }

    fn field(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update((bytes.len() as u64).to_be_bytes());
        self.0.update(bytes);
        self
    }

    fn u64(&mut self, v: u64) -> &mut Self {
        self.field(&v.to_be_bytes())
    }

    fn finish(self, domain: &'static str) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: self.0.finalize().into(),
        }
    }
}

/// Canonical digest over an evidence-ID set: IDs are sorted and
/// deduplicated before framing, so append-only growth changes the digest
/// deterministically and insertion order can never produce two names for
/// one set.
#[must_use]
pub fn evidence_set_digest(keys: &[String]) -> TypedDigest {
    let mut canonical: Vec<&str> = keys.iter().map(String::as_str).collect();
    canonical.sort_unstable();
    canonical.dedup();
    let mut framing = Framing::new(EVIDENCE_SET_DOMAIN);
    framing.u64(canonical.len() as u64);
    for key in canonical {
        framing.field(key.as_bytes());
    }
    framing.finish(EVIDENCE_SET_DOMAIN)
}

const fn tier_tag(tier: TrustEvidenceTier) -> &'static str {
    match tier {
        TrustEvidenceTier::UnverifiedCandidate => "unverified-candidate",
        TrustEvidenceTier::ShadowMatched => "shadow-matched",
        TrustEvidenceTier::ReproducibleSameWorker => "reproducible-same-worker",
        TrustEvidenceTier::ReproducibleCrossWorker => "reproducible-cross-worker",
        TrustEvidenceTier::CiPolicyApproved => "ci-policy-approved",
        TrustEvidenceTier::ProjectReleaseEligible => "project-release-eligible",
    }
}

/// One completed re-evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustReevaluation {
    /// The policy version evaluated against.
    pub policy_version: u32,
    /// Tier derived from the current verification evidence.
    pub observed_tier: TrustEvidenceTier,
    /// Whether a compromise report is present in the evidence set.
    pub compromised: bool,
    /// Number of failed verification samples (adverse evidence).
    pub adverse_samples: u64,
    /// Canonical digest of the evidence-ID set at evaluation time.
    pub evidence_set: TypedDigest,
    /// The serving disposition written.
    pub disposition: &'static str,
    /// The ledger version appended by this evaluation.
    pub ledger_version: u32,
}

/// Derive the observed tier from distinct successful attempts bound to
/// THIS action and a known worker. Repeated sample rows for one attempt
/// are not independent executions; missing attribution is not a new
/// worker identity. Labels observed evidence only — never semantic
/// correctness (plan §113).
fn observed_tier(
    store: &mut dyn RabsMetadataStore,
    action: &TypedDigest,
) -> Result<(TrustEvidenceTier, u64), StoreError> {
    let samples = store.list_verification_samples(action)?;
    let adverse = samples.iter().filter(|sample| !sample.passed).count() as u64;
    let rows = store.query(
        "SELECT DISTINCT a.id_hex, a.worker FROM verification_samples s \
         JOIN action_attempts a ON a.id_hex = s.attempt_hex \
         JOIN action_generations g ON g.id_hex = a.generation_hex \
         WHERE s.action_key = ?1 AND g.action_key = ?1 AND s.passed = 1 \
         ORDER BY a.id_hex",
        &[SqlValue::Text(digest_key(action))],
    )?;
    let mut passed_workers = BTreeSet::new();
    let mut passed_attempts = 0_u64;
    for row in rows {
        match row.as_slice() {
            [SqlValue::Text(_), SqlValue::Text(worker)] => {
                if !worker.is_empty() {
                    passed_attempts += 1;
                    passed_workers.insert(worker.clone());
                }
            }
            _ => {
                return Err(StoreError::Backend(
                    "invalid verification attempt attribution row".to_owned(),
                ));
            }
        }
    }
    let tier = match (passed_attempts, passed_workers.len()) {
        (0, _) => TrustEvidenceTier::UnverifiedCandidate,
        (1, _) => TrustEvidenceTier::ShadowMatched,
        (_, 0 | 1) => TrustEvidenceTier::ReproducibleSameWorker,
        (_, _) => TrustEvidenceTier::ReproducibleCrossWorker,
    };
    Ok((tier, adverse))
}

/// Re-evaluate one action's serving from its CURRENT evidence under the
/// latest non-revoked policy. Appends a ledger row and rewrites the
/// serving disposition; the publication row is never touched (I42 — the
/// tests pin this byte-for-byte). Existing quarantine and named blocking
/// references remain authoritative, even when all new evidence passes.
pub fn reevaluate_action(
    store: &mut dyn RabsMetadataStore,
    authority: &TypedDigest,
    action: &TypedDigest,
    policies: &[TrustPolicy],
    seq: u64,
) -> Result<TrustReevaluation, TrustEvidenceError> {
    if !store.has_publication(action)? {
        return Err(TrustEvidenceError::NotPublished);
    }
    let policy = latest_nonrevoked_policy(policies).ok_or(TrustEvidenceError::NoActivePolicy)?;
    require_active_authority(store, authority)?;
    let action_key = digest_key(action);
    let action_quarantined = action_quarantine_present(store, &action_key)?;
    let serving = store.serving_record(&action_key)?;
    let serving_blocked = serving.as_ref().is_some_and(|record| {
        record.disposition == DISPOSITION_QUARANTINED || !record.blocking.is_empty()
    });
    let keys = store.list_evidence_keys(action)?;
    let compromised = keys
        .iter()
        .any(|key| key.starts_with(&format!("{COMPROMISE_REPORT_DOMAIN}:")));
    let evidence_set = evidence_set_digest(&keys);
    let (tier, adverse_samples) = observed_tier(store, action)?;

    let (disposition, state_tag) = if compromised {
        (DISPOSITION_QUARANTINED, "compromised")
    } else if adverse_samples > 0 {
        (DISPOSITION_QUARANTINED, "adverse-evidence")
    } else if action_quarantined || serving_blocked {
        (DISPOSITION_QUARANTINED, "unresolved-quarantine")
    } else if tier >= policy.required_tier {
        (DISPOSITION_SERVABLE, tier_tag(tier))
    } else {
        (DISPOSITION_EVIDENCE_PENDING, tier_tag(tier))
    };

    // Quarantine FIRST, but do not overwrite an unresolved incident's
    // original reason. Named object/location blockers remain in the
    // serving record; reevaluation neither drops nor repairs them.
    if !action_quarantined && (compromised || adverse_samples > 0) {
        store.add_quarantine(
            QuarantineScope::ActionEntry,
            &action_key,
            if compromised {
                "post-publication compromise report in evidence set"
            } else {
                "failed verification sample"
            },
        )?;
    }
    let ledger_version = store
        .latest_trust_evaluation(action)?
        .map_or(Some(1), |latest| latest.version.checked_add(1))
        .ok_or(TrustEvidenceError::LedgerVersionExhausted)?;
    store.append_trust_evaluation(
        authority,
        action,
        &TrustEvaluationRow {
            version: ledger_version,
            state: state_tag.to_owned(),
            reason: format!(
                "policy v{}; evidence-set {}; adverse {}; compromised {}; prior-blocker {}",
                policy.version,
                digest_key(&evidence_set),
                adverse_samples,
                compromised,
                action_quarantined || serving_blocked
            ),
            evaluated_seq: seq,
        },
    )?;
    store.set_serving_disposition_key(&action_key, disposition)?;
    Ok(TrustReevaluation {
        policy_version: policy.version,
        observed_tier: tier,
        compromised,
        adverse_samples,
        evidence_set,
        disposition,
        ledger_version,
    })
}

/// Attach a post-publication compromise report to an action's evidence
/// set (append-only) and immediately re-evaluate. The report digest MUST
/// carry [`COMPROMISE_REPORT_DOMAIN`]; wrong domains, unpublished actions,
/// and already-stale authorities are refused before any store write.
///
/// Once admitted, quarantine lands FIRST. A later error, including
/// [`TrustEvidenceError::NoActivePolicy`], does not undo that protection.
/// Recovery must use the explicit repair flow rather than retrying with
/// a more permissive policy.
#[allow(clippy::too_many_arguments)]
pub fn report_compromise(
    store: &mut dyn RabsMetadataStore,
    authority: &TypedDigest,
    action: &TypedDigest,
    report: &TypedDigest,
    generation: u128,
    attempt: u128,
    policies: &[TrustPolicy],
    seq: u64,
) -> Result<TrustReevaluation, TrustEvidenceError> {
    if report.domain != COMPROMISE_REPORT_DOMAIN {
        return Err(TrustEvidenceError::NotACompromiseReport {
            presented: report.domain.to_owned(),
        });
    }
    // The report is evidence about the COMMITTED canonical result, so it
    // binds to the published manifest key (H029; I37).
    let manifest_key = store
        .published_manifest_key(action)?
        .ok_or(TrustEvidenceError::NotPublished)?;
    require_active_authority(store, authority)?;
    let action_key = digest_key(action);
    if !action_quarantine_present(store, &action_key)? {
        store.add_quarantine(
            QuarantineScope::ActionEntry,
            &action_key,
            "post-publication compromise report admitted",
        )?;
    }
    store.append_evidence(action, &manifest_key, report, generation, attempt)?;
    reevaluate_action(store, authority, action, policies, seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{
        ActionEntryRow, AuthorityRow, CommitOutcome, FsqliteEngine, PublicationRow, ResultKindTag,
        RusqliteEngine, SqlMetadataStore,
    };
    use crate::serving_state::{ServeDecision, serving_gate};
    use rabs_protocol::serving::ServingValidity;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_path(tag: &str) -> std::path::PathBuf {
        let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("rabs-h033-{}-{}-{}.db", std::process::id(), tag, n))
    }

    fn digest(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
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

    fn policy(version: u32, revoked: bool, required: TrustEvidenceTier) -> TrustPolicy {
        TrustPolicy {
            version,
            revoked,
            required_tier: required,
        }
    }

    /// Publish action 7 with generation 10 and attempts 20 (worker-a) +
    /// 21 (worker-b); returns (active authority, action key).
    fn published_fixture(store: &mut dyn RabsMetadataStore) -> (TypedDigest, TypedDigest) {
        store.acquire_authority(&authority_row(1)).unwrap();
        let active = digest("rabs.authority.sha256.v1", 1);
        let action = ActionEntryRow {
            action_key: digest("rabs.action-key.sha256.v1", 7),
            key_epoch: 0,
            projection_epoch: 0,
        };
        store.upsert_action_entry(&action).unwrap();
        store
            .create_generation(&active, 10, &action.action_key)
            .unwrap();
        store.record_attempt(20, 10, "worker-a", 5).unwrap();
        store.record_attempt(21, 10, "worker-b", 6).unwrap();
        let row = PublicationRow {
            action_key: action.action_key.clone(),
            descriptor_digest: digest("rabs.descriptor.sha256.v1", 1),
            manifest_digest: digest("rabs.result-manifest.sha256.v1", 1),
            evidence_digest: digest("rabs.evidence-bundle.sha256.v1", 1),
            winner_generation: 10,
            winner_attempt: 20,
            result_kind: ResultKindTag::Success,
            pin_id: 40,
            pin_owner: "coordinator".to_owned(),
            provisional_ancestors: Vec::new(),
        };
        assert_eq!(
            store.commit_publication(&active, None, &row).unwrap(),
            CommitOutcome::Committed
        );
        (active, action.action_key)
    }

    /// The publication's dump lines — the canonical bytes that H033 must
    /// NEVER rewrite.
    fn publication_lines(store: &mut dyn RabsMetadataStore) -> Vec<String> {
        store
            .differential_snapshot()
            .unwrap()
            .into_iter()
            .filter(|line| line.starts_with("action_publications|"))
            .collect()
    }

    /// T032: evidence promotion and demotion move the ledger + serving,
    /// never the publication.
    fn t032_promotion_demotion(store: &mut dyn RabsMetadataStore) -> Vec<String> {
        let (active, action) = published_fixture(store);
        let frozen = publication_lines(store);
        let policies = vec![policy(1, false, TrustEvidenceTier::ShadowMatched)];

        // No verification evidence yet: pending, ledger v1.
        let eval = reevaluate_action(store, &active, &action, &policies, 100).unwrap();
        assert_eq!(eval.observed_tier, TrustEvidenceTier::UnverifiedCandidate);
        assert_eq!(eval.disposition, DISPOSITION_EVIDENCE_PENDING);
        assert_eq!(eval.ledger_version, 1);

        // One passed verification: PROMOTION to servable.
        store
            .record_verification_sample(&action, 20, true, 101)
            .unwrap();
        let eval = reevaluate_action(store, &active, &action, &policies, 102).unwrap();
        assert_eq!(eval.observed_tier, TrustEvidenceTier::ShadowMatched);
        assert_eq!(eval.disposition, DISPOSITION_SERVABLE);
        assert_eq!(eval.ledger_version, 2);
        assert_eq!(
            store.serving_disposition_key(&digest_key(&action)).unwrap(),
            Some(DISPOSITION_SERVABLE.to_owned())
        );

        // A second passed verification from a DIFFERENT worker.
        store
            .record_verification_sample(&action, 21, true, 103)
            .unwrap();
        let eval = reevaluate_action(store, &active, &action, &policies, 104).unwrap();
        assert_eq!(
            eval.observed_tier,
            TrustEvidenceTier::ReproducibleCrossWorker
        );
        assert_eq!(eval.disposition, DISPOSITION_SERVABLE);

        // A failed verification is adverse evidence: DEMOTION to
        // quarantined, and the quarantine row exists.
        store
            .record_verification_sample(&action, 21, false, 105)
            .unwrap();
        let eval = reevaluate_action(store, &active, &action, &policies, 106).unwrap();
        assert_eq!(eval.adverse_samples, 1);
        assert_eq!(eval.disposition, DISPOSITION_QUARANTINED);
        assert_eq!(eval.ledger_version, 4);
        assert_eq!(
            store.serving_disposition_key(&digest_key(&action)).unwrap(),
            Some(DISPOSITION_QUARANTINED.to_owned())
        );

        // I42: the publication rows are byte-identical through all of it.
        assert_eq!(publication_lines(store), frozen);
        store.differential_snapshot().unwrap()
    }

    #[test]
    fn t032_promotion_demotion_reference() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        t032_promotion_demotion(&mut store);
    }

    #[test]
    fn t032_promotion_demotion_differential_reference_vs_frankensqlite() {
        let reference_engine = RusqliteEngine::open(&fresh_path("ref")).unwrap();
        let mut reference = SqlMetadataStore::open(reference_engine).unwrap();
        let candidate_engine = FsqliteEngine::open(&fresh_path("fsq")).unwrap();
        let mut candidate = SqlMetadataStore::open(candidate_engine).unwrap();
        assert_eq!(
            t032_promotion_demotion(&mut reference),
            t032_promotion_demotion(&mut candidate)
        );
    }

    #[test]
    fn t032_policy_change_reevaluates_serving() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        let (active, action) = published_fixture(&mut store);
        store
            .record_verification_sample(&action, 20, true, 100)
            .unwrap();

        // Policy v1 accepts a shadow match: servable.
        let v1 = vec![policy(1, false, TrustEvidenceTier::ShadowMatched)];
        let eval = reevaluate_action(&mut store, &active, &action, &v1, 101).unwrap();
        assert_eq!(eval.disposition, DISPOSITION_SERVABLE);

        // Policy v2 (stricter) supersedes: the SAME evidence no longer
        // suffices — serving demotes without any new evidence.
        let v2 = vec![
            policy(1, false, TrustEvidenceTier::ShadowMatched),
            policy(2, false, TrustEvidenceTier::ReproducibleCrossWorker),
        ];
        let eval = reevaluate_action(&mut store, &active, &action, &v2, 102).unwrap();
        assert_eq!(eval.policy_version, 2);
        assert_eq!(eval.disposition, DISPOSITION_EVIDENCE_PENDING);

        // v2 revoked: evaluation falls back to the latest NON-revoked
        // policy (v1) and serving returns.
        let v2_revoked = vec![
            policy(1, false, TrustEvidenceTier::ShadowMatched),
            policy(2, true, TrustEvidenceTier::ReproducibleCrossWorker),
        ];
        let eval = reevaluate_action(&mut store, &active, &action, &v2_revoked, 103).unwrap();
        assert_eq!(eval.policy_version, 1);
        assert_eq!(eval.disposition, DISPOSITION_SERVABLE);

        // Every policy revoked: typed refusal, serving state untouched.
        let all_revoked = vec![policy(1, true, TrustEvidenceTier::ShadowMatched)];
        assert_eq!(
            reevaluate_action(&mut store, &active, &action, &all_revoked, 104),
            Err(TrustEvidenceError::NoActivePolicy)
        );
        assert_eq!(
            store.serving_disposition_key(&digest_key(&action)).unwrap(),
            Some(DISPOSITION_SERVABLE.to_owned()),
            "refused evaluation must not move serving state"
        );
    }

    #[test]
    fn t032_post_publication_compromise() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        let (active, action) = published_fixture(&mut store);
        store
            .record_verification_sample(&action, 20, true, 100)
            .unwrap();
        let policies = vec![policy(1, false, TrustEvidenceTier::ShadowMatched)];
        let eval = reevaluate_action(&mut store, &active, &action, &policies, 101).unwrap();
        assert_eq!(eval.disposition, DISPOSITION_SERVABLE);
        let frozen = publication_lines(&mut store);

        // A report under the WRONG domain is refused before any write.
        let ledger_before = store.latest_trust_evaluation(&action).unwrap();
        let bogus = digest("rabs.evidence-bundle.sha256.v1", 66);
        assert_eq!(
            report_compromise(&mut store, &active, &action, &bogus, 10, 20, &policies, 102),
            Err(TrustEvidenceError::NotACompromiseReport {
                presented: "rabs.evidence-bundle.sha256.v1".to_owned()
            })
        );
        assert_eq!(
            store.latest_trust_evaluation(&action).unwrap(),
            ledger_before,
            "refused report must append nothing"
        );

        // The real compromise report: appended to the index, quarantined,
        // ledger demoted — the publication untouched.
        let report = digest(COMPROMISE_REPORT_DOMAIN, 66);
        let eval = report_compromise(
            &mut store, &active, &action, &report, 10, 20, &policies, 103,
        )
        .unwrap();
        assert!(eval.compromised);
        assert_eq!(eval.disposition, DISPOSITION_QUARANTINED);
        assert!(
            store
                .list_evidence_keys(&action)
                .unwrap()
                .iter()
                .any(|key| key.starts_with(&format!("{COMPROMISE_REPORT_DOMAIN}:"))),
            "compromise report must live in the append-only index"
        );
        assert_eq!(
            store
                .latest_trust_evaluation(&action)
                .unwrap()
                .unwrap()
                .state,
            "compromised"
        );

        // Re-evaluating WITHOUT new evidence stays quarantined: the
        // append-only index cannot forget the report.
        let eval = reevaluate_action(&mut store, &active, &action, &policies, 104).unwrap();
        assert!(eval.compromised);
        assert_eq!(eval.disposition, DISPOSITION_QUARANTINED);

        assert_eq!(publication_lines(&mut store), frozen);
    }

    #[test]
    fn evidence_set_digest_is_order_insensitive_and_deduplicated() {
        let a = evidence_set_digest(&["d:aa".to_owned(), "d:bb".to_owned(), "d:cc".to_owned()]);
        let b = evidence_set_digest(&[
            "d:cc".to_owned(),
            "d:aa".to_owned(),
            "d:bb".to_owned(),
            "d:aa".to_owned(),
        ]);
        assert_eq!(a, b, "insertion order and duplicates never rename a set");
        let grown = evidence_set_digest(&[
            "d:aa".to_owned(),
            "d:bb".to_owned(),
            "d:cc".to_owned(),
            "d:dd".to_owned(),
        ]);
        assert_ne!(a, grown, "growth must rename the set");
        // Length-delimited framing: a boundary shift is a different set.
        let shifted = evidence_set_digest(&["d:aab".to_owned(), "d:b".to_owned()]);
        let plain = evidence_set_digest(&["d:aa".to_owned(), "d:bb".to_owned()]);
        assert_ne!(shifted, plain);
    }

    #[test]
    fn duplicate_evidence_appends_do_not_rename_the_set() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        let (_, action) = published_fixture(&mut store);
        let before = store.list_evidence_keys(&action).unwrap();
        let manifest_key = store.published_manifest_key(&action).unwrap().unwrap();
        // Re-append the winner's evidence digest (idempotent per H011).
        store
            .append_evidence(
                &action,
                &manifest_key,
                &digest("rabs.evidence-bundle.sha256.v1", 1),
                10,
                20,
            )
            .unwrap();
        let after = store.list_evidence_keys(&action).unwrap();
        assert_eq!(before, after);
        assert_eq!(evidence_set_digest(&before), evidence_set_digest(&after));
    }

    #[test]
    fn unpublished_actions_are_refused() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        store.acquire_authority(&authority_row(1)).unwrap();
        let active = digest("rabs.authority.sha256.v1", 1);
        let unpublished = digest("rabs.action-key.sha256.v1", 99);
        let policies = vec![policy(1, false, TrustEvidenceTier::ShadowMatched)];
        assert_eq!(
            reevaluate_action(&mut store, &active, &unpublished, &policies, 100),
            Err(TrustEvidenceError::NotPublished)
        );
    }

    /// Unattributed, foreign-action and repeated samples never invent
    /// independent executions. Real independent attempts still promote.
    /// Once quarantined, even a weaker policy cannot restore serving.
    fn independent_evidence_and_sticky_quarantine(
        store: &mut dyn RabsMetadataStore,
    ) -> Vec<String> {
        let (active, action) = published_fixture(store);
        let action_key = digest_key(&action);
        let frozen = publication_lines(store);
        let policies = vec![policy(1, false, TrustEvidenceTier::ReproducibleCrossWorker)];

        // Unknown attempts used to fabricate distinct worker identities.
        for attempt in [90, 91] {
            store
                .record_verification_sample(&action, attempt, true, attempt)
                .unwrap();
        }
        // A real worker on another action is not evidence for this one.
        let foreign = digest("rabs.action-key.sha256.v1", 8);
        store
            .upsert_action_entry(&ActionEntryRow {
                action_key: foreign.clone(),
                key_epoch: 0,
                projection_epoch: 0,
            })
            .unwrap();
        store.create_generation(&active, 11, &foreign).unwrap();
        store.record_attempt(30, 11, "worker-c", 92).unwrap();
        store
            .record_verification_sample(&action, 30, true, 93)
            .unwrap();
        // Empty attribution is not a worker identity either.
        store.record_attempt(31, 10, "", 94).unwrap();
        store
            .record_verification_sample(&action, 31, true, 95)
            .unwrap();
        let eval = reevaluate_action(store, &active, &action, &policies, 100).unwrap();
        assert_eq!(eval.observed_tier, TrustEvidenceTier::UnverifiedCandidate);
        assert_eq!(eval.disposition, DISPOSITION_EVIDENCE_PENDING);

        for seq in [101, 102, 103] {
            store
                .record_verification_sample(&action, 20, true, seq)
                .unwrap();
        }
        let eval = reevaluate_action(store, &active, &action, &policies, 104).unwrap();
        assert_eq!(eval.observed_tier, TrustEvidenceTier::ShadowMatched);
        assert_eq!(eval.disposition, DISPOSITION_EVIDENCE_PENDING);

        store.record_attempt(22, 10, "worker-a", 105).unwrap();
        store
            .record_verification_sample(&action, 22, true, 106)
            .unwrap();
        let eval = reevaluate_action(store, &active, &action, &policies, 107).unwrap();
        assert_eq!(eval.observed_tier, TrustEvidenceTier::ReproducibleSameWorker);
        assert_eq!(eval.disposition, DISPOSITION_EVIDENCE_PENDING);
        store
            .record_verification_sample(&action, 21, true, 108)
            .unwrap();
        let eval = reevaluate_action(store, &active, &action, &policies, 109).unwrap();
        assert_eq!(eval.observed_tier, TrustEvidenceTier::ReproducibleCrossWorker);
        assert_eq!(eval.disposition, DISPOSITION_SERVABLE);

        store
            .add_quarantine(QuarantineScope::ActionEntry, &action_key, "closure corruption")
            .unwrap();
        let record = store.serving_record(&action_key).unwrap().unwrap();
        assert_eq!(record.disposition, DISPOSITION_SERVABLE);
        assert!(record.blocking.is_empty());
        let weaker = vec![policy(2, false, TrustEvidenceTier::UnverifiedCandidate)];
        let eval = reevaluate_action(store, &active, &action, &weaker, 110).unwrap();
        assert_eq!(eval.disposition, DISPOSITION_QUARANTINED);
        assert_eq!(
            store.latest_trust_evaluation(&action).unwrap().unwrap().state,
            "unresolved-quarantine"
        );
        assert_eq!(
            store
                .query(
                    "SELECT reason FROM quarantines WHERE scope = 'action-entry' AND subject = ?1",
                    &[SqlValue::Text(action_key.clone())],
                )
                .unwrap(),
            vec![vec![SqlValue::Text("closure corruption".to_owned())]]
        );
        assert!(matches!(
            serving_gate(store, &action_key, 200, 0).unwrap(),
            ServeDecision::NotServable { .. }
        ));
        assert_eq!(publication_lines(store), frozen);
        store.differential_snapshot().unwrap()
    }

    #[test]
    fn independent_evidence_and_quarantine_reference() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        independent_evidence_and_sticky_quarantine(&mut store);
    }

    #[test]
    fn independent_evidence_and_quarantine_differential() {
        let mut reference =
            SqlMetadataStore::open(RusqliteEngine::open(&fresh_path("evidence-ref")).unwrap()).unwrap();
        let mut candidate =
            SqlMetadataStore::open(FsqliteEngine::open(&fresh_path("evidence-fsq")).unwrap()).unwrap();
        assert_eq!(
            independent_evidence_and_sticky_quarantine(&mut reference),
            independent_evidence_and_sticky_quarantine(&mut candidate)
        );
    }

    #[test]
    fn positive_evidence_preserves_named_blockers_and_quarantined_disposition() {
        for named_blocker in [false, true] {
            let engine = RusqliteEngine::open_in_memory().unwrap();
            let mut store = SqlMetadataStore::open(engine).unwrap();
            let (active, action) = published_fixture(&mut store);
            let action_key = digest_key(&action);
            let policies = vec![policy(1, false, TrustEvidenceTier::ShadowMatched)];
            store.record_verification_sample(&action, 20, true, 100).unwrap();
            let blocking = if named_blocker {
                store
                    .add_quarantine(QuarantineScope::LogicalObject, "object:damaged", "bad bytes")
                    .unwrap();
                vec![(QuarantineScope::LogicalObject, "object:damaged".to_owned())]
            } else {
                Vec::new()
            };
            store
                .put_serving_record(
                    &active,
                    &action_key,
                    if named_blocker { DISPOSITION_SERVABLE } else { DISPOSITION_QUARANTINED },
                    1,
                    &ServingValidity {
                        evaluated_at_unix_micros: 0,
                        maximum_age_micros: None,
                        clock_uncertainty_micros: 0,
                        coordinator_clock_epoch: 0,
                    },
                    &blocking,
                )
                .unwrap();
            let before = store.serving_record(&action_key).unwrap().unwrap();
            let eval = reevaluate_action(&mut store, &active, &action, &policies, 101).unwrap();
            assert_eq!(eval.disposition, DISPOSITION_QUARANTINED);
            let after = store.serving_record(&action_key).unwrap().unwrap();
            assert_eq!(after.blocking, before.blocking);
            assert_eq!(after.state_revision, before.state_revision);
            assert!(matches!(
                serving_gate(&mut store, &action_key, 200, 0).unwrap(),
                ServeDecision::NotServable { .. }
            ));
        }
    }

    fn compromise_without_policy_is_still_blocked(
        store: &mut dyn RabsMetadataStore,
    ) -> Vec<String> {
        let (active, action) = published_fixture(store);
        let action_key = digest_key(&action);
        let frozen = publication_lines(store);
        let report = digest(COMPROMISE_REPORT_DOMAIN, 66);
        let policies = vec![policy(1, false, TrustEvidenceTier::ShadowMatched)];
        let wrong = digest("rabs.authority.sha256.v1", 2);
        let before = store.differential_snapshot().unwrap();
        assert_eq!(
            report_compromise(store, &wrong, &action, &report, 10, 20, &policies, 100),
            Err(TrustEvidenceError::Store(StoreError::NotActiveAuthority))
        );
        assert_eq!(
            reevaluate_action(store, &wrong, &action, &policies, 100),
            Err(TrustEvidenceError::Store(StoreError::NotActiveAuthority))
        );
        assert_eq!(store.differential_snapshot().unwrap(), before);
        assert_eq!(serving_gate(store, &action_key, 200, 0).unwrap(), ServeDecision::Servable);

        assert_eq!(
            report_compromise(store, &active, &action, &report, 10, 20, &[], 101),
            Err(TrustEvidenceError::NoActivePolicy)
        );
        assert!(store.list_evidence_keys(&action).unwrap().contains(&digest_key(&report)));
        assert_eq!(
            serving_gate(store, &action_key, 200, 0).unwrap(),
            ServeDecision::Blocked {
                references: vec![("action-entry".to_owned(), action_key.clone())],
            }
        );
        let revoked = vec![policy(1, true, TrustEvidenceTier::ShadowMatched)];
        assert_eq!(
            report_compromise(store, &active, &action, &report, 10, 20, &revoked, 102),
            Err(TrustEvidenceError::NoActivePolicy)
        );
        assert!(matches!(
            serving_gate(store, &action_key, 200, 0).unwrap(),
            ServeDecision::Blocked { .. }
        ));
        assert_eq!(publication_lines(store), frozen);
        store.differential_snapshot().unwrap()
    }

    #[test]
    fn compromise_without_policy_reference() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        compromise_without_policy_is_still_blocked(&mut store);
    }

    #[test]
    fn compromise_without_policy_differential() {
        let mut reference =
            SqlMetadataStore::open(RusqliteEngine::open(&fresh_path("compromise-ref")).unwrap()).unwrap();
        let mut candidate =
            SqlMetadataStore::open(FsqliteEngine::open(&fresh_path("compromise-fsq")).unwrap()).unwrap();
        assert_eq!(
            compromise_without_policy_is_still_blocked(&mut reference),
            compromise_without_policy_is_still_blocked(&mut candidate)
        );
    }
}
