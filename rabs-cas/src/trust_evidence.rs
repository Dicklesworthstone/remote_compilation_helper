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
//! under the LATEST NON-REVOKED policy: verification samples (joined to
//! their attempts' workers) derive the observed tier; a failed sample is
//! adverse evidence; a compromise report — recognizable by its digest
//! DOMAIN, never by parsing reason strings — forces quarantine. With no
//! active policy the evaluation is a typed refusal and existing state is
//! left untouched (fail toward the last evaluated state, mirroring
//! R127's fail-toward-retention).
//!
//! Write ordering inside one evaluation (each store call is its own
//! transaction): quarantine first, ledger second, disposition LAST — a
//! crash between steps can leave a stricter-than-necessary state, never
//! a more permissive one.

use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use rabs_protocol::serving::TrustEvidenceTier;
use sha2::{Digest, Sha256};

use crate::metadata_store::{
    QuarantineScope, RabsMetadataStore, StoreError, TrustEvaluationRow, digest_key,
};

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
    /// Every supplied policy is revoked (or none were supplied): the
    /// evaluation is refused and serving state is left untouched.
    NoActivePolicy,
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

/// Derive the observed tier from verification samples joined to their
/// attempts' workers. Labels observed evidence only — never semantic
/// correctness (plan §113): one passed verification is a shadow match,
/// repeats on one worker are same-worker reproduction, passes on two or
/// more workers are cross-worker reproduction.
fn observed_tier(
    store: &mut dyn RabsMetadataStore,
    action: &TypedDigest,
) -> Result<(TrustEvidenceTier, u64), StoreError> {
    let samples = store.list_verification_samples(action)?;
    let adverse = samples.iter().filter(|sample| !sample.passed).count() as u64;
    let mut passed_workers = Vec::new();
    let mut passed_samples = 0_u64;
    for sample in &samples {
        if !sample.passed {
            continue;
        }
        passed_samples += 1;
        let worker = store
            .attempt_worker_by_hex(&sample.attempt_hex)?
            .unwrap_or_else(|| format!("unattributed:{}", sample.attempt_hex));
        if !passed_workers.contains(&worker) {
            passed_workers.push(worker);
        }
    }
    let tier = match (passed_samples, passed_workers.len()) {
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
/// tests pin this byte-for-byte).
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
    } else if tier >= policy.required_tier {
        (DISPOSITION_SERVABLE, tier_tag(tier))
    } else {
        (DISPOSITION_EVIDENCE_PENDING, tier_tag(tier))
    };

    // Quarantine FIRST (stricter state can only be added early, never
    // skipped by a crash after the disposition write).
    if disposition == DISPOSITION_QUARANTINED {
        store.add_quarantine(
            QuarantineScope::ActionEntry,
            &digest_key(action),
            if compromised {
                "post-publication compromise report in evidence set"
            } else {
                "failed verification sample"
            },
        )?;
    }
    let ledger_version = store
        .latest_trust_evaluation(action)?
        .map_or(1, |latest| latest.version + 1);
    store.append_trust_evaluation(
        authority,
        action,
        &TrustEvaluationRow {
            version: ledger_version,
            state: state_tag.to_owned(),
            reason: format!(
                "policy v{}; evidence-set {}; adverse {}; compromised {}",
                policy.version,
                digest_key(&evidence_set),
                adverse_samples,
                compromised
            ),
            evaluated_seq: seq,
        },
    )?;
    store.set_serving_disposition_key(&digest_key(action), disposition)?;
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
/// carry [`COMPROMISE_REPORT_DOMAIN`]; anything else is refused before
/// any store write.
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
            store.commit_publication(&active, &row).unwrap(),
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
}
