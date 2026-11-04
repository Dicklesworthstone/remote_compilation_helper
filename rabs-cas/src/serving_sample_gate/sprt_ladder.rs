//! Opt-in, evidence-driven verification floors for the live dependency class.
//!
//! RABS_SPRT_SAMPLING=1 enables this gate. The existing per-action evidence
//! requirements still apply. The live coordinator also obtains its replay
//! ceiling through SamplingPolicy::replay_install_limit, then validates and
//! spends its existing durable installation receipt before writing outputs.
//!
//! Every failure is already a class-wide veto in class_quarantine. For the
//! remaining zero-failure sequence, the plan's Bernoulli SPRT has an exact
//! integer crossing: 69,762 distinct admitted comparisons per step. Three
//! disjoint windows lower the verification floor 100 -> 25 -> 5 -> 1 percent.
//! These are policy floors, not a claim that build outcomes are IID Bernoulli
//! trials or that a deployed compiler has a measured 1e-6 divergence rate.
//!
//! Fold bounded pages of the existing receipt journal. Consume each attributed
//! attempt BEFORE advancing the checkpoint: a crash may lose positive credit,
//! never count a retransmission twice. rowid is a scan cursor, NOT evidence or
//! identity. Renumbering/replaying rows cannot bypass the stable attempt marker.
//! A cursor rollback can cause conservative undercounting; it cannot promote.

use super::PrivateExecutionReason;
use crate::metadata_store::{RabsMetadataStore, SqlValue, StoreError};
use std::sync::OnceLock;

const CLASS_KIND: &str = "rabs-live-action-class-v1";
const CLASS: &str = "rustc-dependency-compile";
const VERIFIED: &str = "rabs-live-verification-v1";
const INSTALL: &str = "rabs-live-replay-install-v1";
const STATE: &str = "rabs-sprt-checkpoint-v1";
const COUNTED: &str = "rabs-sprt-counted-attempt-v1";
const PROMOTION: &str = "rabs-sprt-promotion-v1";
const PAGE: usize = 128;
const PASSES_PER_STEP: u64 = 69_762;
const FINAL_PASSES: u64 = 3 * PASSES_PER_STEP;

// The primary-key rowid range makes work proportional to NEW journal rows,
// rather than sorting/scanning every earlier successful comparison per hit.
// Do not return other receipt payloads, which may contain large diagnostics.
const PAGE_SQL: &str = r#"
SELECT rowid, kind,
       CASE WHEN kind = ?1 THEN substr(subject, 1, 256) ELSE NULL END,
       CASE WHEN kind = ?1 THEN seq ELSE NULL END,
       CASE WHEN kind = ?1 THEN substr(decision, 1, 64) ELSE NULL END,
       CASE WHEN kind = ?1 THEN substr(reason, 1, 256) ELSE NULL END
FROM decision_receipts WHERE rowid > ?2 ORDER BY rowid LIMIT 128
"#;
const RECEIPT_SQL: &str = r#"
SELECT decision, reason FROM decision_receipts
WHERE kind = ?1 AND subject = ?2 AND seq = ?3
"#;
// decision_receipts is append-only. Its (kind, subject, seq) primary key
// supports loading the latest generation without scanning checkpoint history.
// Generation is independent of the journal cursor: a conservative cursor reset
// must not rewrite an earlier receipt or resurrect an older positive count.
const CHECKPOINT_SQL: &str = r#"
SELECT seq, decision, reason FROM decision_receipts
WHERE kind = ?1 AND subject = ?2 ORDER BY seq DESC LIMIT 1
"#;
// Only the production publication engine's receipt plus its exact sample and
// actual attempt/generation can earn credit. Raw samples and winner re-offers
// cannot. Membership is bound by submission, not by a request's risk flag.
const ATTRIBUTED_SQL: &str = r#"
SELECT a.id_hex FROM action_attempts AS a
JOIN action_generations AS g ON g.id_hex = a.generation_hex
JOIN verification_samples AS v ON v.attempt_hex = a.id_hex
JOIN action_publications AS p ON p.action_key = g.action_key
JOIN decision_receipts AS c ON c.subject = g.action_key
WHERE a.id_hex = ?1 AND a.worker != '' AND g.action_key = ?2 AND v.action_key = ?2
AND v.seq = ?3 AND v.passed = 1 AND p.winner_attempt_hex != a.id_hex
AND c.kind = ?4 AND c.seq = 0 AND c.decision = ?5
LIMIT 1
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Fixed,
    Sprt,
    Invalid,
}

impl Mode {
    fn parse(value: Option<&str>) -> Self {
        match value {
            None | Some("0" | "false" | "off") => Self::Fixed,
            Some("1" | "true" | "on") => Self::Sprt,
            Some(_) => Self::Invalid,
        }
    }
}

fn mode() -> Mode {
    static MODE: OnceLock<Mode> = OnceLock::new();
    *MODE.get_or_init(|| match std::env::var("RABS_SPRT_SAMPLING") {
        Ok(value) => Mode::parse(Some(&value)),
        Err(std::env::VarError::NotPresent) => Mode::Fixed,
        Err(std::env::VarError::NotUnicode(_)) => Mode::Invalid,
    })
}

pub(super) fn enabled() -> bool {
    // An invalid opt-in must reach refusal, not silently choose fixed replay.
    mode() != Mode::Fixed
}

fn corrupt(reason: &str) -> StoreError {
    StoreError::Corruption(format!("SPRT: {reason}"))
}

fn number(text: &str) -> Result<u64, StoreError> {
    let number: u64 = text.parse().map_err(|_| corrupt("invalid counter"))?;
    if number.to_string() != text {
        return Err(corrupt("noncanonical counter"));
    }
    Ok(number)
}

fn receipt(
    store: &mut dyn RabsMetadataStore,
    kind: &str,
    subject: &str,
    seq: u64,
) -> Result<Option<(String, String)>, StoreError> {
    let rows = store.query(
        RECEIPT_SQL,
        &[
            SqlValue::Text(kind.into()),
            SqlValue::Text(subject.into()),
            SqlValue::Int(i64::try_from(seq).map_err(|_| corrupt("receipt sequence overflow"))?),
        ],
    )?;
    match rows.as_slice() {
        [] => Ok(None),
        [row] => match row.as_slice() {
            [SqlValue::Text(decision), SqlValue::Text(reason)] => {
                Ok(Some((decision.clone(), reason.clone())))
            }
            _ => Err(corrupt("receipt shape")),
        },
        _ => Err(corrupt("ambiguous receipt")),
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Checkpoint {
    cursor: i64,
    passes: u64,
}

impl Checkpoint {
    fn validate(self) -> Result<Self, StoreError> {
        let cursor = u64::try_from(self.cursor).map_err(|_| corrupt("negative cursor"))?;
        if self.passes > FINAL_PASSES || self.passes > cursor {
            return Err(corrupt("inconsistent checkpoint"));
        }
        Ok(self)
    }

    fn latest(store: &mut dyn RabsMetadataStore) -> Result<Option<(i64, Self)>, StoreError> {
        let rows = store.query(
            CHECKPOINT_SQL,
            &[SqlValue::Text(STATE.into()), SqlValue::Text(CLASS.into())],
        )?;
        match rows.as_slice() {
            [] => Ok(None),
            [row] => match row.as_slice() {
                [
                    SqlValue::Int(generation),
                    SqlValue::Text(passes),
                    SqlValue::Text(cursor),
                ] if *generation >= 0 => {
                    let checkpoint = Self {
                        cursor: i64::try_from(number(cursor)?)
                            .map_err(|_| corrupt("cursor overflow"))?,
                        passes: number(passes)?,
                    }
                    .validate()?;
                    Ok(Some((*generation, checkpoint)))
                }
                _ => Err(corrupt("checkpoint receipt shape")),
            },
            _ => Err(corrupt("ambiguous checkpoint")),
        }
    }

    fn load(store: &mut dyn RabsMetadataStore) -> Result<Self, StoreError> {
        // A legacy seq-0 record is the first generation, not a mutable slot.
        // Never fall back to it if a newer checkpoint is malformed/unreadable.
        Ok(Self::latest(store)?.map_or_else(Self::default, |(_, checkpoint)| checkpoint))
    }

    /// The caller keeps the existing exclusive CAS lock from load/scan through
    /// this append. Markers precede credit, and publication follows persistence.
    /// An exact retry after an ambiguous append is read-only; a changed state
    /// consumes the next generation. No upsert, deletion, or conflict fallback.
    fn persist(self, store: &mut dyn RabsMetadataStore) -> Result<(), StoreError> {
        self.validate()?;
        let generation = match Self::latest(store)? {
            Some((_, previous)) if previous == self => return Ok(()),
            Some((generation, _)) => generation
                .checked_add(1)
                .ok_or_else(|| corrupt("checkpoint generation overflow"))?,
            None => 0,
        };
        store.record_decision_receipt(
            STATE,
            CLASS,
            u64::try_from(generation).map_err(|_| corrupt("negative checkpoint generation"))?,
            &self.passes.to_string(),
            &self.cursor.to_string(),
        )
    }

    fn step(self) -> usize {
        (self.passes / PASSES_PER_STEP).min(3) as usize
    }

    fn verification_bps(self) -> u32 {
        [10_000, 2_500, 500, 100][self.step()]
    }

    fn replay_limit(self) -> u64 {
        [0, 3, 19, 99][self.step()]
    }
}

fn admitted(
    store: &mut dyn RabsMetadataStore,
    action: &str,
    seq: i64,
    attempt: &str,
    manifest: &str,
) -> Result<bool, StoreError> {
    if seq < 0
        || attempt.len() != 32
        || !attempt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || store.published_manifest_key_str(action)?.as_deref() != Some(manifest)
    {
        return Ok(false);
    }
    let rows = store.query(
        ATTRIBUTED_SQL,
        &[
            SqlValue::Text(attempt.into()),
            SqlValue::Text(action.into()),
            SqlValue::Int(seq),
            SqlValue::Text(CLASS_KIND.into()),
            SqlValue::Text(CLASS.into()),
        ],
    )?;
    match rows.as_slice() {
        [] => Ok(false),
        [row] if matches!(row.as_slice(), [SqlValue::Text(id)] if id == attempt) => Ok(true),
        _ => Err(corrupt("attribution shape")),
    }
}

/// The caller holds its existing CAS lock across this whole sequence. A marker
/// can survive without credit; credit must NEVER survive without its marker.
fn advance(store: &mut dyn RabsMetadataStore) -> Result<Checkpoint, StoreError> {
    let mut checkpoint = Checkpoint::load(store)?;
    if checkpoint.passes == FINAL_PASSES {
        return Ok(checkpoint);
    }
    let original = checkpoint;
    let rows = store.query(
        PAGE_SQL,
        &[
            SqlValue::Text(VERIFIED.into()),
            SqlValue::Int(checkpoint.cursor),
        ],
    )?;
    if rows.len() > PAGE {
        return Err(corrupt("unbounded journal page"));
    }
    let mut external_progress = false;
    for row in &rows {
        let [SqlValue::Int(cursor), SqlValue::Text(kind), fields @ ..] = row.as_slice() else {
            return Err(corrupt("journal row shape"));
        };
        if fields.len() != 4 || *cursor <= checkpoint.cursor {
            return Err(corrupt("unordered journal page"));
        }
        checkpoint.cursor = *cursor;
        external_progress |= ![STATE, COUNTED, PROMOTION].contains(&kind.as_str());
        if kind != VERIFIED {
            continue;
        }
        let [
            SqlValue::Text(action),
            SqlValue::Int(seq),
            SqlValue::Text(attempt),
            SqlValue::Text(manifest),
        ] = fields
        else {
            return Err(corrupt("verification receipt shape"));
        };
        if !admitted(store, action, *seq, attempt, manifest)? {
            continue;
        }
        let subject = format!("{action}:{attempt}");
        match receipt(store, COUNTED, &subject, 0)? {
            Some((decision, reason)) if decision == "consumed" && reason == CLASS => continue,
            Some(_) => return Err(corrupt("conflicting attempt marker")),
            None => {}
        }
        // A lost checkpoint update intentionally loses this positive credit.
        // Retrying after an ambiguous write cannot manufacture another trial.
        store.record_decision_receipt(COUNTED, &subject, 0, "consumed", CLASS)?;
        checkpoint.passes += 1;
        if checkpoint.passes == FINAL_PASSES {
            break;
        }
    }
    // Do not append checkpoints forever just to scan our own checkpoint.
    // Full pages still advance, even if filled entirely by our own markers.
    if checkpoint != original && (external_progress || rows.len() == PAGE) {
        checkpoint.persist(store)?;
    }
    Ok(checkpoint)
}

/// Audit receipts are durable before the newly qualified policy can be used.
/// They never authorize serving by themselves; counters and all negative
/// evidence are checked afresh. Each crossing spends a DIFFERENT trial window.
fn record_crossings(
    store: &mut dyn RabsMetadataStore,
    checkpoint: Checkpoint,
) -> Result<(), StoreError> {
    for step in 1..=checkpoint.step() {
        let decision = [
            "",
            "verification-bps=2500",
            "verification-bps=500",
            "verification-bps=100",
        ][step];
        let reason = format!(
            "bernoulli-sprt-v1;p0=0.000001;p1=0.0001;alpha=0.001;beta=0.001;\
             window-passes={PASSES_PER_STEP};cumulative-passes={};\
             llr=-6.906786798374720935;accept-h0=-6.906754778648553518",
            step as u64 * PASSES_PER_STEP,
        );
        match receipt(store, PROMOTION, CLASS, step as u64)? {
            Some((old_decision, old_reason))
                if old_decision == decision && old_reason == reason => {}
            Some(_) => return Err(corrupt("conflicting promotion receipt")),
            None => {
                store.record_decision_receipt(PROMOTION, CLASS, step as u64, decision, &reason)?
            }
        }
    }
    Ok(())
}

fn used_since_comparison(
    store: &mut dyn RabsMetadataStore,
    action: &str,
) -> Result<Option<u64>, StoreError> {
    let rows = store.query(
        "SELECT seq FROM decision_receipts WHERE kind = ?1 AND subject = ?2 ORDER BY seq DESC LIMIT 1",
        &[SqlValue::Text(VERIFIED.into()), SqlValue::Text(action.into())],
    )?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let [SqlValue::Int(seq)] = row.as_slice() else {
        return Err(corrupt("latest comparison shape"));
    };
    if *seq < 0 {
        return Err(corrupt("negative comparison sequence"));
    }
    let rows = store.query(
        "SELECT COUNT(*) FROM decision_receipts WHERE kind = ?1 AND subject = ?2",
        &[
            SqlValue::Text(INSTALL.into()),
            SqlValue::Text(format!("{action}:{seq}")),
        ],
    )?;
    match rows.as_slice() {
        [row] => match row.as_slice() {
            [SqlValue::Int(used)] if *used >= 0 => Ok(Some(*used as u64)),
            _ => Err(corrupt("install count shape")),
        },
        _ => Err(corrupt("ambiguous install count")),
    }
}

/// Live-class gate, called only AFTER class-wide negative evidence was checked
/// under this same lock. No cache-install permit is consumed here; the live
/// coordinator revalidates and spends its durable permit before output writes.
pub(super) fn refusal(
    store: &mut dyn RabsMetadataStore,
    action: &str,
) -> Result<Option<PrivateExecutionReason>, StoreError> {
    if mode() == Mode::Invalid {
        return Err(corrupt("invalid RABS_SPRT_SAMPLING setting"));
    }
    if !matches!(receipt(store, CLASS_KIND, action, 0)?, Some((class, _)) if class == CLASS) {
        return Ok(None);
    }
    // Positive policy state is coordinator-owned. Never checkpoint while the
    // store has no active authority, even though the caller normally checks it.
    if store.active_authority()?.is_none() {
        return Err(StoreError::NotActiveAuthority);
    }
    let checkpoint = advance(store)?;
    record_crossings(store, checkpoint)?;
    let used = used_since_comparison(store, action)?;
    if checkpoint.replay_limit() == 0 || used.is_none_or(|used| used >= checkpoint.replay_limit()) {
        return Ok(Some(PrivateExecutionReason::ClassVerificationRequired {
            class: CLASS.into(),
            credited_comparisons: checkpoint.passes,
            verification_basis_points: checkpoint.verification_bps(),
        }));
    }
    Ok(None)
}

impl super::SamplingPolicy {
    /// Evidence-qualified live replay ceiling, not an installation permit.
    ///
    /// `None` retains the caller's fixed policy when SPRT is explicitly off or
    /// the action has no live-class binding. `Some(0)` requires fresh execution;
    /// it MUST NOT fall back to the fixed allowance. With SPRT on, recheck the
    /// existing class, evidence and cadence gates and return 0/3/19/99 from the
    /// persisted, receipted checkpoint. Invalid configuration/state is an error.
    ///
    /// Hold the same exclusive metadata lock through this call, validation of
    /// the comparison/manifest binding, durable receipt spending and install.
    /// The caller must still enforce release qualification, TTL, output closure
    /// and destination ownership. No receipt is spent or reset by this method.
    ///
    /// # Errors
    /// [`StoreError`] for invalid configuration, unreadable evidence, malformed
    /// state or failed durable checkpoint/promotion writes.
    pub fn replay_install_limit(
        &self,
        store: &mut dyn RabsMetadataStore,
        action: &rabs_protocol::result_identity::TypedDigest,
    ) -> Result<Option<u64>, StoreError> {
        replay_limit_with_mode(store, action, self, mode())
    }
}

fn replay_limit_with_mode(
    store: &mut dyn RabsMetadataStore,
    action: &rabs_protocol::result_identity::TypedDigest,
    policy: &super::SamplingPolicy,
    selected: Mode,
) -> Result<Option<u64>, StoreError> {
    match selected {
        Mode::Fixed => return Ok(None),
        Mode::Invalid => return Err(corrupt("invalid RABS_SPRT_SAMPLING setting")),
        Mode::Sprt => {}
    }
    let key = crate::metadata_store::digest_key(action);
    match receipt(store, CLASS_KIND, &key, 0)? {
        None => return Ok(None),
        Some((class, _)) if class == CLASS => {}
        Some(_) => return Ok(Some(0)),
    }
    // Reuse the actual policy gate, never a second interpretation of its
    // evidence. In particular a checkpoint cannot overrule sibling divergence
    // or reset the spent receipts of the latest independent comparison.
    match super::decide(
        store,
        action,
        super::ActionClassRisk::LowRiskRegistry,
        policy,
        true,
    )? {
        super::SampleGateDecision::ExecutePrivately(_) => Ok(Some(0)),
        super::SampleGateDecision::ServeFromCache => {
            Ok(Some(Checkpoint::load(store)?.replay_limit()))
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod replay_budget_tests {
    use super::*;
    use crate::metadata_store::{RusqliteEngine, SqlMetadataStore};
    use crate::serving_sample_gate::SamplingPolicy;
    use crate::serving_sample_gate::tests::{action, published, samples};

    fn fixture(store: &mut dyn RabsMetadataStore) -> String {
        let key = published(store, 1, 10);
        store
            .record_decision_receipt(CLASS_KIND, &key, 0, CLASS, "synthetic descriptor binding")
            .unwrap();
        samples(store, 1, 10, 3, 0);
        store.record_attempt(20_001, 10, "verifier", 100).unwrap();
        store
            .record_verification_sample(&action(1), 20_001, true, 100)
            .unwrap();
        let manifest = store.published_manifest_key_str(&key).unwrap().unwrap();
        store
            .record_decision_receipt(VERIFIED, &key, 100, &format!("{:032x}", 20_001), &manifest)
            .unwrap();
        key
    }

    fn ceiling(
        store: &mut dyn RabsMetadataStore,
        selected: Mode,
    ) -> Result<Option<u64>, StoreError> {
        replay_limit_with_mode(
            store,
            &action(1),
            &SamplingPolicy::sample_all(2, 10_000),
            selected,
        )
    }

    #[test]
    fn replay_budget_configuration_is_explicit_and_invalid_never_means_fixed() {
        for value in [None, Some("0"), Some("false"), Some("off")] {
            assert_eq!(Mode::parse(value), Mode::Fixed);
        }
        for value in ["1", "true", "on"] {
            assert_eq!(Mode::parse(Some(value)), Mode::Sprt);
        }
        for value in ["", "yes", "TRUE", "01", " on", "on ", "-1"] {
            assert_eq!(Mode::parse(Some(value)), Mode::Invalid);
        }
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        let before = store.differential_snapshot().unwrap();
        assert_eq!(ceiling(&mut store, Mode::Fixed).unwrap(), None);
        assert!(ceiling(&mut store, Mode::Invalid).is_err());
        assert_eq!(store.differential_snapshot().unwrap(), before);
    }

    #[test]
    fn every_sprt_stage_controls_the_actual_replay_ceiling_without_spending_receipts() {
        for (stage, limit) in [(0, 0), (1, 3), (2, 19), (3, 99)] {
            let mut store =
                SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
            let key = fixture(&mut store);
            // Deliberately inject the checkpoint to isolate the consumer of a
            // qualified boundary. This is NOT evidence that trials were earned;
            // the reducer/attribution tests above exercise those independently.
            Checkpoint {
                cursor: FINAL_PASSES as i64,
                passes: stage * PASSES_PER_STEP,
            }
            .persist(&mut store)
            .unwrap();
            let manifest = store.published_manifest_key_str(&key).unwrap().unwrap();
            for used in 0..limit {
                assert_eq!(ceiling(&mut store, Mode::Sprt).unwrap(), Some(limit));
                assert_eq!(used_since_comparison(&mut store, &key).unwrap(), Some(used));
                // Switching off is a policy choice, NOT a receipt reset.
                assert_eq!(ceiling(&mut store, Mode::Fixed).unwrap(), None);
                assert_eq!(used_since_comparison(&mut store, &key).unwrap(), Some(used));
                store
                    .record_decision_receipt(
                        INSTALL,
                        &format!("{key}:100"),
                        used,
                        "install",
                        &manifest,
                    )
                    .unwrap();
            }
            assert_eq!(ceiling(&mut store, Mode::Sprt).unwrap(), Some(0));
            assert_eq!(
                used_since_comparison(&mut store, &key).unwrap(),
                Some(limit)
            );
            assert_eq!(
                store.published_manifest_key_str(&key).unwrap().as_deref(),
                Some(manifest.as_str())
            );
        }
    }

    #[test]
    fn advanced_checkpoint_cannot_override_class_safety_or_current_policy() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        fixture(&mut store);
        Checkpoint {
            cursor: FINAL_PASSES as i64,
            passes: FINAL_PASSES,
        }
        .persist(&mut store)
        .unwrap();
        assert_eq!(ceiling(&mut store, Mode::Sprt).unwrap(), Some(99));
        for policy in [
            SamplingPolicy::sample_all(100, 10_000),
            SamplingPolicy::sample_all(2, 10_001),
        ] {
            assert_eq!(
                replay_limit_with_mode(&mut store, &action(1), &policy, Mode::Sprt).unwrap(),
                Some(0)
            );
        }
        let sibling = published(&mut store, 2, 11);
        store
            .record_decision_receipt(CLASS_KIND, &sibling, 0, CLASS, "synthetic sibling")
            .unwrap();
        store
            .record_verification_sample(&action(2), 999_999, false, 1)
            .unwrap();
        let before = store.differential_snapshot().unwrap();
        assert_eq!(ceiling(&mut store, Mode::Sprt).unwrap(), Some(0));
        assert_eq!(store.differential_snapshot().unwrap(), before);
    }

    #[test]
    fn unbound_and_private_classes_cannot_borrow_a_promoted_dependency_ceiling() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        assert_eq!(ceiling(&mut store, Mode::Sprt).unwrap(), None);
        // Class bindings are immutable too: create a private action rather
        // than attempting to overwrite fixture()'s live dependency binding.
        let key = published(&mut store, 1, 10);
        store
            .record_decision_receipt(CLASS_KIND, &key, 0, "private-only", "not a dependency")
            .unwrap();
        Checkpoint {
            cursor: FINAL_PASSES as i64,
            passes: FINAL_PASSES,
        }
        .persist(&mut store)
        .unwrap();
        let before = store.differential_snapshot().unwrap();
        assert_eq!(ceiling(&mut store, Mode::Sprt).unwrap(), Some(0));
        assert_eq!(store.differential_snapshot().unwrap(), before);
    }

    #[test]
    fn malformed_checkpoint_or_conflicting_promotion_never_falls_back_to_fixed() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        fixture(&mut store);
        store
            .record_decision_receipt(STATE, CLASS, 0, "not-a-counter", "100")
            .unwrap();
        assert!(ceiling(&mut store, Mode::Sprt).is_err());
        // Corruption is not repaired by superseding its receipt. Exercise the
        // independent promotion-conflict case against a fresh, valid store.
        assert!(Checkpoint::default().persist(&mut store).is_err());
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        fixture(&mut store);
        Checkpoint {
            cursor: FINAL_PASSES as i64,
            passes: FINAL_PASSES,
        }
        .persist(&mut store)
        .unwrap();
        store
            .record_decision_receipt(PROMOTION, CLASS, 1, "verification-bps=0", "forged")
            .unwrap();
        assert!(ceiling(&mut store, Mode::Sprt).is_err());
    }

    #[test]
    fn empty_worker_identity_cannot_earn_positive_class_credit() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        let key = fixture(&mut store);
        store.record_attempt(20_002, 10, "", 101).unwrap();
        store
            .record_verification_sample(&action(1), 20_002, true, 101)
            .unwrap();
        let manifest = store.published_manifest_key_str(&key).unwrap().unwrap();
        store
            .record_decision_receipt(VERIFIED, &key, 101, &format!("{:032x}", 20_002), &manifest)
            .unwrap();
        assert!(
            !admitted(
                &mut store,
                &key,
                101,
                &format!("{:032x}", 20_002),
                &manifest
            )
            .unwrap()
        );
        assert!(
            admitted(
                &mut store,
                &key,
                100,
                &format!("{:032x}", 20_001),
                &manifest
            )
            .unwrap()
        );
    }
}
