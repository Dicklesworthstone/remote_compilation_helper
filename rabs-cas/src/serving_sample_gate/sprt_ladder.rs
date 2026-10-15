//! Opt-in, evidence-driven verification floors for the live dependency class.
//!
//! RABS_SPRT_SAMPLING=1 enables this ADDITIONAL gate. The existing per-action
//! evidence requirements and 16-install ceiling still apply; this module can
//! require more verification, never mint an installation or renew its budget.
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
// Only the production publication engine's receipt plus its exact sample and
// actual attempt/generation can earn credit. Raw samples and winner re-offers
// cannot. Membership is bound by submission, not by a request's risk flag.
const ATTRIBUTED_SQL: &str = r#"
SELECT a.id_hex FROM action_attempts AS a
JOIN action_generations AS g ON g.id_hex = a.generation_hex
JOIN verification_samples AS v ON v.attempt_hex = a.id_hex
JOIN action_publications AS p ON p.action_key = g.action_key
JOIN decision_receipts AS c ON c.subject = g.action_key
WHERE a.id_hex = ?1 AND g.action_key = ?2 AND v.action_key = ?2
AND v.seq = ?3 AND v.passed = 1 AND p.winner_attempt_hex != a.id_hex
AND c.kind = ?4 AND c.seq = 0 AND c.decision = ?5
LIMIT 1
"#;

pub(super) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        matches!(
            std::env::var("RABS_SPRT_SAMPLING").as_deref(),
            Ok("1" | "true" | "on")
        )
    })
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
    fn load(store: &mut dyn RabsMetadataStore) -> Result<Self, StoreError> {
        let Some((passes, cursor)) = receipt(store, STATE, CLASS, 0)? else {
            return Ok(Self::default());
        };
        let passes = number(&passes)?;
        let cursor = i64::try_from(number(&cursor)?).map_err(|_| corrupt("cursor overflow"))?;
        if passes > FINAL_PASSES || passes > cursor as u64 {
            return Err(corrupt("inconsistent checkpoint"));
        }
        Ok(Self { cursor, passes })
    }

    fn persist(self, store: &mut dyn RabsMetadataStore) -> Result<(), StoreError> {
        store.record_decision_receipt(
            STATE,
            CLASS,
            0,
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
        ] = fields else {
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
    // Do not rewrite the checkpoint forever just to scan our own checkpoint.
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
            None => store.record_decision_receipt(PROMOTION, CLASS, step as u64, decision, &reason)?,
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
        &[SqlValue::Text(INSTALL.into()), SqlValue::Text(format!("{action}:{seq}"))],
    )?;
    match rows.as_slice() {
        [row] => match row.as_slice() {
            [SqlValue::Int(used)] if *used >= 0 => Ok(Some(*used as u64)),
            _ => Err(corrupt("install count shape")),
        },
        _ => Err(corrupt("ambiguous install count")),
    }
}

/// Additional live-class gate, called only AFTER class-wide negative evidence
/// was checked under this same lock. Generic/legacy CAS clients are unchanged.
/// No cache-install permit is consumed here; the existing live coordinator
/// revalidates and spends its own durable permit before writing any output.
pub(super) fn refusal(
    store: &mut dyn RabsMetadataStore,
    action: &str,
) -> Result<Option<PrivateExecutionReason>, StoreError> {
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
    if checkpoint.replay_limit() == 0
        || used.is_none_or(|used| used >= checkpoint.replay_limit())
    {
        return Ok(Some(PrivateExecutionReason::ClassVerificationRequired {
            class: CLASS.into(),
            credited_comparisons: checkpoint.passes,
            verification_basis_points: checkpoint.verification_bps(),
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests;
