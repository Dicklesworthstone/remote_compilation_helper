//! Incremental recovery of previous-incarnation compiler capture pins.
//!
//! Called by CapturePins::drop after the ordinary handoff, under the SAME
//! exclusively mounted CAS metadata lock. Boot already fences previous action
//! generations. Each call examines at most one page; a durable cursor in the
//! existing receipt ledger resumes the next page without OFFSET/release skips.
//! The cursor is scoped to the full current coordinator authority. Completion
//! stops rescanning this boot's history: an old process cannot add more pins
//! after the exclusive mount fenced it. A fresh boot starts its own scan.
//!
//! Checkpoints FOLLOW releases. Interruption can repeat a read, never skip an
//! unconfirmed release. Neither elapsed time nor an execution-lease deadline is
//! abandonment proof. Legacy, malformed, unknown and contradictory witnesses
//! retain their roots. This module never deletes files, locations or evidence.

use super::super::CAPTURE_PIN_CLASS;
use super::CaptureEvidence;
use rabs_cas::metadata_store::{RabsMetadataStore, SqlValue, StoreError, digest_key};
use rabs_cas::pin_leases::{ReleaseOutcome, Releaser, release_pin_scoped};
use rabs_cas::publication::authority_digest;
use rabs_protocol::authority::CoordinatorAuthority;

const PAGE_SIZE: usize = 32;
const CURSOR_KIND: &str = "rabs-capture-recovery-cursor-v1";

// Bound witness payloads at SQL projection, BEFORE allocating/deserializing
// them in Rust. An oversized historical witness is retained, not executed.
const SCAN_SQL: &str = "SELECT id_hex, owner, root_key, \
    CASE WHEN length(evidence) <= 8192 THEN evidence ELSE NULL END, id FROM pins \
    WHERE released = 0 AND class = ?1 AND id_hex > ?2 \
    AND durable = 1 AND expires_at_seq IS NULL AND renewal_seq = 0 \
    ORDER BY id_hex LIMIT 32";

const CURSOR_SQL: &str = "SELECT seq, decision, \
    CASE WHEN length(reason) <= 32 THEN reason ELSE NULL END \
    FROM decision_receipts WHERE kind = ?1 AND subject = ?2 \
    ORDER BY seq DESC LIMIT 1";

// Require both directions of the normalized attempt/lease link. Missing legacy
// NULL bindings, reused numeric IDs and stale/mismatched workers cannot pass.
const FENCED_SQL: &str = "SELECT 1 FROM coordinator_authorities c \
    JOIN action_generations g ON g.authority_key = c.key \
    JOIN action_attempts a ON a.generation_hex = g.id_hex \
    JOIN execution_leases l ON l.attempt_hex = a.id_hex \
        AND l.id_hex = a.execution_lease_hex \
    WHERE c.key = ?1 AND c.cluster_id = ?2 AND c.incarnation = ?3 \
        AND c.term = ?4 AND c.released = 1 \
        AND g.id_hex = ?5 AND g.id = ?6 AND g.action_key = ?7 \
        AND g.tombstoned = 1 AND g.per_key_ordinal = ?8 \
        AND a.id_hex = ?9 AND a.id = ?10 AND a.worker = ?11 \
        AND a.worker_boot_generation = ?12 AND a.worker_incarnation = ?13 \
        AND a.execution_lease_hex = ?14 AND l.id_hex = ?14 AND l.id = ?15 \
        AND l.renewal_seq >= ?16 AND c.algo = 'sha256-v1' \
        AND c.domain = ?17 AND c.bytes = ?18";

fn corrupt(detail: &str) -> StoreError {
    StoreError::Corruption(format!("capture recovery {detail}"))
}

fn canonical_id(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl CaptureEvidence {
    fn key(domain: &str, digest: &[u8; 32]) -> String {
        use std::fmt::Write;
        let mut key = format!("{domain}:");
        for byte in digest {
            let _ = write!(key, "{byte:02x}");
        }
        key
    }

    fn fenced(&self, store: &mut dyn RabsMetadataStore) -> Result<bool, StoreError> {
        let (Ok(term), Ok(renewal)) = (i64::try_from(self.term), i64::try_from(self.renewal))
        else {
            return Ok(false);
        };
        let authority = authority_digest(&self.coordinator());
        let rows = store.query(
            FENCED_SQL,
            &[
                SqlValue::Text(digest_key(&authority)),
                SqlValue::Text(self.cluster.clone()),
                SqlValue::Blob(self.coordinator_incarnation.to_be_bytes().to_vec()),
                SqlValue::Int(term),
                SqlValue::Text(format!("{:032x}", self.generation)),
                SqlValue::Blob(self.generation.to_be_bytes().to_vec()),
                SqlValue::Text(Self::key(&self.action_domain, &self.action_bytes)),
                SqlValue::Blob(self.ordinal.to_be_bytes().to_vec()),
                SqlValue::Text(format!("{:032x}", self.attempt)),
                SqlValue::Blob(self.attempt.to_be_bytes().to_vec()),
                SqlValue::Text(self.worker.clone()),
                SqlValue::Blob(self.worker_boot.to_be_bytes().to_vec()),
                SqlValue::Blob(self.worker_incarnation.to_be_bytes().to_vec()),
                SqlValue::Text(format!("{:032x}", self.lease)),
                SqlValue::Blob(self.lease.to_be_bytes().to_vec()),
                SqlValue::Int(renewal),
                SqlValue::Text(authority.domain.to_owned()),
                SqlValue::Blob(authority.bytes.to_vec()),
            ],
        )?;
        match rows.as_slice() {
            [] => Ok(false),
            [row] if matches!(row.as_slice(), [SqlValue::Int(1)]) => Ok(true),
            _ => Err(corrupt("binding shape")),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RecoveryPage {
    pub(crate) scanned: usize,
    pub(crate) released: usize,
    pub(crate) complete: bool,
}

/// One page under the caller's exclusive mount and metadata lock. This is
/// metadata custody recovery, NOT a permission to serve or a GC unlink plan.
/// SQL work is row-bounded; a single backend transaction may still block on I/O.
pub(crate) fn reconcile_page(
    store: &mut dyn RabsMetadataStore,
    active: &CoordinatorAuthority,
) -> Result<RecoveryPage, StoreError> {
    let digest = authority_digest(active);
    store.intern_domain(digest.domain);
    let Some(held) = store.active_authority()? else {
        return Err(StoreError::NotActiveAuthority);
    };
    if held.digest != digest
        || held.cluster_id != active.cluster_id.0
        || held.incarnation != active.incarnation_id.0
        || held.term != active.term
    {
        return Err(StoreError::NotActiveAuthority);
    }
    let subject = digest_key(&digest);
    let cursor = store.query(
        CURSOR_SQL,
        &[
            SqlValue::Text(CURSOR_KIND.to_owned()),
            SqlValue::Text(subject.clone()),
        ],
    )?;
    let (seq, mut after) = match cursor.as_slice() {
        [] => (1, String::new()),
        [row] => {
            let [
                SqlValue::Int(seq),
                SqlValue::Text(state),
                SqlValue::Text(after),
            ] = row.as_slice()
            else {
                return Err(corrupt("cursor shape"));
            };
            if *seq <= 0 || (!after.is_empty() && !canonical_id(after)) {
                return Err(corrupt("cursor identity"));
            }
            if state == "complete" {
                return Ok(RecoveryPage {
                    complete: true,
                    ..RecoveryPage::default()
                });
            }
            if state != "pending" || after.is_empty() {
                return Err(corrupt("cursor state"));
            }
            let next = seq
                .checked_add(1)
                .ok_or_else(|| corrupt("cursor exhausted"))?;
            (next as u64, after.clone())
        }
        _ => return Err(corrupt("cursor row count")),
    };
    let rows = store.query(
        SCAN_SQL,
        &[
            SqlValue::Text(CAPTURE_PIN_CLASS.to_owned()),
            SqlValue::Text(after.clone()),
        ],
    )?;
    if rows.len() > PAGE_SIZE {
        return Err(corrupt("page bound"));
    }
    let mut page = RecoveryPage {
        scanned: rows.len(),
        released: 0,
        complete: rows.len() < PAGE_SIZE,
    };
    let releaser = Releaser::Coordinator(active.clone());
    for row in rows {
        let [
            SqlValue::Text(id_hex),
            SqlValue::Text(owner),
            SqlValue::Text(root),
            encoded,
            raw_id,
        ] = row.as_slice()
        else {
            return Err(corrupt("pin shape"));
        };
        if !canonical_id(id_hex) || id_hex <= &after {
            return Err(corrupt("pin ordering"));
        }
        after.clone_from(id_hex);
        let SqlValue::Text(encoded) = encoded else {
            continue;
        };
        // SQLite length(TEXT) counts characters, not UTF-8 bytes; retain the
        // byte check too. No Value intermediary may round full-width u128 IDs.
        if encoded.len() > super::MAX_EVIDENCE_BYTES {
            continue;
        }
        let Ok(witness) = serde_json::from_str::<CaptureEvidence>(encoded) else {
            continue;
        };
        if witness.version != super::EVIDENCE_VERSION
            || witness.cluster != active.cluster_id.0
            || authority_digest(&witness.coordinator()) == digest
            || witness.owner() != *owner
            || CaptureEvidence::key(&witness.root_domain, &witness.root_bytes) != *root
        {
            continue;
        }
        let id = witness.pin_id(owner);
        if format!("{id:032x}") != *id_hex
            || !matches!(raw_id, SqlValue::Blob(bytes) if bytes.as_slice() == id.to_be_bytes())
            || !witness.fenced(store)?
        {
            continue;
        }
        match release_pin_scoped(store, id, &releaser)? {
            ReleaseOutcome::Released => page.released += 1,
            ReleaseOutcome::AlreadyReleased => {}
            _ => return Err(corrupt("scoped release refused")),
        }
    }
    // Append only after every confirmed release. A failed checkpoint leaves
    // the old cursor: retries simply exclude already-released rows. Completed
    // scans write no more receipts until a new coordinator authority starts.
    store.record_decision_receipt(
        CURSOR_KIND,
        &subject,
        seq,
        if page.complete { "complete" } else { "pending" },
        &after,
    )?;
    Ok(page)
}

#[cfg(test)]
mod tests;
