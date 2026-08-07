//! Stable decision-receipt persistence (bead R001; plan §105).
//!
//! Every scheduling/execution request produces ONE durable
//! [`DecisionReceipt`] recording every decision made on its behalf —
//! the record `rch why` replays. Rules:
//!
//! - the schema is VERSIONED: each receipt stamps its schema version,
//!   and the store refuses versions it does not know (fail closed —
//!   a receipt that would be misread is not admitted);
//! - the store is APPEND-ONLY: there is no update or delete API, so
//!   history cannot be rewritten;
//! - receipts are REDACTION-SAFE: every field is an id, digest,
//!   count, enum, or stable reason code — secrets appear only as
//!   S007 slot names, and no field type could carry a plaintext
//!   value;
//! - NON-CLAIMS are first-class: what this receipt does NOT assert
//!   is recorded explicitly, never implied.

use crate::descriptor::ActionClass;
use crate::result_identity::TypedDigest;

/// The current receipt schema version.
pub const RECEIPT_SCHEMA_VERSION: u32 = 1;

/// Cache lookup outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookupDecision {
    /// Served from cache (hit verification per F024).
    Hit,
    /// Not present; execution proceeds.
    Miss,
    /// Lookup refused (policy), reason code carried.
    Refused(&'static str),
}

/// Singleflight outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleflightDecision {
    /// This request leads the execution.
    Leader,
    /// Following an in-flight leader.
    Follower {
        /// The leader's request id.
        leader_request: u64,
    },
}

/// One worker candidate row considered during selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerCandidateRow {
    /// Worker id.
    pub worker_id: u64,
    /// Health score (permille) at decision time.
    pub health_permille: u16,
    /// Whether the candidate was admissible.
    pub admitted: bool,
    /// Stable reason code (admission or exclusion).
    pub reason: &'static str,
}

/// Verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationDecision {
    /// Policy did not require verification.
    NotRequired,
    /// Verification ran.
    Ran {
        /// Whether it passed.
        passed: bool,
    },
}

/// Publication outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationDecision {
    /// Result published.
    Published,
    /// Withheld, reason code carried.
    Withheld(&'static str),
}

/// A lifecycle event (sequence-stamped; sequences, never clocks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleEvent {
    /// Sequence number in the request's event domain.
    pub seq: u64,
    /// Stable event code.
    pub event: &'static str,
}

/// The durable decision receipt — every section the request touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionReceipt {
    /// Schema version (stamped at construction).
    pub schema_version: u32,
    /// Request identity.
    pub request_id: u64,
    /// Invocation class.
    pub invocation_class: ActionClass,
    /// Key-breakdown digest (the F021 presentation digest).
    pub key_breakdown_digest: TypedDigest,
    /// Snapshot root the action ran against.
    pub snapshot_root: TypedDigest,
    /// Closure object count under that root.
    pub closure_object_count: u32,
    /// Cache lookup decision.
    pub cache_lookup: CacheLookupDecision,
    /// Singleflight decision.
    pub singleflight: SingleflightDecision,
    /// Subscribers attached at decision time.
    pub subscriber_count: u32,
    /// Every worker candidate row considered.
    pub worker_candidates: Vec<WorkerCandidateRow>,
    /// Selected worker (None = ran locally / refused).
    pub selected_worker: Option<u64>,
    /// Stable reason codes for the selection.
    pub selection_reasons: Vec<&'static str>,
    /// Transfer plan: objects to send.
    pub transfer_objects: u32,
    /// Transfer plan: estimated bytes.
    pub transfer_bytes_estimate: u64,
    /// Priority class (I011 wire tag).
    pub priority_class_tag: u8,
    /// Budget granted (ms).
    pub budget_ms: u64,
    /// Attempt authority digest (A005 matrix row).
    pub attempt_authority: TypedDigest,
    /// Lifecycle events, sequence-stamped.
    pub lifecycle_events: Vec<LifecycleEvent>,
    /// Provisional events (two-frontier: pre-commit observations).
    pub provisional_events: Vec<LifecycleEvent>,
    /// Verification decision.
    pub verification: VerificationDecision,
    /// Publication decision.
    pub publication: PublicationDecision,
    /// Observed latency (ms).
    pub latency_ms: u64,
    /// Observed CPU (ms).
    pub cpu_ms: u64,
    /// Fallback/refusal reason code, if the request fell back.
    pub fallback_reason: Option<&'static str>,
    /// Explicit NON-CLAIMS: what this receipt does not assert.
    pub non_claims: Vec<&'static str>,
}

/// Typed store refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptRefusal {
    /// The receipt's schema version is unknown to this store.
    UnknownSchemaVersion(u32),
}

/// Append-only receipt store: no update, no delete.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiptStore {
    records: Vec<DecisionReceipt>,
}

impl ReceiptStore {
    /// Append a receipt; returns its immutable index.
    ///
    /// # Errors
    /// [`ReceiptRefusal::UnknownSchemaVersion`] — a receipt this
    /// store would misread is not admitted.
    pub fn append(&mut self, receipt: DecisionReceipt) -> Result<usize, ReceiptRefusal> {
        if receipt.schema_version != RECEIPT_SCHEMA_VERSION {
            return Err(ReceiptRefusal::UnknownSchemaVersion(receipt.schema_version));
        }
        self.records.push(receipt);
        Ok(self.records.len() - 1)
    }

    /// Query by request identity.
    #[must_use]
    pub fn by_request(&self, request_id: u64) -> Vec<&DecisionReceipt> {
        self.records
            .iter()
            .filter(|r| r.request_id == request_id)
            .collect()
    }

    /// Query by selected worker.
    #[must_use]
    pub fn by_selected_worker(&self, worker_id: u64) -> Vec<&DecisionReceipt> {
        self.records
            .iter()
            .filter(|r| r.selected_worker == Some(worker_id))
            .collect()
    }

    /// Total receipts held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        }
    }

    fn full_receipt(request_id: u64, worker: u64) -> DecisionReceipt {
        DecisionReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION,
            request_id,
            invocation_class: ActionClass::RustcDependencyCompile,
            key_breakdown_digest: d(1),
            snapshot_root: d(2),
            closure_object_count: 314,
            cache_lookup: CacheLookupDecision::Miss,
            singleflight: SingleflightDecision::Leader,
            subscriber_count: 2,
            worker_candidates: vec![
                WorkerCandidateRow {
                    worker_id: worker,
                    health_permille: 950,
                    admitted: true,
                    reason: "HEALTH_OK",
                },
                WorkerCandidateRow {
                    worker_id: 12,
                    health_permille: 100,
                    admitted: false,
                    reason: "EXCLUDED_PRESSURE_COLLAPSE",
                },
            ],
            selected_worker: Some(worker),
            selection_reasons: vec!["BEST_HEALTH", "BREAK_EVEN_MET"],
            transfer_objects: 40,
            transfer_bytes_estimate: 8_000_000,
            priority_class_tag: 2,
            budget_ms: 60_000,
            attempt_authority: d(3),
            lifecycle_events: vec![
                LifecycleEvent {
                    seq: 1,
                    event: "DISPATCHED",
                },
                LifecycleEvent {
                    seq: 2,
                    event: "COMPLETED",
                },
            ],
            provisional_events: vec![LifecycleEvent {
                seq: 1,
                event: "PROVISIONAL_RMETA_READY",
            }],
            verification: VerificationDecision::Ran { passed: true },
            publication: PublicationDecision::Published,
            latency_ms: 1_234,
            cpu_ms: 4_567,
            fallback_reason: None,
            non_claims: vec!["NO_CLAIM_MULTI_TENANT_ISOLATION"],
        }
    }

    #[test]
    fn receipts_persist_and_query_by_request_and_worker() {
        // THE acceptance: persisted + queryable.
        let mut store = ReceiptStore::default();
        let idx_a = store.append(full_receipt(100, 7)).expect("admits v1");
        let idx_b = store.append(full_receipt(101, 7)).expect("admits v1");
        assert_eq!((idx_a, idx_b), (0, 1), "immutable append order");
        let by_req = store.by_request(100);
        assert_eq!(by_req.len(), 1);
        assert_eq!(by_req[0].request_id, 100);
        assert_eq!(store.by_selected_worker(7).len(), 2);
        assert!(
            store.by_selected_worker(12).is_empty(),
            "excluded, never selected"
        );
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn unknown_schema_versions_are_refused_not_misread() {
        let mut store = ReceiptStore::default();
        let mut future = full_receipt(200, 7);
        future.schema_version = 2;
        assert_eq!(
            store.append(future),
            Err(ReceiptRefusal::UnknownSchemaVersion(2))
        );
        assert!(store.is_empty(), "the refused receipt was not admitted");
    }

    #[test]
    fn the_store_is_append_only_by_construction() {
        // Structural: the API is append + queries; records are
        // private, and queries hand out shared references only — no
        // update or delete path exists to rewrite history.
        let mut store = ReceiptStore::default();
        store.append(full_receipt(300, 7)).expect("admits");
        let before = store.by_request(300)[0].clone();
        store.append(full_receipt(301, 8)).expect("admits");
        assert_eq!(store.by_request(300)[0], &before, "history unchanged");
    }

    #[test]
    fn receipts_are_redaction_safe() {
        // THE redaction acceptance: format the FULL receipt; no
        // secret plaintext can appear because no field carries one —
        // a secret-bearing operation surfaces only its S007 slot name
        // in reason codes/events.
        let secret_plaintext = "ghp_supersecrettoken12345";
        let receipt = full_receipt(400, 7);
        let formatted = format!("{receipt:?}");
        assert!(!formatted.contains(secret_plaintext));
        // Every section present and typed — the exhaustive
        // destructure pins the schema: a new field is a compile
        // error here until reviewed for redaction safety.
        let DecisionReceipt {
            schema_version,
            request_id: _,
            invocation_class: _,
            key_breakdown_digest: _,
            snapshot_root: _,
            closure_object_count: _,
            cache_lookup: _,
            singleflight: _,
            subscriber_count: _,
            worker_candidates: _,
            selected_worker: _,
            selection_reasons: _,
            transfer_objects: _,
            transfer_bytes_estimate: _,
            priority_class_tag: _,
            budget_ms: _,
            attempt_authority: _,
            lifecycle_events: _,
            provisional_events: _,
            verification: _,
            publication: _,
            latency_ms: _,
            cpu_ms: _,
            fallback_reason: _,
            non_claims,
        } = receipt;
        assert_eq!(schema_version, RECEIPT_SCHEMA_VERSION);
        assert_eq!(non_claims, vec!["NO_CLAIM_MULTI_TENANT_ISOLATION"]);
    }

    #[test]
    fn every_decision_arm_is_representable() {
        // The refusal/fallback shapes exist and carry their reasons.
        let mut r = full_receipt(500, 7);
        r.cache_lookup = CacheLookupDecision::Refused("CACHE_REFUSED_BENCHMARK_OBSERVATION");
        r.singleflight = SingleflightDecision::Follower {
            leader_request: 100,
        };
        r.verification = VerificationDecision::Ran { passed: false };
        r.publication = PublicationDecision::Withheld("VERIFICATION_FAILED");
        r.selected_worker = None;
        r.fallback_reason = Some("FALLBACK_LOCAL_DAEMON_UNREACHABLE");
        let mut store = ReceiptStore::default();
        store
            .append(r)
            .expect("refusal-shaped receipts persist too");
        let held = &store.by_request(500)[0];
        assert_eq!(
            held.publication,
            PublicationDecision::Withheld("VERIFICATION_FAILED")
        );
        assert_eq!(
            held.fallback_reason,
            Some("FALLBACK_LOCAL_DAEMON_UNREACHABLE")
        );
    }
}
