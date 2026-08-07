//! `rch why` query engine — miss/rebuild/worker/volatile/slow (bead
//! R002; plan §105; explainability is a product pillar).
//!
//! Every answer is built from persisted structures (key breakdowns,
//! decision receipts, the DAG, observations) and carries STABLE
//! reason codes — never prose-only. The M0 contract implemented
//! here:
//!
//! - `why action KEY` — the raw component breakdown;
//! - `why miss` — the STRUCTURED BREAKDOWN DIFF: which of the twelve
//!   components changed between the request's key and the nearest
//!   cached candidate, by stable component name (the taxonomy), plus
//!   epoch mismatches;
//! - `why rebuild ARTIFACT` — the affected actions and serial tail
//!   (the R011 walk);
//! - `why worker` — the candidate table + selection reasons from the
//!   R001 receipt;
//! - `why volatile ACTION` — the first offending volatile access
//!   from the O003 observation;
//! - `why slow` — where the time went, classified against the
//!   receipt's own numbers.

use crate::action_dag::ActionDag;
use crate::action_key::ActionKeyBreakdown;
use crate::dag_browser::rebuild_tail;
use crate::test_observation::{ServingClass, TestObservation, VolatileAccess};
use rabs_protocol::decision_receipt::DecisionReceipt;
use rabs_protocol::result_identity::TypedDigest;

/// Stable reason codes.
pub const WHY_KEY_COMPONENT_CHANGED: &str = "WHY_KEY_COMPONENT_CHANGED";
/// Key-epoch mismatch.
pub const WHY_KEY_EPOCH_CHANGED: &str = "WHY_KEY_EPOCH_CHANGED";
/// Projection-epoch mismatch.
pub const WHY_PROJECTION_EPOCH_CHANGED: &str = "WHY_PROJECTION_EPOCH_CHANGED";
/// Volatile access made the result non-serveable.
pub const WHY_VOLATILE_ACCESS: &str = "WHY_VOLATILE_ACCESS";
/// The action is clean (no volatility).
pub const WHY_NOT_VOLATILE: &str = "WHY_NOT_VOLATILE";
/// Slow: transfer dominated.
pub const WHY_SLOW_TRANSFER_BOUND: &str = "WHY_SLOW_TRANSFER_BOUND";
/// Slow: execution dominated.
pub const WHY_SLOW_EXECUTION_BOUND: &str = "WHY_SLOW_EXECUTION_BOUND";
/// Slow: neither dominated — queue/scheduling overhead.
pub const WHY_SLOW_QUEUE_BOUND: &str = "WHY_SLOW_QUEUE_BOUND";

/// One line of a miss diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissDiffRow {
    /// Stable reason code.
    pub reason_code: &'static str,
    /// The component name (the stable taxonomy) or epoch field.
    pub component: &'static str,
}

/// `why miss`: the structured breakdown diff.
#[must_use]
pub fn why_miss(requested: &ActionKeyBreakdown, cached: &ActionKeyBreakdown) -> Vec<MissDiffRow> {
    let mut rows = Vec::new();
    if requested.key_epoch != cached.key_epoch {
        rows.push(MissDiffRow {
            reason_code: WHY_KEY_EPOCH_CHANGED,
            component: "key_epoch",
        });
    }
    if requested.projection_epoch != cached.projection_epoch {
        rows.push(MissDiffRow {
            reason_code: WHY_PROJECTION_EPOCH_CHANGED,
            component: "projection_epoch",
        });
    }
    for component in &requested.components {
        let cached_digest = cached
            .components
            .iter()
            .find(|c| c.name == component.name)
            .map(|c| &c.digest);
        if cached_digest != Some(&component.digest) {
            rows.push(MissDiffRow {
                reason_code: WHY_KEY_COMPONENT_CHANGED,
                component: component.name,
            });
        }
    }
    rows
}

/// `why action KEY`: the raw component rows (M0 fidelity).
#[must_use]
pub fn why_action(breakdown: &ActionKeyBreakdown) -> Vec<(&'static str, TypedDigest)> {
    breakdown
        .components
        .iter()
        .map(|c| (c.name, c.digest.clone()))
        .collect()
}

/// `why rebuild ARTIFACT`: affected actions + serial tail (R011).
#[must_use]
pub fn why_rebuild(dag: &ActionDag, artifact: &TypedDigest) -> (Vec<TypedDigest>, u64) {
    let tail = rebuild_tail(dag, artifact);
    (tail.affected, tail.tail_ms)
}

/// One worker-decision row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerWhyRow {
    /// The worker.
    pub worker_id: u64,
    /// Whether it was admitted.
    pub admitted: bool,
    /// The stable reason.
    pub reason: &'static str,
    /// Whether it was the one selected.
    pub selected: bool,
}

/// `why worker DECISION-ID`: the candidate table from the receipt.
#[must_use]
pub fn why_worker(receipt: &DecisionReceipt) -> Vec<WorkerWhyRow> {
    receipt
        .worker_candidates
        .iter()
        .map(|row| WorkerWhyRow {
            worker_id: row.worker_id,
            admitted: row.admitted,
            reason: row.reason,
            selected: receipt.selected_worker == Some(row.worker_id),
        })
        .collect()
}

/// `why volatile ACTION`: the offending access, or the clean answer.
#[must_use]
pub fn why_volatile(observation: &TestObservation) -> (&'static str, Option<VolatileAccess>) {
    match observation.serving_class() {
        ServingClass::Serveable => (WHY_NOT_VOLATILE, None),
        ServingClass::ObservationOnly(access) => (WHY_VOLATILE_ACCESS, Some(access)),
    }
}

/// `why slow BUILD-ID`: classify where the time went from the
/// receipt's own numbers (transfer estimate at ~10 MB/s floor,
/// execution = cpu_ms).
#[must_use]
pub fn why_slow(receipt: &DecisionReceipt) -> (&'static str, u64) {
    let transfer_ms = receipt.transfer_bytes_estimate / 10_000; // ~10MB/s
    let execution_ms = receipt.cpu_ms;
    let half = receipt.latency_ms / 2;
    if transfer_ms > half {
        (WHY_SLOW_TRANSFER_BOUND, transfer_ms)
    } else if execution_ms > half {
        (WHY_SLOW_EXECUTION_BOUND, execution_ms)
    } else {
        (
            WHY_SLOW_QUEUE_BOUND,
            receipt
                .latency_ms
                .saturating_sub(transfer_ms + execution_ms),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_key::BreakdownComponent;
    use rabs_protocol::decision_receipt::{
        CacheLookupDecision, PublicationDecision, SingleflightDecision, VerificationDecision,
        WorkerCandidateRow,
    };
    use rabs_protocol::descriptor::ActionClass;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        }
    }

    fn breakdown(toolchain: u8, environment: u8) -> ActionKeyBreakdown {
        ActionKeyBreakdown {
            key_epoch: 1,
            projection_epoch: 1,
            action_class_tag: 1,
            components: vec![
                BreakdownComponent {
                    name: "toolchain",
                    digest: d(toolchain),
                },
                BreakdownComponent {
                    name: "environment",
                    digest: d(environment),
                },
                BreakdownComponent {
                    name: "invocation",
                    digest: d(3),
                },
            ],
            final_key: d(9),
        }
    }

    #[test]
    fn why_miss_is_the_structured_breakdown_diff() {
        // THE miss acceptance: the diff names exactly the changed
        // components by their stable taxonomy names.
        let requested = breakdown(1, 2);
        let cached = breakdown(1, 8); // environment differs
        assert_eq!(
            why_miss(&requested, &cached),
            vec![MissDiffRow {
                reason_code: WHY_KEY_COMPONENT_CHANGED,
                component: "environment",
            }]
        );
        // Epoch mismatches surface as their own rows.
        let mut old_epoch = breakdown(1, 2);
        old_epoch.key_epoch = 0;
        let rows = why_miss(&breakdown(1, 2), &old_epoch);
        assert_eq!(rows[0].reason_code, WHY_KEY_EPOCH_CHANGED);
        // Identical breakdowns diff to nothing (a hit, not a miss).
        assert!(why_miss(&breakdown(1, 2), &breakdown(1, 2)).is_empty());
    }

    #[test]
    fn why_action_lists_the_raw_components() {
        let rows = why_action(&breakdown(1, 2));
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], ("toolchain", d(1)));
        assert_eq!(rows[1], ("environment", d(2)));
    }

    #[test]
    fn why_worker_renders_the_receipt_candidate_table() {
        let receipt = DecisionReceipt {
            schema_version: 1,
            request_id: 7,
            invocation_class: ActionClass::RustcDependencyCompile,
            key_breakdown_digest: d(1),
            snapshot_root: d(2),
            closure_object_count: 1,
            cache_lookup: CacheLookupDecision::Miss,
            singleflight: SingleflightDecision::Leader,
            subscriber_count: 1,
            worker_candidates: vec![
                WorkerCandidateRow {
                    worker_id: 5,
                    health_permille: 950,
                    admitted: true,
                    reason: "HEALTH_OK",
                },
                WorkerCandidateRow {
                    worker_id: 6,
                    health_permille: 100,
                    admitted: false,
                    reason: "EXCLUDED_PRESSURE_COLLAPSE",
                },
            ],
            selected_worker: Some(5),
            selection_reasons: vec!["BEST_HEALTH"],
            transfer_objects: 1,
            transfer_bytes_estimate: 0,
            priority_class_tag: 2,
            budget_ms: 1,
            attempt_authority: d(3),
            lifecycle_events: vec![],
            provisional_events: vec![],
            verification: VerificationDecision::NotRequired,
            publication: PublicationDecision::Published,
            latency_ms: 100,
            cpu_ms: 10,
            fallback_reason: None,
            non_claims: vec![],
        };
        assert_eq!(
            why_worker(&receipt),
            vec![
                WorkerWhyRow {
                    worker_id: 5,
                    admitted: true,
                    reason: "HEALTH_OK",
                    selected: true,
                },
                WorkerWhyRow {
                    worker_id: 6,
                    admitted: false,
                    reason: "EXCLUDED_PRESSURE_COLLAPSE",
                    selected: false,
                },
            ]
        );
        // why slow on the same receipt: nothing dominates — queue.
        assert_eq!(why_slow(&receipt).0, WHY_SLOW_QUEUE_BOUND);
        // Transfer-bound variant.
        let mut heavy = receipt.clone();
        heavy.transfer_bytes_estimate = 900_000; // ~90ms of 100ms
        assert_eq!(why_slow(&heavy), (WHY_SLOW_TRANSFER_BOUND, 90));
        // Execution-bound variant.
        let mut hot = receipt;
        hot.cpu_ms = 80;
        assert_eq!(why_slow(&hot), (WHY_SLOW_EXECUTION_BOUND, 80));
    }

    #[test]
    fn why_volatile_names_the_offending_access() {
        let mut obs = TestObservation::default();
        assert_eq!(why_volatile(&obs), (WHY_NOT_VOLATILE, None));
        obs.volatile.push(VolatileAccess::Network {
            endpoint: "api.example.com:443".into(),
        });
        let (code, access) = why_volatile(&obs);
        assert_eq!(code, WHY_VOLATILE_ACCESS);
        assert_eq!(
            access,
            Some(VolatileAccess::Network {
                endpoint: "api.example.com:443".into(),
            })
        );
    }

    #[test]
    fn why_rebuild_reuses_the_dag_walk() {
        use crate::action_dag::{ActionNode, EdgeFirmness};
        let key = |tag: u8| TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.action-key.sha256.v1",
            bytes: [tag; 32],
        };
        let dag = ActionDag {
            nodes: vec![
                ActionNode {
                    action_key: key(1),
                    consumes: vec![],
                    produces: vec![d(10)],
                    cost_ms: 400,
                },
                ActionNode {
                    action_key: key(2),
                    consumes: vec![(d(10), EdgeFirmness::Observed)],
                    produces: vec![],
                    cost_ms: 800,
                },
            ],
        };
        assert_eq!(why_rebuild(&dag, &d(10)), (vec![key(2)], 800));
    }
}
