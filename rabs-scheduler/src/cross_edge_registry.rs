//! Cross-edge demand convergence on the ONE coordinator registry
//! (bead I018; invariant I5; risk R44).
//!
//! Edges never host authoritative actors. Every edge submits its
//! final action keys to the single coordinator registry, and IDENTICAL
//! demands from different edges converge onto ONE actor — the
//! fleet-wide single-flight. Without this, each host daemon gives only
//! PER-HOST singleflight while the fleet claim is false (R44): two
//! edges demanding the same key would run two actors and duplicate the
//! whole pipeline.
//!
//! This module is the registry's pure decision core:
//!
//! - [`CrossEdgeRegistry::submit`] returns [`DemandOutcome`]:
//!   `ActorCreated` for the first demand of a key, `JoinedExistingActor`
//!   for every identical demand after — the saved-work counter is the
//!   dedup measurement, per submission, deterministic;
//! - an edge attempting to host a LOCAL authoritative actor for a key
//!   the coordinator already converges is a typed refusal
//!   ([`refuse_local_actor_claim`]) — that claim is exactly how the
//!   fleet-wide singleflight silently becomes per-host;
//! - replay discipline: identical submission sequences produce
//!   identical outcome sequences (the lib-level promise).

use std::collections::{BTreeSet, HashMap};

use rabs_protocol::result_identity::TypedDigest;

/// One converged actor entry: who demanded it first, and every edge
/// that has since joined.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ActorEntry {
    first_edge: String,
    joined_edges: BTreeSet<String>,
}

/// The cross-edge demand registry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrossEdgeRegistry {
    entries: HashMap<TypedDigest, ActorEntry>,
    /// Total submissions that JOINED an existing actor (the saved-work
    /// measurement: each one would have been a duplicate pipeline).
    saved_submissions: u64,
    /// Total submissions seen (denominator for the ratio).
    total_submissions: u64,
}

/// The outcome of one edge demand submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DemandOutcome {
    /// First demand for this key: THE coordinator actor was created.
    ActorCreated,
    /// An identical demand from another edge joined the EXISTING
    /// actor — no second pipeline was built.
    JoinedExistingActor {
        /// How many edges had already joined before this one.
        prior_joins: u64,
    },
}

/// A local-actor-claim refusal: hosting an authoritative actor on an
/// edge for a key the coordinator registry converges would split the
/// fleet-wide singleflight into per-host singleflights (I5/R44).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalClaimRefusal {
    /// The key whose single authority lives in the coordinator
    /// registry.
    pub key: TypedDigest,
}

impl CrossEdgeRegistry {
    /// Submit one edge's final demand for `key`.
    pub fn submit(&mut self, edge: &str, key: TypedDigest) -> DemandOutcome {
        self.total_submissions += 1;
        match self.entries.get_mut(&key) {
            None => {
                let mut joined = BTreeSet::new();
                joined.insert(edge.to_owned());
                self.entries.insert(
                    key,
                    ActorEntry {
                        first_edge: edge.to_owned(),
                        joined_edges: joined,
                    },
                );
                DemandOutcome::ActorCreated
            }
            Some(entry) => {
                let prior_joins = u64::try_from(entry.joined_edges.len()).unwrap_or(u64::MAX);
                entry.joined_edges.insert(edge.to_owned());
                self.saved_submissions += 1;
                DemandOutcome::JoinedExistingActor { prior_joins }
            }
        }
    }

    /// Distinct actors the coordinator hosts (one per distinct key —
    /// NEVER one per edge-demand).
    #[must_use]
    pub fn actor_count(&self) -> usize {
        self.entries.len()
    }

    /// Submissions that joined instead of duplicating (the saved-work
    /// measurement).
    #[must_use]
    pub fn saved_submissions(&self) -> u64 {
        self.saved_submissions
    }

    /// Total submissions (the ratio's denominator).
    #[must_use]
    pub fn total_submissions(&self) -> u64 {
        self.total_submissions
    }

    /// Saved-work share of all submissions: dedups / submissions as a
    /// rational pair (numerator, denominator) so callers cannot lose
    /// precision to floats. `(0, 0)` when nothing was submitted.
    #[must_use]
    pub fn saved_work_ratio(&self) -> (u64, u64) {
        (self.saved_submissions, self.total_submissions)
    }

    /// Every edge currently converged on `key`.
    #[must_use]
    pub fn edges_for(&self, key: &TypedDigest) -> Vec<&str> {
        match self.entries.get(key) {
            None => Vec::new(),
            Some(entry) => {
                let mut v: Vec<&str> = entry.joined_edges.iter().map(String::as_str).collect();
                v.sort_unstable();
                v
            }
        }
    }

    /// Whether the coordinator registry owns `key`.
    #[must_use]
    pub fn owns(&self, key: &TypedDigest) -> bool {
        self.entries.contains_key(key)
    }
}

/// Refuse an edge's attempt to host a LOCAL authoritative actor for a
/// key the coordinator registry already converges. All edges submit
/// final keys to THE registry; the local-hosting shortcut is the R44
/// failure mode in person.
///
/// # Errors
/// [`LocalClaimRefusal`] naming the owned key; `Ok(())` only for a
/// key the registry does not own (nothing to split — yet; the edge
/// should SUBMIT instead of hosting).
pub fn refuse_local_actor_claim(
    registry: &CrossEdgeRegistry,
    key: &TypedDigest,
) -> Result<(), LocalClaimRefusal> {
    if registry.owns(key) {
        return Err(LocalClaimRefusal { key: key.clone() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.action-key.sha256.v1",
            bytes: [tag; 32],
        }
    }

    use rabs_protocol::result_identity::DigestAlgorithm;

    #[test]
    fn cross_edge_identical_demands_join_one_actor() {
        // THE acceptance: three edges demand the SAME key. Exactly one
        // actor exists; the second and third JOINED it.
        let mut reg = CrossEdgeRegistry::default();
        assert_eq!(reg.submit("edge-a", key(1)), DemandOutcome::ActorCreated);
        assert_eq!(
            reg.submit("edge-b", key(1)),
            DemandOutcome::JoinedExistingActor { prior_joins: 1 }
        );
        assert_eq!(
            reg.submit("edge-c", key(1)),
            DemandOutcome::JoinedExistingActor { prior_joins: 2 }
        );
        assert_eq!(reg.actor_count(), 1, "one actor, not three");
        assert_eq!(
            reg.edges_for(&key(1)),
            vec!["edge-a", "edge-b", "edge-c"],
            "all three edges converged on the ONE actor"
        );
    }

    #[test]
    fn distinct_keys_create_distinct_actors() {
        let mut reg = CrossEdgeRegistry::default();
        assert_eq!(reg.submit("edge-a", key(1)), DemandOutcome::ActorCreated);
        assert_eq!(reg.submit("edge-a", key(2)), DemandOutcome::ActorCreated);
        assert_eq!(reg.actor_count(), 2);
        // Same edge re-submitting a key it created is still a JOIN of
        // the existing actor, not a second one.
        assert_eq!(
            reg.submit("edge-a", key(1)),
            DemandOutcome::JoinedExistingActor { prior_joins: 1 }
        );
        assert_eq!(reg.actor_count(), 2);
    }

    #[test]
    fn saved_work_is_measured_per_submission_with_exact_denominator() {
        // 5 submissions over 2 keys: 3 joins, 2 creations.
        let mut reg = CrossEdgeRegistry::default();
        reg.submit("e1", key(1));
        reg.submit("e2", key(1));
        reg.submit("e3", key(1));
        reg.submit("e1", key(2));
        reg.submit("e4", key(2));
        // Per-subscriber latency/work SAVING: each join skipped one
        // whole duplicate pipeline. Deterministic counters, exact
        // rational — 3/5 saved.
        assert_eq!(reg.saved_work_ratio(), (3, 5));
        assert_eq!(reg.saved_submissions(), 3);
        assert_eq!(reg.total_submissions(), 5);
        // Empty registry reports (0, 0), not a fake ratio.
        assert_eq!(CrossEdgeRegistry::default().saved_work_ratio(), (0, 0));
    }

    #[test]
    fn local_actor_claims_on_coordinator_keys_are_refused() {
        let mut reg = CrossEdgeRegistry::default();
        reg.submit("edge-a", key(7));
        // Edge-b tries to host its OWN actor for key 7: refused typed —
        // that is the R44 per-host-singleflight lie in person.
        assert_eq!(
            refuse_local_actor_claim(&reg, &key(7)),
            Err(LocalClaimRefusal { key: key(7) })
        );
        // A key nobody demanded yet: nothing to split, allowed — but
        // the honest move remains SUBMITTING it.
        assert!(refuse_local_actor_claim(&reg, &key(8)).is_ok());
    }

    #[test]
    fn identical_sequences_replay_identically() {
        // The lib-level promise: identical inputs → identical decision
        // sequences. Two registries fed the same script agree at every
        // step AND end equal.
        let script = [
            ("edge-a", 1u8),
            ("edge-b", 1),
            ("edge-b", 1),
            ("edge-c", 2),
            ("edge-a", 2),
        ];
        let mut a = CrossEdgeRegistry::default();
        let mut b = CrossEdgeRegistry::default();
        for (edge, tag) in script {
            assert_eq!(a.submit(edge, key(tag)), b.submit(edge, key(tag)));
        }
        assert_eq!(a, b);
    }

    #[test]
    fn i026_t052_sharded_registry_and_capacity_scenarios_hot_key_backpressure_flood_recovery() {
        // 1. Sharded registry by ActionKey with bounded per-actor mailboxes and isolated lanes.
        let config = ShardedCoordinatorConfig {
            shard_count: 8,
            max_actor_mailbox_depth: 4,
            max_serialized_writer_depth: 3,
            max_telemetry_bulk_depth: 5,
        };
        let mut sharded = ShardedCoordinatorRegistry::new(config).expect("valid sharded config");

        // Verify operation classification: ONLY generation-create, serving-mutate, and
        // publication-commit require serialized metadata sections. Slow subscribers,
        // inventory scans, audits, and dashboards stay OUTSIDE actor critical sections.
        for op in [
            CoordinatorOperationKind::GenerationCreate,
            CoordinatorOperationKind::ServingMutate,
            CoordinatorOperationKind::PublicationCommit,
        ] {
            assert_eq!(op.lane(), CoordinatorQueueLane::ActorMutation);
            assert!(op.requires_serialized_metadata_section());
        }
        for op in [
            CoordinatorOperationKind::AuthorityFencing,
            CoordinatorOperationKind::Cancellation,
            CoordinatorOperationKind::LeaseRenewal,
        ] {
            assert_eq!(op.lane(), CoordinatorQueueLane::CriticalControl);
            assert!(!op.requires_serialized_metadata_section());
        }
        for op in [
            CoordinatorOperationKind::LookupOrJoin,
            CoordinatorOperationKind::SlowSubscriberDelivery,
            CoordinatorOperationKind::InventoryScan,
            CoordinatorOperationKind::AuditScan,
            CoordinatorOperationKind::DashboardQuery,
        ] {
            assert_eq!(
                op.lane(),
                CoordinatorQueueLane::ReadOrFanoutOutsideCriticalSection
            );
            assert!(!op.requires_serialized_metadata_section());
        }

        // 2. Scenario A (T052): Hot-key contention across 15 agents vs cold keys on other shards.
        let hot_key = key(42);
        let cold_key = key(7);
        assert_ne!(
            sharded.shard_index_for(&hot_key),
            sharded.shard_index_for(&cold_key)
        );

        // First 4 hot-key submissions fill the actor's bounded mailbox (depth 4).
        for agent_idx in 0..4 {
            let agent = format!("agent-{agent_idx}");
            let res = sharded.submit_demand(&agent, hot_key.clone(), true);
            assert!(res.is_ok(), "submission {agent_idx} within mailbox bound");
        }
        // 5th hot-key submission while mailbox is full degrades to explicit
        // PreFrontierFallback (when pre-frontier) or ExplicitDefer (never a second coordinator!).
        assert_eq!(
            sharded.submit_demand("agent-4", hot_key.clone(), true),
            Err(OverloadDisposition::PreFrontierFallback {
                shard_index: sharded.shard_index_for(&hot_key),
                mailbox_depth: 4,
            })
        );
        assert_eq!(
            sharded.submit_demand("agent-5", hot_key.clone(), false),
            Err(OverloadDisposition::ExplicitDefer {
                reason: OverloadReason::ActorMailboxFull {
                    shard_index: sharded.shard_index_for(&hot_key),
                    mailbox_depth: 4,
                },
            })
        );
        // Meanwhile, cold_key on another shard is completely unaffected by hot_key's full mailbox!
        assert_eq!(
            sharded.submit_demand("agent-cold", cold_key.clone(), true),
            Ok(DemandOutcome::ActorCreated)
        );
        // Drain one message from hot_key's mailbox -> next join succeeds!
        sharded.complete_actor_mailbox_item(&hot_key);
        assert!(
            sharded
                .submit_demand("agent-6", hot_key.clone(), true)
                .is_ok()
        );

        // 3. Scenario B (T052): Metadata writer backpressure + slow subscriber + telemetry flood.
        // Saturate telemetry/bulk queue (max depth 5):
        for _ in 0..5 {
            assert!(
                sharded
                    .admit_operation(CoordinatorOperationKind::TelemetryIngestion, false)
                    .is_ok()
            );
        }
        assert_eq!(
            sharded.admit_operation(CoordinatorOperationKind::TelemetryIngestion, false),
            Err(OverloadDisposition::ExplicitRefuse {
                reason: OverloadReason::TelemetryOrBulkQueueFull { depth: 5 },
            })
        );

        // Saturate serialized metadata writer queue (max depth 3):
        for _ in 0..3 {
            assert!(
                sharded
                    .admit_operation(CoordinatorOperationKind::PublicationCommit, false)
                    .is_ok()
            );
        }
        assert_eq!(
            sharded.admit_operation(CoordinatorOperationKind::PublicationCommit, false),
            Err(OverloadDisposition::ExplicitDefer {
                reason: OverloadReason::SerializedWriterBackpressure { depth: 3 },
            })
        );

        // Even while BOTH telemetry and serialized writer queues are 100% saturated,
        // CriticalControl (AuthorityFencing, Cancellation, LeaseRenewal) and
        // ReadOrFanoutOutsideCriticalSection (SlowSubscriberDelivery, InventoryScan, RecoveryScan)
        // succeed without stalling!
        for critical_op in [
            CoordinatorOperationKind::AuthorityFencing,
            CoordinatorOperationKind::Cancellation,
            CoordinatorOperationKind::LeaseRenewal,
            CoordinatorOperationKind::SlowSubscriberDelivery,
            CoordinatorOperationKind::InventoryScan,
        ] {
            assert!(
                sharded.admit_operation(critical_op, false).is_ok(),
                "{critical_op:?} must not be blocked by telemetry flood or writer backpressure"
            );
        }

        // 4. Scenario C (I026/T052): Coordinator capacity release gate under 15-agent replay +
        //    burst + recovery scan.
        let gate_policy = CoordinatorCapacityGatePolicy::default_v1_release_gate();
        let passing_metrics = CoordinatorCapacityMetrics {
            agent_replay_sessions: 15,
            lookup_join_p99_us: 450,
            admission_p99_us: 1_200,
            publication_commit_p99_us: 4_500,
            critical_control_p99_us: 800,
            loop_lag_p99_us: 1_500,
            max_observed_actor_mailbox_depth: 32,
            max_observed_writer_queue_depth: 16,
            cpu_utilization_bps: 6_500,
            memory_rss_mib: 512,
            recovery_scan_duration_ms: 850,
        };
        let approval = evaluate_coordinator_capacity_gate(&gate_policy, &passing_metrics)
            .expect("15-agent replay within SLO passes release gate");
        assert_eq!(approval.agent_replay_sessions, 15);

        // Under-sampled replay (<15 agents) or breached recovery scan / commit latency fails gate:
        let under_sampled = CoordinatorCapacityMetrics {
            agent_replay_sessions: 8,
            ..passing_metrics
        };
        assert_eq!(
            evaluate_coordinator_capacity_gate(&gate_policy, &under_sampled),
            Err(
                CoordinatorCapacityGateRefusal::InsufficientAgentReplayCoverage {
                    observed_agents: 8,
                    required_agents: 15,
                }
            )
        );

        let slow_recovery = CoordinatorCapacityMetrics {
            recovery_scan_duration_ms: 15_000,
            ..passing_metrics
        };
        assert_eq!(
            evaluate_coordinator_capacity_gate(&gate_policy, &slow_recovery),
            Err(CoordinatorCapacityGateRefusal::RecoveryScanExceededBudget {
                observed_ms: 15_000,
                max_ms: gate_policy.max_recovery_scan_duration_ms,
            })
        );
    }
}

// ---------------------------------------------------------------------------
// I026 / T052: Sharded coordinator registries, bounded mailboxes, queue
// isolation, and coordinator capacity release gate (risk R130)
// ---------------------------------------------------------------------------

/// Isolated coordinator queue lanes (bead I026; risk R130).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorQueueLane {
    /// Authority fencing, cancellation, and lease renewals — isolated from
    /// bulk planning, telemetry, and writer backpressure.
    CriticalControl,
    /// Serialized metadata section: ONLY generation-create, serving-mutate,
    /// and publication-commit transactions enter this lane.
    ActorMutation,
    /// Lookups/joins, slow subscriber fanout, inventory scans, audits, and
    /// dashboard queries — executed outside actor critical sections.
    ReadOrFanoutOutsideCriticalSection,
    /// Telemetry ingestion and bulk planning — isolated and sheddable under
    /// flood so control and active actions never stall.
    TelemetryAndBulkPlanning,
}

/// Coordinator operations classified by queue lane and critical-section scope
/// (bead I026).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorOperationKind {
    /// Epoch/incarnation authority fencing.
    AuthorityFencing,
    /// Action or subscriber cancellation.
    Cancellation,
    /// Worker or edge lease renewal.
    LeaseRenewal,
    /// Creating a new execution generation (serializes in metadata store).
    GenerationCreate,
    /// Mutating serving eligibility / quarantine state (serializes in metadata store).
    ServingMutate,
    /// Committing a publication transaction (serializes in metadata store).
    PublicationCommit,
    /// ActionKey lookup or singleflight join.
    LookupOrJoin,
    /// Delivering events/frames to a slow subscriber outside actor lock.
    SlowSubscriberDelivery,
    /// CAS / worker inventory scan outside actor lock.
    InventoryScan,
    /// Trust/provenance audit scan outside actor lock.
    AuditScan,
    /// Operator dashboard snapshot query outside actor lock.
    DashboardQuery,
    /// Telemetry batch ingestion.
    TelemetryIngestion,
    /// Speculative or bulk placement planning.
    BulkPlanning,
}

impl CoordinatorOperationKind {
    /// Which isolated queue lane handles this operation.
    #[must_use]
    pub const fn lane(self) -> CoordinatorQueueLane {
        match self {
            Self::AuthorityFencing | Self::Cancellation | Self::LeaseRenewal => {
                CoordinatorQueueLane::CriticalControl
            }
            Self::GenerationCreate | Self::ServingMutate | Self::PublicationCommit => {
                CoordinatorQueueLane::ActorMutation
            }
            Self::LookupOrJoin
            | Self::SlowSubscriberDelivery
            | Self::InventoryScan
            | Self::AuditScan
            | Self::DashboardQuery => CoordinatorQueueLane::ReadOrFanoutOutsideCriticalSection,
            Self::TelemetryIngestion | Self::BulkPlanning => {
                CoordinatorQueueLane::TelemetryAndBulkPlanning
            }
        }
    }

    /// Whether this operation enters a serialized metadata transaction
    /// (I026: only generation-create, serving-mutate, and publication-commit).
    #[must_use]
    pub const fn requires_serialized_metadata_section(self) -> bool {
        matches!(
            self,
            Self::GenerationCreate | Self::ServingMutate | Self::PublicationCommit
        )
    }
}

/// Configuration for [`ShardedCoordinatorRegistry`] (bead I026).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardedCoordinatorConfig {
    /// Number of `ActionKey` registry shards (`>= 1`).
    pub shard_count: usize,
    /// Maximum queued messages in any single actor's mailbox.
    pub max_actor_mailbox_depth: usize,
    /// Maximum concurrent/queued serialized metadata writer transactions.
    pub max_serialized_writer_depth: usize,
    /// Maximum queued telemetry / bulk-planning items before shedding.
    pub max_telemetry_bulk_depth: usize,
}

/// Specific overload cause reported when a bounded mailbox or lane saturates
/// (beads I026, T052).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverloadReason {
    /// The target actor's bounded mailbox is full (hot-key contention).
    ActorMailboxFull {
        /// Shard hosting the hot key.
        shard_index: usize,
        /// Current mailbox depth.
        mailbox_depth: usize,
    },
    /// The serialized metadata writer queue is full (writer backpressure).
    SerializedWriterBackpressure {
        /// Current writer queue depth.
        depth: usize,
    },
    /// The telemetry/bulk planning queue is full (telemetry flood).
    TelemetryOrBulkQueueFull {
        /// Current telemetry/bulk queue depth.
        depth: usize,
    },
}

/// Bounded overload disposition (bead I026): overload degrades via explicit
/// defer, explicit refuse, or pre-frontier local fallback — NEVER by spawning
/// a second coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverloadDisposition {
    /// Caller should back off and retry after bounded delay.
    ExplicitDefer {
        /// Why the operation was deferred.
        reason: OverloadReason,
    },
    /// Operation is shed/refused immediately (e.g. non-critical telemetry flood).
    ExplicitRefuse {
        /// Why the operation was refused.
        reason: OverloadReason,
    },
    /// Edge wrapper is still pre-frontier and may fail open to local execution
    /// without violating single-coordinator authority.
    PreFrontierFallback {
        /// Shard whose actor mailbox was full.
        shard_index: usize,
        /// Mailbox depth at fallback decision.
        mailbox_depth: usize,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ShardState {
    registry: CrossEdgeRegistry,
    actor_mailbox_depths: HashMap<TypedDigest, usize>,
}

/// Sharded coordinator action/discovery registry with bounded per-actor
/// mailboxes and isolated control/writer/telemetry queues (beads I026, T052).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardedCoordinatorRegistry {
    config: ShardedCoordinatorConfig,
    shards: Vec<ShardState>,
    serialized_writer_depth: usize,
    telemetry_bulk_depth: usize,
    critical_control_processed: u64,
    outside_critical_section_processed: u64,
}

impl ShardedCoordinatorRegistry {
    /// Construct a sharded coordinator registry. Returns `None` if any bound is
    /// zero.
    #[must_use]
    pub fn new(config: ShardedCoordinatorConfig) -> Option<Self> {
        if config.shard_count == 0
            || config.max_actor_mailbox_depth == 0
            || config.max_serialized_writer_depth == 0
            || config.max_telemetry_bulk_depth == 0
        {
            return None;
        }
        Some(Self {
            config,
            shards: (0..config.shard_count)
                .map(|_| ShardState::default())
                .collect(),
            serialized_writer_depth: 0,
            telemetry_bulk_depth: 0,
            critical_control_processed: 0,
            outside_critical_section_processed: 0,
        })
    }

    /// Deterministic shard index for `key` derived from the first 8 bytes of
    /// `key.bytes`.
    #[must_use]
    pub fn shard_index_for(&self, key: &TypedDigest) -> usize {
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&key.bytes[..8]);
        let hash = u64::from_le_bytes(prefix);
        usize::try_from(hash % (self.config.shard_count as u64)).unwrap_or(0)
    }

    /// Submit a demand for `key` to its owning shard, enforcing the per-actor
    /// bounded mailbox.
    ///
    /// # Errors
    /// Returns [`OverloadDisposition::PreFrontierFallback`] (if `pre_frontier`
    /// is true) or [`OverloadDisposition::ExplicitDefer`] when the actor's
    /// mailbox is at `max_actor_mailbox_depth`.
    pub fn submit_demand(
        &mut self,
        edge: &str,
        key: TypedDigest,
        pre_frontier: bool,
    ) -> Result<DemandOutcome, OverloadDisposition> {
        let shard_index = self.shard_index_for(&key);
        let shard = &mut self.shards[shard_index];
        let depth = shard.actor_mailbox_depths.get(&key).copied().unwrap_or(0);
        if depth >= self.config.max_actor_mailbox_depth {
            return if pre_frontier {
                Err(OverloadDisposition::PreFrontierFallback {
                    shard_index,
                    mailbox_depth: depth,
                })
            } else {
                Err(OverloadDisposition::ExplicitDefer {
                    reason: OverloadReason::ActorMailboxFull {
                        shard_index,
                        mailbox_depth: depth,
                    },
                })
            };
        }
        shard.actor_mailbox_depths.insert(key.clone(), depth + 1);
        Ok(shard.registry.submit(edge, key))
    }

    /// Complete one queued item from `key`'s actor mailbox.
    pub fn complete_actor_mailbox_item(&mut self, key: &TypedDigest) {
        let shard_index = self.shard_index_for(key);
        if let Some(depth) = self.shards[shard_index].actor_mailbox_depths.get_mut(key) {
            *depth = depth.saturating_sub(1);
        }
    }

    /// Admit an operation into its isolated coordinator lane.
    ///
    /// # Errors
    /// Returns an [`OverloadDisposition`] when the operation's bounded queue is
    /// full. `CriticalControl` and `ReadOrFanoutOutsideCriticalSection` never
    /// block on `ActorMutation` or `TelemetryAndBulkPlanning`.
    pub fn admit_operation(
        &mut self,
        op: CoordinatorOperationKind,
        pre_frontier: bool,
    ) -> Result<CoordinatorQueueLane, OverloadDisposition> {
        let lane = op.lane();
        match lane {
            CoordinatorQueueLane::CriticalControl => {
                self.critical_control_processed += 1;
                Ok(lane)
            }
            CoordinatorQueueLane::ReadOrFanoutOutsideCriticalSection => {
                self.outside_critical_section_processed += 1;
                Ok(lane)
            }
            CoordinatorQueueLane::ActorMutation => {
                if self.serialized_writer_depth >= self.config.max_serialized_writer_depth {
                    let reason = OverloadReason::SerializedWriterBackpressure {
                        depth: self.serialized_writer_depth,
                    };
                    return if pre_frontier {
                        Err(OverloadDisposition::PreFrontierFallback {
                            shard_index: 0,
                            mailbox_depth: self.serialized_writer_depth,
                        })
                    } else {
                        Err(OverloadDisposition::ExplicitDefer { reason })
                    };
                }
                self.serialized_writer_depth += 1;
                Ok(lane)
            }
            CoordinatorQueueLane::TelemetryAndBulkPlanning => {
                if self.telemetry_bulk_depth >= self.config.max_telemetry_bulk_depth {
                    return Err(OverloadDisposition::ExplicitRefuse {
                        reason: OverloadReason::TelemetryOrBulkQueueFull {
                            depth: self.telemetry_bulk_depth,
                        },
                    });
                }
                self.telemetry_bulk_depth += 1;
                Ok(lane)
            }
        }
    }
}

/// Measured capacity metrics from a coordinator burst/storm/recovery benchmark
/// run (beads I026, T052; risk R130).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoordinatorCapacityMetrics {
    /// Number of concurrent agent replay sessions exercised (`>= 15` required).
    pub agent_replay_sessions: u32,
    /// p99 lookup/join latency in microseconds.
    pub lookup_join_p99_us: u64,
    /// p99 admission latency in microseconds.
    pub admission_p99_us: u64,
    /// p99 serialized publication-commit latency in microseconds.
    pub publication_commit_p99_us: u64,
    /// p99 authority/cancellation/lease-renewal latency in microseconds.
    pub critical_control_p99_us: u64,
    /// p99 runtime event-loop lag in microseconds.
    pub loop_lag_p99_us: u64,
    /// Peak observed per-actor mailbox depth.
    pub max_observed_actor_mailbox_depth: usize,
    /// Peak observed serialized metadata writer queue depth.
    pub max_observed_writer_queue_depth: usize,
    /// Peak coordinator CPU utilization in basis points (`0..=10_000`).
    pub cpu_utilization_bps: u16,
    /// Peak coordinator resident memory in MiB.
    pub memory_rss_mib: u64,
    /// Recovery scan duration in milliseconds.
    pub recovery_scan_duration_ms: u64,
}

/// Release-gate thresholds for coordinator capacity (beads I026, T052).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoordinatorCapacityGatePolicy {
    /// Minimum concurrent agent replay sessions required (`15` per I026).
    pub min_agent_replay_sessions: u32,
    /// Maximum allowed lookup/join p99 latency in microseconds.
    pub max_lookup_join_p99_us: u64,
    /// Maximum allowed admission p99 latency in microseconds.
    pub max_admission_p99_us: u64,
    /// Maximum allowed publication-commit p99 latency in microseconds.
    pub max_publication_commit_p99_us: u64,
    /// Maximum allowed critical-control p99 latency in microseconds.
    pub max_critical_control_p99_us: u64,
    /// Maximum allowed event-loop lag p99 in microseconds.
    pub max_loop_lag_p99_us: u64,
    /// Maximum allowed actor mailbox depth.
    pub max_actor_mailbox_depth: usize,
    /// Maximum allowed serialized writer queue depth.
    pub max_writer_queue_depth: usize,
    /// Maximum allowed CPU utilization in basis points.
    pub max_cpu_utilization_bps: u16,
    /// Maximum allowed memory RSS in MiB.
    pub max_memory_rss_mib: u64,
    /// Maximum allowed recovery scan duration in milliseconds.
    pub max_recovery_scan_duration_ms: u64,
}

impl CoordinatorCapacityGatePolicy {
    /// Canonical V1 release-gate thresholds under 15-agent replay + burst +
    /// long-lived sessions (bead I026).
    #[must_use]
    pub const fn default_v1_release_gate() -> Self {
        Self {
            min_agent_replay_sessions: 15,
            max_lookup_join_p99_us: 2_000,
            max_admission_p99_us: 5_000,
            max_publication_commit_p99_us: 15_000,
            max_critical_control_p99_us: 2_500,
            max_loop_lag_p99_us: 5_000,
            max_actor_mailbox_depth: 64,
            max_writer_queue_depth: 32,
            max_cpu_utilization_bps: 8_500,
            max_memory_rss_mib: 1_024,
            max_recovery_scan_duration_ms: 2_000,
        }
    }
}

/// Typed release-gate refusal when coordinator capacity metrics breach SLO
/// thresholds (beads I026, T052).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorCapacityGateRefusal {
    /// Replay benchmark ran fewer than the required 15 agent sessions.
    InsufficientAgentReplayCoverage {
        /// Observed agent replay sessions.
        observed_agents: u32,
        /// Required agent replay sessions.
        required_agents: u32,
    },
    /// Lookup/join p99 latency exceeded budget.
    LookupJoinLatencyExceeded {
        /// Observed microseconds.
        observed_us: u64,
        /// Maximum microseconds.
        max_us: u64,
    },
    /// Admission p99 latency exceeded budget.
    AdmissionLatencyExceeded {
        /// Observed microseconds.
        observed_us: u64,
        /// Maximum microseconds.
        max_us: u64,
    },
    /// Serialized publication-commit p99 latency exceeded budget.
    PublicationCommitLatencyExceeded {
        /// Observed microseconds.
        observed_us: u64,
        /// Maximum microseconds.
        max_us: u64,
    },
    /// Authority/cancellation/lease-renewal p99 latency exceeded budget.
    CriticalControlLatencyExceeded {
        /// Observed microseconds.
        observed_us: u64,
        /// Maximum microseconds.
        max_us: u64,
    },
    /// Runtime loop lag p99 exceeded budget.
    LoopLagExceeded {
        /// Observed microseconds.
        observed_us: u64,
        /// Maximum microseconds.
        max_us: u64,
    },
    /// Per-actor mailbox or writer queue depth exceeded bound.
    QueueDepthExceeded {
        /// Observedactor mailbox depth.
        observed_actor_depth: usize,
        /// Observed writer queue depth.
        observed_writer_depth: usize,
    },
    /// CPU or memory footprint exceeded budget.
    ResourceFootprintExceeded {
        /// Observed CPU bps.
        observed_cpu_bps: u16,
        /// Observed RSS MiB.
        observed_memory_mib: u64,
    },
    /// Startup/reconnect recovery scan exceeded budget.
    RecoveryScanExceededBudget {
        /// Observed milliseconds.
        observed_ms: u64,
        /// Maximum milliseconds.
        max_ms: u64,
    },
}

/// Proof that the coordinator capacity release gate passed (beads I026, T052).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoordinatorCapacityApproval {
    /// Number of concurrent agent replay sessions verified.
    pub agent_replay_sessions: u32,
    /// Verified lookup/join p99 latency in microseconds.
    pub lookup_join_p99_us: u64,
    /// Verified publication-commit p99 latency in microseconds.
    pub publication_commit_p99_us: u64,
    /// Verified recovery scan duration in milliseconds.
    pub recovery_scan_duration_ms: u64,
}

/// Evaluate measured coordinator capacity metrics against the release-gate
/// policy (beads I026, T052).
///
/// # Errors
/// Returns [`CoordinatorCapacityGateRefusal`] naming the first violated
/// threshold.
pub const fn evaluate_coordinator_capacity_gate(
    policy: &CoordinatorCapacityGatePolicy,
    metrics: &CoordinatorCapacityMetrics,
) -> Result<CoordinatorCapacityApproval, CoordinatorCapacityGateRefusal> {
    if metrics.agent_replay_sessions < policy.min_agent_replay_sessions {
        return Err(
            CoordinatorCapacityGateRefusal::InsufficientAgentReplayCoverage {
                observed_agents: metrics.agent_replay_sessions,
                required_agents: policy.min_agent_replay_sessions,
            },
        );
    }
    if metrics.lookup_join_p99_us > policy.max_lookup_join_p99_us {
        return Err(CoordinatorCapacityGateRefusal::LookupJoinLatencyExceeded {
            observed_us: metrics.lookup_join_p99_us,
            max_us: policy.max_lookup_join_p99_us,
        });
    }
    if metrics.admission_p99_us > policy.max_admission_p99_us {
        return Err(CoordinatorCapacityGateRefusal::AdmissionLatencyExceeded {
            observed_us: metrics.admission_p99_us,
            max_us: policy.max_admission_p99_us,
        });
    }
    if metrics.publication_commit_p99_us > policy.max_publication_commit_p99_us {
        return Err(
            CoordinatorCapacityGateRefusal::PublicationCommitLatencyExceeded {
                observed_us: metrics.publication_commit_p99_us,
                max_us: policy.max_publication_commit_p99_us,
            },
        );
    }
    if metrics.critical_control_p99_us > policy.max_critical_control_p99_us {
        return Err(
            CoordinatorCapacityGateRefusal::CriticalControlLatencyExceeded {
                observed_us: metrics.critical_control_p99_us,
                max_us: policy.max_critical_control_p99_us,
            },
        );
    }
    if metrics.loop_lag_p99_us > policy.max_loop_lag_p99_us {
        return Err(CoordinatorCapacityGateRefusal::LoopLagExceeded {
            observed_us: metrics.loop_lag_p99_us,
            max_us: policy.max_loop_lag_p99_us,
        });
    }
    if metrics.max_observed_actor_mailbox_depth > policy.max_actor_mailbox_depth
        || metrics.max_observed_writer_queue_depth > policy.max_writer_queue_depth
    {
        return Err(CoordinatorCapacityGateRefusal::QueueDepthExceeded {
            observed_actor_depth: metrics.max_observed_actor_mailbox_depth,
            observed_writer_depth: metrics.max_observed_writer_queue_depth,
        });
    }
    if metrics.cpu_utilization_bps > policy.max_cpu_utilization_bps
        || metrics.memory_rss_mib > policy.max_memory_rss_mib
    {
        return Err(CoordinatorCapacityGateRefusal::ResourceFootprintExceeded {
            observed_cpu_bps: metrics.cpu_utilization_bps,
            observed_memory_mib: metrics.memory_rss_mib,
        });
    }
    if metrics.recovery_scan_duration_ms > policy.max_recovery_scan_duration_ms {
        return Err(CoordinatorCapacityGateRefusal::RecoveryScanExceededBudget {
            observed_ms: metrics.recovery_scan_duration_ms,
            max_ms: policy.max_recovery_scan_duration_ms,
        });
    }
    Ok(CoordinatorCapacityApproval {
        agent_replay_sessions: metrics.agent_replay_sessions,
        lookup_join_p99_us: metrics.lookup_join_p99_us,
        publication_commit_p99_us: metrics.publication_commit_p99_us,
        recovery_scan_duration_ms: metrics.recovery_scan_duration_ms,
    })
}
