//! # rabs-coord role — the ONE active fleet coordinator authority
//!
//! Owns (plan §10.8): the single active durable `CoordinatorAuthority`
//! (exclusive local lock + durably advanced term + fresh incarnation on
//! every start; V1 has NO automatic cross-host failover — disaster recovery
//! is operator-fenced); fleet-wide `DiscoveryActor` and `ActionActor`
//! registries (sharded by `ActionKey`, bounded mailboxes, isolated critical
//! queues — risk R130); action-key/policy validation; the metadata store and
//! action index; global scheduling, Cargo root permits, worker selection;
//! source/object availability planning; attempt leases and fencing;
//! **coordinator-only** action-result commit (I8/I9/I10 — workers offer,
//! the coordinator's compare-and-set transaction commits); operation
//! reconciliation; provenance, trust, explainability, GC policy, and
//! speculation.
//!
//! On term/incarnation change the coordinator closes or supersedes every
//! prior-authority active generation before issuing new publication-eligible
//! leases; prior-authority prepared candidates may contribute verified
//! immutable blobs and evidence but can never publish (risk R120).

pub mod target_lease;

pub mod live;
