//! # rabs-edge role — per client/developer host
//!
//! Owns (plan §10.8): the local wrapper Unix-socket endpoint; the
//! daemon-dead circuit breaker and safe **nonpublishing** local fallback
//! (permitted only before that subscriber's transcript exposure and
//! stateful commit intent — invariants I11/I43/I46); canonical Cargo-driver
//! launch; coherent source snapshot + path-dependency capture (I2);
//! edge-local object cache and upload; virtual-to-requesting-worktree path
//! translation; target-tree materialization under the per-operation
//! destination arbiter (I45); subscriber connection lifecycle with the
//! two-frontier delivery state machine; reconnect to the coordinator.
//!
//! The edge **never** independently leases workers or commits shared
//! actions (I5): it is a subscriber proxy. Edge restarts advance a durable
//! boot generation + fresh incarnation ID; exactly one incarnation owns
//! subscriber/materialization rights per boot generation outside an
//! explicit bounded handoff (risk R118).

pub mod diagnostic_rewrite;
