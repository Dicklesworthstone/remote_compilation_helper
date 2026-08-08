//! # rabs-cas — durable CAS, action cache, and publication transactions
//!
//! Owns immutable blob/pack/chunk storage, the action-cache index, object
//! lifecycle, and the coordinator-only atomic publication transaction
//! (invariants I8/I10/I15/I33; Epic H beads H001–H041).
//!
//! Core commitments encoded here as they land:
//!
//! - streaming digest verification and atomic `put_if_absent` (private temp
//!   → verify → fsync per durability policy → atomic rename + directory
//!   fsync; no partial path ever published; same-digest/different-bytes is a
//!   collision **incident**, never a pick-one);
//! - logical object identity separate from stored representation
//!   (`StoredRepresentationId`; risk R81) — raw/zstd/packed encodings
//!   coexist without path ambiguity and never change action keys;
//! - deterministic small-object packs and content-defined chunk manifests,
//!   acyclic and bounded (risk R95);
//! - pins/leases with authority-scoped monotonic renewal — expiry never
//!   compares unsynchronized wall clocks (risk R127); workers can never
//!   release a publication root;
//! - mark → tombstone → grace → recheck → unlink GC that provably preserves
//!   pinned/reachable objects (risk R26/R58);
//! - scoped quarantine: location < logical object/manifest < action entry
//!   (risk R51);
//! - metadata-store abstraction: reference SQLite-compatible backend is the
//!   differential/crash truth; FrankenSQLite is dogfood, authoritative only
//!   after passing the identical suite (risk R59);
//! - large object bytes never enter the metadata database; the database
//!   never lives on NFS/shared mutable storage.
//!
//! ## Dependency rules (binding; enforced by dependency-direction CI, bead A002)
//!
//! - May depend on `rabs-protocol` (and, as Epic H lands, explicitly
//!   reviewed pure digest/compression/storage crates).
//! - **No Tokio, no Asupersync** in the core storage path; async adaptation
//!   happens in `rabs-asupersync`.
//! - Filesystem effects are this crate's business; network effects are not.

pub mod ancestor_selection;
pub mod ancestry_index;
pub mod authority_gate;
pub mod chunking;
pub mod closure_validation;
pub mod collision_policy;
pub mod dependency_snapshot;
pub mod gc;
pub mod link_bundle;
pub mod manifest_validation;
pub mod materialization;
pub mod metadata_store;
pub mod pin_leases;
pub mod publication;
pub mod serving_state;
pub mod startup_reconciliation;
pub mod tree_manifest;
pub mod trust_evidence;
