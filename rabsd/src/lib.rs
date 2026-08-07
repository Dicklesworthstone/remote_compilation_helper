//! # rabsd — the RABS edge + coordinator daemon
//!
//! The initial deployment ships `rabs-edge` and `rabs-coord` in this one
//! binary, but their **authority, durable state, and protocol interfaces
//! remain distinct from the beginning** (plan Part I §1). The role split is
//! structural: [`edge`] and [`coord`] are separate modules with separate
//! state, and the RABS/ATP application protocol between them exists even
//! in-process, so splitting into two binaries later is a deployment change,
//! not a redesign.
//!
//! Role authority is deliberately asymmetric:
//! - the **edge** owns the sub-10 ms wrapper path and safe local fallback;
//! - the **coordinator** alone owns fleet-wide singleflight, leases,
//!   scheduling decisions, and committed action-result pointers (I5/I10);
//! - workers (`rabs-wkr`) prepare and offer results but never commit.

pub mod coord;
pub mod edge;
