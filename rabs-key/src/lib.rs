//! # rabs-key — canonical semantic key construction and explainability
//!
//! Builds `ActionKey`s that are simultaneously **sound** (every semantically
//! relevant input included) and **stable** (no irrelevant instability):
//! goal G2 — the system never chooses between correctness and hit rate.
//!
//! Responsibilities (populated by Epic F beads F001–F035):
//!
//! - normalized invocation model, including full nested wrapper-chain
//!   decoding (`$RUSTC_WRAPPER $RUSTC_WORKSPACE_WRAPPER $RUSTC …`);
//! - separation of the full command-snapshot identity from the fine-grained
//!   minimal action-input closure (I3/I4; risk R41);
//! - positive and negative filesystem dependency normalization;
//! - exact presented-environment normalization (I21 — never inferred from
//!   `getenv` tracing);
//! - conservative dependency-artifact identity (I22) with versioned, gated
//!   projections;
//! - toolchain and output-platform contract hashing (I23 splits keyed
//!   output semantics from scheduler-only execution eligibility);
//! - sandbox and build-path semantic-policy hashing (I41);
//! - canonical compiler-event and presentation-variant keys (I24);
//! - `ActionKeyBreakdown` with every key, plus key diffing for `rch why`;
//! - versioned key/projection epochs — an epoch bump creates a cold
//!   namespace and never reinterprets old entries.
//!
//! V1 authoritative digests are SHA-256 over length-delimited canonical
//! bytes with typed algorithm + domain identifiers (e.g.
//! `"rabs.action-key.sha256.v1"`); raw 32-byte values from different domains
//! are never interchangeable (bead F034; risk R121).
//!
//! ## Dependency rules (binding; enforced by dependency-direction CI, bead A002)
//!
//! - May depend on `rabs-protocol` only (a pure digest crate may be added
//!   under explicit review when F034 lands).
//! - **Zero filesystem, network, or process effects**: callers supply all
//!   observed bytes; this crate only normalizes, serializes, and hashes.
//! - No Tokio, no Asupersync.

pub mod action_key;
pub mod authority_binding;
pub mod canonical;
pub mod dep_info;
pub mod dependency_identity;
pub mod dependency_projection;
pub mod environment;
pub mod epochs;
pub mod event_contracts;
pub mod extern_resolution;
pub mod family_key;
pub mod fragmentation;
pub mod hit_verification;
pub mod invocation;
pub mod key_diff;
pub mod logical_output_map;
pub mod output_declarations;
pub mod output_platform;
pub mod presentation;
pub mod projection_differential;
pub mod public_api_hash;
pub mod response_files;
pub mod toolchain;
pub mod typed_digest;
