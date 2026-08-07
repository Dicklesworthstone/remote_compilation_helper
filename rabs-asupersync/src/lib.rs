//! # rabs-asupersync — the sole RABS ↔ Asupersync/ATP adapter
//!
//! The ONLY broad adapter between RABS domain types and Asupersync/ATP
//! implementation types (plan §10.7). Everything runtime-shaped funnels
//! through here so the rest of RABS stays runtime-agnostic and lab-testable.
//!
//! Responsibilities (Epic G and Epic J beads):
//!
//! - `Cx`/region ownership adapters and the edge/coordinator/worker region
//!   trees, reflected into tracing/crashpacks so every leaked effect
//!   attributes to region → authority → operation → generation → action →
//!   attempt;
//! - RABS obligation adapters (root permits, leases, fences, pins,
//!   delivery/publication obligations — invariant I7);
//! - managed process groups with cancel → drain → escalate → reap and
//!   precise termination classification (only classified deterministic
//!   failures are publication-eligible — I16);
//! - remote named-computation registry hosting, ATP session/stream/object
//!   adapters, supervision configuration, lab scenario helpers,
//!   observability conversion, pressure/admission bridging;
//! - API compatibility shims across pinned Asupersync revisions (the exact
//!   revision pin + ADR is bead A003; the upgrade report is A010).
//!
//! ## Dependency rules (binding; enforced by dependency-direction CI, bead A002)
//!
//! - This is the one crate permitted to depend on Asupersync (added by
//!   bead A003 at an exact pinned revision).
//! - **No durable or public RABS schema may contain a type from this
//!   crate** (invariant I14; boundary tests in bead A008). Conversion is
//!   always two-way through `rabs-protocol` owned types.
//! - Domain crates (`rabs-protocol`, `rabs-action`, `rabs-key`,
//!   `rabs-scheduler`, core `rabs-cas`) must never depend on this crate.
