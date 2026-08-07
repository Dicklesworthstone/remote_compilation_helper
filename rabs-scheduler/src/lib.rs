//! # rabs-scheduler — build-action admission and placement policy
//!
//! The RABS **action** scheduler (admitting expensive Cargo/compiler/linker/
//! test processes fleet-wide) — deliberately distinct from Asupersync's
//! internal runtime scheduler (Part XII of the plan; Epic I beads I001–I026).
//!
//! Owns as policy (pure, deterministic, receipt-producing):
//!
//! - Cargo root-permit brokerage: every managed Cargo process consumes a
//!   brokered root permit backing Cargo's implicit token; a grant of
//!   capacity `C` is one implicit token plus at most `C-1` transferable
//!   jobserver tokens (risk R48);
//! - the fixed acyclic acquisition order — admission → placement +
//!   transfer reservation → materialization + disk reservation → execution
//!   admission → jobserver token immediately before spawn; no compiler
//!   token is ever held during bulk transfer;
//! - plane-specific frontier vs execution grants (risk R102);
//! - worker candidate scoring over pressure/eligibility snapshots (which
//!   are scheduler evidence, never action-key inputs — I23);
//! - hard eligibility exclusions before scoring; stale health fails closed
//!   for remote-required work (risk R25);
//! - transfer break-even, critical-path priorities, hedging policy (shared
//!   generation, independent leases — I31), speculative/foreground
//!   promotion, SLO brownout (I18), weighted fairness with starvation
//!   bounds, bounded provisional-lineage waiters (risk R112);
//! - structured candidate receipts and final decisions that replay
//!   identically from identical inputs.
//!
//! ## Dependency rules (binding; enforced by dependency-direction CI, bead A002)
//!
//! - May depend on `rabs-protocol` only.
//! - **Zero I/O, zero clocks, zero Tokio/Asupersync**: evidence in, decision
//!   + receipt out. The daemon hosting loop lives in `rabs-coord`.
