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

//! ## Live daemon path vs deferred policy/model inventory
//!
//! To prevent unwired policy libraries from masquerading as live runtime
//! capability (bead `rabs-root-4pidu.8.2`), submodules are grouped truthfully:
//!
//! - **Live daemon path** (called by `rabsd/src/main.rs`, `edge::server`, or
//!   `coord::live` / `coord::canonical_local`):
//!   - [`server`]: Unix-socket wrapper server, admission preflight, live-dependency consults
//!   - [`shadow`]: shadow-plane consult descriptor and receipt/index recorder
//!   - [`live_facts`]: descriptor-relative stable file reading and toolchain probing
//!   - [`dep_info`]: `.d` dep-info parsing and rewriting during output installation
//!   - [`destination_arbiter`]: atomic scoped output reservation and installation
//!   - [`diagnostic_rewrite`]: virtual-to-worktree diagnostic path translation
//! - **Deferred policy / model libraries** (unit-tested specifications with zero
//!   live callers from `rabsd/src/main.rs`; awaiting M7/M11/M13 cutover):
//!   - [`build_script_state`]: OUT_DIR pre/post-state swap model (M11)
//!   - [`cargo_resolution`] + [`snapshot_lineage`]: offline Cargo resolution & snapshot lineage (M13)
//!   - [`checksum_freshness`] + [`mtime_choreography`]: `-Zchecksum-freshness` & mtime floor policy (M11)
//!   - [`content_index`]: edge content-identity memoization & audit model (M11)
//!   - [`shadow_lifecycle`] + [`transport_suites`]: ATP shadow comparator & fault-injection suites (M7/M8)

// --- Live daemon path ---
pub mod dep_info;
pub mod destination_arbiter;
pub mod diagnostic_rewrite;
pub mod live_facts;
pub mod server;
pub mod shadow;

// --- Deferred policy / model libraries (unit-tested; not yet on live daemon path) ---
pub mod build_script_state;
pub mod cargo_resolution;
pub mod checksum_freshness;
pub mod content_index;
pub mod mtime_choreography;
pub mod shadow_lifecycle;
pub mod snapshot_lineage;
pub mod transport_suites;
