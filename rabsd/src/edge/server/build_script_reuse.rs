//! Compose evidence-gated placement projections for the live dependency lane.
//!
//! The exact-key validators run before any projection. Each enabled profile
//! preserves the real compiler environment and filesystem guards, installs a
//! tracked-read veto, and binds a distinct policy identity. Neither profile
//! admits execution, publishes results, nor grants cache-installation authority.

#[path = "cargo_placement_reuse.rs"]
mod cargo_placement;
#[path = "empty_out_dir_reuse.rs"]
mod empty_out_dir;

use crate::edge::live_facts::PackageFacts;
use rabs_key::live_dependency::{
    DependencyActionPlan, DependencyDirectoryFact, ExternFact, LiveDependencyKey, LiveRefusal,
    ToolchainFacts,
};
use rabs_protocol::input_evidence::ActionInputManifest;

pub(super) fn enabled() -> bool {
    empty_out_dir::enabled()
}

/// Keep the existing empty-OUT_DIR opt-in independent of Cargo build layout.
/// Cargo placement is projected first; the existing generated-tree capture then
/// decides whether empty-OUT_DIR reuse is also sound for this exact invocation.
pub(super) fn key(
    plan: &mut DependencyActionPlan,
    toolchain: &ToolchainFacts,
    externs: &[ExternFact],
    directories: &[DependencyDirectoryFact],
    package: &PackageFacts,
    inputs: &ActionInputManifest,
    enable_empty_out_dir: bool,
) -> Result<LiveDependencyKey, LiveRefusal> {
    cargo_placement::key(
        plan,
        cargo_placement::enabled(),
        cargo_placement::layout_enabled(),
        |candidate| {
            empty_out_dir::key(
                candidate,
                toolchain,
                externs,
                directories,
                package,
                inputs,
                enable_empty_out_dir,
            )
        },
    )
}
