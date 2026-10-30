//! The worker upload lane and canonical service use the same bounded,
//! generation-aware toolchain ownership cache. Its ownership and filesystem
//! regressions live with the effects-owning implementation in rabs-sandbox.

pub(super) use rabs_sandbox::toolchain_cache::{CAPACITY, Cache};
