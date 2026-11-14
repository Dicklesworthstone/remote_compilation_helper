//! Worker access to the shared, bounded SDK byte cache.
//!
//! Tests compile the same implementation source locally so the existing private
//! spool-corruption test remains possible without a production mutation API.

#[cfg(not(test))]
pub(super) use rabs_sandbox::toolchain_file_cache::{
    CacheWriter, SnapshotRange, Snapshots, same_state,
};
#[cfg(not(test))]
pub use rabs_sandbox::toolchain_file_cache::{MAX_TOOLCHAIN_FILE_CACHE_BYTES, ToolchainFileCache};

#[cfg(test)]
use rabs_sandbox::{toolchain_dataset, toolchain_transfer};
#[cfg(test)]
#[path = "../../../rabs-sandbox/src/toolchain_file_cache.rs"]
mod shared;
#[cfg(test)]
pub(super) use shared::{CacheWriter, SnapshotRange, Snapshots, same_state};
#[cfg(test)]
pub use shared::{MAX_TOOLCHAIN_FILE_CACHE_BYTES, ToolchainFileCache};
