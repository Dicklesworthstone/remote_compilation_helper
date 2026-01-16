//! Remote Compilation Helper - Common Library
//!
//! Shared types, patterns, and utilities used by rch, rchd, and rch-wkr.

#![forbid(unsafe_code)]

pub mod patterns;
pub mod protocol;
pub mod types;

pub use patterns::{Classification, CompilationKind, classify_command};
pub use protocol::{HookInput, HookOutput, ToolInput};
pub use types::{
    CompilationConfig, GeneralConfig, RchConfig, SelectionRequest, SelectionResponse,
    TransferConfig, WorkerConfig, WorkerId, WorkerStatus,
};
