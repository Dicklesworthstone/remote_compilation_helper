//! Remote Compilation Helper - Common Library
//!
//! Shared types, patterns, and utilities used by rch, rchd, and rch-wkr.

// Use deny instead of forbid to allow specific overrides for env var manipulation
// in tests and profile defaults (env::set_var/remove_var are unsafe in Rust 2024)
#![deny(unsafe_code)]

pub mod config;
pub mod discovery;
pub mod mock;
pub mod patterns;
#[cfg(test)]
mod patterns_security_test;
pub mod protocol;
pub mod ssh;
pub mod toolchain;
pub mod types;

pub use patterns::{Classification, CompilationKind, classify_command};
pub use protocol::{HookInput, HookOutput, ToolInput};
pub use ssh::{CommandResult, KnownHostsPolicy, SshClient, SshOptions, SshPool};
pub use toolchain::{ToolchainInfo, wrap_command_with_toolchain};
pub use types::{
    BuildLocation, BuildRecord, BuildStats, CircuitBreakerConfig, CircuitState, CircuitStats,
    CompilationConfig, GeneralConfig, RchConfig, ReleaseRequest, RequiredRuntime, SelectedWorker,
    SelectionReason, SelectionRequest, SelectionResponse, TransferConfig, WorkerCapabilities,
    WorkerConfig, WorkerId, WorkerStatus,
};

// Config module re-exports
pub use config::{
    ConfigSource, ConfigWarning, EnvError, EnvParser, Profile, Severity, Sourced, validate_config,
};

// Discovery module re-exports
pub use discovery::{
    DiscoveredHost, DiscoverySource, discover_all, parse_shell_aliases, parse_shell_aliases_content,
    parse_ssh_config, parse_ssh_config_content,
};
