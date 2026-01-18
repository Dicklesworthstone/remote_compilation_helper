//! Remote Compilation Helper - Common Library
//!
//! Shared types, patterns, and utilities used by rch, rchd, and rch-wkr.

// Use deny instead of forbid to allow specific overrides for env var manipulation
// in tests and profile defaults (env::set_var/remove_var are unsafe in Rust 2024)
#![deny(unsafe_code)]

pub mod binary_hash;
pub mod config;
pub mod discovery;
pub mod e2e;
pub mod logging;
pub mod mock;
pub mod mock_worker;
pub mod patterns;
#[cfg(test)]
mod patterns_security_test;
pub mod protocol;
pub mod remote_compilation;
pub mod remote_verification;
pub mod ssh;
pub mod test_change;
pub mod toolchain;
pub mod types;

pub use binary_hash::{
    BinaryHashResult, binaries_equivalent, binary_contains_marker, compute_binary_hash,
};
pub use logging::{LogConfig, LogFormat, LoggingGuards, init_logging};
pub use mock_worker::MockWorkerServer;
pub use patterns::{
    Classification, ClassificationDetails, ClassificationTier, CompilationKind, TierDecision,
    classify_command, classify_command_detailed,
};
pub use protocol::{HookInput, HookOutput, ToolInput};
pub use ssh::{CommandResult, KnownHostsPolicy, SshClient, SshOptions, SshPool};
pub use test_change::{TestChangeGuard, TestCodeChange};
pub use toolchain::{ToolchainInfo, wrap_command_with_toolchain};
pub use types::{
    BuildLocation, BuildRecord, BuildStats, CircuitBreakerConfig, CircuitState, CircuitStats,
    CompilationConfig, CompilationMetrics, CompilationTimer, CompilationTimingBreakdown,
    GeneralConfig, MetricsAggregator, OutputConfig, OutputVisibility, RchConfig, ReleaseRequest,
    RequiredRuntime, SelectedWorker, SelectionReason, SelectionRequest, SelectionResponse,
    SelfTestConfig, SelfTestFailureAction, SelfTestWorkers, TransferConfig, WorkerCapabilities,
    WorkerConfig, WorkerId, WorkerStatus, default_socket_path,
};

// Config module re-exports
pub use config::{
    ConfigSource, ConfigValueSource, ConfigWarning, EnvError, EnvParser, Profile, Severity,
    Sourced, validate_config,
};

// Discovery module re-exports
pub use discovery::{
    DiscoveredHost, DiscoverySource, discover_all, parse_shell_aliases,
    parse_shell_aliases_content, parse_ssh_config, parse_ssh_config_content,
};
