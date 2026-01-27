//! Remote Compilation Helper - Common Library
//!
//! Shared types, patterns, and utilities used by rch, rchd, and rch-wkr.

// Use deny instead of forbid to allow specific overrides for env var manipulation
// in tests and profile defaults (env::set_var/remove_var are unsafe in Rust 2024)
#![deny(unsafe_code)]

pub mod api;
pub mod artifact_verify;
pub mod binary_hash;
pub mod config;
pub mod discovery;
pub mod e2e;
pub mod errors;
pub mod hooks;
pub mod logging;
pub mod mock;
pub mod mock_worker;
pub mod patterns;
#[cfg(test)]
mod patterns_security_test;
#[cfg(test)]
mod proptest_tests;
pub mod protocol;
pub mod remote_compilation;
pub mod remote_verification;
pub mod ssh;
pub mod test_change;
pub mod testing;
pub mod toolchain;
pub mod types;
pub mod ui;

pub use artifact_verify::{
    ArtifactManifest, FileHash, VerificationFailure, VerificationResult, compute_file_hash,
    create_manifest, verify_artifacts,
};
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
pub use toolchain::{ToolchainInfo, wrap_command_with_color, wrap_command_with_toolchain};
pub use types::{
    AffinityConfig, BuildLocation, BuildRecord, BuildStats, CircuitBreakerConfig, CircuitState,
    CircuitStats, ColorMode, CommandPriority, CommandTimingBreakdown, CompilationConfig,
    CompilationMetrics, CompilationTimer, CompilationTimingBreakdown, EnvironmentConfig,
    ExecutionConfig, FairnessConfig, GeneralConfig, MetricsAggregator, OutputConfig,
    OutputVisibility, RchConfig, ReleaseRequest, RequiredRuntime, RetryConfig, SavedTimeStats,
    SelectedWorker, SelectionConfig, SelectionReason, SelectionRequest, SelectionResponse,
    SelectionStrategy, SelectionWeightConfig, SelfHealingConfig, SelfTestConfig,
    SelfTestFailureAction, SelfTestWorkers, TransferConfig, WorkerCapabilities, WorkerConfig,
    WorkerId, WorkerStatus, default_socket_path, validate_remote_base,
};

// Testing module re-exports
pub use testing::{TestLogEntry, TestLogger, TestPhase, TestResult};

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

// UI module re-exports
pub use ui::{
    ErrorPanel, ErrorSeverity, Icons, IntoErrorPanel, OutputContext, RchTheme, ResultExt,
    anyhow_to_json, anyhow_to_panel, display_anyhow_error, display_error, display_error_with_code,
    error_to_json, error_to_panel,
};

// Errors module re-exports
pub use errors::{ErrorCategory, ErrorCode, ErrorEntry};

// API module re-exports (unified API types for CLI and daemon)
pub use api::{API_VERSION, ApiError, ApiResponse, ErrorContext, LegacyErrorCode};

// Hooks module re-exports (daemon self-healing)
pub use hooks::{HookResult, is_claude_code_installed, verify_and_install_claude_code_hook};

// Global test logging initialization - enables JSONL output for all unit tests
#[cfg(test)]
#[ctor::ctor]
fn init_test_logging() {
    testing::init_global_test_logging();
}
