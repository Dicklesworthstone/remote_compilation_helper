//! Remote Compilation Helper - Common Library
//!
//! Shared types, patterns, and utilities used by rch, rchd, and rch-wkr.

// Use deny instead of forbid to allow specific overrides for env var manipulation
// in tests and profile defaults (env::set_var/remove_var are unsafe in Rust 2024)
#![deny(unsafe_code)]

use std::sync::OnceLock;

pub mod api;
pub mod artifact_verify;
pub mod binary_hash;
pub mod cargo_path_deps;
pub mod config;
pub mod dependency_closure_planner;
pub mod discovery;
pub mod e2e;
pub mod errors;
pub mod hooks;
pub mod logging;
pub mod mock;
pub mod mock_worker;
pub mod path_topology;
pub mod patterns;
#[cfg(test)]
mod patterns_security_test;
#[cfg(test)]
mod proptest_tests;
pub mod protocol;
#[cfg(unix)]
pub mod remote_compilation;
#[cfg(unix)]
pub mod remote_verification;
pub mod repo_updater_contract;
pub mod schema_versions;
#[cfg(unix)]
pub mod ssh;
#[cfg(all(test, unix))]
mod ssh_timeout_test;
pub mod ssh_utils;
pub mod test_change;
pub mod testing;
pub mod toolchain;
pub mod types;
pub mod ui;
pub mod util;

pub const BUILD_COMMIT_ENV_VARS: &[&str] = &[
    "RCH_GIT_COMMIT",
    "VERGEN_GIT_SHA",
    "GIT_COMMIT",
    "GITHUB_SHA",
];

pub fn build_commit() -> Option<&'static str> {
    [
        option_env!("RCH_GIT_COMMIT"),
        option_env!("VERGEN_GIT_SHA"),
        option_env!("GIT_COMMIT"),
        option_env!("GITHUB_SHA"),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .find(|value| !value.is_empty())
}

pub fn build_version_value() -> String {
    build_version_value_with_commit(env!("CARGO_PKG_VERSION"), build_commit())
}

pub fn build_version_value_static() -> &'static str {
    static VERSION_VALUE: OnceLock<String> = OnceLock::new();

    VERSION_VALUE.get_or_init(build_version_value).as_str()
}

pub fn build_version_value_with_commit(package_version: &str, commit: Option<&str>) -> String {
    let mut value = package_version.to_string();

    if let Some(commit) = commit.map(str::trim).filter(|value| !value.is_empty()) {
        value.push_str(" (commit ");
        value.push_str(short_commit(commit));
        value.push(')');
    }

    value
}

fn short_commit(commit: &str) -> &str {
    commit
        .char_indices()
        .nth(12)
        .map_or(commit, |(index, _)| &commit[..index])
}

pub use artifact_verify::{
    ArtifactManifest, FileHash, VerificationFailure, VerificationResult, compute_file_hash,
    create_manifest, verify_artifacts,
};
pub use binary_hash::{
    BinaryHashResult, binaries_equivalent, binary_contains_marker, compute_binary_hash,
};
pub use cargo_path_deps::{
    CargoPathDependencyEdge, CargoPathDependencyError, CargoPathDependencyErrorKind,
    CargoPathDependencyGraph, CargoPathDependencyPackage, resolve_cargo_path_dependency_graph,
    resolve_cargo_path_dependency_graph_with_policy,
};
pub use dependency_closure_planner::{
    DependencyClosurePlan, DependencyClosurePlanState, DependencyPlanIssue, DependencyRiskClass,
    DependencySyncAction, DependencySyncMetadata, DependencySyncReason,
    build_dependency_closure_plan, build_dependency_closure_plan_with_policy,
    plan_dependency_closure_from_graph,
};
pub use logging::{LogConfig, LogFormat, LoggingGuards, init_logging};
pub use mock_worker::MockWorkerServer;
pub use path_topology::{
    DEFAULT_ALIAS_PROJECT_ROOT, DEFAULT_CANONICAL_PROJECT_ROOT, NormalizationDecision,
    NormalizedProjectPath, PathNormalizationError, PathNormalizationErrorKind, PathTopologyPolicy,
    normalize_project_path, normalize_project_path_with_policy,
};
pub use patterns::{
    Classification, ClassificationDetails, ClassificationTier, CompilationKind, TierDecision,
    classify_command, classify_command_detailed, split_shell_commands,
};
pub use protocol::{HookInput, HookOutput, ToolInput};
pub use repo_updater_contract::{
    MockRepoUpdaterAdapter, REPO_UPDATER_ALIAS_PROJECTS_ROOT, REPO_UPDATER_CANONICAL_PROJECTS_ROOT,
    REPO_UPDATER_CONTRACT_SCHEMA_VERSION, REPO_UPDATER_DEFAULT_BINARY,
    REPO_UPDATER_MIN_SUPPORTED_VERSION, RepoUpdaterAdapter, RepoUpdaterAdapterCommand,
    RepoUpdaterAdapterContract, RepoUpdaterAdapterRequest, RepoUpdaterAdapterResponse,
    RepoUpdaterFailure, RepoUpdaterFailureKind, RepoUpdaterFallbackMode,
    RepoUpdaterIdempotencyGuarantee, RepoUpdaterJsonEnvelope, RepoUpdaterOutputFormat,
    RepoUpdaterResponseStatus, RepoUpdaterVersionCompatibility, RepoUpdaterVersionPolicy,
    build_invocation, classify_exit_code, evaluate_version_compatibility,
    map_failure_kind_to_error_code, repo_updater_envelope_schema, repo_updater_request_schema,
    repo_updater_response_schema,
};
// Platform-independent SSH utilities (available everywhere)
pub use ssh_utils::{
    CommandResult, EnvPrefix, build_env_prefix, is_retryable_transport_error,
    is_retryable_transport_error_text, shell_escape_value,
};
// Unix-only SSH client (uses openssh crate)
#[cfg(unix)]
pub use ssh::{KnownHostsPolicy, SshClient, SshOptions, SshPool};
pub use test_change::{TestChangeGuard, TestCodeChange};
pub use toolchain::{ToolchainInfo, wrap_command_with_color, wrap_command_with_toolchain};
pub use types::{
    AffinityConfig, BuildCancellationMetadata, BuildCancellationWorkerHealth, BuildHeartbeatPhase,
    BuildHeartbeatRequest, BuildLocation, BuildRecord, BuildStats, CircuitBreakerConfig,
    CircuitState, CircuitStats, ColorMode, CommandPriority, CommandTimingBreakdown,
    CompilationConfig, CompilationMetrics, CompilationTimer, CompilationTimingBreakdown,
    EnvironmentConfig, ExecutionConfig, FairnessConfig, FleetConfig, GeneralConfig,
    MetricsAggregator, OutputConfig, OutputVisibility, PathTopologyConfig, RchConfig,
    ReleaseRequest, RequiredRuntime, RetryConfig, SavedTimeStats, SelectedWorker, SelectionConfig,
    SelectionDiagnostics, SelectionReason, SelectionRequest, SelectionResponse, SelectionStrategy,
    SelectionWeightConfig, SelfHealingConfig, SelfHealingLogLevel, SelfTestConfig,
    SelfTestFailureAction, SelfTestWorkers, TransferConfig, WorkerCapabilities, WorkerConfig,
    WorkerId, WorkerSelectionDiagnostic, WorkerSelectionDiagnosticDecision, WorkerStatus,
    default_socket_path, validate_remote_base,
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
pub use errors::{
    CodeExplanation, CodeNamespace, ErrorCategory, ErrorCode, ErrorEntry, ReliabilityCategoryKind,
    ReliabilityReasonCode, RunbookEntry,
};

// Schema-version registry re-exports
pub use schema_versions::current_version as schema_version;
pub use schema_versions::{ALL_COMPONENTS as SCHEMA_VERSION_COMPONENTS, SchemaComponent};

// API module re-exports (unified API types for CLI and daemon)
pub use api::{API_VERSION, ApiError, ApiResponse, ErrorContext, LegacyErrorCode};

// Hooks module re-exports (daemon self-healing)
pub use hooks::{HookResult, is_claude_code_installed, verify_and_install_claude_code_hook};

#[cfg(test)]
mod build_version_tests {
    use super::{BUILD_COMMIT_ENV_VARS, build_version_value_with_commit};

    #[test]
    fn build_version_value_omits_missing_commit() {
        assert_eq!(build_version_value_with_commit("1.0.24", None), "1.0.24");
    }

    #[test]
    fn build_version_value_trims_and_shortens_commit() {
        assert_eq!(
            build_version_value_with_commit(
                "1.0.24",
                Some(" 2fa1249a18dfd05ae5e319e8d10bfd3c9ea1af55 "),
            ),
            "1.0.24 (commit 2fa1249a18df)"
        );
    }

    #[test]
    fn build_version_value_ignores_empty_commit() {
        assert_eq!(
            build_version_value_with_commit("1.0.24", Some("  ")),
            "1.0.24"
        );
    }

    #[test]
    fn build_commit_env_var_order_is_documented() {
        assert_eq!(
            BUILD_COMMIT_ENV_VARS,
            &[
                "RCH_GIT_COMMIT",
                "VERGEN_GIT_SHA",
                "GIT_COMMIT",
                "GITHUB_SHA"
            ]
        );
    }
}
