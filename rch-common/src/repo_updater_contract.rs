//! Stable contract for integrating RCH with `repo_updater` (`ru`).
//!
//! This module defines:
//! - adapter command surface and invocation args
//! - request/response schemas for deterministic integration
//! - timeout/retry/idempotency semantics
//! - version-compatibility policy
//! - trust/auth boundaries for repo convergence operations
//! - error taxonomy mapped into RCH error codes
//! - a mockable adapter interface for unit/integration tests

use schemars::{JsonSchema, schema::RootSchema, schema_for};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::ErrorCode;

/// Schema version for the RCH <-> repo_updater adapter contract.
pub const REPO_UPDATER_CONTRACT_SCHEMA_VERSION: &str = "1.0.0";
/// Canonical projects root expected on workers.
pub const REPO_UPDATER_CANONICAL_PROJECTS_ROOT: &str = "/data/projects";
/// Required alias for compatibility with existing tooling.
pub const REPO_UPDATER_ALIAS_PROJECTS_ROOT: &str = "/dp";
/// Default adapter binary name.
pub const REPO_UPDATER_DEFAULT_BINARY: &str = "ru";
/// Known-good minimum ru version for this contract.
pub const REPO_UPDATER_MIN_SUPPORTED_VERSION: &str = "1.2.0";

/// Stable command surface used by RCH to invoke repo_updater.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoUpdaterAdapterCommand {
    /// `ru list --paths` for current local projection of configured repos.
    ListPaths,
    /// `ru status --no-fetch` for non-mutating drift snapshot.
    StatusNoFetch,
    /// `ru sync --dry-run` for mutation-free convergence preview.
    SyncDryRun,
    /// `ru sync` for actual convergence.
    SyncApply,
    /// `ru robot-docs schemas` for schema/shape preflight checks.
    RobotDocsSchemas,
    /// `ru --version` for compatibility checks.
    Version,
}

impl RepoUpdaterAdapterCommand {
    /// Command-line args (excluding binary name) for each stable operation.
    #[must_use]
    pub fn args(self) -> &'static [&'static str] {
        match self {
            Self::ListPaths => &["list", "--paths", "--non-interactive", "--format", "json"],
            Self::StatusNoFetch => &[
                "status",
                "--no-fetch",
                "--non-interactive",
                "--format",
                "json",
            ],
            Self::SyncDryRun => &["sync", "--dry-run", "--non-interactive", "--format", "json"],
            Self::SyncApply => &["sync", "--non-interactive", "--format", "json"],
            Self::RobotDocsSchemas => &["robot-docs", "schemas", "--format", "json"],
            Self::Version => &["--version"],
        }
    }

    /// Expected `command` field inside ru JSON envelope.
    #[must_use]
    pub const fn expected_envelope_command(self) -> &'static str {
        match self {
            Self::ListPaths => "list",
            Self::StatusNoFetch => "status",
            Self::SyncDryRun | Self::SyncApply => "sync",
            Self::RobotDocsSchemas => "robot-docs",
            Self::Version => "version",
        }
    }

    /// Idempotency guarantee promised by this command class.
    #[must_use]
    pub const fn idempotency(self) -> RepoUpdaterIdempotencyGuarantee {
        match self {
            Self::ListPaths | Self::StatusNoFetch | Self::RobotDocsSchemas | Self::Version => {
                RepoUpdaterIdempotencyGuarantee::StrongReadOnly
            }
            Self::SyncDryRun => RepoUpdaterIdempotencyGuarantee::StrongReadOnly,
            Self::SyncApply => RepoUpdaterIdempotencyGuarantee::EventualConvergence,
        }
    }

    /// Whether this command may mutate repositories.
    #[must_use]
    pub const fn mutating(self) -> bool {
        matches!(self, Self::SyncApply)
    }
}

/// Idempotency contract class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoUpdaterIdempotencyGuarantee {
    /// Repeated invocation with same inputs is deterministic and non-mutating.
    StrongReadOnly,
    /// Repeated invocation converges toward same final repo state.
    EventualConvergence,
}

/// Output format expected from adapter command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoUpdaterOutputFormat {
    Json,
    Toon,
}

/// Compatibility status when evaluating adapter version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoUpdaterVersionCompatibility {
    Compatible,
    TooOld,
    NewerMinorUntested,
    NewerMajorUnsupported,
    InvalidVersion,
}

/// Adapter-side failure taxonomy normalized by RCH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoUpdaterFailureKind {
    AdapterUnavailable,
    VersionIncompatible,
    TrustBoundaryViolation,
    HostValidationFailed,
    AuthFailure,
    Timeout,
    RetryExhausted,
    InvalidEnvelope,
    JsonDecodeFailure,
    CommandFailed,
    PartialFailure,
    Interrupted,
    Internal,
}

/// Exit-code meaning based on ru robot docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoUpdaterExitDisposition {
    Success,
    PartialFailure,
    Conflicts,
    SystemError,
    InvalidArguments,
    Interrupted,
    Unknown,
}

/// Alias mapping requirement for worker path topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoPathAliasRequirement {
    pub alias: PathBuf,
    pub canonical_target: PathBuf,
}

/// Host and path-trust boundaries for repo convergence operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterTrustBoundaryPolicy {
    pub canonical_projects_root: PathBuf,
    pub required_aliases: Vec<RepoPathAliasRequirement>,
    pub allowed_repo_hosts: Vec<String>,
    pub allow_owner_repo_shorthand: bool,
    pub reject_local_path_specs: bool,
}

impl Default for RepoUpdaterTrustBoundaryPolicy {
    fn default() -> Self {
        Self {
            canonical_projects_root: PathBuf::from(REPO_UPDATER_CANONICAL_PROJECTS_ROOT),
            required_aliases: vec![RepoPathAliasRequirement {
                alias: PathBuf::from(REPO_UPDATER_ALIAS_PROJECTS_ROOT),
                canonical_target: PathBuf::from(REPO_UPDATER_CANONICAL_PROJECTS_ROOT),
            }],
            allowed_repo_hosts: vec!["github.com".to_string()],
            allow_owner_repo_shorthand: true,
            reject_local_path_specs: true,
        }
    }
}

/// Authentication policy for adapter invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoUpdaterAuthMode {
    InheritEnvironment,
    RequireGhAuth,
    RequireTokenEnv,
}

/// Auth-related policy constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterAuthPolicy {
    pub mode: RepoUpdaterAuthMode,
    pub required_env_vars: Vec<String>,
    pub redacted_env_vars: Vec<String>,
}

impl Default for RepoUpdaterAuthPolicy {
    fn default() -> Self {
        Self {
            mode: RepoUpdaterAuthMode::InheritEnvironment,
            required_env_vars: Vec::new(),
            redacted_env_vars: vec!["GH_TOKEN".to_string(), "GITHUB_TOKEN".to_string()],
        }
    }
}

/// Timeout budgets for repo_updater operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterTimeoutPolicy {
    pub read_timeout_secs: u64,
    pub sync_timeout_secs: u64,
    pub schema_probe_timeout_secs: u64,
    pub version_timeout_secs: u64,
}

impl Default for RepoUpdaterTimeoutPolicy {
    fn default() -> Self {
        Self {
            read_timeout_secs: 8,
            sync_timeout_secs: 180,
            schema_probe_timeout_secs: 10,
            version_timeout_secs: 3,
        }
    }
}

/// Retry behavior for idempotent convergence operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterRetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub backoff_multiplier_percent: u16,
    pub retry_on_timeout: bool,
    pub retry_on_partial_failure: bool,
}

impl Default for RepoUpdaterRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 250,
            max_backoff_ms: 2_000,
            backoff_multiplier_percent: 200,
            retry_on_timeout: true,
            retry_on_partial_failure: true,
        }
    }
}

/// Explicit timeout/retry budget per command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterCommandBudget {
    pub command: RepoUpdaterAdapterCommand,
    pub timeout_secs: u64,
    pub retries: u32,
}

/// Version policy used for compatibility gating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterVersionPolicy {
    pub min_supported_version: String,
    pub max_tested_major: u64,
    pub max_tested_minor: u64,
    pub allow_newer_patch: bool,
    pub allow_newer_minor_within_major: bool,
}

impl Default for RepoUpdaterVersionPolicy {
    fn default() -> Self {
        Self {
            min_supported_version: REPO_UPDATER_MIN_SUPPORTED_VERSION.to_string(),
            max_tested_major: 1,
            max_tested_minor: 2,
            allow_newer_patch: true,
            allow_newer_minor_within_major: false,
        }
    }
}

/// Fallback behavior when adapter is unavailable or incompatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoUpdaterFallbackMode {
    /// Continue build flow without convergence (RCH fail-open default).
    FailOpenLocalProceed,
    /// Stop remote flow when convergence preflight fails.
    FailClosedBlockRemoteBuild,
}

/// Policy for fallback semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterFallbackPolicy {
    pub mode: RepoUpdaterFallbackMode,
    pub fallback_reason_code: String,
}

impl Default for RepoUpdaterFallbackPolicy {
    fn default() -> Self {
        Self {
            mode: RepoUpdaterFallbackMode::FailOpenLocalProceed,
            fallback_reason_code: "REPO_UPDATER_FAIL_OPEN".to_string(),
        }
    }
}

/// Full contract bundle for repo_updater integration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterAdapterContract {
    pub schema_version: String,
    pub adapter_binary: String,
    pub timeout_policy: RepoUpdaterTimeoutPolicy,
    pub retry_policy: RepoUpdaterRetryPolicy,
    pub command_budgets: Vec<RepoUpdaterCommandBudget>,
    pub version_policy: RepoUpdaterVersionPolicy,
    pub trust_policy: RepoUpdaterTrustBoundaryPolicy,
    pub auth_policy: RepoUpdaterAuthPolicy,
    pub fallback_policy: RepoUpdaterFallbackPolicy,
}

impl Default for RepoUpdaterAdapterContract {
    fn default() -> Self {
        Self {
            schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
            adapter_binary: REPO_UPDATER_DEFAULT_BINARY.to_string(),
            timeout_policy: RepoUpdaterTimeoutPolicy::default(),
            retry_policy: RepoUpdaterRetryPolicy::default(),
            command_budgets: vec![
                RepoUpdaterCommandBudget {
                    command: RepoUpdaterAdapterCommand::ListPaths,
                    timeout_secs: 8,
                    retries: 1,
                },
                RepoUpdaterCommandBudget {
                    command: RepoUpdaterAdapterCommand::StatusNoFetch,
                    timeout_secs: 12,
                    retries: 1,
                },
                RepoUpdaterCommandBudget {
                    command: RepoUpdaterAdapterCommand::SyncDryRun,
                    timeout_secs: 45,
                    retries: 1,
                },
                RepoUpdaterCommandBudget {
                    command: RepoUpdaterAdapterCommand::SyncApply,
                    timeout_secs: 180,
                    retries: 1,
                },
                RepoUpdaterCommandBudget {
                    command: RepoUpdaterAdapterCommand::RobotDocsSchemas,
                    timeout_secs: 10,
                    retries: 0,
                },
                RepoUpdaterCommandBudget {
                    command: RepoUpdaterAdapterCommand::Version,
                    timeout_secs: 3,
                    retries: 0,
                },
            ],
            version_policy: RepoUpdaterVersionPolicy::default(),
            trust_policy: RepoUpdaterTrustBoundaryPolicy::default(),
            auth_policy: RepoUpdaterAuthPolicy::default(),
            fallback_policy: RepoUpdaterFallbackPolicy::default(),
        }
    }
}

/// Request emitted by rchd to repo_updater adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterAdapterRequest {
    pub schema_version: String,
    pub correlation_id: String,
    pub worker_id: String,
    pub command: RepoUpdaterAdapterCommand,
    pub requested_at_unix_ms: i64,
    pub projects_root: PathBuf,
    pub repo_specs: Vec<String>,
    pub idempotency_key: String,
    pub retry_attempt: u32,
    pub timeout_secs: u64,
    pub expected_output_format: RepoUpdaterOutputFormat,
}

/// Optional envelope metadata from ru output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct RepoUpdaterEnvelopeMeta {
    pub duration_seconds: Option<u64>,
    pub exit_code: Option<i32>,
}

/// Raw ru envelope shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterJsonEnvelope {
    pub generated_at: String,
    pub version: String,
    pub output_format: RepoUpdaterOutputFormat,
    pub command: String,
    pub data: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RepoUpdaterEnvelopeMeta>,
}

/// Repo-level normalized status item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct RepoUpdaterRepoRecord {
    pub repo: String,
    pub path: Option<PathBuf>,
    pub action: Option<String>,
    pub status: Option<String>,
    pub dirty: Option<bool>,
    pub ahead: Option<i64>,
    pub behind: Option<i64>,
}

/// Normalized sync summary fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct RepoUpdaterSyncSummary {
    pub total: u64,
    pub cloned: u64,
    pub pulled: u64,
    pub skipped: u64,
    pub failed: u64,
}

/// High-level normalized response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoUpdaterResponseStatus {
    Success,
    PartialFailure,
    Conflict,
    Failed,
    AdapterUnavailable,
    VersionIncompatible,
    FallbackApplied,
}

/// Structured failure payload for adapter response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterFailure {
    pub kind: RepoUpdaterFailureKind,
    pub code: String,
    pub message: String,
    pub mapped_rch_error: String,
    pub remediation: Vec<String>,
    pub adapter_exit_code: Option<i32>,
}

/// Normalized adapter response consumed by rchd convergence pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterAdapterResponse {
    pub schema_version: String,
    pub correlation_id: String,
    pub command: RepoUpdaterAdapterCommand,
    pub adapter_version: String,
    pub status: RepoUpdaterResponseStatus,
    pub idempotency_guarantee: RepoUpdaterIdempotencyGuarantee,
    pub fallback_applied: bool,
    pub sync_summary: Option<RepoUpdaterSyncSummary>,
    pub repos: Vec<RepoUpdaterRepoRecord>,
    pub envelope_meta: Option<RepoUpdaterEnvelopeMeta>,
    pub failure: Option<RepoUpdaterFailure>,
}

/// Invocation details for an adapter command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterInvocation {
    pub binary: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// Contract validation failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RepoUpdaterContractError {
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaVersionMismatch { expected: String, actual: String },
    #[error("invalid projects root: {0}")]
    InvalidProjectsRoot(String),
    #[error("unsupported repo host: {0}")]
    UnsupportedRepoHost(String),
    #[error("missing idempotency key")]
    MissingIdempotencyKey,
    #[error("invalid timeout_secs: {0}")]
    InvalidTimeout(u64),
    #[error("retry attempt {attempt} exceeds max attempts {max_attempts}")]
    RetryAttemptExceeded { attempt: u32, max_attempts: u32 },
    #[error("allowlist for repo hosts cannot be empty")]
    EmptyHostAllowlist,
    #[error("command budgets contain duplicate entries for {0:?}")]
    DuplicateCommandBudget(RepoUpdaterAdapterCommand),
}

impl RepoUpdaterAdapterContract {
    /// Validate contract-level invariants.
    pub fn validate(&self) -> Result<(), RepoUpdaterContractError> {
        if self.trust_policy.allowed_repo_hosts.is_empty() {
            return Err(RepoUpdaterContractError::EmptyHostAllowlist);
        }

        let mut seen: Vec<RepoUpdaterAdapterCommand> = Vec::new();
        for budget in &self.command_budgets {
            if budget.timeout_secs == 0 {
                return Err(RepoUpdaterContractError::InvalidTimeout(0));
            }
            if seen.contains(&budget.command) {
                return Err(RepoUpdaterContractError::DuplicateCommandBudget(
                    budget.command,
                ));
            }
            seen.push(budget.command);
        }

        Ok(())
    }
}

impl RepoUpdaterAdapterRequest {
    /// Validate request semantics against contract policy.
    pub fn validate(
        &self,
        contract: &RepoUpdaterAdapterContract,
    ) -> Result<(), RepoUpdaterContractError> {
        if self.schema_version != REPO_UPDATER_CONTRACT_SCHEMA_VERSION {
            return Err(RepoUpdaterContractError::SchemaVersionMismatch {
                expected: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(RepoUpdaterContractError::MissingIdempotencyKey);
        }
        if self.timeout_secs == 0 {
            return Err(RepoUpdaterContractError::InvalidTimeout(self.timeout_secs));
        }
        if self.retry_attempt >= contract.retry_policy.max_attempts {
            return Err(RepoUpdaterContractError::RetryAttemptExceeded {
                attempt: self.retry_attempt,
                max_attempts: contract.retry_policy.max_attempts,
            });
        }
        if normalize_projects_root(&self.projects_root, &contract.trust_policy).is_none() {
            return Err(RepoUpdaterContractError::InvalidProjectsRoot(
                self.projects_root.display().to_string(),
            ));
        }

        for spec in &self.repo_specs {
            if let Some(host) =
                extract_repo_host(spec, contract.trust_policy.allow_owner_repo_shorthand)
            {
                let allowed = contract
                    .trust_policy
                    .allowed_repo_hosts
                    .iter()
                    .any(|allowed_host| allowed_host.eq_ignore_ascii_case(&host));
                if !allowed {
                    return Err(RepoUpdaterContractError::UnsupportedRepoHost(host));
                }
            } else if contract.trust_policy.reject_local_path_specs {
                return Err(RepoUpdaterContractError::UnsupportedRepoHost(spec.clone()));
            }
        }

        Ok(())
    }
}

/// Adapter interface that can be mocked in deterministic tests.
pub trait RepoUpdaterAdapter: Send + Sync {
    fn execute(
        &self,
        request: &RepoUpdaterAdapterRequest,
        contract: &RepoUpdaterAdapterContract,
    ) -> Result<RepoUpdaterAdapterResponse, RepoUpdaterFailure>;
}

/// Deterministic in-memory mock for adapter integration tests.
#[derive(Debug, Clone, Default)]
pub struct MockRepoUpdaterAdapter {
    scripted_results: Arc<Mutex<Vec<Result<RepoUpdaterAdapterResponse, RepoUpdaterFailure>>>>,
    recorded_calls: Arc<Mutex<Vec<RepoUpdaterAdapterRequest>>>,
}

impl MockRepoUpdaterAdapter {
    /// Append a scripted adapter result. Results are consumed FIFO.
    pub fn push_result(&self, result: Result<RepoUpdaterAdapterResponse, RepoUpdaterFailure>) {
        let mut guard = self
            .scripted_results
            .lock()
            .expect("scripted_results mutex poisoned");
        guard.push(result);
    }

    /// Snapshot of all execute calls received by the mock.
    #[must_use]
    pub fn calls(&self) -> Vec<RepoUpdaterAdapterRequest> {
        self.recorded_calls
            .lock()
            .expect("recorded_calls mutex poisoned")
            .clone()
    }
}

impl RepoUpdaterAdapter for MockRepoUpdaterAdapter {
    fn execute(
        &self,
        request: &RepoUpdaterAdapterRequest,
        contract: &RepoUpdaterAdapterContract,
    ) -> Result<RepoUpdaterAdapterResponse, RepoUpdaterFailure> {
        if let Err(error) = request.validate(contract) {
            return Err(RepoUpdaterFailure {
                kind: RepoUpdaterFailureKind::TrustBoundaryViolation,
                code: "RU_REQ_INVALID".to_string(),
                message: error.to_string(),
                mapped_rch_error: map_failure_kind_to_error_code(
                    RepoUpdaterFailureKind::TrustBoundaryViolation,
                )
                .code_string(),
                remediation: vec![
                    "Verify projects root is canonicalized to /data/projects".to_string(),
                    "Validate repo specs against host allowlist".to_string(),
                ],
                adapter_exit_code: None,
            });
        }

        self.recorded_calls
            .lock()
            .expect("recorded_calls mutex poisoned")
            .push(request.clone());

        let mut scripted = self
            .scripted_results
            .lock()
            .expect("scripted_results mutex poisoned");
        if scripted.is_empty() {
            return Err(RepoUpdaterFailure {
                kind: RepoUpdaterFailureKind::Internal,
                code: "RU_MOCK_NO_RESULT".to_string(),
                message: "mock adapter has no scripted results".to_string(),
                mapped_rch_error: map_failure_kind_to_error_code(RepoUpdaterFailureKind::Internal)
                    .code_string(),
                remediation: vec![
                    "Add at least one scripted result before calling execute()".to_string(),
                ],
                adapter_exit_code: None,
            });
        }

        scripted.remove(0)
    }
}

/// Compute invocation command/env for a request.
#[must_use]
pub fn build_invocation(
    request: &RepoUpdaterAdapterRequest,
    contract: &RepoUpdaterAdapterContract,
) -> RepoUpdaterInvocation {
    let mut args = request
        .command
        .args()
        .iter()
        .map(|arg| (*arg).to_string())
        .collect::<Vec<_>>();

    if !request.repo_specs.is_empty()
        && matches!(
            request.command,
            RepoUpdaterAdapterCommand::SyncDryRun | RepoUpdaterAdapterCommand::SyncApply
        )
    {
        args.extend(request.repo_specs.iter().cloned());
    }

    let env = vec![
        (
            "RU_PROJECTS_DIR".to_string(),
            normalize_projects_root(&request.projects_root, &contract.trust_policy)
                .unwrap_or_else(|| contract.trust_policy.canonical_projects_root.clone())
                .display()
                .to_string(),
        ),
        (
            "RCH_REPO_IDEMPOTENCY_KEY".to_string(),
            request.idempotency_key.clone(),
        ),
    ];

    RepoUpdaterInvocation {
        binary: contract.adapter_binary.clone(),
        args,
        env,
    }
}

/// Map ru exit code to deterministic disposition.
#[must_use]
pub const fn classify_exit_code(exit_code: i32) -> RepoUpdaterExitDisposition {
    match exit_code {
        0 => RepoUpdaterExitDisposition::Success,
        1 => RepoUpdaterExitDisposition::PartialFailure,
        2 => RepoUpdaterExitDisposition::Conflicts,
        3 => RepoUpdaterExitDisposition::SystemError,
        4 => RepoUpdaterExitDisposition::InvalidArguments,
        5 => RepoUpdaterExitDisposition::Interrupted,
        _ => RepoUpdaterExitDisposition::Unknown,
    }
}

/// Map adapter failure kind into canonical RCH error code.
#[must_use]
pub const fn map_failure_kind_to_error_code(kind: RepoUpdaterFailureKind) -> ErrorCode {
    match kind {
        RepoUpdaterFailureKind::AdapterUnavailable => ErrorCode::ConfigNoWorkers,
        RepoUpdaterFailureKind::VersionIncompatible => ErrorCode::InternalDaemonProtocol,
        RepoUpdaterFailureKind::TrustBoundaryViolation => ErrorCode::ConfigValidationError,
        RepoUpdaterFailureKind::HostValidationFailed => ErrorCode::ConfigValidationError,
        RepoUpdaterFailureKind::AuthFailure => ErrorCode::SshAuthFailed,
        RepoUpdaterFailureKind::Timeout => ErrorCode::TransferTimeout,
        RepoUpdaterFailureKind::RetryExhausted => ErrorCode::InternalStateError,
        RepoUpdaterFailureKind::InvalidEnvelope | RepoUpdaterFailureKind::JsonDecodeFailure => {
            ErrorCode::InternalSerdeError
        }
        RepoUpdaterFailureKind::CommandFailed => ErrorCode::WorkerStateError,
        RepoUpdaterFailureKind::PartialFailure => ErrorCode::WorkerLoadQueryFailed,
        RepoUpdaterFailureKind::Interrupted => ErrorCode::InternalIpcError,
        RepoUpdaterFailureKind::Internal => ErrorCode::InternalStateError,
    }
}

/// Evaluate adapter version against compatibility policy.
#[must_use]
pub fn evaluate_version_compatibility(
    version: &str,
    policy: &RepoUpdaterVersionPolicy,
) -> RepoUpdaterVersionCompatibility {
    let Some(actual) = parse_semver(version) else {
        return RepoUpdaterVersionCompatibility::InvalidVersion;
    };
    let Some(minimum) = parse_semver(&policy.min_supported_version) else {
        return RepoUpdaterVersionCompatibility::InvalidVersion;
    };

    if actual < minimum {
        return RepoUpdaterVersionCompatibility::TooOld;
    }
    if actual.major > policy.max_tested_major {
        return RepoUpdaterVersionCompatibility::NewerMajorUnsupported;
    }
    if actual.major == policy.max_tested_major && actual.minor > policy.max_tested_minor {
        if policy.allow_newer_minor_within_major {
            return RepoUpdaterVersionCompatibility::Compatible;
        }
        return RepoUpdaterVersionCompatibility::NewerMinorUntested;
    }

    RepoUpdaterVersionCompatibility::Compatible
}

/// Build JSON schema for adapter request.
#[must_use]
pub fn repo_updater_request_schema() -> RootSchema {
    schema_for!(RepoUpdaterAdapterRequest)
}

/// Build JSON schema for normalized adapter response.
#[must_use]
pub fn repo_updater_response_schema() -> RootSchema {
    schema_for!(RepoUpdaterAdapterResponse)
}

/// Build JSON schema for raw ru envelope.
#[must_use]
pub fn repo_updater_envelope_schema() -> RootSchema {
    schema_for!(RepoUpdaterJsonEnvelope)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Semver {
    major: u64,
    minor: u64,
    patch: u64,
}

fn parse_semver(input: &str) -> Option<Semver> {
    let trimmed = input.trim().trim_start_matches('v');
    let mut parts = trimmed.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch_raw = parts.next()?;
    let patch = patch_raw
        .split(|c: char| !(c.is_ascii_digit()))
        .next()
        .and_then(|segment| segment.parse::<u64>().ok())?;
    Some(Semver {
        major,
        minor,
        patch,
    })
}

fn normalize_projects_root(
    candidate: &Path,
    policy: &RepoUpdaterTrustBoundaryPolicy,
) -> Option<PathBuf> {
    let normalized_candidate = normalize_path(candidate);
    let canonical = normalize_path(&policy.canonical_projects_root);
    if normalized_candidate == canonical {
        return Some(canonical);
    }

    for alias in &policy.required_aliases {
        let alias_path = normalize_path(&alias.alias);
        let alias_target = normalize_path(&alias.canonical_target);
        if normalized_candidate == alias_path {
            return Some(alias_target);
        }
    }

    None
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    if normalized.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        normalized
    }
}

fn extract_repo_host(spec: &str, allow_owner_repo_shorthand: bool) -> Option<String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return None;
    }

    let repo_spec = trimmed
        .split_once(" as ")
        .map_or(trimmed, |(lhs, _)| lhs.trim());

    if repo_spec.starts_with("http://")
        || repo_spec.starts_with("https://")
        || repo_spec.starts_with("ssh://")
    {
        let after_scheme = repo_spec.split_once("://")?.1;
        let authority = after_scheme.split('/').next()?;
        let host_port = authority.rsplit_once('@').map_or(authority, |(_, rhs)| rhs);
        let host = host_port.split(':').next().unwrap_or(host_port);
        return Some(host.to_string());
    }

    if let (Some(at_index), Some(colon_index)) = (repo_spec.find('@'), repo_spec.find(':'))
        && at_index < colon_index
    {
        return Some(repo_spec[at_index + 1..colon_index].to_string());
    }

    if allow_owner_repo_shorthand {
        let shorthand = repo_spec.split_once('@').map_or(repo_spec, |(lhs, _)| lhs);
        if shorthand.contains('/') && !shorthand.starts_with('/') && !shorthand.starts_with("./") {
            return Some("github.com".to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> RepoUpdaterAdapterRequest {
        RepoUpdaterAdapterRequest {
            schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
            correlation_id: "corr-ru-123".to_string(),
            worker_id: "worker-a".to_string(),
            command: RepoUpdaterAdapterCommand::SyncDryRun,
            requested_at_unix_ms: 1_770_000_000_000,
            projects_root: PathBuf::from(REPO_UPDATER_CANONICAL_PROJECTS_ROOT),
            repo_specs: vec![
                "Dicklesworthstone/remote_compilation_helper".to_string(),
                "https://github.com/Dicklesworthstone/repo_updater".to_string(),
            ],
            idempotency_key: "idemp-123".to_string(),
            retry_attempt: 0,
            timeout_secs: 30,
            expected_output_format: RepoUpdaterOutputFormat::Json,
        }
    }

    #[test]
    fn repo_updater_contract_default_validates() {
        let contract = RepoUpdaterAdapterContract::default();
        contract.validate().expect("default contract must validate");
    }

    #[test]
    fn repo_updater_contract_command_surface_is_stable() {
        assert_eq!(
            RepoUpdaterAdapterCommand::SyncDryRun.args(),
            ["sync", "--dry-run", "--non-interactive", "--format", "json"]
        );
        assert_eq!(
            RepoUpdaterAdapterCommand::StatusNoFetch.args(),
            [
                "status",
                "--no-fetch",
                "--non-interactive",
                "--format",
                "json"
            ]
        );
        assert_eq!(
            RepoUpdaterAdapterCommand::RobotDocsSchemas.args(),
            ["robot-docs", "schemas", "--format", "json"]
        );
    }

    #[test]
    fn repo_updater_contract_rejects_invalid_projects_root() {
        let contract = RepoUpdaterAdapterContract::default();
        let request = RepoUpdaterAdapterRequest {
            projects_root: PathBuf::from("/tmp/not-allowed"),
            ..sample_request()
        };
        let err = request
            .validate(&contract)
            .expect_err("must reject invalid root");
        assert!(matches!(
            err,
            RepoUpdaterContractError::InvalidProjectsRoot(_)
        ));
    }

    #[test]
    fn repo_updater_contract_accepts_dp_alias_projects_root() {
        let contract = RepoUpdaterAdapterContract::default();
        let request = RepoUpdaterAdapterRequest {
            projects_root: PathBuf::from(REPO_UPDATER_ALIAS_PROJECTS_ROOT),
            ..sample_request()
        };
        request
            .validate(&contract)
            .expect("alias /dp should be accepted");
    }

    #[test]
    fn repo_updater_contract_rejects_untrusted_repo_host() {
        let contract = RepoUpdaterAdapterContract::default();
        let request = RepoUpdaterAdapterRequest {
            repo_specs: vec!["https://gitlab.com/example/repo".to_string()],
            ..sample_request()
        };
        let err = request.validate(&contract).expect_err("must reject host");
        assert!(matches!(
            err,
            RepoUpdaterContractError::UnsupportedRepoHost(_)
        ));
    }

    #[test]
    fn repo_updater_contract_version_compatibility_matrix() {
        let policy = RepoUpdaterVersionPolicy::default();
        assert_eq!(
            evaluate_version_compatibility("1.2.1", &policy),
            RepoUpdaterVersionCompatibility::Compatible
        );
        assert_eq!(
            evaluate_version_compatibility("1.1.9", &policy),
            RepoUpdaterVersionCompatibility::TooOld
        );
        assert_eq!(
            evaluate_version_compatibility("2.0.0", &policy),
            RepoUpdaterVersionCompatibility::NewerMajorUnsupported
        );
        assert_eq!(
            evaluate_version_compatibility("abc", &policy),
            RepoUpdaterVersionCompatibility::InvalidVersion
        );
    }

    #[test]
    fn repo_updater_contract_exit_code_mapping() {
        assert_eq!(classify_exit_code(0), RepoUpdaterExitDisposition::Success);
        assert_eq!(
            classify_exit_code(1),
            RepoUpdaterExitDisposition::PartialFailure
        );
        assert_eq!(classify_exit_code(2), RepoUpdaterExitDisposition::Conflicts);
        assert_eq!(classify_exit_code(99), RepoUpdaterExitDisposition::Unknown);
    }

    #[test]
    fn repo_updater_contract_error_mapping_is_stable() {
        assert_eq!(
            map_failure_kind_to_error_code(RepoUpdaterFailureKind::Timeout),
            ErrorCode::TransferTimeout
        );
        assert_eq!(
            map_failure_kind_to_error_code(RepoUpdaterFailureKind::AuthFailure),
            ErrorCode::SshAuthFailed
        );
        assert_eq!(
            map_failure_kind_to_error_code(RepoUpdaterFailureKind::InvalidEnvelope),
            ErrorCode::InternalSerdeError
        );
    }

    #[test]
    fn repo_updater_contract_build_invocation_sets_projects_root_and_idempotency_key() {
        let contract = RepoUpdaterAdapterContract::default();
        let request = sample_request();
        let invocation = build_invocation(&request, &contract);

        assert_eq!(invocation.binary, "ru");
        assert!(invocation.args.contains(&"sync".to_string()));
        assert!(
            invocation
                .env
                .iter()
                .any(|(k, v)| k == "RU_PROJECTS_DIR" && v == REPO_UPDATER_CANONICAL_PROJECTS_ROOT)
        );
        assert!(
            invocation
                .env
                .iter()
                .any(|(k, v)| k == "RCH_REPO_IDEMPOTENCY_KEY" && v == "idemp-123")
        );
    }

    #[test]
    fn repo_updater_contract_mock_adapter_records_calls_and_returns_scripted_result() {
        let adapter = MockRepoUpdaterAdapter::default();
        let contract = RepoUpdaterAdapterContract::default();
        let request = sample_request();

        let scripted = RepoUpdaterAdapterResponse {
            schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
            correlation_id: request.correlation_id.clone(),
            command: request.command,
            adapter_version: "1.2.1".to_string(),
            status: RepoUpdaterResponseStatus::Success,
            idempotency_guarantee: request.command.idempotency(),
            fallback_applied: false,
            sync_summary: Some(RepoUpdaterSyncSummary {
                total: 2,
                cloned: 0,
                pulled: 1,
                skipped: 1,
                failed: 0,
            }),
            repos: vec![RepoUpdaterRepoRecord {
                repo: "Dicklesworthstone/remote_compilation_helper".to_string(),
                path: Some(PathBuf::from("/data/projects/remote_compilation_helper")),
                action: Some("pull".to_string()),
                status: Some("updated".to_string()),
                dirty: Some(false),
                ahead: Some(0),
                behind: Some(0),
            }],
            envelope_meta: Some(RepoUpdaterEnvelopeMeta {
                duration_seconds: Some(2),
                exit_code: Some(0),
            }),
            failure: None,
        };
        adapter.push_result(Ok(scripted.clone()));

        let result = adapter
            .execute(&request, &contract)
            .expect("scripted success should be returned");
        assert_eq!(result, scripted);

        let calls = adapter.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].idempotency_key, "idemp-123");
    }

    #[test]
    fn repo_updater_contract_schema_contains_core_fields() {
        let request_schema = repo_updater_request_schema();
        let request_json = serde_json::to_value(&request_schema).expect("schema to value");
        let request_props = request_json
            .get("properties")
            .and_then(|props| props.as_object())
            .or_else(|| {
                request_json
                    .get("definitions")
                    .and_then(|defs| defs.get("RepoUpdaterAdapterRequest"))
                    .and_then(|node| node.get("properties"))
                    .and_then(|props| props.as_object())
            })
            .expect("request properties");
        assert!(request_props.contains_key("schema_version"));
        assert!(request_props.contains_key("projects_root"));
        assert!(request_props.contains_key("idempotency_key"));

        let response_schema = repo_updater_response_schema();
        let response_json = serde_json::to_value(&response_schema).expect("schema to value");
        let response_props = response_json
            .get("properties")
            .and_then(|props| props.as_object())
            .or_else(|| {
                response_json
                    .get("definitions")
                    .and_then(|defs| defs.get("RepoUpdaterAdapterResponse"))
                    .and_then(|node| node.get("properties"))
                    .and_then(|props| props.as_object())
            })
            .expect("response properties");
        assert!(response_props.contains_key("status"));
        assert!(response_props.contains_key("failure"));
    }

    #[test]
    fn repo_updater_contract_envelope_parser_compatibility() {
        let json = r#"{
            "generated_at":"2026-02-16T21:00:00Z",
            "version":"1.2.1",
            "output_format":"json",
            "command":"sync",
            "data":{"summary":{"total":1,"cloned":0,"pulled":1,"skipped":0,"failed":0}},
            "meta":{"duration_seconds":2,"exit_code":0}
        }"#;
        let envelope: RepoUpdaterJsonEnvelope =
            serde_json::from_str(json).expect("must parse stable envelope");
        assert_eq!(envelope.version, "1.2.1");
        assert_eq!(envelope.command, "sync");
        assert_eq!(envelope.output_format, RepoUpdaterOutputFormat::Json);
        assert_eq!(
            envelope
                .meta
                .expect("meta should be present")
                .exit_code
                .expect("exit code present"),
            0
        );
    }
}
