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
/// Env flag enabling operator override handling in trust policy.
pub const REPO_UPDATER_ALLOW_OVERRIDE_ENV: &str = "RCH_REPO_CONVERGENCE_ALLOW_OVERRIDE";
/// Env var for comma-separated repo allowlist used by repo convergence.
pub const REPO_UPDATER_ALLOWLIST_ENV: &str = "RCH_REPO_CONVERGENCE_ALLOWLIST";
/// Env var for comma-separated host allowlist used by repo convergence.
pub const REPO_UPDATER_ALLOWED_HOSTS_ENV: &str = "RCH_REPO_CONVERGENCE_ALLOWED_HOSTS";
/// Override metadata env: operator identifier.
pub const REPO_UPDATER_OVERRIDE_OPERATOR_ID_ENV: &str = "RCH_REPO_OVERRIDE_OPERATOR_ID";
/// Override metadata env: human-readable justification.
pub const REPO_UPDATER_OVERRIDE_JUSTIFICATION_ENV: &str = "RCH_REPO_OVERRIDE_JUSTIFICATION";
/// Override metadata env: ticket or change-request identifier.
pub const REPO_UPDATER_OVERRIDE_TICKET_REF_ENV: &str = "RCH_REPO_OVERRIDE_TICKET_REF";
/// Override metadata env: durable audit event identifier.
pub const REPO_UPDATER_OVERRIDE_AUDIT_EVENT_ID_ENV: &str = "RCH_REPO_OVERRIDE_AUDIT_EVENT_ID";
/// Override metadata env: approval timestamp (unix ms).
pub const REPO_UPDATER_OVERRIDE_APPROVED_AT_MS_ENV: &str = "RCH_REPO_OVERRIDE_APPROVED_AT_MS";
/// Auth metadata env: credential source (`gh_cli`, `token_env`, `ssh_agent`).
pub const REPO_UPDATER_AUTH_SOURCE_ENV: &str = "RCH_REPO_AUTH_SOURCE";
/// Auth policy env: required auth mode (`inherit_environment|require_gh_auth|require_token_env`).
pub const REPO_UPDATER_AUTH_MODE_ENV: &str = "RCH_REPO_AUTH_MODE";
/// Auth metadata env: credential identifier/fingerprint.
pub const REPO_UPDATER_AUTH_CREDENTIAL_ID_ENV: &str = "RCH_REPO_AUTH_CREDENTIAL_ID";
/// Auth metadata env: credential issued-at timestamp (unix ms).
pub const REPO_UPDATER_AUTH_ISSUED_AT_MS_ENV: &str = "RCH_REPO_AUTH_ISSUED_AT_MS";
/// Auth metadata env: credential expires-at timestamp (unix ms).
pub const REPO_UPDATER_AUTH_EXPIRES_AT_MS_ENV: &str = "RCH_REPO_AUTH_EXPIRES_AT_MS";
/// Auth metadata env: comma-separated granted scopes.
pub const REPO_UPDATER_AUTH_SCOPES_ENV: &str = "RCH_REPO_AUTH_SCOPES";
/// Auth metadata env: explicit revocation flag.
pub const REPO_UPDATER_AUTH_REVOKED_ENV: &str = "RCH_REPO_AUTH_REVOKED";
/// Auth metadata env: comma-separated `host=fingerprint` verified identities.
pub const REPO_UPDATER_AUTH_VERIFIED_HOSTS_ENV: &str = "RCH_REPO_AUTH_VERIFIED_HOSTS";
/// Auth policy env: comma-separated required scopes.
pub const REPO_UPDATER_REQUIRED_SCOPES_ENV: &str = "RCH_REPO_REQUIRED_SCOPES";
/// Auth policy env: max credential age in seconds before rotation is required.
pub const REPO_UPDATER_ROTATION_MAX_AGE_SECS_ENV: &str = "RCH_REPO_AUTH_ROTATION_MAX_AGE_SECS";
/// Auth policy env: require host identity verification (`1|true|yes|on`).
pub const REPO_UPDATER_REQUIRE_HOST_IDENTITY_ENV: &str = "RCH_REPO_REQUIRE_HOST_IDENTITY";
/// Auth policy env: comma-separated `host=fingerprint` trusted host identities.
pub const REPO_UPDATER_TRUSTED_HOST_IDENTITIES_ENV: &str = "RCH_REPO_TRUSTED_HOST_IDENTITIES";

const fn default_enforce_repo_spec_allowlist() -> bool {
    true
}

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
            // Use `--json` global flag for backward compatibility with older
            // repo_updater versions that do not support `--format json`.
            Self::ListPaths => &["list", "--paths", "--non-interactive", "--json"],
            Self::StatusNoFetch => &["status", "--no-fetch", "--non-interactive", "--json"],
            Self::SyncDryRun => &["sync", "--dry-run", "--non-interactive", "--json"],
            Self::SyncApply => &["sync", "--non-interactive", "--json"],
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
    #[serde(default = "default_enforce_repo_spec_allowlist")]
    pub enforce_repo_spec_allowlist: bool,
    #[serde(default)]
    pub allowlisted_repo_specs: Vec<String>,
    pub allow_owner_repo_shorthand: bool,
    pub reject_local_path_specs: bool,
    #[serde(default)]
    pub allow_operator_override: bool,
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
            enforce_repo_spec_allowlist: true,
            allowlisted_repo_specs: Vec::new(),
            allow_owner_repo_shorthand: true,
            reject_local_path_specs: true,
            allow_operator_override: false,
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

/// Credential source asserted for a convergence request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoUpdaterCredentialSource {
    GhCli,
    TokenEnv,
    SshAgent,
}

/// Trusted host key binding used for identity verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterTrustedHostIdentity {
    pub host: String,
    pub key_fingerprint: String,
}

/// Verified host identity record observed for a specific request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterVerifiedHostIdentity {
    pub host: String,
    pub key_fingerprint: String,
    pub verified_at_unix_ms: i64,
}

/// Request-scoped credential and identity context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterAuthContext {
    pub source: RepoUpdaterCredentialSource,
    pub credential_id: String,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub granted_scopes: Vec<String>,
    pub revoked: bool,
    pub verified_hosts: Vec<RepoUpdaterVerifiedHostIdentity>,
}

/// Auth-related policy constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterAuthPolicy {
    pub mode: RepoUpdaterAuthMode,
    pub required_env_vars: Vec<String>,
    pub redacted_env_vars: Vec<String>,
    pub required_scopes: Vec<String>,
    pub rotation_max_age_secs: u64,
    pub require_host_identity_verification: bool,
    pub trusted_host_identities: Vec<RepoUpdaterTrustedHostIdentity>,
}

impl Default for RepoUpdaterAuthPolicy {
    fn default() -> Self {
        Self {
            mode: RepoUpdaterAuthMode::RequireTokenEnv,
            required_env_vars: Vec::new(),
            redacted_env_vars: vec!["GH_TOKEN".to_string(), "GITHUB_TOKEN".to_string()],
            required_scopes: vec!["repo:read".to_string()],
            rotation_max_age_secs: 86_400,
            require_host_identity_verification: true,
            trusted_host_identities: vec![RepoUpdaterTrustedHostIdentity {
                host: "github.com".to_string(),
                key_fingerprint: "SHA256:+DiY3wvvV6TuJJhbpZisF/J84OHwY2l7uxD9f4HBlz8".to_string(),
            }],
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_context: Option<RepoUpdaterAuthContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_override: Option<RepoUpdaterOperatorOverride>,
}

/// Explicit operator override metadata for convergence-scope exceptions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoUpdaterOperatorOverride {
    pub operator_id: String,
    pub justification: String,
    pub ticket_ref: String,
    pub audit_event_id: String,
    pub approved_at_unix_ms: i64,
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
    #[error("repo spec is not allowlisted: {0}")]
    RepoSpecNotAllowlisted(String),
    #[error("local path repo spec denied by policy: {0}")]
    LocalPathSpecDenied(String),
    #[error("operator override is required for unallowlisted repo specs")]
    OperatorOverrideRequired,
    #[error("operator override is disabled by policy")]
    OperatorOverrideDisabled,
    #[error("operator override metadata is malformed: {0}")]
    MalformedOperatorOverride(String),
    #[error("malformed trust policy: {0}")]
    MalformedTrustPolicy(String),
    #[error("missing auth context for mutating convergence command")]
    MissingAuthContext,
    #[error("credential source {actual:?} is not permitted for auth mode {mode:?}")]
    AuthSourceMismatch {
        mode: RepoUpdaterAuthMode,
        actual: RepoUpdaterCredentialSource,
    },
    #[error("credential has been explicitly revoked")]
    AuthCredentialRevoked,
    #[error("credential expired at {expires_at_unix_ms}")]
    AuthCredentialExpired { expires_at_unix_ms: i64 },
    #[error("credential age exceeds rotation policy (age={age_secs}s max={max_age_secs}s)")]
    AuthCredentialTooOld { age_secs: u64, max_age_secs: u64 },
    #[error("credential is missing required scope: {0}")]
    AuthScopeDenied(String),
    #[error("host identity missing for {0}")]
    HostIdentityMissing(String),
    #[error("host identity mismatch for {host} (expected {expected}, got {actual})")]
    HostIdentityMismatch {
        host: String,
        expected: String,
        actual: String,
    },
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

impl RepoUpdaterContractError {
    /// Stable deterministic reason code for diagnostics and automation.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::SchemaVersionMismatch { .. } => "RU_POLICY_SCHEMA_VERSION_MISMATCH",
            Self::InvalidProjectsRoot(_) => "RU_POLICY_PROJECTS_ROOT_OUT_OF_SCOPE",
            Self::UnsupportedRepoHost(_) => "RU_POLICY_REPO_HOST_DENIED",
            Self::RepoSpecNotAllowlisted(_) => "RU_POLICY_REPO_SPEC_NOT_ALLOWLISTED",
            Self::LocalPathSpecDenied(_) => "RU_POLICY_LOCAL_PATH_SPEC_DENIED",
            Self::OperatorOverrideRequired => "RU_POLICY_OPERATOR_OVERRIDE_REQUIRED",
            Self::OperatorOverrideDisabled => "RU_POLICY_OPERATOR_OVERRIDE_DISABLED",
            Self::MalformedOperatorOverride(_) => "RU_POLICY_OPERATOR_OVERRIDE_MALFORMED",
            Self::MalformedTrustPolicy(_) => "RU_POLICY_TRUST_POLICY_MALFORMED",
            Self::MissingAuthContext => "RU_AUTH_CONTEXT_MISSING",
            Self::AuthSourceMismatch { .. } => "RU_AUTH_SOURCE_MISMATCH",
            Self::AuthCredentialRevoked => "RU_AUTH_CREDENTIAL_REVOKED",
            Self::AuthCredentialExpired { .. } => "RU_AUTH_CREDENTIAL_EXPIRED",
            Self::AuthCredentialTooOld { .. } => "RU_AUTH_ROTATION_REQUIRED",
            Self::AuthScopeDenied(_) => "RU_AUTH_SCOPE_DENIED",
            Self::HostIdentityMissing(_) => "RU_HOST_IDENTITY_MISSING",
            Self::HostIdentityMismatch { .. } => "RU_HOST_IDENTITY_MISMATCH",
            Self::MissingIdempotencyKey => "RU_POLICY_MISSING_IDEMPOTENCY_KEY",
            Self::InvalidTimeout(_) => "RU_POLICY_INVALID_TIMEOUT",
            Self::RetryAttemptExceeded { .. } => "RU_POLICY_RETRY_ATTEMPT_EXCEEDED",
            Self::EmptyHostAllowlist => "RU_POLICY_EMPTY_HOST_ALLOWLIST",
            Self::DuplicateCommandBudget(_) => "RU_POLICY_DUPLICATE_COMMAND_BUDGET",
        }
    }

    /// Operator-facing remediation guidance aligned with reason_code().
    #[must_use]
    pub const fn remediation(&self) -> &'static str {
        match self {
            Self::SchemaVersionMismatch { .. } => {
                "Align repo_updater and RCH contract schema versions before retrying."
            }
            Self::InvalidProjectsRoot(_) => {
                "Use /data/projects (or /dp alias) as projects_root; traversal and out-of-scope paths are denied."
            }
            Self::UnsupportedRepoHost(_) => {
                "Add the repo host to the trust-policy host allowlist or use an approved host."
            }
            Self::RepoSpecNotAllowlisted(_) => {
                "Add the repo spec to the explicit convergence allowlist, or provide an operator override."
            }
            Self::LocalPathSpecDenied(_) => {
                "Use remote repo specs (hosted) or relax local-path policy explicitly."
            }
            Self::OperatorOverrideRequired => {
                "Provide explicit operator override metadata with audit fields for this request."
            }
            Self::OperatorOverrideDisabled => {
                "Enable operator overrides in trust policy before sending override metadata."
            }
            Self::MalformedOperatorOverride(_) => {
                "Populate all required override fields: operator_id, justification, ticket_ref, audit_event_id, approved_at_unix_ms."
            }
            Self::MalformedTrustPolicy(_) => {
                "Fix malformed trust policy entries (empty allowlist rows, unsupported host mappings, or invalid values)."
            }
            Self::MissingAuthContext => {
                "Provide authenticated credential context for mutating repo convergence operations."
            }
            Self::AuthSourceMismatch { .. } => {
                "Use the credential source required by auth policy (gh_cli/token_env) before retrying."
            }
            Self::AuthCredentialRevoked => {
                "Rotate to a non-revoked credential and update the worker-side secret source."
            }
            Self::AuthCredentialExpired { .. } => {
                "Refresh credentials and retry with a non-expired token/key."
            }
            Self::AuthCredentialTooOld { .. } => {
                "Rotate credentials to satisfy the maximum credential age policy."
            }
            Self::AuthScopeDenied(_) => {
                "Grant the missing scope (least privilege) or adjust policy requirements."
            }
            Self::HostIdentityMissing(_) => {
                "Collect and attach verified host identity metadata for each repo host."
            }
            Self::HostIdentityMismatch { .. } => {
                "Fix host-key trust configuration or re-verify host identity before convergence."
            }
            Self::MissingIdempotencyKey => "Set a stable idempotency_key for convergence requests.",
            Self::InvalidTimeout(_) => "Use a timeout_secs value greater than zero.",
            Self::RetryAttemptExceeded { .. } => {
                "Reset retry_attempt or increase max_attempts in retry policy."
            }
            Self::EmptyHostAllowlist => "Configure at least one allowed repo host.",
            Self::DuplicateCommandBudget(_) => {
                "Remove duplicate command budgets so each command has a single timeout policy."
            }
        }
    }

    /// Canonical failure taxonomy bucket for this validation error.
    #[must_use]
    pub const fn failure_kind(&self) -> RepoUpdaterFailureKind {
        match self {
            Self::MissingAuthContext
            | Self::AuthSourceMismatch { .. }
            | Self::AuthCredentialRevoked
            | Self::AuthCredentialExpired { .. }
            | Self::AuthCredentialTooOld { .. }
            | Self::AuthScopeDenied(_) => RepoUpdaterFailureKind::AuthFailure,
            Self::HostIdentityMissing(_) | Self::HostIdentityMismatch { .. } => {
                RepoUpdaterFailureKind::HostValidationFailed
            }
            _ => RepoUpdaterFailureKind::TrustBoundaryViolation,
        }
    }
}

impl RepoUpdaterAdapterContract {
    /// Validate contract-level invariants.
    pub fn validate(&self) -> Result<(), RepoUpdaterContractError> {
        if self.trust_policy.allowed_repo_hosts.is_empty() {
            return Err(RepoUpdaterContractError::EmptyHostAllowlist);
        }

        for allowlisted_spec in &self.trust_policy.allowlisted_repo_specs {
            if allowlisted_spec.trim().is_empty() {
                return Err(RepoUpdaterContractError::MalformedTrustPolicy(
                    "allowlisted_repo_specs contains empty entry".to_string(),
                ));
            }

            if let Some(host) = extract_repo_host(
                allowlisted_spec,
                self.trust_policy.allow_owner_repo_shorthand,
            ) {
                let host_allowed = self
                    .trust_policy
                    .allowed_repo_hosts
                    .iter()
                    .any(|allowed_host| allowed_host.eq_ignore_ascii_case(&host));
                if !host_allowed {
                    return Err(RepoUpdaterContractError::MalformedTrustPolicy(format!(
                        "allowlisted spec '{}' references host '{}' not present in allowed_repo_hosts",
                        allowlisted_spec, host
                    )));
                }
            } else if self.trust_policy.reject_local_path_specs {
                return Err(RepoUpdaterContractError::MalformedTrustPolicy(format!(
                    "allowlisted spec '{}' is local-path-like but reject_local_path_specs=true",
                    allowlisted_spec
                )));
            }
        }

        if self.auth_policy.rotation_max_age_secs == 0 {
            return Err(RepoUpdaterContractError::MalformedTrustPolicy(
                "auth_policy.rotation_max_age_secs must be > 0".to_string(),
            ));
        }
        for scope in &self.auth_policy.required_scopes {
            if scope.trim().is_empty() {
                return Err(RepoUpdaterContractError::MalformedTrustPolicy(
                    "auth_policy.required_scopes contains empty entry".to_string(),
                ));
            }
        }
        if self.auth_policy.require_host_identity_verification
            && self.auth_policy.trusted_host_identities.is_empty()
        {
            return Err(RepoUpdaterContractError::MalformedTrustPolicy(
                "auth_policy.require_host_identity_verification=true but trusted_host_identities is empty".to_string(),
            ));
        }
        for identity in &self.auth_policy.trusted_host_identities {
            if identity.host.trim().is_empty() || identity.key_fingerprint.trim().is_empty() {
                return Err(RepoUpdaterContractError::MalformedTrustPolicy(
                    "auth_policy.trusted_host_identities contains empty host or fingerprint"
                        .to_string(),
                ));
            }
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
        contract.validate()?;
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

        let operator_override_active = if let Some(override_metadata) = &self.operator_override {
            if !contract.trust_policy.allow_operator_override {
                return Err(RepoUpdaterContractError::OperatorOverrideDisabled);
            }
            validate_operator_override(override_metadata)?;
            true
        } else {
            false
        };

        if self.command.mutating() {
            validate_auth_context(self, contract)?;
        }

        for spec in &self.repo_specs {
            let normalized_spec = spec.trim();
            if normalized_spec.is_empty() {
                return Err(RepoUpdaterContractError::MalformedTrustPolicy(
                    "repo_specs contains empty entry".to_string(),
                ));
            }

            if let Some(host) = extract_repo_host(
                normalized_spec,
                contract.trust_policy.allow_owner_repo_shorthand,
            ) {
                let allowed = contract
                    .trust_policy
                    .allowed_repo_hosts
                    .iter()
                    .any(|allowed_host| allowed_host.eq_ignore_ascii_case(&host));
                if !allowed {
                    return Err(RepoUpdaterContractError::UnsupportedRepoHost(host));
                }
            } else if contract.trust_policy.reject_local_path_specs {
                return Err(RepoUpdaterContractError::LocalPathSpecDenied(
                    normalized_spec.to_string(),
                ));
            }

            if contract.trust_policy.enforce_repo_spec_allowlist
                && !repo_spec_is_allowlisted(
                    normalized_spec,
                    &contract.trust_policy.allowlisted_repo_specs,
                )
            {
                if operator_override_active {
                    continue;
                }
                if contract.trust_policy.allow_operator_override {
                    return Err(RepoUpdaterContractError::OperatorOverrideRequired);
                }
                return Err(RepoUpdaterContractError::RepoSpecNotAllowlisted(
                    normalized_spec.to_string(),
                ));
            }
        }

        Ok(())
    }
}

fn validate_auth_context(
    request: &RepoUpdaterAdapterRequest,
    contract: &RepoUpdaterAdapterContract,
) -> Result<(), RepoUpdaterContractError> {
    let Some(auth_context) = request.auth_context.as_ref() else {
        return Err(RepoUpdaterContractError::MissingAuthContext);
    };

    if auth_context.credential_id.trim().is_empty() {
        return Err(RepoUpdaterContractError::MalformedTrustPolicy(
            "auth_context.credential_id is empty".to_string(),
        ));
    }
    if auth_context.revoked {
        return Err(RepoUpdaterContractError::AuthCredentialRevoked);
    }
    if auth_context.expires_at_unix_ms <= request.requested_at_unix_ms {
        return Err(RepoUpdaterContractError::AuthCredentialExpired {
            expires_at_unix_ms: auth_context.expires_at_unix_ms,
        });
    }
    if auth_context.issued_at_unix_ms <= 0 {
        return Err(RepoUpdaterContractError::MalformedTrustPolicy(
            "auth_context.issued_at_unix_ms must be > 0".to_string(),
        ));
    }
    let credential_age_ms = request.requested_at_unix_ms - auth_context.issued_at_unix_ms;
    if credential_age_ms < 0 {
        return Err(RepoUpdaterContractError::MalformedTrustPolicy(
            "auth_context.issued_at_unix_ms cannot be in the future".to_string(),
        ));
    }
    let credential_age_secs = (credential_age_ms / 1_000) as u64;
    if credential_age_secs > contract.auth_policy.rotation_max_age_secs {
        return Err(RepoUpdaterContractError::AuthCredentialTooOld {
            age_secs: credential_age_secs,
            max_age_secs: contract.auth_policy.rotation_max_age_secs,
        });
    }

    match contract.auth_policy.mode {
        RepoUpdaterAuthMode::InheritEnvironment => {}
        RepoUpdaterAuthMode::RequireGhAuth => {
            if auth_context.source != RepoUpdaterCredentialSource::GhCli {
                return Err(RepoUpdaterContractError::AuthSourceMismatch {
                    mode: RepoUpdaterAuthMode::RequireGhAuth,
                    actual: auth_context.source,
                });
            }
        }
        RepoUpdaterAuthMode::RequireTokenEnv => {
            if auth_context.source != RepoUpdaterCredentialSource::TokenEnv {
                return Err(RepoUpdaterContractError::AuthSourceMismatch {
                    mode: RepoUpdaterAuthMode::RequireTokenEnv,
                    actual: auth_context.source,
                });
            }
        }
    }

    for required_scope in &contract.auth_policy.required_scopes {
        let has_scope = auth_context
            .granted_scopes
            .iter()
            .any(|granted_scope| granted_scope.eq_ignore_ascii_case(required_scope));
        if !has_scope {
            return Err(RepoUpdaterContractError::AuthScopeDenied(
                required_scope.clone(),
            ));
        }
    }

    if contract.auth_policy.require_host_identity_verification {
        for spec in &request.repo_specs {
            let Some(host) =
                extract_repo_host(spec, contract.trust_policy.allow_owner_repo_shorthand)
            else {
                continue;
            };
            let Some(verified_host) = auth_context
                .verified_hosts
                .iter()
                .find(|identity| identity.host.eq_ignore_ascii_case(&host))
            else {
                return Err(RepoUpdaterContractError::HostIdentityMissing(host));
            };
            let Some(trusted_host) = contract
                .auth_policy
                .trusted_host_identities
                .iter()
                .find(|identity| identity.host.eq_ignore_ascii_case(&host))
            else {
                return Err(RepoUpdaterContractError::HostIdentityMissing(
                    verified_host.host.clone(),
                ));
            };
            if !verified_host
                .key_fingerprint
                .eq_ignore_ascii_case(&trusted_host.key_fingerprint)
            {
                return Err(RepoUpdaterContractError::HostIdentityMismatch {
                    host: host.clone(),
                    expected: trusted_host.key_fingerprint.clone(),
                    actual: verified_host.key_fingerprint.clone(),
                });
            }
        }
    }

    Ok(())
}

fn validate_operator_override(
    metadata: &RepoUpdaterOperatorOverride,
) -> Result<(), RepoUpdaterContractError> {
    if metadata.operator_id.trim().is_empty() {
        return Err(RepoUpdaterContractError::MalformedOperatorOverride(
            "operator_id is empty".to_string(),
        ));
    }
    if metadata.justification.trim().is_empty() {
        return Err(RepoUpdaterContractError::MalformedOperatorOverride(
            "justification is empty".to_string(),
        ));
    }
    if metadata.ticket_ref.trim().is_empty() {
        return Err(RepoUpdaterContractError::MalformedOperatorOverride(
            "ticket_ref is empty".to_string(),
        ));
    }
    if metadata.audit_event_id.trim().is_empty() {
        return Err(RepoUpdaterContractError::MalformedOperatorOverride(
            "audit_event_id is empty".to_string(),
        ));
    }
    if metadata.approved_at_unix_ms <= 0 {
        return Err(RepoUpdaterContractError::MalformedOperatorOverride(
            "approved_at_unix_ms must be > 0".to_string(),
        ));
    }
    Ok(())
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
            let failure_kind = error.failure_kind();
            return Err(RepoUpdaterFailure {
                kind: failure_kind,
                code: error.reason_code().to_string(),
                message: error.to_string(),
                mapped_rch_error: map_failure_kind_to_error_code(failure_kind).code_string(),
                remediation: vec![error.remediation().to_string()],
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

    let mut env = vec![
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

    if let Some(override_metadata) = &request.operator_override {
        env.push((
            REPO_UPDATER_OVERRIDE_OPERATOR_ID_ENV.to_string(),
            override_metadata.operator_id.clone(),
        ));
        env.push((
            REPO_UPDATER_OVERRIDE_JUSTIFICATION_ENV.to_string(),
            override_metadata.justification.clone(),
        ));
        env.push((
            REPO_UPDATER_OVERRIDE_TICKET_REF_ENV.to_string(),
            override_metadata.ticket_ref.clone(),
        ));
        env.push((
            REPO_UPDATER_OVERRIDE_AUDIT_EVENT_ID_ENV.to_string(),
            override_metadata.audit_event_id.clone(),
        ));
        env.push((
            REPO_UPDATER_OVERRIDE_APPROVED_AT_MS_ENV.to_string(),
            override_metadata.approved_at_unix_ms.to_string(),
        ));
    }
    if let Some(auth_context) = &request.auth_context {
        let source = match auth_context.source {
            RepoUpdaterCredentialSource::GhCli => "gh_cli",
            RepoUpdaterCredentialSource::TokenEnv => "token_env",
            RepoUpdaterCredentialSource::SshAgent => "ssh_agent",
        };
        env.push((REPO_UPDATER_AUTH_SOURCE_ENV.to_string(), source.to_string()));
        env.push((
            REPO_UPDATER_AUTH_CREDENTIAL_ID_ENV.to_string(),
            auth_context.credential_id.clone(),
        ));
        env.push((
            REPO_UPDATER_AUTH_ISSUED_AT_MS_ENV.to_string(),
            auth_context.issued_at_unix_ms.to_string(),
        ));
        env.push((
            REPO_UPDATER_AUTH_EXPIRES_AT_MS_ENV.to_string(),
            auth_context.expires_at_unix_ms.to_string(),
        ));
        env.push((
            REPO_UPDATER_AUTH_SCOPES_ENV.to_string(),
            auth_context.granted_scopes.join(","),
        ));
        env.push((
            REPO_UPDATER_AUTH_REVOKED_ENV.to_string(),
            auth_context.revoked.to_string(),
        ));
        let verified_hosts = auth_context
            .verified_hosts
            .iter()
            .map(|identity| format!("{}={}", identity.host, identity.key_fingerprint))
            .collect::<Vec<_>>()
            .join(",");
        env.push((
            REPO_UPDATER_AUTH_VERIFIED_HOSTS_ENV.to_string(),
            verified_hosts,
        ));
    }

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

fn normalize_repo_spec_for_allowlist(spec: &str) -> String {
    spec.trim()
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_string()
}

fn repo_spec_is_allowlisted(spec: &str, allowlist: &[String]) -> bool {
    let normalized = normalize_repo_spec_for_allowlist(spec);
    allowlist.iter().any(|allowlisted| {
        normalize_repo_spec_for_allowlist(allowlisted).eq_ignore_ascii_case(&normalized)
    })
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
            auth_context: None,
            operator_override: None,
        }
    }

    fn contract_with_allowlisted_sample_specs() -> RepoUpdaterAdapterContract {
        let mut contract = RepoUpdaterAdapterContract::default();
        contract.trust_policy.allowlisted_repo_specs = sample_request().repo_specs;
        contract
    }

    fn sample_sync_apply_request_with_auth() -> RepoUpdaterAdapterRequest {
        RepoUpdaterAdapterRequest {
            schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
            correlation_id: "corr-ru-auth-001".to_string(),
            worker_id: "worker-a".to_string(),
            command: RepoUpdaterAdapterCommand::SyncApply,
            requested_at_unix_ms: 1_770_000_500_000,
            projects_root: PathBuf::from(REPO_UPDATER_CANONICAL_PROJECTS_ROOT),
            repo_specs: vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()],
            idempotency_key: "idemp-auth-001".to_string(),
            retry_attempt: 0,
            timeout_secs: 60,
            expected_output_format: RepoUpdaterOutputFormat::Json,
            auth_context: Some(RepoUpdaterAuthContext {
                source: RepoUpdaterCredentialSource::TokenEnv,
                credential_id: "cred-123".to_string(),
                issued_at_unix_ms: 1_770_000_000_000,
                expires_at_unix_ms: 1_770_100_000_000,
                granted_scopes: vec!["repo:read".to_string(), "repo:status".to_string()],
                revoked: false,
                verified_hosts: vec![RepoUpdaterVerifiedHostIdentity {
                    host: "github.com".to_string(),
                    key_fingerprint: "SHA256:+DiY3wvvV6TuJJhbpZisF/J84OHwY2l7uxD9f4HBlz8"
                        .to_string(),
                    verified_at_unix_ms: 1_770_000_500_000,
                }],
            }),
            operator_override: None,
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
            ["sync", "--dry-run", "--non-interactive", "--json"]
        );
        assert_eq!(
            RepoUpdaterAdapterCommand::StatusNoFetch.args(),
            ["status", "--no-fetch", "--non-interactive", "--json"]
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
        let contract = contract_with_allowlisted_sample_specs();
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
    fn repo_updater_contract_default_deny_rejects_unallowlisted_specs() {
        let contract = RepoUpdaterAdapterContract::default();
        let request = sample_request();
        let err = request
            .validate(&contract)
            .expect_err("default policy should deny unallowlisted repos");
        assert!(matches!(
            err,
            RepoUpdaterContractError::RepoSpecNotAllowlisted(_)
        ));
        assert_eq!(err.reason_code(), "RU_POLICY_REPO_SPEC_NOT_ALLOWLISTED");
    }

    #[test]
    fn repo_updater_contract_allowlist_allows_explicit_spec_set() {
        let contract = contract_with_allowlisted_sample_specs();
        sample_request()
            .validate(&contract)
            .expect("allowlisted repo specs should pass validation");
    }

    #[test]
    fn repo_updater_contract_rejects_projects_root_traversal() {
        let contract = contract_with_allowlisted_sample_specs();
        let request = RepoUpdaterAdapterRequest {
            projects_root: PathBuf::from("/dp/../tmp"),
            ..sample_request()
        };
        let err = request
            .validate(&contract)
            .expect_err("traversal/out-of-scope roots must be rejected");
        assert!(matches!(
            err,
            RepoUpdaterContractError::InvalidProjectsRoot(_)
        ));
        assert_eq!(err.reason_code(), "RU_POLICY_PROJECTS_ROOT_OUT_OF_SCOPE");
    }

    #[test]
    fn repo_updater_contract_operator_override_allows_exception_with_audit_metadata() {
        let mut contract = RepoUpdaterAdapterContract::default();
        contract.trust_policy.allow_operator_override = true;

        let request = RepoUpdaterAdapterRequest {
            operator_override: Some(RepoUpdaterOperatorOverride {
                operator_id: "ops-user".to_string(),
                justification: "Emergency sync required for release gate".to_string(),
                ticket_ref: "OPS-42".to_string(),
                audit_event_id: "audit-evt-0001".to_string(),
                approved_at_unix_ms: 1_770_000_123_000,
            }),
            ..sample_request()
        };

        request
            .validate(&contract)
            .expect("valid operator override should satisfy default-deny allowlist");
    }

    #[test]
    fn repo_updater_contract_operator_override_requires_enablement() {
        let request = RepoUpdaterAdapterRequest {
            operator_override: Some(RepoUpdaterOperatorOverride {
                operator_id: "ops-user".to_string(),
                justification: "Approved".to_string(),
                ticket_ref: "OPS-43".to_string(),
                audit_event_id: "audit-evt-0002".to_string(),
                approved_at_unix_ms: 1_770_000_223_000,
            }),
            ..sample_request()
        };

        let err = request
            .validate(&RepoUpdaterAdapterContract::default())
            .expect_err("override must be rejected when allow_operator_override=false");
        assert!(matches!(
            err,
            RepoUpdaterContractError::OperatorOverrideDisabled
        ));
        assert_eq!(err.reason_code(), "RU_POLICY_OPERATOR_OVERRIDE_DISABLED");
    }

    #[test]
    fn repo_updater_contract_rejects_malformed_operator_override() {
        let mut contract = RepoUpdaterAdapterContract::default();
        contract.trust_policy.allow_operator_override = true;

        let request = RepoUpdaterAdapterRequest {
            operator_override: Some(RepoUpdaterOperatorOverride {
                operator_id: "ops-user".to_string(),
                justification: "".to_string(),
                ticket_ref: "OPS-44".to_string(),
                audit_event_id: "audit-evt-0003".to_string(),
                approved_at_unix_ms: 1_770_000_323_000,
            }),
            ..sample_request()
        };

        let err = request
            .validate(&contract)
            .expect_err("malformed override metadata must be rejected");
        assert!(matches!(
            err,
            RepoUpdaterContractError::MalformedOperatorOverride(_)
        ));
        assert_eq!(err.reason_code(), "RU_POLICY_OPERATOR_OVERRIDE_MALFORMED");
    }

    #[test]
    fn repo_updater_contract_rejects_malformed_allowlist_policy() {
        let mut contract = RepoUpdaterAdapterContract::default();
        contract.trust_policy.allowlisted_repo_specs = vec![" ".to_string()];
        let err = contract
            .validate()
            .expect_err("empty allowlist entries should fail validation");
        assert!(matches!(
            err,
            RepoUpdaterContractError::MalformedTrustPolicy(_)
        ));
        assert_eq!(err.reason_code(), "RU_POLICY_TRUST_POLICY_MALFORMED");
    }

    #[test]
    fn repo_updater_contract_requires_auth_context_for_sync_apply() {
        let mut contract = RepoUpdaterAdapterContract::default();
        contract.trust_policy.allowlisted_repo_specs =
            vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
        let mut request = sample_sync_apply_request_with_auth();
        request.auth_context = None;

        let err = request
            .validate(&contract)
            .expect_err("mutating convergence must require auth context");
        assert!(matches!(err, RepoUpdaterContractError::MissingAuthContext));
        assert_eq!(err.reason_code(), "RU_AUTH_CONTEXT_MISSING");
        assert_eq!(err.failure_kind(), RepoUpdaterFailureKind::AuthFailure);
    }

    #[test]
    fn repo_updater_contract_rejects_expired_credentials() {
        let mut contract = RepoUpdaterAdapterContract::default();
        contract.trust_policy.allowlisted_repo_specs =
            vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
        let mut request = sample_sync_apply_request_with_auth();
        request
            .auth_context
            .as_mut()
            .expect("auth context present")
            .expires_at_unix_ms = 1_769_999_999_000;

        let err = request
            .validate(&contract)
            .expect_err("expired credentials must be rejected");
        assert!(matches!(
            err,
            RepoUpdaterContractError::AuthCredentialExpired { .. }
        ));
        assert_eq!(err.reason_code(), "RU_AUTH_CREDENTIAL_EXPIRED");
    }

    #[test]
    fn repo_updater_contract_rejects_revoked_credentials() {
        let mut contract = RepoUpdaterAdapterContract::default();
        contract.trust_policy.allowlisted_repo_specs =
            vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
        let mut request = sample_sync_apply_request_with_auth();
        request
            .auth_context
            .as_mut()
            .expect("auth context present")
            .revoked = true;

        let err = request
            .validate(&contract)
            .expect_err("revoked credentials must be rejected");
        assert!(matches!(
            err,
            RepoUpdaterContractError::AuthCredentialRevoked
        ));
        assert_eq!(err.reason_code(), "RU_AUTH_CREDENTIAL_REVOKED");
    }

    #[test]
    fn repo_updater_contract_rejects_missing_required_scope() {
        let mut contract = RepoUpdaterAdapterContract::default();
        contract.trust_policy.allowlisted_repo_specs =
            vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
        contract.auth_policy.required_scopes = vec!["repo:write".to_string()];
        let request = sample_sync_apply_request_with_auth();

        let err = request
            .validate(&contract)
            .expect_err("missing scope should fail auth validation");
        assert!(matches!(err, RepoUpdaterContractError::AuthScopeDenied(_)));
        assert_eq!(err.reason_code(), "RU_AUTH_SCOPE_DENIED");
    }

    #[test]
    fn repo_updater_contract_rejects_invalid_credential_source() {
        let mut contract = RepoUpdaterAdapterContract::default();
        contract.trust_policy.allowlisted_repo_specs =
            vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
        contract.auth_policy.mode = RepoUpdaterAuthMode::RequireGhAuth;
        let request = sample_sync_apply_request_with_auth();

        let err = request
            .validate(&contract)
            .expect_err("source mismatch should fail auth-mode checks");
        assert!(matches!(
            err,
            RepoUpdaterContractError::AuthSourceMismatch { .. }
        ));
        assert_eq!(err.reason_code(), "RU_AUTH_SOURCE_MISMATCH");
    }

    #[test]
    fn repo_updater_contract_rejects_host_identity_mismatch() {
        let mut contract = RepoUpdaterAdapterContract::default();
        contract.trust_policy.allowlisted_repo_specs =
            vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
        let mut request = sample_sync_apply_request_with_auth();
        request
            .auth_context
            .as_mut()
            .expect("auth context present")
            .verified_hosts[0]
            .key_fingerprint = "SHA256:INVALID".to_string();

        let err = request
            .validate(&contract)
            .expect_err("host-key mismatch must be rejected");
        assert!(matches!(
            err,
            RepoUpdaterContractError::HostIdentityMismatch { .. }
        ));
        assert_eq!(err.reason_code(), "RU_HOST_IDENTITY_MISMATCH");
        assert_eq!(
            err.failure_kind(),
            RepoUpdaterFailureKind::HostValidationFailed
        );
    }

    #[test]
    fn repo_updater_contract_accepts_valid_sync_apply_auth_context() {
        let mut contract = RepoUpdaterAdapterContract::default();
        contract.trust_policy.allowlisted_repo_specs =
            vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
        let request = sample_sync_apply_request_with_auth();
        request
            .validate(&contract)
            .expect("valid credential + host identity context should pass");
    }

    #[test]
    fn repo_updater_contract_mock_adapter_classifies_auth_failures() {
        let adapter = MockRepoUpdaterAdapter::default();
        let mut contract = RepoUpdaterAdapterContract::default();
        contract.trust_policy.allowlisted_repo_specs =
            vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
        let mut request = sample_sync_apply_request_with_auth();
        request
            .auth_context
            .as_mut()
            .expect("auth context present")
            .revoked = true;

        let err = adapter
            .execute(&request, &contract)
            .expect_err("revoked credentials should fail before adapter execution");
        assert_eq!(err.kind, RepoUpdaterFailureKind::AuthFailure);
        assert_eq!(err.code, "RU_AUTH_CREDENTIAL_REVOKED");
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
    fn repo_updater_contract_build_invocation_includes_override_audit_env() {
        let contract = RepoUpdaterAdapterContract::default();
        let request = RepoUpdaterAdapterRequest {
            operator_override: Some(RepoUpdaterOperatorOverride {
                operator_id: "ops-user".to_string(),
                justification: "approved exception".to_string(),
                ticket_ref: "OPS-45".to_string(),
                audit_event_id: "audit-evt-0004".to_string(),
                approved_at_unix_ms: 1_770_000_423_000,
            }),
            ..sample_request()
        };
        let invocation = build_invocation(&request, &contract);

        assert!(
            invocation
                .env
                .iter()
                .any(|(k, v)| { k == REPO_UPDATER_OVERRIDE_OPERATOR_ID_ENV && v == "ops-user" })
        );
        assert!(invocation.env.iter().any(|(k, v)| {
            k == REPO_UPDATER_OVERRIDE_AUDIT_EVENT_ID_ENV && v == "audit-evt-0004"
        }));
    }

    #[test]
    fn repo_updater_contract_build_invocation_includes_auth_env_context() {
        let contract = RepoUpdaterAdapterContract::default();
        let request = sample_sync_apply_request_with_auth();
        let invocation = build_invocation(&request, &contract);

        assert!(
            invocation
                .env
                .iter()
                .any(|(k, v)| k == REPO_UPDATER_AUTH_SOURCE_ENV && v == "token_env")
        );
        assert!(
            invocation
                .env
                .iter()
                .any(|(k, v)| k == REPO_UPDATER_AUTH_CREDENTIAL_ID_ENV && v == "cred-123")
        );
    }

    #[test]
    fn repo_updater_contract_mock_adapter_records_calls_and_returns_scripted_result() {
        let adapter = MockRepoUpdaterAdapter::default();
        let contract = contract_with_allowlisted_sample_specs();
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
