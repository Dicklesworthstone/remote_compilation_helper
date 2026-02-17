//! Stable process triage integration contract.
//!
//! This module defines a shared schema for invoking external process-triage
//! helpers and safely interpreting their actions/results.

use schemars::{JsonSchema, schema::RootSchema, schema_for};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Stable schema version for the process-triage integration contract.
pub const PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION: &str = "1.0.0";

/// Stable command surface for invoking the process-triage adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessTriageAdapterCommand {
    Analyze,
    Execute,
    Health,
    Version,
}

impl ProcessTriageAdapterCommand {
    /// Return CLI arguments for the command surface.
    pub fn args(self) -> &'static [&'static str] {
        match self {
            Self::Analyze => &["process-triage", "analyze", "--json"],
            Self::Execute => &["process-triage", "execute", "--json"],
            Self::Health => &["process-triage", "health", "--json"],
            Self::Version => &["process-triage", "version", "--json"],
        }
    }
}

/// Supported process-triage action classes ordered by risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessTriageActionClass {
    ObserveOnly,
    SoftTerminate,
    HardTerminate,
    ReclaimDisk,
}

impl ProcessTriageActionClass {
    fn risk_rank(self) -> u8 {
        match self {
            Self::ObserveOnly => 0,
            Self::ReclaimDisk => 1,
            Self::SoftTerminate => 2,
            Self::HardTerminate => 3,
        }
    }
}

/// Trigger class that initiated process triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessTriageTrigger {
    DiskPressure,
    WorkerHealth,
    BuildTimeout,
    Manual,
}

/// Process classification label from detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessClassification {
    BuildRelated,
    Suspicious,
    Interactive,
    SystemCritical,
    Unknown,
}

/// Escalation levels used by safe-action policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessTriageEscalationLevel {
    Automatic,
    Supervised,
    ManualReview,
    Blocked,
}

/// Failure taxonomy for process triage adapter interactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessTriageFailureKind {
    DetectorUncertain,
    PolicyViolation,
    TransportError,
    ExecutorRuntimeError,
    Timeout,
    PartialResult,
    InvalidRequest,
}

/// Adapter command budget used in timeout/retry policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriageCommandBudget {
    pub command: ProcessTriageAdapterCommand,
    pub timeout_secs: u64,
    pub retries: u32,
}

/// Timeout policy contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriageTimeoutPolicy {
    pub request_timeout_secs: u64,
    pub action_timeout_secs: u64,
    pub total_timeout_secs: u64,
}

impl Default for ProcessTriageTimeoutPolicy {
    fn default() -> Self {
        Self {
            request_timeout_secs: 8,
            action_timeout_secs: 15,
            total_timeout_secs: 30,
        }
    }
}

/// Retry policy contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriageRetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub backoff_multiplier_percent: u16,
}

impl Default for ProcessTriageRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 250,
            max_backoff_ms: 2_000,
            backoff_multiplier_percent: 200,
        }
    }
}

/// Escalation thresholds used by policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriageEscalationThresholds {
    pub min_confidence_for_automatic: u8,
    pub max_actions_before_manual_review: u32,
    pub max_hard_terminations_before_manual_review: u32,
}

impl Default for ProcessTriageEscalationThresholds {
    fn default() -> Self {
        Self {
            min_confidence_for_automatic: 85,
            max_actions_before_manual_review: 5,
            max_hard_terminations_before_manual_review: 1,
        }
    }
}

/// Safe-action policy with explicit allowlist/denylist and escalation rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriageSafeActionPolicy {
    pub policy_version: String,
    pub allow_action_classes: Vec<ProcessTriageActionClass>,
    pub deny_action_classes: Vec<ProcessTriageActionClass>,
    pub managed_process_patterns: Vec<String>,
    pub protected_process_patterns: Vec<String>,
    pub escalation: ProcessTriageEscalationThresholds,
    pub require_audit_record: bool,
}

impl Default for ProcessTriageSafeActionPolicy {
    fn default() -> Self {
        Self {
            policy_version: "v1".to_string(),
            allow_action_classes: vec![
                ProcessTriageActionClass::ObserveOnly,
                ProcessTriageActionClass::SoftTerminate,
                ProcessTriageActionClass::ReclaimDisk,
            ],
            deny_action_classes: vec![ProcessTriageActionClass::HardTerminate],
            managed_process_patterns: vec![
                "cargo".to_string(),
                "rustc".to_string(),
                "clang".to_string(),
            ],
            protected_process_patterns: vec![
                "sshd".to_string(),
                "systemd".to_string(),
                "init".to_string(),
            ],
            escalation: ProcessTriageEscalationThresholds::default(),
            require_audit_record: true,
        }
    }
}

/// Full contract bundle for process triage integration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriageContract {
    pub schema_version: String,
    pub timeout_policy: ProcessTriageTimeoutPolicy,
    pub retry_policy: ProcessTriageRetryPolicy,
    pub command_budgets: Vec<ProcessTriageCommandBudget>,
    pub safe_action_policy: ProcessTriageSafeActionPolicy,
}

impl Default for ProcessTriageContract {
    fn default() -> Self {
        Self {
            schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
            timeout_policy: ProcessTriageTimeoutPolicy::default(),
            retry_policy: ProcessTriageRetryPolicy::default(),
            command_budgets: vec![
                ProcessTriageCommandBudget {
                    command: ProcessTriageAdapterCommand::Analyze,
                    timeout_secs: 8,
                    retries: 1,
                },
                ProcessTriageCommandBudget {
                    command: ProcessTriageAdapterCommand::Execute,
                    timeout_secs: 15,
                    retries: 1,
                },
                ProcessTriageCommandBudget {
                    command: ProcessTriageAdapterCommand::Health,
                    timeout_secs: 3,
                    retries: 2,
                },
                ProcessTriageCommandBudget {
                    command: ProcessTriageAdapterCommand::Version,
                    timeout_secs: 2,
                    retries: 0,
                },
            ],
            safe_action_policy: ProcessTriageSafeActionPolicy::default(),
        }
    }
}

/// Observed process sample from detector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessDescriptor {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub owner: String,
    pub command: String,
    pub classification: ProcessClassification,
    pub cpu_percent_milli: u32,
    pub rss_mb: u32,
    pub runtime_secs: u64,
}

/// Action request item proposed by detector/planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriageActionRequest {
    pub action_class: ProcessTriageActionClass,
    pub pid: u32,
    pub reason_code: String,
    pub signal: Option<String>,
}

/// Adapter request schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriageRequest {
    pub schema_version: String,
    pub correlation_id: String,
    pub worker_id: String,
    pub observed_at_unix_ms: i64,
    pub trigger: ProcessTriageTrigger,
    pub detector_confidence_percent: u8,
    pub retry_attempt: u32,
    pub candidate_processes: Vec<ProcessDescriptor>,
    pub requested_actions: Vec<ProcessTriageActionRequest>,
}

/// Action execution outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessTriageActionOutcome {
    Skipped,
    Executed,
    Failed,
    Escalated,
}

/// Action result in response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriageActionResult {
    pub pid: u32,
    pub action_class: ProcessTriageActionClass,
    pub outcome: ProcessTriageActionOutcome,
    pub note: Option<String>,
}

/// High-level response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessTriageResponseStatus {
    Applied,
    PartiallyApplied,
    EscalatedNoAction,
    RejectedByPolicy,
    Failed,
}

/// Failure payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriageFailure {
    pub kind: ProcessTriageFailureKind,
    pub code: String,
    pub message: String,
    pub remediation: Vec<String>,
}

/// Audit record required for every process triage response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriageAuditRecord {
    pub policy_version: String,
    pub evaluated_by: String,
    pub evaluated_at_unix_ms: i64,
    pub decision_code: String,
    pub requires_operator_ack: bool,
    pub audit_required: bool,
}

/// Adapter response schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriageResponse {
    pub schema_version: String,
    pub correlation_id: String,
    pub status: ProcessTriageResponseStatus,
    pub escalation_level: ProcessTriageEscalationLevel,
    pub executed_actions: Vec<ProcessTriageActionResult>,
    pub failure: Option<ProcessTriageFailure>,
    pub audit: ProcessTriageAuditRecord,
}

/// Deterministic policy decision for a single action request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTriagePolicyDecision {
    pub permitted: bool,
    pub escalation_level: ProcessTriageEscalationLevel,
    pub effective_action: Option<ProcessTriageActionClass>,
    pub decision_code: String,
    pub reason: String,
    pub requires_operator_ack: bool,
    pub audit_required: bool,
}

/// Contract validation failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProcessTriageContractError {
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaVersionMismatch { expected: String, actual: String },
    #[error("detector confidence percent must be <= 100, got {0}")]
    InvalidConfidence(u8),
    #[error("requested_actions must not be empty")]
    EmptyRequestedActions,
    #[error("requested action references unknown pid {0}")]
    UnknownActionPid(u32),
    #[error("timeout policy has invalid value for {field}: {value}")]
    InvalidTimeout { field: &'static str, value: u64 },
    #[error("retry policy has invalid value for {field}: {value}")]
    InvalidRetryPolicy { field: &'static str, value: u64 },
    #[error("allowlist/denylist conflict for action class {0:?}")]
    AllowDenyConflict(ProcessTriageActionClass),
    #[error("escalation threshold min_confidence_for_automatic must be <= 100, got {0}")]
    InvalidEscalationConfidence(u8),
}

impl ProcessTriageRequest {
    /// Validate request shape and semantic constraints.
    pub fn validate(&self) -> Result<(), ProcessTriageContractError> {
        if self.schema_version != PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION {
            return Err(ProcessTriageContractError::SchemaVersionMismatch {
                expected: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.detector_confidence_percent > 100 {
            return Err(ProcessTriageContractError::InvalidConfidence(
                self.detector_confidence_percent,
            ));
        }
        if self.requested_actions.is_empty() {
            return Err(ProcessTriageContractError::EmptyRequestedActions);
        }

        let candidate_pids: HashSet<u32> = self.candidate_processes.iter().map(|p| p.pid).collect();
        for action in &self.requested_actions {
            if !candidate_pids.contains(&action.pid) {
                return Err(ProcessTriageContractError::UnknownActionPid(action.pid));
            }
        }

        Ok(())
    }
}

impl ProcessTriageContract {
    /// Validate contract configuration.
    pub fn validate(&self) -> Result<(), ProcessTriageContractError> {
        if self.timeout_policy.request_timeout_secs == 0 {
            return Err(ProcessTriageContractError::InvalidTimeout {
                field: "request_timeout_secs",
                value: self.timeout_policy.request_timeout_secs,
            });
        }
        if self.timeout_policy.action_timeout_secs == 0 {
            return Err(ProcessTriageContractError::InvalidTimeout {
                field: "action_timeout_secs",
                value: self.timeout_policy.action_timeout_secs,
            });
        }
        if self.timeout_policy.total_timeout_secs == 0 {
            return Err(ProcessTriageContractError::InvalidTimeout {
                field: "total_timeout_secs",
                value: self.timeout_policy.total_timeout_secs,
            });
        }
        if self.retry_policy.max_attempts == 0 {
            return Err(ProcessTriageContractError::InvalidRetryPolicy {
                field: "max_attempts",
                value: self.retry_policy.max_attempts as u64,
            });
        }
        if self.retry_policy.initial_backoff_ms == 0 {
            return Err(ProcessTriageContractError::InvalidRetryPolicy {
                field: "initial_backoff_ms",
                value: self.retry_policy.initial_backoff_ms,
            });
        }
        if self.retry_policy.max_backoff_ms < self.retry_policy.initial_backoff_ms {
            return Err(ProcessTriageContractError::InvalidRetryPolicy {
                field: "max_backoff_ms",
                value: self.retry_policy.max_backoff_ms,
            });
        }
        if self
            .safe_action_policy
            .escalation
            .min_confidence_for_automatic
            > 100
        {
            return Err(ProcessTriageContractError::InvalidEscalationConfidence(
                self.safe_action_policy
                    .escalation
                    .min_confidence_for_automatic,
            ));
        }

        let allow: HashSet<ProcessTriageActionClass> = self
            .safe_action_policy
            .allow_action_classes
            .iter()
            .copied()
            .collect();
        let deny: HashSet<ProcessTriageActionClass> = self
            .safe_action_policy
            .deny_action_classes
            .iter()
            .copied()
            .collect();

        if let Some(action) = allow.intersection(&deny).next() {
            return Err(ProcessTriageContractError::AllowDenyConflict(*action));
        }

        Ok(())
    }
}

/// Evaluate a requested action against the safe-action policy.
pub fn evaluate_triage_action(
    request: &ProcessTriageRequest,
    contract: &ProcessTriageContract,
    action: &ProcessTriageActionRequest,
) -> ProcessTriagePolicyDecision {
    let policy = &contract.safe_action_policy;
    let allow: HashSet<ProcessTriageActionClass> =
        policy.allow_action_classes.iter().copied().collect();
    let deny: HashSet<ProcessTriageActionClass> =
        policy.deny_action_classes.iter().copied().collect();

    if deny.contains(&action.action_class) {
        return ProcessTriagePolicyDecision {
            permitted: false,
            escalation_level: ProcessTriageEscalationLevel::Blocked,
            effective_action: None,
            decision_code: "PT_BLOCK_DENYLIST".to_string(),
            reason: format!("action class {:?} is denylisted", action.action_class),
            requires_operator_ack: true,
            audit_required: policy.require_audit_record,
        };
    }

    if !allow.contains(&action.action_class) {
        return ProcessTriagePolicyDecision {
            permitted: false,
            escalation_level: ProcessTriageEscalationLevel::Blocked,
            effective_action: None,
            decision_code: "PT_BLOCK_NOT_ALLOWLISTED".to_string(),
            reason: format!("action class {:?} is not allowlisted", action.action_class),
            requires_operator_ack: true,
            audit_required: policy.require_audit_record,
        };
    }

    let target = request
        .candidate_processes
        .iter()
        .find(|proc_desc| proc_desc.pid == action.pid);

    if let Some(proc_desc) = target {
        let cmd_lower = proc_desc.command.to_ascii_lowercase();
        if pattern_matches(&cmd_lower, &policy.protected_process_patterns) {
            return ProcessTriagePolicyDecision {
                permitted: false,
                escalation_level: ProcessTriageEscalationLevel::Blocked,
                effective_action: None,
                decision_code: "PT_BLOCK_PROTECTED_PROCESS".to_string(),
                reason: format!(
                    "target process '{}' matches protected patterns",
                    proc_desc.command
                ),
                requires_operator_ack: true,
                audit_required: policy.require_audit_record,
            };
        }
        if !policy.managed_process_patterns.is_empty()
            && !pattern_matches(&cmd_lower, &policy.managed_process_patterns)
        {
            return ProcessTriagePolicyDecision {
                permitted: false,
                escalation_level: ProcessTriageEscalationLevel::Blocked,
                effective_action: None,
                decision_code: "PT_BLOCK_OUT_OF_SCOPE_PROCESS".to_string(),
                reason: format!(
                    "target process '{}' does not match managed patterns",
                    proc_desc.command
                ),
                requires_operator_ack: true,
                audit_required: policy.require_audit_record,
            };
        }
    }

    if request.detector_confidence_percent < policy.escalation.min_confidence_for_automatic {
        return ProcessTriagePolicyDecision {
            permitted: false,
            escalation_level: ProcessTriageEscalationLevel::ManualReview,
            effective_action: None,
            decision_code: "PT_MANUAL_LOW_CONFIDENCE".to_string(),
            reason: format!(
                "detector confidence {} is below automatic threshold {}",
                request.detector_confidence_percent, policy.escalation.min_confidence_for_automatic
            ),
            requires_operator_ack: true,
            audit_required: policy.require_audit_record,
        };
    }

    if request.retry_attempt + 1 >= contract.retry_policy.max_attempts {
        return ProcessTriagePolicyDecision {
            permitted: false,
            escalation_level: ProcessTriageEscalationLevel::ManualReview,
            effective_action: None,
            decision_code: "PT_MANUAL_RETRY_EXHAUSTED".to_string(),
            reason: format!(
                "retry attempt {} reached max attempts {}",
                request.retry_attempt + 1,
                contract.retry_policy.max_attempts
            ),
            requires_operator_ack: true,
            audit_required: policy.require_audit_record,
        };
    }

    let hard_kill_requests = request
        .requested_actions
        .iter()
        .filter(|req| req.action_class == ProcessTriageActionClass::HardTerminate)
        .count() as u32;

    if hard_kill_requests > policy.escalation.max_hard_terminations_before_manual_review {
        return ProcessTriagePolicyDecision {
            permitted: false,
            escalation_level: ProcessTriageEscalationLevel::ManualReview,
            effective_action: None,
            decision_code: "PT_MANUAL_HARD_KILL_THRESHOLD".to_string(),
            reason: format!(
                "requested hard terminations {} exceeds threshold {}",
                hard_kill_requests, policy.escalation.max_hard_terminations_before_manual_review
            ),
            requires_operator_ack: true,
            audit_required: policy.require_audit_record,
        };
    }

    if request.requested_actions.len() as u32 > policy.escalation.max_actions_before_manual_review {
        let downgraded_action = if action.action_class.risk_rank()
            > ProcessTriageActionClass::ObserveOnly.risk_rank()
        {
            ProcessTriageActionClass::ObserveOnly
        } else {
            action.action_class
        };

        return ProcessTriagePolicyDecision {
            permitted: true,
            escalation_level: ProcessTriageEscalationLevel::Supervised,
            effective_action: Some(downgraded_action),
            decision_code: "PT_SUPERVISED_ACTION_VOLUME".to_string(),
            reason: format!(
                "requested action count {} exceeds threshold {}, action downgraded for supervised mode",
                request.requested_actions.len(),
                policy.escalation.max_actions_before_manual_review
            ),
            requires_operator_ack: true,
            audit_required: policy.require_audit_record,
        };
    }

    ProcessTriagePolicyDecision {
        permitted: true,
        escalation_level: ProcessTriageEscalationLevel::Automatic,
        effective_action: Some(action.action_class),
        decision_code: "PT_ALLOW_AUTOMATIC".to_string(),
        reason: "action satisfies allowlist and escalation thresholds".to_string(),
        requires_operator_ack: false,
        audit_required: policy.require_audit_record,
    }
}

fn pattern_matches(command_lower: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .map(|p| p.to_ascii_lowercase())
        .any(|p| !p.is_empty() && command_lower.contains(&p))
}

/// JSON schema for request payload.
pub fn process_triage_request_schema() -> RootSchema {
    schema_for!(ProcessTriageRequest)
}

/// JSON schema for response payload.
pub fn process_triage_response_schema() -> RootSchema {
    schema_for!(ProcessTriageResponse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn sample_request() -> ProcessTriageRequest {
        ProcessTriageRequest {
            schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
            correlation_id: "corr-123".to_string(),
            worker_id: "worker-a".to_string(),
            observed_at_unix_ms: 1_768_768_123_000,
            trigger: ProcessTriageTrigger::WorkerHealth,
            detector_confidence_percent: 96,
            retry_attempt: 0,
            candidate_processes: vec![
                ProcessDescriptor {
                    pid: 1001,
                    ppid: Some(1000),
                    owner: "ubuntu".to_string(),
                    command: "cargo test --workspace".to_string(),
                    classification: ProcessClassification::BuildRelated,
                    cpu_percent_milli: 92500,
                    rss_mb: 2100,
                    runtime_secs: 240,
                },
                ProcessDescriptor {
                    pid: 1002,
                    ppid: Some(1),
                    owner: "root".to_string(),
                    command: "sshd: ubuntu@pts/4".to_string(),
                    classification: ProcessClassification::SystemCritical,
                    cpu_percent_milli: 100,
                    rss_mb: 32,
                    runtime_secs: 8600,
                },
            ],
            requested_actions: vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 1001,
                reason_code: "stuck_compile".to_string(),
                signal: Some("TERM".to_string()),
            }],
        }
    }

    fn extract_ref_name(schema: &Value) -> Option<String> {
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            return reference.rsplit('/').next().map(str::to_string);
        }

        for key in ["anyOf", "oneOf", "allOf"] {
            if let Some(reference) =
                schema
                    .get(key)
                    .and_then(Value::as_array)
                    .and_then(|variants| {
                        variants
                            .iter()
                            .find_map(|variant| variant.get("$ref").and_then(Value::as_str))
                    })
            {
                return reference.rsplit('/').next().map(str::to_string);
            }
        }

        None
    }

    fn find_schema_properties(
        schema_json: &Value,
        required: &[&str],
    ) -> serde_json::Map<String, Value> {
        let root_properties = schema_json
            .get("properties")
            .and_then(Value::as_object)
            .filter(|properties| required.iter().all(|key| properties.contains_key(*key)))
            .cloned();
        if let Some(properties) = root_properties {
            return properties;
        }

        let definition_properties = schema_json
            .get("definitions")
            .and_then(Value::as_object)
            .and_then(|definitions| {
                definitions.values().find_map(|node| {
                    let properties = node.get("properties")?.as_object()?;
                    if required.iter().all(|key| properties.contains_key(*key)) {
                        Some(properties.clone())
                    } else {
                        None
                    }
                })
            });
        if let Some(properties) = definition_properties {
            return properties;
        }

        panic!("schema properties not found for required keys: {required:?}");
    }

    fn definition_properties(
        schema_json: &Value,
        definition_name: &str,
    ) -> serde_json::Map<String, Value> {
        schema_json
            .get("definitions")
            .and_then(Value::as_object)
            .and_then(|definitions| definitions.get(definition_name))
            .and_then(|definition| definition.get("properties"))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_else(|| panic!("definition '{definition_name}' missing properties"))
    }

    fn definition_enum(schema_json: &Value, definition_name: &str) -> Vec<String> {
        schema_json
            .get("definitions")
            .and_then(Value::as_object)
            .and_then(|definitions| definitions.get(definition_name))
            .and_then(|definition| definition.get("enum"))
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_else(|| panic!("definition '{definition_name}' missing enum values"))
    }

    #[test]
    fn process_triage_contract_request_roundtrip() {
        let request = sample_request();
        request.validate().expect("sample request should validate");

        let json = serde_json::to_string(&request).expect("serialize request");
        let restored: ProcessTriageRequest =
            serde_json::from_str(&json).expect("deserialize request");
        assert_eq!(
            restored.schema_version,
            PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION
        );
        assert_eq!(restored.worker_id, "worker-a");
        assert_eq!(restored.requested_actions.len(), 1);
    }

    #[test]
    fn process_triage_contract_policy_validation_rejects_allow_deny_overlap() {
        let mut contract = ProcessTriageContract::default();
        contract
            .safe_action_policy
            .deny_action_classes
            .push(ProcessTriageActionClass::SoftTerminate);

        let result = contract.validate();
        assert!(matches!(
            result,
            Err(ProcessTriageContractError::AllowDenyConflict(
                ProcessTriageActionClass::SoftTerminate
            ))
        ));
    }

    #[test]
    fn process_triage_contract_blocks_protected_process() {
        let contract = ProcessTriageContract::default();
        let request = ProcessTriageRequest {
            requested_actions: vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 1002,
                reason_code: "force_cleanup".to_string(),
                signal: Some("TERM".to_string()),
            }],
            ..sample_request()
        };

        let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
        assert!(!decision.permitted);
        assert_eq!(
            decision.escalation_level,
            ProcessTriageEscalationLevel::Blocked
        );
        assert_eq!(decision.decision_code, "PT_BLOCK_PROTECTED_PROCESS");
    }

    #[test]
    fn process_triage_contract_requires_manual_review_on_low_confidence() {
        let contract = ProcessTriageContract::default();
        let request = ProcessTriageRequest {
            detector_confidence_percent: 40,
            ..sample_request()
        };

        let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
        assert!(!decision.permitted);
        assert_eq!(
            decision.escalation_level,
            ProcessTriageEscalationLevel::ManualReview
        );
        assert_eq!(decision.decision_code, "PT_MANUAL_LOW_CONFIDENCE");
    }

    #[test]
    fn process_triage_contract_respects_denylist() {
        let mut contract = ProcessTriageContract::default();
        contract.safe_action_policy.allow_action_classes = vec![
            ProcessTriageActionClass::ObserveOnly,
            ProcessTriageActionClass::HardTerminate,
        ];
        contract.safe_action_policy.deny_action_classes =
            vec![ProcessTriageActionClass::HardTerminate];

        let request = ProcessTriageRequest {
            requested_actions: vec![ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::HardTerminate,
                pid: 1001,
                reason_code: "stuck_compile".to_string(),
                signal: Some("KILL".to_string()),
            }],
            ..sample_request()
        };

        let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
        assert!(!decision.permitted);
        assert_eq!(
            decision.escalation_level,
            ProcessTriageEscalationLevel::Blocked
        );
        assert_eq!(decision.decision_code, "PT_BLOCK_DENYLIST");
    }

    #[test]
    fn process_triage_contract_schema_contains_core_fields() {
        let schema = process_triage_request_schema();
        let schema_json = serde_json::to_value(&schema).expect("schema to json");
        let root_properties = schema_json
            .get("properties")
            .and_then(|props| props.as_object())
            .cloned();
        let definition_properties = schema_json
            .get("definitions")
            .and_then(|defs| defs.as_object())
            .and_then(|defs| {
                defs.values().find_map(|node| {
                    let properties = node.get("properties")?.as_object()?;
                    if properties.contains_key("worker_id")
                        && properties.contains_key("requested_actions")
                    {
                        Some(properties.clone())
                    } else {
                        None
                    }
                })
            });
        let properties = root_properties
            .or(definition_properties)
            .expect("request properties in schema");

        assert!(properties.contains_key("schema_version"));
        assert!(properties.contains_key("worker_id"));
        assert!(properties.contains_key("requested_actions"));
    }

    #[test]
    fn process_triage_contract_response_schema_requires_audit_record() {
        let schema = process_triage_response_schema();
        let schema_json = serde_json::to_value(&schema).expect("schema to json");
        let response_properties =
            find_schema_properties(&schema_json, &["status", "executed_actions", "audit"]);
        let audit_schema = response_properties
            .get("audit")
            .expect("response schema should contain audit field");
        let audit_properties = if let Some(definition_name) = extract_ref_name(audit_schema) {
            definition_properties(&schema_json, &definition_name)
        } else {
            audit_schema
                .get("properties")
                .and_then(Value::as_object)
                .cloned()
                .expect("audit schema should provide properties")
        };

        assert!(audit_properties.contains_key("policy_version"));
        assert!(audit_properties.contains_key("decision_code"));
        assert!(audit_properties.contains_key("audit_required"));
    }

    #[test]
    fn process_triage_contract_response_schema_exposes_failure_kind_taxonomy() {
        let schema = process_triage_response_schema();
        let schema_json = serde_json::to_value(&schema).expect("schema to json");
        let response_properties = find_schema_properties(&schema_json, &["status", "failure"]);
        let failure_schema = response_properties
            .get("failure")
            .expect("response schema should contain failure field");
        let failure_definition = extract_ref_name(failure_schema)
            .expect("failure field should reference ProcessTriageFailure schema");
        let failure_properties = definition_properties(&schema_json, &failure_definition);
        let kind_schema = failure_properties
            .get("kind")
            .expect("failure schema should contain kind field");
        let kind_values = if let Some(definition_name) = extract_ref_name(kind_schema) {
            definition_enum(&schema_json, &definition_name)
        } else {
            kind_schema
                .get("enum")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .expect("kind schema should expose enum values")
        };

        for expected in [
            "detector_uncertain",
            "policy_violation",
            "transport_error",
            "executor_runtime_error",
            "timeout",
            "partial_result",
            "invalid_request",
        ] {
            assert!(
                kind_values.iter().any(|value| value == expected),
                "missing failure kind: {}",
                expected
            );
        }
    }

    #[test]
    fn process_triage_contract_parser_compatibility() {
        let json = r#"{
            "schema_version":"1.0.0",
            "correlation_id":"corr-xyz",
            "worker_id":"worker-z",
            "observed_at_unix_ms":1768768123000,
            "trigger":"disk_pressure",
            "detector_confidence_percent":88,
            "retry_attempt":1,
            "candidate_processes":[{
                "pid":4242,
                "ppid":1,
                "owner":"ubuntu",
                "command":"cargo clippy --workspace",
                "classification":"build_related",
                "cpu_percent_milli":50000,
                "rss_mb":700,
                "runtime_secs":128
            }],
            "requested_actions":[{
                "action_class":"soft_terminate",
                "pid":4242,
                "reason_code":"timeout",
                "signal":"TERM"
            }]
        }"#;

        let request: ProcessTriageRequest = serde_json::from_str(json).expect("compat parse");
        assert_eq!(
            request.schema_version,
            PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION
        );
        assert_eq!(request.trigger, ProcessTriageTrigger::DiskPressure);
        assert_eq!(request.requested_actions.len(), 1);
    }
}
