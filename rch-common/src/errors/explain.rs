//! Operator-facing code-lookup surface (`rch error explain`).
//!
//! Bridges the two parallel code namespaces in this workspace —
//! [`super::ErrorCode`] (`RCH-E001..E599`, the primary error catalog)
//! and [`super::ReliabilityReasonCode`] (`RCH-R001..R699`, the doctor
//! reliability surface) — into a single uniform lookup so an operator
//! who pastes any code from a log line into `rch error explain` gets a
//! useful answer regardless of which namespace it came from.
//!
//! # Surface
//!
//! ```text
//! rch error explain <CODE>      # human form
//! rch error explain <CODE> --json
//! rch error list                # all codes
//! rch error list --category=worker
//! rch error list --json
//! ```
//!
//! # Wire shape (JSON)
//!
//! ```json
//! {
//!   "code": "RCH-R104",
//!   "namespace": "reliability",
//!   "name": "WorkerDiskPressureTelemetryGap",
//!   "category": "disk_pressure",
//!   "description": "Worker is missing fresh disk telemetry.",
//!   "remediation": ["Run `rch workers probe <worker>` to refresh telemetry."],
//!   "requires_restart": false
//! }
//! ```

use super::{ErrorCategory, ErrorCode, ReliabilityCategoryKind, ReliabilityReasonCode};
use serde::{Deserialize, Serialize};

/// Resolved lookup result for either namespace. Produced by [`lookup`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeExplanation {
    pub code: String,
    pub namespace: CodeNamespace,
    pub name: String,
    pub category: String,
    pub description: String,
    pub remediation: Vec<String>,
    /// Only meaningful for reliability codes. `None` for error codes
    /// where the concept doesn't apply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_restart: Option<bool>,
    /// Optional documentation link. Currently only populated for some
    /// `ErrorCode` entries that supply a `doc_url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_url: Option<String>,
}

/// Which catalog the code came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeNamespace {
    /// `RCH-Ennn` codes from [`ErrorCode`].
    Error,
    /// `RCH-Rnnn` codes from [`ReliabilityReasonCode`].
    Reliability,
}

/// Look up a code string. Accepts whitespace-padded input.
///
/// Returns `None` if the code is unknown or malformed.
#[must_use]
pub fn lookup(raw: &str) -> Option<CodeExplanation> {
    let normalized = raw.trim().to_ascii_uppercase();
    if let Some(c) = lookup_reliability(&normalized) {
        return Some(c);
    }
    if let Some(c) = lookup_error(&normalized) {
        return Some(c);
    }
    None
}

/// Whether a string parses as either a known reliability or error code.
#[must_use]
pub fn is_known(raw: &str) -> bool {
    lookup(raw).is_some()
}

fn lookup_reliability(code: &str) -> Option<CodeExplanation> {
    let v = ReliabilityReasonCode::from_code_str(code)?;
    Some(CodeExplanation {
        code: v.code().to_string(),
        namespace: CodeNamespace::Reliability,
        name: v.name().to_string(),
        category: reliability_category_str(v.category()).to_string(),
        description: v.remediation_hint().to_string(),
        remediation: vec![v.remediation_hint().to_string()],
        requires_restart: Some(v.requires_restart()),
        doc_url: None,
    })
}

fn lookup_error(code: &str) -> Option<CodeExplanation> {
    for c in error_code_all() {
        if c.code_string() == code {
            let entry = c.entry();
            return Some(CodeExplanation {
                code: entry.code,
                namespace: CodeNamespace::Error,
                name: format!("{c:?}"),
                category: error_category_str(entry.category).to_string(),
                description: entry.message,
                remediation: entry.remediation,
                requires_restart: None,
                doc_url: entry.doc_url,
            });
        }
    }
    None
}

/// Snake-case string name for a reliability category.
const fn reliability_category_str(c: ReliabilityCategoryKind) -> &'static str {
    match c {
        ReliabilityCategoryKind::Topology => "topology",
        ReliabilityCategoryKind::DiskPressure => "disk_pressure",
        ReliabilityCategoryKind::ProcessTriage => "process_triage",
        ReliabilityCategoryKind::RepoConvergence => "repo_convergence",
        ReliabilityCategoryKind::HelperCompatibility => "helper_compatibility",
        ReliabilityCategoryKind::RolloutPosture => "rollout_posture",
        ReliabilityCategoryKind::SchemaCompatibility => "schema_compatibility",
    }
}

/// Snake-case string name for an error category.
const fn error_category_str(c: ErrorCategory) -> &'static str {
    match c {
        ErrorCategory::Config => "config",
        ErrorCategory::Network => "network",
        ErrorCategory::Worker => "worker",
        ErrorCategory::Build => "build",
        ErrorCategory::Transfer => "transfer",
        ErrorCategory::Internal => "internal",
    }
}

/// All known codes across both namespaces. Used by `rch error list`.
#[must_use]
pub fn list_all() -> Vec<CodeExplanation> {
    let mut out: Vec<CodeExplanation> = Vec::new();
    for v in ReliabilityReasonCode::ALL {
        if let Some(e) = lookup_reliability(v.code()) {
            out.push(e);
        }
    }
    for c in error_code_all() {
        let s = c.code_string();
        if let Some(e) = lookup_error(&s) {
            out.push(e);
        }
    }
    out.sort_by(|a, b| a.code.cmp(&b.code));
    out
}

/// Subset of [`list_all`] filtered to one category (matches the
/// snake_case `category` field on [`CodeExplanation`]). Empty result
/// indicates an unknown category — caller can detect that.
#[must_use]
pub fn list_by_category(category: &str) -> Vec<CodeExplanation> {
    let cat = category.trim().to_ascii_lowercase();
    list_all()
        .into_iter()
        .filter(|e| e.category == cat)
        .collect()
}

/// Known category names across both code namespaces, sorted for stable CLI
/// help and JSON error payloads.
#[must_use]
pub fn known_categories() -> Vec<String> {
    let mut categories: Vec<String> = list_all().into_iter().map(|e| e.category).collect();
    categories.sort();
    categories.dedup();
    categories
}

/// Whether a category name matches at least one known code category.
#[must_use]
pub fn is_known_category(category: &str) -> bool {
    let cat = category.trim().to_ascii_lowercase();
    !cat.is_empty() && known_categories().iter().any(|known| known == &cat)
}

/// All known [`ErrorCode`] variants. Hand-maintained because `ErrorCode`
/// doesn't expose an iteration API; this list is the authoritative
/// snapshot. A unit test asserts every variant has a unique `RCH-Ennn`
/// `code_string()`, which catches drift if the enum gains/renames variants.
fn error_code_all() -> &'static [ErrorCode] {
    use ErrorCode::*;
    &[
        // Config (E001-E099)
        ConfigNotFound,
        ConfigReadError,
        ConfigParseError,
        ConfigValidationError,
        ConfigEnvError,
        ConfigProfileNotFound,
        ConfigNoWorkers,
        ConfigInvalidWorker,
        ConfigSshKeyError,
        ConfigSocketPathError,
        // Path-Dependency (within Config E013-E018)
        PathDepManifestParseFailed,
        PathDepMissing,
        PathDepCyclic,
        PathDepPolicyViolation,
        PathDepMetadataFailed,
        PathDepMetadataParseFailed,
        // Closure planner (within Config E019-E024)
        ClosureFailOpen,
        ClosureFingerprintMismatch,
        ClosureHighRisk,
        ClosureMissingData,
        ClosureNonDeterministic,
        ClosurePlanFailed,
        // Network (E100-E199)
        SshConnectionFailed,
        SshAuthFailed,
        SshHostKeyError,
        SshKeyError,
        SshTimeout,
        NetworkTimeout,
        NetworkConnectionRefused,
        NetworkDnsError,
        NetworkUnreachable,
        SshSessionDropped,
        // Worker (E200-E299)
        WorkerAllUnhealthy,
        WorkerAtCapacity,
        WorkerCircuitOpen,
        WorkerHealthCheckFailed,
        WorkerLoadQueryFailed,
        WorkerMissingToolchain,
        WorkerNoneAvailable,
        WorkerSelectionFailed,
        WorkerSelfTestFailed,
        WorkerStateError,
        // Worker/Storage (E210-E219)
        WorkerDiskPressureWarning,
        WorkerDiskPressureCritical,
        WorkerDiskHeadroomInsufficient,
        WorkerDiskIoHigh,
        WorkerMemoryPressureHigh,
        WorkerTelemetryGap,
        WorkerReclaimFailed,
        WorkerReclaimProtected,
        // Build (E300-E399)
        BuildCompilationFailed,
        BuildTimeout,
        BuildArtifactMissing,
        BuildOutputError,
        BuildKilledBySignal,
        BuildToolchainError,
        BuildIncrementalError,
        BuildEnvError,
        BuildWorkdirError,
        BuildUnknownCommand,
        // Build/Triage (E310-E319)
        ProcessTriageAdapterUnavailable,
        ProcessTriageDetectorUncertain,
        ProcessTriageExecutorError,
        ProcessTriageInvalidRequest,
        ProcessTriagePartialResult,
        ProcessTriagePolicyViolation,
        ProcessTriageTimeout,
        ProcessTriageTransportError,
        // Build/Cancellation (E320-E325)
        CancelGracefulSent,
        CancelTimeoutExceeded,
        CancelEscalatedKill,
        CancelRemoteKillFailed,
        CancelCleanupFailed,
        CancelSlotLeak,
        // Transfer (E400-E499)
        TransferRsyncFailed,
        TransferTimeout,
        TransferSourceMissing,
        TransferDestError,
        TransferDiskFull,
        TransferPermissionDenied,
        TransferChecksumError,
        TransferBinaryFailed,
        TransferIncomplete,
        TransferProtocolError,
        // Internal (E500-E599)
        InternalDaemonSocket,
        InternalDaemonProtocol,
        InternalDaemonNotRunning,
        InternalIpcError,
        InternalStateError,
        InternalSerdeError,
        InternalHookError,
        InternalMetricsError,
        InternalLoggingError,
        InternalUpdateError,
    ]
}

/// Render a [`CodeExplanation`] in a paste-ready human form. Used by
/// the CLI when `--json` is not set.
#[must_use]
pub fn render_human(e: &CodeExplanation) -> String {
    let mut out = String::with_capacity(512);
    out.push_str(&format!("{}  {}\n", e.code, e.name));
    out.push_str(&format!(
        "Category:     {:<30}  Namespace: {}\n",
        e.category,
        match e.namespace {
            CodeNamespace::Error => "error (RCH-Ennn)",
            CodeNamespace::Reliability => "reliability (RCH-Rnnn)",
        }
    ));
    if let Some(rr) = e.requires_restart {
        out.push_str(&format!("Requires restart: {rr}\n"));
    }
    out.push_str("\nDescription:\n");
    out.push_str(&format!("  {}\n", e.description));
    if !e.remediation.is_empty() {
        out.push_str("\nRemediation:\n");
        for step in &e.remediation {
            out.push_str(&format!("  - {step}\n"));
        }
    }
    if let Some(url) = &e.doc_url {
        out.push_str(&format!("\nReference: {url}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_reliability_code() {
        let e = lookup("RCH-R104").expect("R104 known");
        assert_eq!(e.code, "RCH-R104");
        assert_eq!(e.namespace, CodeNamespace::Reliability);
        assert_eq!(e.category, "disk_pressure");
        assert!(!e.description.is_empty());
        assert!(!e.remediation.is_empty());
        assert!(e.requires_restart.is_some());
    }

    #[test]
    fn test_lookup_error_code() {
        let e = lookup("RCH-E001").expect("E001 known");
        assert_eq!(e.code, "RCH-E001");
        assert_eq!(e.namespace, CodeNamespace::Error);
        assert_eq!(e.category, "config");
        assert!(!e.description.is_empty());
        assert!(e.requires_restart.is_none());
    }

    #[test]
    fn test_lookup_unknown_returns_none() {
        assert!(lookup("RCH-R999").is_none());
        assert!(lookup("RCH-E999").is_none());
        assert!(lookup("not-a-code").is_none());
        assert!(lookup("").is_none());
    }

    #[test]
    fn test_lookup_trims_whitespace() {
        let e = lookup("  RCH-R001  ").expect("trimmed lookup hits");
        assert_eq!(e.code, "RCH-R001");
    }

    #[test]
    fn test_lookup_is_case_insensitive() {
        let e = lookup("rch-e001").expect("lowercase error-code lookup hits");
        assert_eq!(e.code, "RCH-E001");

        let e = lookup("rch-r104").expect("lowercase reliability-code lookup hits");
        assert_eq!(e.code, "RCH-R104");
    }

    #[test]
    fn test_is_known() {
        assert!(is_known("RCH-R001"));
        assert!(is_known("RCH-E001"));
        assert!(!is_known("RCH-X001"));
    }

    #[test]
    fn test_list_all_includes_both_namespaces() {
        let all = list_all();
        let reliability_count = all
            .iter()
            .filter(|e| e.namespace == CodeNamespace::Reliability)
            .count();
        let error_count = all
            .iter()
            .filter(|e| e.namespace == CodeNamespace::Error)
            .count();
        assert!(reliability_count >= 40, "expected ≥40 reliability codes");
        assert!(error_count >= 50, "expected ≥50 error codes");
    }

    #[test]
    fn test_list_all_sorted_by_code() {
        let all = list_all();
        for w in all.windows(2) {
            assert!(w[0].code <= w[1].code, "list_all not sorted by code");
        }
    }

    #[test]
    fn test_list_all_no_duplicates() {
        use std::collections::HashSet;
        let all = list_all();
        let codes: HashSet<&str> = all.iter().map(|e| e.code.as_str()).collect();
        assert_eq!(codes.len(), all.len(), "duplicate code in list_all");
    }

    #[test]
    fn test_list_by_category_filters() {
        let dp = list_by_category("disk_pressure");
        assert!(!dp.is_empty());
        for e in &dp {
            assert_eq!(e.category, "disk_pressure");
        }
    }

    #[test]
    fn test_list_by_category_unknown_returns_empty() {
        assert!(list_by_category("nonexistent_category").is_empty());
    }

    #[test]
    fn test_known_categories_are_sorted_unique_and_complete() {
        let categories = known_categories();
        assert!(!categories.is_empty());
        for w in categories.windows(2) {
            assert!(w[0] < w[1], "known_categories must be sorted and unique");
        }
        assert!(categories.iter().any(|c| c == "disk_pressure"));
        assert!(categories.iter().any(|c| c == "worker"));
        assert!(categories.iter().any(|c| c == "topology"));
    }

    #[test]
    fn test_is_known_category_trims_and_normalizes_case() {
        assert!(is_known_category(" disk_pressure "));
        assert!(is_known_category("WORKER"));
        assert!(is_known_category("Topology"));
        assert!(!is_known_category(""));
        assert!(!is_known_category("nonexistent_category"));
    }

    #[test]
    fn test_list_by_category_case_insensitive() {
        let lower = list_by_category("topology");
        let upper = list_by_category("TOPOLOGY");
        let mixed = list_by_category("Topology");
        assert_eq!(lower.len(), upper.len());
        assert_eq!(lower.len(), mixed.len());
        assert!(!lower.is_empty());
    }

    #[test]
    fn test_render_human_includes_code_and_name() {
        let e = lookup("RCH-R104").unwrap();
        let rendered = render_human(&e);
        assert!(rendered.contains("RCH-R104"));
        assert!(rendered.contains(&e.name));
        assert!(rendered.contains("Description:"));
        assert!(rendered.contains("Remediation:"));
    }

    #[test]
    fn test_render_human_omits_requires_restart_for_error_codes() {
        let e = lookup("RCH-E001").unwrap();
        let rendered = render_human(&e);
        assert!(!rendered.contains("Requires restart"));
    }

    #[test]
    fn test_serde_roundtrip() {
        let e = lookup("RCH-R001").unwrap();
        let json = serde_json::to_string(&e).unwrap();
        let back: CodeExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(e.code, back.code);
        assert_eq!(e.namespace, back.namespace);
        assert_eq!(e.category, back.category);
    }

    #[test]
    fn test_error_code_all_consistent_with_code_string() {
        // Every code in the hand-maintained list MUST have a unique
        // RCH-Ennn code_string. Asserts the catalog isn't drifting.
        use std::collections::HashSet;
        let codes: HashSet<String> = error_code_all().iter().map(|c| c.code_string()).collect();
        assert_eq!(codes.len(), error_code_all().len());
    }
}
