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
//!   "remediation": ["Telemetry refresh is automatic; wait for the next poll, or run `rch daemon restart` to force a fresh poll cycle."],
//!   "requires_restart": false
//! }
//! ```

use super::{ErrorCategory, ErrorCode, ReliabilityCategoryKind, ReliabilityReasonCode};
use crate::incident::IncidentReasonCode;
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
    /// `RCH-Innn` incident/refusal reason codes from [`IncidentReasonCode`].
    Incident,
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
    if let Some(c) = lookup_incident(&normalized) {
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

/// Resolve an `RCH-Innn` incident/refusal reason code. The incident registry
/// ([`IncidentReasonCode`]) owns the canonical code list and operator-facing
/// failure-class strings; the description/category/remediation are authored
/// here (the codes are operational/policy reasons, several of which have no
/// single error-catalog analogue).
fn lookup_incident(code: &str) -> Option<CodeExplanation> {
    let v = IncidentReasonCode::from_code_str(code)?;
    Some(CodeExplanation {
        code: v.code().to_string(),
        namespace: CodeNamespace::Incident,
        name: format!("{v:?}"),
        category: incident_category(v).to_string(),
        description: incident_description(v).to_string(),
        remediation: incident_remediation(v),
        requires_restart: None,
        doc_url: None,
    })
}

/// Snake-case category for an incident reason code (aligns with the reliability
/// failure taxonomy where it overlaps).
const fn incident_category(v: IncidentReasonCode) -> &'static str {
    use IncidentReasonCode as I;
    match v {
        I::NoAdmissibleWorkers | I::HardPreflight => "admission",
        I::CriticalPressure | I::DiskFull => "disk_pressure",
        I::InsufficientSlots | I::QueueAmbiguity => "capacity",
        I::ActiveProjectExclusion => "path_deps",
        I::MissingRuntimeToolchainTarget => "capability",
        I::OsArchMismatch | I::WrongUserPathWorkerBinary => "worker_binary",
        I::TelemetryStale => "telemetry",
        I::CircuitOpen => "worker",
        I::DaemonSocketRefused => "daemon",
        I::LocalFallback => "fallback",
        I::ProofRefusal => "proof",
        I::RsyncVanishedFile | I::ArtifactMiss => "transfer",
        I::ToolchainDrift => "self_test",
    }
}

/// One-line operator-facing description for an incident reason code.
const fn incident_description(v: IncidentReasonCode) -> &'static str {
    use IncidentReasonCode as I;
    match v {
        I::NoAdmissibleWorkers => "No worker passed admission — every candidate was rejected.",
        I::CriticalPressure => {
            "A worker (or the pool) was under critical disk/memory pressure and could not admit work."
        }
        I::InsufficientSlots => "Not enough free build slots to admit the request right now.",
        I::HardPreflight => "A hard preflight check rejected the only candidate worker(s).",
        I::ActiveProjectExclusion => {
            "The active project root was excluded from offload by a path-dependency or topology rule."
        }
        I::MissingRuntimeToolchainTarget => {
            "A required runtime, toolchain, or Rust target was missing on the worker(s)."
        }
        I::OsArchMismatch => {
            "The worker's OS/arch did not match the required artifact/target triple."
        }
        I::TelemetryStale => "Worker telemetry was stale or its age could not be determined.",
        I::CircuitOpen => "The worker's circuit breaker was open (repeated failures isolated it).",
        I::DaemonSocketRefused => {
            "The daemon Unix socket refused or could not accept the connection."
        }
        I::LocalFallback => {
            "The build fell back to local execution (fail-open) instead of offloading."
        }
        I::ProofRefusal => {
            "Proof mode (RCH_REQUIRE_REMOTE) refused to proceed because remote execution could not be guaranteed."
        }
        I::RsyncVanishedFile => "rsync reported a source file that vanished mid-transfer.",
        I::ArtifactMiss => "An expected build artifact was missing on retrieval.",
        I::QueueAmbiguity => "A build's local/remote job identity could not be correlated cleanly.",
        I::DiskFull => "The target disk was full.",
        I::WrongUserPathWorkerBinary => {
            "A wrong-user or wrong-path/arch rch-wkr binary was detected on the worker."
        }
        I::ToolchainDrift => {
            "A self-test canary built successfully but its bytes differ from the orchestrator's reference because the worker's toolchain differs — a healthy worker, not a failure."
        }
    }
}

/// Authored remediation steps for an incident reason code. These match the
/// next-actions surfaced by `rch admit` and the canonical rch skill's RCH-Innn
/// table, so the explainer and the live surfaces agree.
fn incident_remediation(v: IncidentReasonCode) -> Vec<String> {
    use IncidentReasonCode as I;
    let steps: &[&str] = match v {
        I::NoAdmissibleWorkers => &[
            "Run `rch status --fleet` to see whether the fleet is absent, overloaded, or missing a capability.",
            "Run `rch admit \"<command>\"` for the per-candidate rejection reasons.",
        ],
        I::CriticalPressure => &[
            "Inspect pressure with `rch doctor --reliability --scope pressure`.",
            "Reclaim space with `rch cache clean --older <dur> --execute` (the daemon's reaper protects active builds).",
        ],
        I::InsufficientSlots => &[
            "Queue instead of falling back: keep `RCH_QUEUE_WHEN_BUSY=1` (the default).",
            "Watch `rch queue`; add workers only if the fleet is genuinely under-provisioned.",
        ],
        I::HardPreflight => &[
            "Run `rch admit \"<command>\"` to see which preflight check failed.",
            "Fix the named capability/topology issue, or target another worker with `RCH_WORKER`.",
        ],
        I::ActiveProjectExclusion => &[
            "Inspect the resolved plan: `rch diagnose \"<command>\" --json` (data.placement).",
            "Ensure required sibling repos exist under the canonical project root on the worker.",
        ],
        I::MissingRuntimeToolchainTarget => &[
            "Refresh worker facts: `rch workers capabilities --refresh`.",
            "Install the missing toolchain/target on the worker, or `rch fleet deploy --worker <id> --force`.",
        ],
        I::OsArchMismatch => &[
            "Re-deploy the correct target triple: `rch fleet deploy --worker <id> --force --verify`.",
            "Confirm the needed target with `rch workers capabilities --refresh`.",
        ],
        I::TelemetryStale => &[
            "Inspect freshness via `rch status --remediation` (telemetry band).",
            "Usually self-heals on the next probe; check host distance/poll interval if it persists.",
        ],
        I::CircuitOpen => &[
            "The breaker self-heals (open, half-open, closed) after a good probe — fix the worker, then `rch workers probe <id>`.",
            "Do not `rch workers disable` a transiently-open worker; it auto-rejoins.",
        ],
        I::DaemonSocketRefused => &[
            "Restart the daemon (it reclaims a stale socket): `rch daemon restart`.",
            "Never `rm` the socket by hand; `rch doctor --fix` repairs common wiring.",
        ],
        I::LocalFallback => &[
            "Expected fail-open behavior when remote is not worth it or unavailable — no action usually needed.",
            "Force offload with `RCH_FORCE_REMOTE=1`, or forbid local fallback with `RCH_REQUIRE_REMOTE=1` (proof mode).",
        ],
        I::ProofRefusal => &[
            "Proof mode is fail-closed by design — fix the underlying remote issue rather than retrying locally.",
            "The proof intent is recorded and replays when capacity returns; inspect `rch status --remediation --json`.",
            "Keep the command as direct argv after `--`; shell-wrapped commands are refused (RCH-E301).",
        ],
        I::RsyncVanishedFile => &[
            "Usually transient (a file changed mid-transfer) — retry the build.",
            "If persistent, exclude churny build dirs via `[transfer] exclude_patterns`.",
        ],
        I::ArtifactMiss => &[
            "Re-run the build; inspect the remote target dir and artifact patterns with `rch diagnose \"<command>\" --json`.",
            "Ensure the worker has disk headroom: `rch doctor --reliability --scope pressure`.",
        ],
        I::QueueAmbiguity => &[
            "Inspect active/queued builds and their ids with `rch queue`.",
            "Clear a wedged build with `rch cancel <id>`; the daemon reattaches recoverable jobs on restart.",
        ],
        I::DiskFull => &[
            "Reclaim worker disk: `rch cache clean --older <dur> --execute` (the reaper protects active builds).",
            "Inspect with `rch doctor --reliability --scope pressure`.",
        ],
        I::WrongUserPathWorkerBinary => &[
            "Re-deploy atomically: `rch fleet deploy --worker <id> --force --verify` — do not hand-patch the worker.",
            "Verify with `rch fleet verify --worker <id>`.",
        ],
        I::ToolchainDrift => &[
            "Advisory only — the worker is healthy; its `rustc` nightly merely differs from the orchestrator's, so codegen differs. No action required.",
            "To silence the advisory, align toolchains: `rch fleet deploy --worker <id>` after matching the worker's `rust-toolchain`, or compare with `rch workers capabilities --refresh`.",
        ],
    };
    steps.iter().map(|s| (*s).to_string()).collect()
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
    for v in IncidentReasonCode::ALL {
        if let Some(e) = lookup_incident(v.code()) {
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

/// All known [`ErrorCode`] variants from the authoritative catalog.
fn error_code_all() -> &'static [ErrorCode] {
    ErrorCode::all()
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
            CodeNamespace::Incident => "incident (RCH-Innn)",
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
    fn test_lookup_dependency_preflight_error_code() {
        let e = lookup("RCH-E410").expect("dependency preflight missing known");
        assert_eq!(e.code, "RCH-E410");
        assert_eq!(e.namespace, CodeNamespace::Error);
        assert_eq!(e.name, "DependencyPreflightMissing");
        assert_eq!(e.category, "transfer");
        assert!(e.description.contains("missing required path"));
        assert!(
            e.remediation
                .iter()
                .any(|step| step.contains("missing remote path"))
        );
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

    #[test]
    fn test_lookup_incident_only_code() {
        // RCH-I012 (ProofRefusal) is an incident-only policy code with no
        // error-catalog analogue — it must still resolve via `rch error explain`.
        let e = lookup("RCH-I012").expect("RCH-I012 known");
        assert_eq!(e.code, "RCH-I012");
        assert_eq!(e.namespace, CodeNamespace::Incident);
        assert_eq!(e.category, "proof");
        assert!(!e.description.is_empty());
        assert!(!e.remediation.is_empty());
        assert!(e.requires_restart.is_none());
    }

    #[test]
    fn test_lookup_incident_code_case_and_whitespace_tolerant() {
        let e = lookup("  rch-i001  ").expect("RCH-I001 known");
        assert_eq!(e.code, "RCH-I001");
        assert_eq!(e.namespace, CodeNamespace::Incident);
    }

    #[test]
    fn test_every_incident_code_resolves_with_description_and_remediation() {
        for v in IncidentReasonCode::ALL {
            let e = lookup(v.code()).unwrap_or_else(|| panic!("{} must resolve", v.code()));
            assert_eq!(e.namespace, CodeNamespace::Incident);
            assert!(
                !e.description.is_empty(),
                "{} has empty description",
                v.code()
            );
            assert!(
                !e.remediation.is_empty(),
                "{} has empty remediation",
                v.code()
            );
            assert!(!e.category.is_empty(), "{} has empty category", v.code());
        }
    }

    #[test]
    fn test_list_all_includes_incident_namespace() {
        let all = list_all();
        let incident_count = all
            .iter()
            .filter(|e| e.namespace == CodeNamespace::Incident)
            .count();
        assert_eq!(
            incident_count,
            IncidentReasonCode::ALL.len(),
            "list_all must include every incident reason code"
        );
        assert!(incident_count >= 17, "expected at least 17 incident codes");
    }

    #[test]
    fn test_render_human_labels_incident_namespace() {
        let e = lookup("RCH-I011").unwrap();
        let rendered = render_human(&e);
        assert!(rendered.contains("RCH-I011"));
        assert!(rendered.contains("incident (RCH-Innn)"));
        assert!(rendered.contains("Remediation:"));
    }
}
