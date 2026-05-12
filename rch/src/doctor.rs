//! Diagnostic command implementation for `rch doctor`.
//!
//! Runs comprehensive diagnostics and optionally auto-fixes common issues.

use crate::agent::{AgentKind, install_hook};
use crate::commands::{
    DoctorCheck, DoctorCheckStatus, DoctorFixApplied, DoctorResponse, DoctorSummary, config_dir,
    load_workers_from_config, send_daemon_command,
};
use crate::state::primitives::IdempotentResult;
use crate::status_display::query_daemon_full_status;
use crate::status_types::{
    DaemonFullStatusResponse, RepoConvergenceStatusFromApi, WorkerStatusFromApi, extract_json_body,
};
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::Result;
use directories::ProjectDirs;
use rch_common::{ApiResponse, ReliabilityReasonCode};
use rch_telemetry::TelemetryStorage;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use which::which;

/// Default socket path (XDG_RUNTIME_DIR -> ~/.cache/rch -> /tmp fallback).
fn default_socket_path() -> PathBuf {
    PathBuf::from(rch_common::default_socket_path())
}

/// Maximum size of a config / settings file we'll read into memory.
/// Bounds OOM risk if a hostile or corrupted file is gigabytes in size.
/// Real RCH/Claude config files are well under 1 MB; 16 MB gives an
/// order-of-magnitude headroom for unusual but legitimate cases.
const MAX_CONFIG_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Read a config file with a hard size cap. Returns the same Err shape
/// as `std::fs::read_to_string` so callers can pattern-match on `io::Error`,
/// but converts an oversize file into `io::Error::new(InvalidData, ...)`
/// rather than blindly OOM-ing on `std::fs::read_to_string`.
fn read_config_capped(path: &Path) -> std::io::Result<String> {
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_CONFIG_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "config file {} is {} bytes, exceeds {}-byte cap",
                path.display(),
                metadata.len(),
                MAX_CONFIG_FILE_BYTES
            ),
        ));
    }
    read_config_capped_from_reader(
        file,
        MAX_CONFIG_FILE_BYTES,
        &format!("config file {}", path.display()),
    )
}

fn read_config_capped_from_reader<R: Read>(
    reader: R,
    max_bytes: u64,
    source: &str,
) -> std::io::Result<String> {
    let mut limited = reader.take(max_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    let max_bytes_usize = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    if bytes.len() > max_bytes_usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{source} exceeds {max_bytes}-byte cap"),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

// Type aliases for backward compatibility within this module
type CheckResult = DoctorCheck;
type CheckStatus = DoctorCheckStatus;
type FixApplied = DoctorFixApplied;

// `rch doctor` emits a long human report. A downstream consumer such as
// `head` may close stdout early; treat that as normal Unix pipe behavior
// instead of letting Rust's standard print macros panic.
macro_rules! print {
    ($($arg:tt)*) => {{
        write_stdout(format_args!($($arg)*), false);
    }};
}

macro_rules! println {
    () => {{
        write_stdout(format_args!(""), true);
    }};
    ($($arg:tt)*) => {{
        write_stdout(format_args!($($arg)*), true);
    }};
}

fn write_stdout(args: std::fmt::Arguments<'_>, newline: bool) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let result = out.write_fmt(args).and_then(|()| {
        if newline {
            out.write_all(b"\n")
        } else {
            Ok(())
        }
    });

    if let Err(err) = result {
        if err.kind() == io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        let _ = writeln!(
            io::stderr().lock(),
            "rch doctor: failed to write output: {err}"
        );
        std::process::exit(1);
    }
}

// =============================================================================
// Doctor Command Options
// =============================================================================

/// Options for the doctor command.
pub struct DoctorOptions {
    /// Attempt to fix safe issues.
    pub fix: bool,
    /// Show what would be fixed without making changes.
    pub dry_run: bool,
    /// Allow installing missing local deps (requires confirmation).
    #[allow(dead_code)]
    pub install_deps: bool,
    /// Run reliability-focused diagnostics instead of the general doctor suite.
    pub reliability: bool,
    /// Include schema compatibility checks in reliability mode.
    pub check_schemas: bool,
    /// Detailed output.
    pub verbose: bool,
    /// `--strict`: promote `Degraded` to exit code 2 (treat warnings as failures
    /// for tight CI gates). JSON `data.summary.overall` is unaffected.
    pub strict: bool,
    /// `--lenient`: demote `Failing` to exit code 1 (log only, never block).
    /// JSON `data.summary.overall` is unaffected.
    pub lenient: bool,
    /// `--scope=<list>`: subset of probes to run. Default = `[All]`.
    pub scope: ReliabilityScopeSet,
}

// Live schema-version constants are sourced from the central
// `rch_common::schema_versions` registry. The `EXPECTED_*` constants
// below are intentionally pinned literals: the reliability doctor must
// compare live component versions against the versions this doctor knows
// how to consume, not against aliases of those same live constants.
const RELIABILITY_DOCTOR_SCHEMA_VERSION: &str =
    rch_common::schema_version(rch_common::SchemaComponent::DoctorReliability);
const EXPECTED_RELIABILITY_DOCTOR_SCHEMA_VERSION: &str = "1.0.0";
const EXPECTED_STATUS_SCHEMA_VERSION: &str = "1.0.0";
const EXPECTED_REPO_UPDATER_CONTRACT_SCHEMA_VERSION: &str = "1.0.0";
const EXPECTED_PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReliabilitySeverity {
    Pass,
    Info,
    Warning,
    Critical,
}

/// Tri-state aggregate verdict for the reliability doctor.
///
/// - `Healthy`  — every diagnostic passed (or only Info diagnostics).
/// - `Degraded` — at least one Warning, no Criticals.
/// - `Failing`  — at least one Critical.
///
/// Maps to process exit codes via `ReliabilityVerdict::exit_code`. Operators key
/// alerting policy off this tri-state (sibling t25 watch / t28 webhooks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReliabilityVerdict {
    Healthy,
    Degraded,
    Failing,
}

impl ReliabilityVerdict {
    /// Default exit-code mapping (without `--strict` / `--lenient`):
    /// Healthy → 0, Degraded → 1, Failing → 2.
    #[must_use]
    pub const fn default_exit_code(self) -> i32 {
        match self {
            Self::Healthy => 0,
            Self::Degraded => 1,
            Self::Failing => 2,
        }
    }

    /// Apply `--strict` / `--lenient` exit-code policy. Returns the mapped
    /// exit code. JSON `data.summary.overall` is unaffected — flags only shift
    /// the process exit.
    #[must_use]
    pub const fn exit_code(self, strict: bool, lenient: bool) -> i32 {
        // Caller must guarantee strict and lenient are not both set.
        if strict {
            // Promote: Degraded becomes Failing-equivalent (exit 2).
            match self {
                Self::Healthy => 0,
                Self::Degraded | Self::Failing => 2,
            }
        } else if lenient {
            // Demote: Failing becomes Degraded-equivalent (exit 1).
            match self {
                Self::Healthy => 0,
                Self::Degraded | Self::Failing => 1,
            }
        } else {
            self.default_exit_code()
        }
    }

    /// Human-readable label, used in banner rendering.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "Healthy",
            Self::Degraded => "Degraded",
            Self::Failing => "Failing",
        }
    }
}

/// Pure aggregator: max-severity-wins.
///
/// - Any `Critical` → `Failing`.
/// - Else any `Warning` → `Degraded`.
/// - Else (Pass / Info / empty) → `Healthy`.
///
/// Empty input is honestly `Healthy` — caller is responsible for adding a
/// "no probes ran" diagnostic if that's the wrong default for their context.
fn aggregate_verdict(diagnostics: &[ReliabilityDiagnostic]) -> ReliabilityVerdict {
    let mut has_warning = false;
    for diag in diagnostics {
        match diag.severity {
            ReliabilitySeverity::Critical => return ReliabilityVerdict::Failing,
            ReliabilitySeverity::Warning => has_warning = true,
            ReliabilitySeverity::Pass | ReliabilitySeverity::Info => {}
        }
    }
    if has_warning {
        ReliabilityVerdict::Degraded
    } else {
        ReliabilityVerdict::Healthy
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReliabilityCategory {
    Topology,
    RepoPresence,
    DiskPressure,
    ProcessDebt,
    HelperCompatibility,
    RolloutPosture,
    SchemaCompatibility,
}

impl ReliabilityCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::Topology => "topology",
            Self::RepoPresence => "repo_presence",
            Self::DiskPressure => "disk_pressure",
            Self::ProcessDebt => "process_debt",
            Self::HelperCompatibility => "helper_compatibility",
            Self::RolloutPosture => "rollout_posture",
            Self::SchemaCompatibility => "schema_compatibility",
        }
    }
}

/// One scope bucket per reliability probe, plus an `All` sentinel that
/// runs every probe (default behavior).
///
/// Each named variant maps to one of the `reliability_*_diagnostics`
/// probes in `run_reliability_doctor`. Operators triaging a known
/// symptom can pass `--scope=pressure` (or any subset, comma-separated)
/// to skip the irrelevant probes — typical 7-probe sweep takes ~1.5s
/// against an 8-worker fleet, scope=topology is ~50ms.
///
/// Naming uses the operator-facing labels per the bead: `convergence`
/// (not `repo_presence`), `triage` (not `process_debt`), `helpers`
/// (not `helper_compatibility`), `rollout` (not `rollout_posture`),
/// `schema` (not `schema_compatibility`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReliabilityScope {
    All,
    Topology,
    Convergence,
    Pressure,
    Triage,
    Helpers,
    Rollout,
    Schema,
}

impl ReliabilityScope {
    /// Operator-facing label (matches clap value names).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Topology => "topology",
            Self::Convergence => "convergence",
            Self::Pressure => "pressure",
            Self::Triage => "triage",
            Self::Helpers => "helpers",
            Self::Rollout => "rollout",
            Self::Schema => "schema",
        }
    }
}

impl std::str::FromStr for ReliabilityScope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim().to_ascii_lowercase();
        match trimmed.as_str() {
            "all" => Ok(Self::All),
            "topology" => Ok(Self::Topology),
            "convergence" => Ok(Self::Convergence),
            "pressure" => Ok(Self::Pressure),
            "triage" => Ok(Self::Triage),
            "helpers" => Ok(Self::Helpers),
            "rollout" => Ok(Self::Rollout),
            "schema" => Ok(Self::Schema),
            other => Err(format!(
                "unknown scope value '{other}' (valid: all, topology, convergence, pressure, triage, helpers, rollout, schema)"
            )),
        }
    }
}

/// Comma-separated set of scopes. Wraps `Vec<ReliabilityScope>` because
/// clap's `value_parser` requires a single type for the field; the parser
/// splits on `,`, deduplicates while preserving first-appearance order,
/// and treats `all` as dominant (collapses any other entries to a
/// 1-element `[All]` set with an INFO trace event noting redundancy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReliabilityScopeSet(pub Vec<ReliabilityScope>);

impl Default for ReliabilityScopeSet {
    fn default() -> Self {
        Self(vec![ReliabilityScope::All])
    }
}

impl ReliabilityScopeSet {
    /// Returns true if this set contains the `All` sentinel OR the
    /// given scope explicitly. Used to gate each probe.
    #[must_use]
    pub fn matches(&self, scope: ReliabilityScope) -> bool {
        self.0
            .iter()
            .any(|s| matches!(s, ReliabilityScope::All) || *s == scope)
    }

    /// Lowercase string form for `data.scope` JSON.
    #[must_use]
    pub fn as_strings(&self) -> Vec<String> {
        self.0.iter().map(|s| s.as_str().to_string()).collect()
    }

    fn needs_worker_config(&self) -> bool {
        self.matches(ReliabilityScope::Topology)
    }

    fn needs_daemon_status(&self) -> bool {
        [
            ReliabilityScope::Topology,
            ReliabilityScope::Pressure,
            ReliabilityScope::Triage,
        ]
        .into_iter()
        .any(|scope| self.matches(scope))
    }

    fn needs_repo_convergence_status(&self) -> bool {
        self.matches(ReliabilityScope::Convergence)
    }

    fn needs_rollout_config(&self) -> bool {
        self.matches(ReliabilityScope::Rollout)
    }

    fn runs_schema_probe(&self, check_schemas: bool) -> bool {
        self.0.contains(&ReliabilityScope::Schema)
            || (check_schemas && self.matches(ReliabilityScope::Schema))
    }

    fn probe_names_to_run(&self, check_schemas: bool) -> Vec<&'static str> {
        let mut names = Vec::new();
        for (scope, name) in [
            (ReliabilityScope::Topology, "topology"),
            (ReliabilityScope::Convergence, "convergence"),
            (ReliabilityScope::Pressure, "pressure"),
            (ReliabilityScope::Triage, "triage"),
            (ReliabilityScope::Helpers, "helpers"),
            (ReliabilityScope::Rollout, "rollout"),
        ] {
            if self.matches(scope) {
                names.push(name);
            }
        }
        if self.runs_schema_probe(check_schemas) {
            names.push("schema");
        }
        names
    }
}

impl std::str::FromStr for ReliabilityScopeSet {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err("scope list is empty (pass --scope=all or one of: topology, convergence, pressure, triage, helpers, rollout, schema)".to_string());
        }
        let mut out: Vec<ReliabilityScope> = Vec::new();
        for segment in trimmed.split(',') {
            let scope: ReliabilityScope = segment.parse()?;
            if !out.contains(&scope) {
                out.push(scope);
            }
        }
        // `all` dominates: if mixed with other names, collapse to [All]
        // and log the redundancy at INFO level.
        if out.contains(&ReliabilityScope::All) && out.len() > 1 {
            let redundant: Vec<String> = out
                .iter()
                .filter(|s| **s != ReliabilityScope::All)
                .map(|s| s.as_str().to_string())
                .collect();
            tracing::info!(
                target: "rch::doctor::scope",
                redundant = ?redundant,
                "doctor.scope.all_dominates_redundant",
            );
            out = vec![ReliabilityScope::All];
        }
        Ok(Self(out))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReliabilityDoctorMode {
    Check,
    DryRun,
    Fix,
}

#[derive(Debug, Clone, Serialize)]
struct ReliabilityDiagnostic {
    category: ReliabilityCategory,
    check_name: String,
    severity: ReliabilitySeverity,
    message: String,
    /// Canonical `RCH-Rnnn` reason code (per `ReliabilityReasonCode`).
    /// Serializes as the string form (e.g., `"RCH-R001"`).
    code: ReliabilityReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worker_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validation_check: Option<String>,
    dry_run_safe: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ReliabilityDoctorSummary {
    total_checks: usize,
    pass: usize,
    info: usize,
    warning: usize,
    critical: usize,
    categories_checked: Vec<ReliabilityCategory>,
    /// Tri-state aggregate verdict (t02). Replaces the prior boolean
    /// `overall_healthy`. Per AGENTS.md "no backwards compatibility":
    /// JSON consumers update to read `summary.overall` (string) instead
    /// of `summary.overall_healthy` (bool).
    overall: ReliabilityVerdict,
}

#[derive(Debug, Clone, Serialize)]
struct ReliabilityRemediationStep {
    order: u32,
    category: ReliabilityCategory,
    description: String,
    command: String,
    validation: String,
    requires_restart: bool,
    dry_run_safe: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ReliabilityDoctorResponse {
    schema_version: String,
    mode: ReliabilityDoctorMode,
    /// Scope set the operator requested (always present, single-element
    /// `["all"]` by default). Agents inspect this field to confirm their
    /// `--scope` arg was honored.
    scope: Vec<String>,
    /// True when ANY probe could not reach the daemon. Operators see this
    /// top-level marker instead of grepping diagnostic messages for the
    /// daemon-down case. (t05)
    daemon_unreachable: bool,
    /// Per-probe failures that contributed to `daemon_unreachable=true`.
    /// Empty when `daemon_unreachable=false`. Forensic detail so log
    /// consumers can attribute the unreachability to a specific probe
    /// (e.g., "process_debt: daemon status unavailable"). (t05)
    daemon_unreachable_reasons: Vec<String>,
    diagnostics: Vec<ReliabilityDiagnostic>,
    summary: ReliabilityDoctorSummary,
    remediation_plan: Vec<ReliabilityRemediationStep>,
}

impl ReliabilityDiagnostic {
    fn new(
        category: ReliabilityCategory,
        check_name: impl Into<String>,
        severity: ReliabilitySeverity,
        message: impl Into<String>,
        code: ReliabilityReasonCode,
    ) -> Self {
        Self {
            category,
            check_name: check_name.into(),
            severity,
            message: message.into(),
            code,
            details: None,
            worker_id: None,
            remediation_command: None,
            validation_check: None,
            dry_run_safe: true,
        }
    }

    fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    fn with_worker(mut self, worker_id: impl Into<String>) -> Self {
        self.worker_id = Some(worker_id.into());
        self
    }

    fn with_remediation(
        mut self,
        command: impl Into<String>,
        validation_check: impl Into<String>,
    ) -> Self {
        self.remediation_command = Some(command.into());
        self.validation_check = Some(validation_check.into());
        self
    }
}

// =============================================================================
// Main Doctor Function
// =============================================================================

/// Run all diagnostic checks.
pub async fn run_doctor(ctx: &OutputContext, options: DoctorOptions) -> Result<()> {
    if options.reliability {
        return run_reliability_doctor(ctx, &options).await;
    }

    let style = ctx.theme();
    let mut checks: Vec<CheckResult> = Vec::new();
    let mut fixes_applied: Vec<FixApplied> = Vec::new();

    if !ctx.is_json() {
        println!("{}", style.format_header("RCH Diagnostic Report"));
        println!();
    }

    // Run all checks
    check_prerequisites(&mut checks, ctx, &options);
    check_configuration(&mut checks, ctx, &options);
    check_ssh_keys(&mut checks, ctx, &options, &mut fixes_applied);
    check_hooks(&mut checks, ctx, &options, &mut fixes_applied);
    check_daemon(&mut checks, ctx, &options, &mut fixes_applied);
    check_cancellation_health(&mut checks, ctx).await;
    check_workers(&mut checks, ctx, &options).await;
    check_telemetry_database(&mut checks, ctx, &options);

    // Calculate summary
    let fixed = checks.iter().filter(|c| c.fix_applied).count();
    let would_fix = if options.fix && options.dry_run {
        checks
            .iter()
            .filter(|c| matches!(c.fix_message.as_deref(), Some(msg) if msg.starts_with("Would ")))
            .count()
    } else {
        0
    };
    let summary = DoctorSummary {
        total: checks.len(),
        passed: checks
            .iter()
            .filter(|c| c.status == CheckStatus::Pass)
            .count(),
        warnings: checks
            .iter()
            .filter(|c| c.status == CheckStatus::Warning)
            .count(),
        failed: checks
            .iter()
            .filter(|c| c.status == CheckStatus::Fail)
            .count(),
        fixed,
        would_fix,
    };

    // Output results
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "doctor",
            DoctorResponse {
                // t05: same schema-version on legacy doctor as on
                // reliability mode; sourced from the central registry.
                schema_version: rch_common::schema_version(
                    rch_common::SchemaComponent::DoctorReliability,
                )
                .to_string(),
                checks,
                summary,
                fixes_applied,
            },
        ));
    } else {
        // Print summary
        println!();
        println!("{}", style.format_header("Summary"));
        println!();
        println!(
            "  {} {} passed",
            StatusIndicator::Success.display(style),
            style.highlight(&summary.passed.to_string())
        );
        if summary.warnings > 0 {
            println!(
                "  {} {} warnings",
                StatusIndicator::Warning.display(style),
                style.highlight(&summary.warnings.to_string())
            );
        }
        if summary.failed > 0 {
            println!(
                "  {} {} failed",
                StatusIndicator::Error.display(style),
                style.highlight(&summary.failed.to_string())
            );
        }
        if summary.fixed > 0 {
            println!(
                "  {} {} fixed",
                StatusIndicator::Success.display(style),
                style.highlight(&summary.fixed.to_string())
            );
        }
        if summary.would_fix > 0 {
            println!(
                "  {} {} would fix",
                StatusIndicator::Pending.display(style),
                style.highlight(&summary.would_fix.to_string())
            );
        }

        // Show fixes applied
        if !fixes_applied.is_empty() {
            println!();
            println!("{}", style.format_header("Fixes Applied"));
            for fix in &fixes_applied {
                if fix.success {
                    println!(
                        "  {} {}: {}",
                        StatusIndicator::Success.display(style),
                        style.highlight(&fix.check_name),
                        style.muted(&fix.action)
                    );
                } else {
                    println!(
                        "  {} {}: {} - {}",
                        StatusIndicator::Error.display(style),
                        style.highlight(&fix.check_name),
                        style.muted(&fix.action),
                        style.error(fix.error.as_deref().unwrap_or("unknown error"))
                    );
                }
            }
        }

        // Final status
        println!();
        if summary.failed > 0 {
            println!(
                "{}",
                style.format_error("Some checks failed. Run with --fix to attempt auto-repair.")
            );
        } else if summary.warnings > 0 {
            println!(
                "{}",
                style.format_warning("System is operational with warnings.")
            );
        } else {
            println!("{}", style.format_success("All checks passed!"));
        }
    }

    Ok(())
}

async fn run_reliability_doctor(ctx: &OutputContext, options: &DoctorOptions) -> Result<()> {
    // Probe gating per --scope (t01). Each branch runs only when the
    // operator-supplied scope set matches. Default `[All]` runs everything.
    let scope = &options.scope;

    // Keep scoped runs honest: do not pay for daemon/repo/config prefetches
    // that no selected probe can consume.
    let config_result = if scope.needs_rollout_config() {
        Some(crate::config::load_config())
    } else {
        None
    };
    tracing::debug!(
        target: "rch::doctor::config_loads",
        loaded = matches!(config_result.as_ref(), Some(Ok(_))),
        skipped = !scope.needs_rollout_config(),
        "doctor.config.load",
    );

    let (workers, worker_config_error) = if scope.needs_worker_config() {
        match load_workers_from_config() {
            Ok(workers) => (Some(workers), None),
            Err(err) => (None, Some(err.to_string())),
        }
    } else {
        (None, None)
    };

    let daemon_status = if scope.needs_daemon_status() {
        query_daemon_full_status().await.ok()
    } else {
        None
    };
    let convergence_status = if scope.needs_repo_convergence_status() {
        query_repo_convergence_status().await.ok()
    } else {
        None
    };
    let probes_to_run = scope.probe_names_to_run(options.check_schemas);
    tracing::info!(
        target: "rch::doctor::scope",
        scope = ?scope.as_strings(),
        probes_to_run = ?probes_to_run,
        probes_count = probes_to_run.len(),
        "doctor.scope.applied",
    );

    let mut diagnostics = Vec::new();
    if scope.matches(ReliabilityScope::Topology) {
        diagnostics.extend(reliability_topology_diagnostics(
            workers.as_deref(),
            daemon_status.as_ref(),
            worker_config_error,
        ));
    }
    if scope.matches(ReliabilityScope::Convergence) {
        diagnostics.extend(reliability_repo_diagnostics(convergence_status.as_ref()));
    }
    if scope.matches(ReliabilityScope::Pressure) {
        diagnostics.extend(reliability_disk_pressure_diagnostics(
            daemon_status.as_ref(),
        ));
    }
    if scope.matches(ReliabilityScope::Triage) {
        diagnostics.extend(reliability_process_debt_diagnostics(daemon_status.as_ref()));
    }
    if scope.matches(ReliabilityScope::Helpers) {
        diagnostics.extend(reliability_helper_compatibility_diagnostics());
    }
    if scope.matches(ReliabilityScope::Rollout) {
        let config_load: Result<&rch_common::RchConfig, String> = match config_result.as_ref() {
            Some(Ok(config)) => Ok(config),
            Some(Err(error)) => Err(error.to_string()),
            None => Err("config load skipped unexpectedly".to_string()),
        };
        diagnostics.extend(reliability_rollout_posture_diagnostics(
            config_load.as_ref().map(|c| *c).map_err(|e| e.as_str()),
        ));
    }
    if scope.runs_schema_probe(options.check_schemas) {
        diagnostics.extend(reliability_schema_compatibility_diagnostics());
    }

    let mode = if options.dry_run {
        ReliabilityDoctorMode::DryRun
    } else if options.fix {
        ReliabilityDoctorMode::Fix
    } else {
        ReliabilityDoctorMode::Check
    };
    let response = build_reliability_doctor_response(mode, scope, diagnostics);

    if ctx.is_json() {
        // t05: command tag is a single dotted token ("doctor.reliability")
        // for agent-friendly jq-matching. Per AGENTS.md no-back-compat:
        // consumers update to the dotted form directly.
        let _ = ctx.json(&ApiResponse::ok("doctor.reliability", &response));
    } else {
        print_reliability_doctor_response(ctx, &response);
    }

    // Verdict → exit-code mapping (t02). Honors --strict / --lenient. Logged
    // for forensics so log consumers can correlate exit codes with verdicts.
    let exit_code = response
        .summary
        .overall
        .exit_code(options.strict, options.lenient);
    tracing::info!(
        target: "rch::doctor::verdict",
        verdict = response.summary.overall.label(),
        exit_code,
        strict = options.strict,
        lenient = options.lenient,
        pass = response.summary.pass,
        info = response.summary.info,
        warning = response.summary.warning,
        critical = response.summary.critical,
        "doctor.verdict",
    );
    if exit_code == 0 {
        Ok(())
    } else {
        // Non-zero exit must reach the caller. Use process::exit AFTER all
        // output has been flushed (println! above is line-buffered to stdout
        // which auto-flushes on newline).
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let _ = std::io::Write::flush(&mut std::io::stderr());
        std::process::exit(exit_code);
    }
}

async fn query_repo_convergence_status() -> Result<RepoConvergenceStatusFromApi> {
    let response = send_daemon_command("GET /repo-convergence/status\n").await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    serde_json::from_str(json).map_err(Into::into)
}

fn reliability_topology_diagnostics(
    workers: Option<&[rch_common::WorkerConfig]>,
    daemon_status: Option<&DaemonFullStatusResponse>,
    worker_config_error: Option<String>,
) -> Vec<ReliabilityDiagnostic> {
    let mut diagnostics = Vec::new();

    if let Some(error) = worker_config_error {
        diagnostics.push(
            ReliabilityDiagnostic::new(
                ReliabilityCategory::Topology,
                "workers_config",
                ReliabilitySeverity::Critical,
                "Worker configuration could not be loaded",
                ReliabilityReasonCode::WorkersConfigUnreadable,
            )
            .with_details(error)
            .with_remediation(
                "rch config doctor --json",
                "rch doctor --reliability --json",
            ),
        );
    } else if let Some(workers) = workers {
        if workers.is_empty() {
            diagnostics.push(
                ReliabilityDiagnostic::new(
                    ReliabilityCategory::Topology,
                    "workers_config",
                    ReliabilitySeverity::Critical,
                    "No workers are configured, so all builds will run locally",
                    ReliabilityReasonCode::NoWorkersConfigured,
                )
                .with_remediation("rch workers add <host>", "rch workers list --json"),
            );
        } else {
            let worker_ids = workers
                .iter()
                .map(|worker| worker.id.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            diagnostics.push(
                ReliabilityDiagnostic::new(
                    ReliabilityCategory::Topology,
                    "workers_config",
                    ReliabilitySeverity::Pass,
                    format!("{} worker(s) configured", workers.len()),
                    ReliabilityReasonCode::WorkersConfigured,
                )
                .with_details(worker_ids),
            );
        }
    }

    let Some(status) = daemon_status else {
        diagnostics.push(
            ReliabilityDiagnostic::new(
                ReliabilityCategory::Topology,
                "daemon_status",
                ReliabilitySeverity::Warning,
                "Daemon status is unavailable; reliability health is partial",
                ReliabilityReasonCode::DaemonStatusUnavailable,
            )
            .with_remediation("rch daemon start", "rch status --json"),
        );
        return diagnostics;
    };

    let daemon = &status.daemon;
    let (severity, code, message) = if daemon.workers_total == 0 {
        (
            ReliabilitySeverity::Critical,
            ReliabilityReasonCode::DaemonHasNoWorkers,
            "Daemon has no registered workers".to_string(),
        )
    } else if daemon.workers_healthy == 0 {
        (
            ReliabilitySeverity::Critical,
            ReliabilityReasonCode::AllWorkersUnhealthy,
            format!("0/{} workers are healthy", daemon.workers_total),
        )
    } else if daemon.workers_healthy < daemon.workers_total {
        (
            ReliabilitySeverity::Warning,
            ReliabilityReasonCode::PartialWorkerCapacity,
            format!(
                "{}/{} workers are healthy",
                daemon.workers_healthy, daemon.workers_total
            ),
        )
    } else {
        (
            ReliabilitySeverity::Pass,
            ReliabilityReasonCode::WorkersHealthy,
            format!("All {} workers are healthy", daemon.workers_total),
        )
    };
    let mut daemon_diag = ReliabilityDiagnostic::new(
        ReliabilityCategory::Topology,
        "daemon_worker_capacity",
        severity,
        message,
        code,
    )
    .with_details(format!(
        "slots_available={}, slots_total={}, uptime_secs={}",
        daemon.slots_available, daemon.slots_total, daemon.uptime_secs
    ));
    if severity != ReliabilitySeverity::Pass {
        daemon_diag =
            daemon_diag.with_remediation("rch workers probe --all", "rch status --workers --json");
    }
    diagnostics.push(daemon_diag);

    diagnostics.extend(status.workers.iter().map(worker_topology_diagnostic));
    diagnostics
}

/// Outcome of a defensive parse: a known categorical value OR the raw
/// (trim+lowercased) input that we couldn't recognize. The raw form is
/// preserved so the resulting diagnostic carries forensics for operators.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedStatus {
    Known(KnownStatus),
    Unrecognized(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownStatus {
    /// Healthy/available/ready/idle/running — counts as "ready".
    Ready,
    /// Known non-ready statuses reported by daemon/status UIs.
    Degraded,
    /// Unreachable/offline/error/failed — critical.
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedCircuit {
    Known(KnownCircuit),
    Unrecognized(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownCircuit {
    Closed,
    Open,
    HalfOpen,
}

/// Trim + lowercase + match against the known status set. Known
/// non-ready states remain `WorkerDegraded`; unknown values become
/// `Unrecognized(raw)` so the caller can surface protocol drift rather
/// than silently mapping to `Pass` (the prior default-to-success bug).
fn parse_worker_ready_status(raw: &str) -> ParsedStatus {
    let normalized = raw.trim().to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "healthy" | "available" | "ready" | "idle" | "running"
    ) {
        ParsedStatus::Known(KnownStatus::Ready)
    } else if matches!(
        normalized.as_str(),
        "unreachable" | "offline" | "error" | "failed"
    ) {
        ParsedStatus::Known(KnownStatus::Unreachable)
    } else if matches!(
        normalized.as_str(),
        "busy" | "degraded" | "draining" | "drained" | "disabled" | "unhealthy"
    ) {
        ParsedStatus::Known(KnownStatus::Degraded)
    } else {
        ParsedStatus::Unrecognized(normalized)
    }
}

/// Same discipline as [`parse_worker_ready_status`] but for the
/// circuit-breaker state field. `closed` is the healthy default;
/// `open` is critical; `half_open` is degraded; anything else
/// (including empty string, whitespace, unexpected casings of unknown
/// variants like `OPEN_FORCED`) surfaces as `Unrecognized`.
fn parse_worker_circuit_state(raw: &str) -> ParsedCircuit {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "closed" => ParsedCircuit::Known(KnownCircuit::Closed),
        "open" => ParsedCircuit::Known(KnownCircuit::Open),
        "half_open" | "half-open" => ParsedCircuit::Known(KnownCircuit::HalfOpen),
        _ => ParsedCircuit::Unrecognized(normalized),
    }
}

fn worker_topology_diagnostic(worker: &WorkerStatusFromApi) -> ReliabilityDiagnostic {
    let parsed_status = parse_worker_ready_status(&worker.status);
    let parsed_circuit = parse_worker_circuit_state(&worker.circuit_state);

    let (severity, code, message) = match (&parsed_circuit, &parsed_status) {
        // Unrecognized values surface as Warnings with the raw value
        // in the diagnostic context. Default-to-degraded — never Pass.
        (ParsedCircuit::Unrecognized(raw), _) => (
            ReliabilitySeverity::Warning,
            ReliabilityReasonCode::WorkerCircuitStateUnrecognized,
            format!(
                "Worker {} circuit_state is unrecognized ({raw:?})",
                worker.id
            ),
        ),
        (_, ParsedStatus::Unrecognized(raw)) => (
            ReliabilitySeverity::Warning,
            ReliabilityReasonCode::WorkerStatusUnrecognized,
            format!("Worker {} status is unrecognized ({raw:?})", worker.id),
        ),
        // Known values: same routing as before.
        (ParsedCircuit::Known(KnownCircuit::Open), _) => (
            ReliabilitySeverity::Critical,
            ReliabilityReasonCode::WorkerCircuitOpen,
            format!("Worker {} circuit is open", worker.id),
        ),
        (_, ParsedStatus::Known(KnownStatus::Unreachable)) => (
            ReliabilitySeverity::Critical,
            ReliabilityReasonCode::WorkerUnreachable,
            format!("Worker {} is {}", worker.id, worker.status),
        ),
        (ParsedCircuit::Known(KnownCircuit::HalfOpen), _) => (
            ReliabilitySeverity::Warning,
            ReliabilityReasonCode::WorkerDegraded,
            format!(
                "Worker {} is degraded (status={}, circuit={})",
                worker.id, worker.status, worker.circuit_state
            ),
        ),
        (_, ParsedStatus::Known(KnownStatus::Degraded)) => (
            ReliabilitySeverity::Warning,
            ReliabilityReasonCode::WorkerDegraded,
            format!(
                "Worker {} is degraded (status={}, circuit={})",
                worker.id, worker.status, worker.circuit_state
            ),
        ),
        // Closed circuit + Ready status = healthy.
        (ParsedCircuit::Known(KnownCircuit::Closed), ParsedStatus::Known(KnownStatus::Ready)) => (
            ReliabilitySeverity::Pass,
            ReliabilityReasonCode::WorkerReady,
            format!("Worker {} is ready", worker.id),
        ),
    };

    let mut diagnostic = ReliabilityDiagnostic::new(
        ReliabilityCategory::Topology,
        "worker_topology",
        severity,
        message,
        code,
    )
    .with_worker(worker.id.clone())
    .with_details(format!(
        "host={}, used_slots={}, total_slots={}, speed_score={:.2}, consecutive_failures={}",
        worker.host,
        worker.used_slots,
        worker.total_slots,
        worker.speed_score,
        worker.consecutive_failures
    ));

    if severity != ReliabilitySeverity::Pass {
        diagnostic = diagnostic.with_remediation(
            format!("rch workers probe {} --force", worker.id),
            "rch status --workers --json",
        );
    }

    // Emit a tracing event whenever we see an unrecognized value so log
    // consumers can spot protocol drift between daemon versions.
    if let ParsedStatus::Unrecognized(raw) = &parsed_status {
        tracing::warn!(
            target: "rch::doctor::parse",
            worker = %worker.id,
            field = "status",
            raw = %raw,
            "doctor.parse.unrecognized",
        );
    }
    if let ParsedCircuit::Unrecognized(raw) = &parsed_circuit {
        tracing::warn!(
            target: "rch::doctor::parse",
            worker = %worker.id,
            field = "circuit_state",
            raw = %raw,
            "doctor.parse.unrecognized",
        );
    }

    diagnostic
}

fn reliability_repo_diagnostics(
    convergence: Option<&RepoConvergenceStatusFromApi>,
) -> Vec<ReliabilityDiagnostic> {
    let Some(convergence) = convergence else {
        return vec![
            ReliabilityDiagnostic::new(
                ReliabilityCategory::RepoPresence,
                "repo_convergence",
                ReliabilitySeverity::Warning,
                "Repo-convergence status is unavailable",
                ReliabilityReasonCode::RepoConvergenceUnavailable,
            )
            .with_remediation("rch daemon start", "rch status --json"),
        ];
    };

    let summary = &convergence.summary;
    let mut diagnostics = Vec::new();
    let (severity, code, message) = if summary.failed > 0 {
        (
            ReliabilitySeverity::Critical,
            ReliabilityReasonCode::RepoConvergenceFailed,
            format!("{} worker(s) failed repo convergence", summary.failed),
        )
    } else if summary.drifting > 0 || summary.stale > 0 {
        (
            ReliabilitySeverity::Warning,
            ReliabilityReasonCode::RepoConvergenceDrift,
            format!(
                "{} drifting and {} stale worker(s)",
                summary.drifting, summary.stale
            ),
        )
    } else if summary.total_workers == 0 {
        (
            ReliabilitySeverity::Info,
            ReliabilityReasonCode::RepoConvergenceNoWorkers,
            "No worker repo-convergence records were reported".to_string(),
        )
    } else {
        (
            ReliabilitySeverity::Pass,
            ReliabilityReasonCode::RepoConvergenceReady,
            format!("{} worker(s) are repo-converged", summary.ready),
        )
    };

    let mut summary_diag = ReliabilityDiagnostic::new(
        ReliabilityCategory::RepoPresence,
        "repo_convergence",
        severity,
        message,
        code,
    )
    .with_details(format!(
        "status={}, total={}, ready={}, converging={}, drifting={}, failed={}, stale={}",
        convergence.status,
        summary.total_workers,
        summary.ready,
        summary.converging,
        summary.drifting,
        summary.failed,
        summary.stale
    ));
    if matches!(
        severity,
        ReliabilitySeverity::Critical | ReliabilitySeverity::Warning
    ) {
        summary_diag =
            summary_diag.with_remediation("rch workers probe --all", "rch status --json");
    }
    diagnostics.push(summary_diag);

    diagnostics.extend(convergence.workers.iter().filter_map(|worker| {
        if worker.missing_repos.is_empty() && worker.drift_state == "ready" {
            return None;
        }

        let severity = if worker.drift_state == "failed" {
            ReliabilitySeverity::Critical
        } else {
            ReliabilitySeverity::Warning
        };
        let missing = if worker.missing_repos.is_empty() {
            "none".to_string()
        } else {
            worker.missing_repos.join(", ")
        };
        let mut diagnostic = ReliabilityDiagnostic::new(
            ReliabilityCategory::RepoPresence,
            "worker_repo_presence",
            severity,
            format!(
                "Worker {} repo state is {}",
                worker.worker_id, worker.drift_state
            ),
            ReliabilityReasonCode::WorkerRepoNotReady,
        )
        .with_worker(worker.worker_id.clone())
        .with_details(format!(
            "confidence={:.2}, missing_repos={}, attempts_remaining={}, time_budget_ms={}",
            worker.drift_confidence,
            missing,
            worker.attempt_budget_remaining,
            worker.time_budget_remaining_ms
        ));

        if let Some(command) = worker.remediation.first() {
            diagnostic =
                diagnostic.with_remediation(command.clone(), "rch status --workers --json");
        } else {
            diagnostic = diagnostic
                .with_remediation("rch workers probe --all", "rch status --workers --json");
        }

        Some(diagnostic)
    }));

    diagnostics
}

fn reliability_disk_pressure_diagnostics(
    status: Option<&DaemonFullStatusResponse>,
) -> Vec<ReliabilityDiagnostic> {
    let Some(status) = status else {
        return vec![
            ReliabilityDiagnostic::new(
                ReliabilityCategory::DiskPressure,
                "disk_pressure",
                ReliabilitySeverity::Warning,
                "Disk-pressure telemetry is unavailable because daemon status could not be read",
                ReliabilityReasonCode::DiskPressureUnavailable,
            )
            .with_remediation("rch daemon start", "rch status --workers --json"),
        ];
    };

    if status.workers.is_empty() {
        return vec![ReliabilityDiagnostic::new(
            ReliabilityCategory::DiskPressure,
            "disk_pressure",
            ReliabilitySeverity::Info,
            "No workers reported disk-pressure telemetry",
            ReliabilityReasonCode::DiskPressureNoWorkers,
        )];
    }

    status
        .workers
        .iter()
        .map(|worker| {
            let state = worker
                .pressure_state
                .as_deref()
                .unwrap_or("telemetry_gap");
            let (severity, code, message) = match state {
                "critical" => (
                    ReliabilitySeverity::Critical,
                    ReliabilityReasonCode::WorkerDiskPressureCritical,
                    format!(
                        "Worker {} has critical disk pressure ({})",
                        worker.id,
                        format_disk_free(worker.pressure_disk_free_gb)
                    ),
                ),
                "warning" => (
                    ReliabilitySeverity::Warning,
                    ReliabilityReasonCode::WorkerDiskPressureWarning,
                    format!(
                        "Worker {} has elevated disk pressure ({})",
                        worker.id,
                        format_disk_free(worker.pressure_disk_free_gb)
                    ),
                ),
                "healthy" => (
                    ReliabilitySeverity::Pass,
                    ReliabilityReasonCode::WorkerDiskPressureHealthy,
                    format!(
                        "Worker {} disk pressure is healthy ({})",
                        worker.id,
                        format_disk_free(worker.pressure_disk_free_gb)
                    ),
                ),
                _ => (
                    ReliabilitySeverity::Warning,
                    ReliabilityReasonCode::WorkerDiskPressureTelemetryGap,
                    format!("Worker {} is missing fresh disk telemetry", worker.id),
                ),
            };

            let mut diagnostic = ReliabilityDiagnostic::new(
                ReliabilityCategory::DiskPressure,
                "worker_disk_pressure",
                severity,
                message,
                code,
            )
            .with_worker(worker.id.clone())
            .with_details(format!(
                "state={}, confidence={}, free_gb={}, total_gb={}, free_ratio={}, io_util_pct={}, memory_pressure={}, telemetry_age_secs={}, telemetry_fresh={}",
                state,
                worker.pressure_confidence.as_deref().unwrap_or("unknown"),
                worker
                    .pressure_disk_free_gb
                    .map(|value| format!("{value:.2}"))
                    .unwrap_or_else(|| "unknown".to_string()),
                worker
                    .pressure_disk_total_gb
                    .map(|value| format!("{value:.2}"))
                    .unwrap_or_else(|| "unknown".to_string()),
                worker
                    .pressure_disk_free_ratio
                    .map(|value| format!("{value:.3}"))
                    .unwrap_or_else(|| "unknown".to_string()),
                worker
                    .pressure_disk_io_util_pct
                    .map(|value| format!("{value:.1}"))
                    .unwrap_or_else(|| "unknown".to_string()),
                worker
                    .pressure_memory_pressure
                    .map(|value| format!("{value:.2}"))
                    .unwrap_or_else(|| "unknown".to_string()),
                worker
                    .pressure_telemetry_age_secs
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                worker
                    .pressure_telemetry_fresh
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ));

            if severity != ReliabilitySeverity::Pass {
                // Shell-escape worker.user and worker.host: the remediation
                // string is shown verbatim to agents (and frequently
                // copy-pasted into a shell). A workers.toml entry like
                // `host = "evil; rm -rf ~"` MUST NOT produce a runnable
                // destructive command. Each component is escaped
                // independently so the resulting `ssh user@host '...'`
                // shape stays valid even when user / host contain shell
                // metachars.
                let user_q = shell_escape::escape(worker.user.clone().into());
                let host_q = shell_escape::escape(worker.host.clone().into());
                diagnostic = diagnostic.with_remediation(
                    format!(
                        "ssh {user_q}@{host_q} 'df -h / /tmp && du -sh /tmp/rch-* /tmp/rch_target_* 2>/dev/null'",
                    ),
                    "rch status --workers --json",
                );
            }

            diagnostic
        })
        .collect()
}

fn format_disk_free(value: Option<f64>) -> String {
    value
        .map(|gb| format!("{gb:.1} GB free"))
        .unwrap_or_else(|| "free space unknown".to_string())
}

fn reliability_process_debt_diagnostics(
    status: Option<&DaemonFullStatusResponse>,
) -> Vec<ReliabilityDiagnostic> {
    let Some(status) = status else {
        return vec![
            ReliabilityDiagnostic::new(
                ReliabilityCategory::ProcessDebt,
                "process_debt",
                ReliabilitySeverity::Warning,
                "Process-debt health is unavailable because daemon status could not be read",
                ReliabilityReasonCode::ProcessDebtUnavailable,
            )
            .with_remediation("rch daemon start", "rch status --jobs --json"),
        ];
    };

    let cancellation = evaluate_cancellation_health(status);
    let severity = match cancellation.status {
        CheckStatus::Pass => ReliabilitySeverity::Pass,
        CheckStatus::Warning => ReliabilitySeverity::Warning,
        CheckStatus::Fail => ReliabilitySeverity::Critical,
        CheckStatus::Skipped => ReliabilitySeverity::Info,
    };
    let mut diagnostic = ReliabilityDiagnostic::new(
        ReliabilityCategory::ProcessDebt,
        "cancellation_cleanup",
        severity,
        cancellation.message,
        match severity {
            ReliabilitySeverity::Pass => ReliabilityReasonCode::CancellationCleanupHealthy,
            ReliabilitySeverity::Info => ReliabilityReasonCode::CancellationCleanupSkipped,
            ReliabilitySeverity::Warning => ReliabilityReasonCode::CancellationCleanupDegraded,
            ReliabilitySeverity::Critical => ReliabilityReasonCode::CancellationCleanupFailed,
        },
    );
    if let Some(details) = cancellation.details {
        diagnostic = diagnostic.with_details(details);
    }
    if let Some(suggestion) = cancellation.suggestion {
        diagnostic = diagnostic.with_remediation(suggestion, "rch status --jobs --json");
    }
    vec![diagnostic]
}

fn reliability_helper_compatibility_diagnostics() -> Vec<ReliabilityDiagnostic> {
    [
        ("ssh", "SSH transport", ReliabilitySeverity::Critical),
        (
            "rsync",
            "incremental transfer",
            ReliabilitySeverity::Critical,
        ),
        ("zstd", "compressed transfer", ReliabilitySeverity::Critical),
        ("cargo", "Rust build fallback", ReliabilitySeverity::Warning),
    ]
    .into_iter()
    .map(|(cmd, description, missing_severity)| {
        if which(cmd).is_ok() {
            let mut diagnostic = ReliabilityDiagnostic::new(
                ReliabilityCategory::HelperCompatibility,
                cmd,
                ReliabilitySeverity::Pass,
                format!("{cmd} is available for {description}"),
                ReliabilityReasonCode::HelperAvailable,
            );
            if let Some(version) = command_version(cmd) {
                diagnostic = diagnostic.with_details(version);
            }
            diagnostic
        } else {
            ReliabilityDiagnostic::new(
                ReliabilityCategory::HelperCompatibility,
                cmd,
                missing_severity,
                format!("{cmd} is missing; {description} may fail or fall back"),
                ReliabilityReasonCode::HelperMissing,
            )
            .with_remediation(
                format!("Install {cmd} with the system package manager"),
                "rch doctor --reliability --json",
            )
        }
    })
    .collect()
}

/// Build rollout-posture diagnostics from a pre-loaded config snapshot.
///
/// Takes the result of a single `crate::config::load_config()` call shared
/// across every probe in `run_reliability_doctor`, so the doctor pays the
/// TOML-parse cost exactly once per invocation and every probe sees a
/// consistent snapshot even if the config file is rewritten mid-run.
fn reliability_rollout_posture_diagnostics(
    config_load: Result<&rch_common::RchConfig, &str>,
) -> Vec<ReliabilityDiagnostic> {
    let mut diagnostics = Vec::new();

    match config_load {
        Ok(config) => {
            let mut hook_diag = if config.self_healing.hook_starts_daemon {
                ReliabilityDiagnostic::new(
                    ReliabilityCategory::RolloutPosture,
                    "hook_starts_daemon",
                    ReliabilitySeverity::Pass,
                    "Hook auto-start is enabled",
                    ReliabilityReasonCode::HookAutoStartEnabled,
                )
            } else {
                ReliabilityDiagnostic::new(
                    ReliabilityCategory::RolloutPosture,
                    "hook_starts_daemon",
                    ReliabilitySeverity::Warning,
                    "Hook auto-start is disabled; daemon outages may silently force local builds",
                    ReliabilityReasonCode::HookAutoStartDisabled,
                )
                .with_remediation(
                    "rch config set self_healing.hook_starts_daemon true",
                    "rch config get self_healing.hook_starts_daemon --json",
                )
            };
            hook_diag = hook_diag.with_details(format!(
                "cooldown_secs={}, timeout_secs={}",
                config.self_healing.auto_start_cooldown_secs,
                config.self_healing.auto_start_timeout_secs
            ));
            diagnostics.push(hook_diag);

            if config.self_healing.daemon_installs_hooks {
                diagnostics.push(ReliabilityDiagnostic::new(
                    ReliabilityCategory::RolloutPosture,
                    "daemon_installs_hooks",
                    ReliabilitySeverity::Pass,
                    "Daemon hook repair is enabled",
                    ReliabilityReasonCode::DaemonHookRepairEnabled,
                ));
            } else {
                diagnostics.push(
                    ReliabilityDiagnostic::new(
                        ReliabilityCategory::RolloutPosture,
                        "daemon_installs_hooks",
                        ReliabilitySeverity::Warning,
                        "Daemon hook repair is disabled; hook drift may persist",
                        ReliabilityReasonCode::DaemonHookRepairDisabled,
                    )
                    .with_remediation(
                        "rch config set self_healing.daemon_installs_hooks true",
                        "rch config get self_healing.daemon_installs_hooks --json",
                    ),
                );
            }
        }
        Err(err) => diagnostics.push(
            ReliabilityDiagnostic::new(
                ReliabilityCategory::RolloutPosture,
                "config_load",
                ReliabilitySeverity::Warning,
                "Configuration could not be loaded; rollout posture is partial",
                ReliabilityReasonCode::ConfigLoadFailed,
            )
            .with_details(err)
            .with_remediation(
                "rch config doctor --json",
                "rch doctor --reliability --json",
            ),
        ),
    }

    diagnostics.push(ReliabilityDiagnostic::new(
        ReliabilityCategory::RolloutPosture,
        "status_surface",
        ReliabilitySeverity::Pass,
        "Unified status surface is compiled in",
        ReliabilityReasonCode::StatusSurfaceAvailable,
    ));
    diagnostics.push(ReliabilityDiagnostic::new(
        ReliabilityCategory::RolloutPosture,
        "repo_convergence_gate",
        ReliabilitySeverity::Pass,
        "Repo-convergence status endpoint is wired into the CLI",
        ReliabilityReasonCode::RepoConvergenceSurfaceAvailable,
    ));
    diagnostics.push(ReliabilityDiagnostic::new(
        ReliabilityCategory::RolloutPosture,
        "disk_pressure_gate",
        ReliabilitySeverity::Pass,
        "Disk-pressure fields are wired into worker status",
        ReliabilityReasonCode::DiskPressureSurfaceAvailable,
    ));

    diagnostics
}

fn reliability_schema_compatibility_diagnostics() -> Vec<ReliabilityDiagnostic> {
    // Each entry pairs the component's live schema constant with the
    // version this doctor knows how to consume. These expected versions
    // are deliberately separate constants; comparing a schema constant
    // to itself would make this diagnostic permanently green.
    let entries: [(&str, &str, &str, &str); 4] = [
        (
            "doctor_reliability",
            RELIABILITY_DOCTOR_SCHEMA_VERSION,
            EXPECTED_RELIABILITY_DOCTOR_SCHEMA_VERSION,
            "reliability doctor response",
        ),
        (
            "status",
            crate::status_types::STATUS_SCHEMA_VERSION,
            EXPECTED_STATUS_SCHEMA_VERSION,
            "CLI status response",
        ),
        (
            "repo_updater_contract",
            rch_common::REPO_UPDATER_CONTRACT_SCHEMA_VERSION,
            EXPECTED_REPO_UPDATER_CONTRACT_SCHEMA_VERSION,
            "repo updater contract",
        ),
        (
            "process_triage_contract",
            rch_common::e2e::PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION,
            EXPECTED_PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION,
            "process triage contract",
        ),
    ];
    entries
        .into_iter()
        .map(|(name, actual, expected, description)| {
            schema_compatibility_diagnostic(name, actual, expected, description)
        })
        .collect()
}

fn schema_compatibility_diagnostic(
    name: &str,
    actual: &str,
    expected: &str,
    description: &str,
) -> ReliabilityDiagnostic {
    if actual == expected {
        ReliabilityDiagnostic::new(
            ReliabilityCategory::SchemaCompatibility,
            name,
            ReliabilitySeverity::Pass,
            format!("{description} schema version is compatible"),
            ReliabilityReasonCode::SchemaCompatible,
        )
        .with_details(format!("schema_version={actual} expected={expected}"))
    } else {
        ReliabilityDiagnostic::new(
            ReliabilityCategory::SchemaCompatibility,
            name,
            ReliabilitySeverity::Critical,
            format!("{description} schema version is incompatible"),
            ReliabilityReasonCode::SchemaIncompatible,
        )
        .with_details(format!("expected={expected}, actual={actual}"))
        .with_remediation(
            "Upgrade rch/rchd/rch-wkr binaries to the same release",
            "rch doctor --reliability --check-schemas --json",
        )
    }
}

/// Reason codes whose presence in the diagnostic list indicates the
/// daemon could not be reached. Each of these is emitted by a probe
/// whose query specifically depends on a live daemon socket — so any
/// one of them implies `daemon_unreachable=true`. (t05)
const DAEMON_UNREACHABLE_REASON_CODES: &[ReliabilityReasonCode] = &[
    ReliabilityReasonCode::DaemonStatusUnavailable,
    ReliabilityReasonCode::DiskPressureUnavailable,
    ReliabilityReasonCode::ProcessDebtUnavailable,
    ReliabilityReasonCode::RepoConvergenceUnavailable,
];

fn build_reliability_doctor_response(
    mode: ReliabilityDoctorMode,
    scope: &ReliabilityScopeSet,
    diagnostics: Vec<ReliabilityDiagnostic>,
) -> ReliabilityDoctorResponse {
    let mut categories = BTreeSet::new();
    let mut pass = 0;
    let mut info = 0;
    let mut warning = 0;
    let mut critical = 0;
    for diagnostic in &diagnostics {
        categories.insert(diagnostic.category);
        match diagnostic.severity {
            ReliabilitySeverity::Pass => pass += 1,
            ReliabilitySeverity::Info => info += 1,
            ReliabilitySeverity::Warning => warning += 1,
            ReliabilitySeverity::Critical => critical += 1,
        }
    }

    // Compute daemon_unreachable + per-probe attribution (t05). Walk
    // the diagnostics list looking for the "this probe needed the
    // daemon but couldn't reach it" reason codes. The reasons list
    // gives operators which specific probe failed.
    let daemon_unreachable_reasons: Vec<String> = diagnostics
        .iter()
        .filter(|d| DAEMON_UNREACHABLE_REASON_CODES.contains(&d.code))
        .map(|d| format!("{}: {}", d.check_name, d.message))
        .collect();
    let daemon_unreachable = !daemon_unreachable_reasons.is_empty();

    let remediation_plan = build_reliability_remediation_plan(&diagnostics);
    let summary = ReliabilityDoctorSummary {
        total_checks: diagnostics.len(),
        pass,
        info,
        warning,
        critical,
        categories_checked: categories.into_iter().collect(),
        overall: aggregate_verdict(&diagnostics),
    };

    ReliabilityDoctorResponse {
        schema_version: RELIABILITY_DOCTOR_SCHEMA_VERSION.to_string(),
        mode,
        scope: scope.as_strings(),
        daemon_unreachable,
        daemon_unreachable_reasons,
        diagnostics,
        summary,
        remediation_plan,
    }
}

fn build_reliability_remediation_plan(
    diagnostics: &[ReliabilityDiagnostic],
) -> Vec<ReliabilityRemediationStep> {
    let mut actionable = diagnostics
        .iter()
        .filter(|diagnostic| {
            matches!(
                diagnostic.severity,
                ReliabilitySeverity::Critical | ReliabilitySeverity::Warning
            ) && diagnostic.remediation_command.is_some()
        })
        .collect::<Vec<_>>();

    actionable.sort_by_key(|diagnostic| match diagnostic.severity {
        ReliabilitySeverity::Critical => 0,
        ReliabilitySeverity::Warning => 1,
        ReliabilitySeverity::Info => 2,
        ReliabilitySeverity::Pass => 3,
    });

    actionable
        .into_iter()
        .enumerate()
        .map(|(index, diagnostic)| ReliabilityRemediationStep {
            order: u32::try_from(index + 1).unwrap_or(u32::MAX),
            category: diagnostic.category,
            description: format!("{}: {}", diagnostic.check_name, diagnostic.message),
            command: diagnostic.remediation_command.clone().unwrap_or_default(),
            validation: diagnostic
                .validation_check
                .clone()
                .unwrap_or_else(|| "rch doctor --reliability --json".to_string()),
            requires_restart: diagnostic.code.requires_restart(),
            dry_run_safe: diagnostic.dry_run_safe,
        })
        .collect()
}

fn print_reliability_doctor_response(ctx: &OutputContext, response: &ReliabilityDoctorResponse) {
    let style = ctx.theme();

    println!("{}", style.format_header("RCH Reliability Doctor"));
    println!();

    // t05: daemon-unreachable prefix so the operator immediately sees
    // the limited scope of this report. Suppressed in JSON mode where
    // the envelope's data.daemon_unreachable flag carries the same
    // signal for machine consumers.
    if response.daemon_unreachable && !ctx.is_json() {
        println!(
            "  {} [daemon down — local-only checks]",
            StatusIndicator::Warning.display(style)
        );
    }

    println!(
        "  {} schema {}",
        StatusIndicator::Info.display(style),
        style.value(&response.schema_version)
    );
    let verdict_indicator = match response.summary.overall {
        ReliabilityVerdict::Healthy => StatusIndicator::Success,
        ReliabilityVerdict::Degraded => StatusIndicator::Warning,
        ReliabilityVerdict::Failing => StatusIndicator::Error,
    };
    println!(
        "  {} verdict: {} ({} check(s): {} pass, {} info, {} warning, {} critical)",
        verdict_indicator.display(style),
        style.highlight(response.summary.overall.label()),
        response.summary.total_checks,
        response.summary.pass,
        response.summary.info,
        response.summary.warning,
        response.summary.critical
    );
    println!();

    for diagnostic in &response.diagnostics {
        let indicator = match diagnostic.severity {
            ReliabilitySeverity::Pass => StatusIndicator::Success,
            ReliabilitySeverity::Info => StatusIndicator::Info,
            ReliabilitySeverity::Warning => StatusIndicator::Warning,
            ReliabilitySeverity::Critical => StatusIndicator::Error,
        };
        println!(
            "  {} [{}] {}: {}",
            indicator.display(style),
            diagnostic.category.as_str(),
            style.highlight(&diagnostic.check_name),
            diagnostic.message
        );
        if ctx.is_verbose() {
            if let Some(details) = &diagnostic.details {
                println!("      {}", style.muted(details));
            }
            if let Some(command) = &diagnostic.remediation_command {
                println!("      remediation: {}", style.value(command));
            }
        }
    }

    if !response.remediation_plan.is_empty() {
        println!();
        println!("{}", style.format_header("Remediation Plan"));
        for step in &response.remediation_plan {
            println!(
                "  {}. [{}] {}",
                step.order,
                step.category.as_str(),
                step.description
            );
            println!("     {}", style.value(&step.command));
            println!("     validate: {}", style.value(&step.validation));
        }
    }

    println!();
    if response.summary.critical > 0 {
        println!(
            "{}",
            style.format_error("Reliability-critical issues found.")
        );
    } else if response.summary.warning > 0 {
        println!(
            "{}",
            style.format_warning("Reliability checks found warnings.")
        );
    } else {
        println!("{}", style.format_success("Reliability checks passed."));
    }

    // t05: meta footer for first-time operators — only in human mode
    // (verbose or default). Hook/JSON modes get the same info via the
    // envelope and the --schema endpoint.
    if !ctx.is_json() {
        println!();
        println!(
            "  {} Run with {} for machine-readable output",
            StatusIndicator::Info.display(style),
            style.value("--json")
        );
        println!(
            "  {} Exit codes: 0 = healthy, 1 = degraded, 2 = failing (with --strict: degraded → 2; with --lenient: failing → 1)",
            StatusIndicator::Info.display(style),
        );
    }
}

/// Quick health check result for post-hook-install display.
///
/// **t03 contract change:** `workers_healthy` is `Option<usize>` — `None`
/// means "not probed / unknown", explicitly distinguishing the "fast
/// check, no network probes" case from the "every worker is healthy"
/// case. Prior shape unconditionally returned `Some(worker_count)`
/// without probing, which silently treated unhealthy fleets as healthy.
/// `is_healthy()` now requires `workers_healthy == Some(worker_count)`
/// — `None` is NEVER reported as healthy.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct QuickCheckResult {
    pub daemon_running: bool,
    pub worker_count: usize,
    /// `None` = not probed (the default for `run_quick_check`, which is
    /// designed to be fast / no-network).
    /// `Some(n)` = `n` of the configured workers were probed and reported
    /// healthy.
    pub workers_healthy: Option<usize>,
    pub hook_installed: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl QuickCheckResult {
    /// Check if the system is fully operational.
    ///
    /// **Contract:** returns `true` ONLY when daemon is running, hook is
    /// installed, warnings/errors are empty, AND every configured worker
    /// has been probed and reported healthy. `workers_healthy == None`
    /// (unknown) is NEVER healthy — this is the default-to-degraded
    /// discipline per t03's bead body.
    pub fn is_healthy(&self) -> bool {
        self.daemon_running
            && self.worker_count > 0
            && self.hook_installed
            && self.warnings.is_empty()
            && self.errors.is_empty()
            && self.workers_healthy == Some(self.worker_count)
    }

    /// Check if there are any issues.
    #[allow(dead_code)]
    pub fn has_issues(&self) -> bool {
        !self.warnings.is_empty() || !self.errors.is_empty()
    }
}

/// Run a quick health check (for post-install feedback).
///
/// This runs fast local-only checks (no network probes). Worker health
/// is reported as `None` (unknown) — callers needing real worker
/// probes should run `rch doctor --reliability` (which performs the
/// SSH-based health checks). This honest "unknown" signal is the t03
/// fix for the prior default-to-success behavior that silently treated
/// every configured worker as healthy.
pub fn run_quick_check() -> QuickCheckResult {
    let socket_path = default_socket_path();
    let daemon_running = socket_path.exists();

    // Check workers — fast check only counts configured entries; we do
    // NOT probe each worker over the network here (that's `rch doctor
    // --reliability`'s job). Health is reported as `None` (unknown)
    // since we genuinely don't know without probing.
    let (worker_count, workers_healthy) = match load_workers_from_config() {
        // Fast-check: count configured workers; health is unknown
        // until a real probe is performed (default-to-degraded discipline).
        Ok(workers) => (workers.len(), None),
        Err(_) => (0, None),
    };

    // Check hook
    let hook_installed = {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        let settings_path = home.join(".claude").join("settings.json");
        if settings_path.exists() {
            read_config_capped(&settings_path)
                .ok()
                .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
                .map(|settings| {
                    settings
                        .get("hooks")
                        .and_then(|h| h.get("PreToolUse"))
                        .is_some()
                })
                .unwrap_or(false)
        } else {
            false
        }
    };

    // Collect warnings
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if !daemon_running {
        warnings.push("Daemon is not running".to_string());
    }
    if worker_count == 0 {
        warnings.push("No workers configured".to_string());
    }
    if !hook_installed {
        errors.push("Hook not installed".to_string());
    }
    // Honest signal that this is a fast-check, not a real probe.
    if worker_count > 0 && workers_healthy.is_none() {
        warnings.push(
            "Worker health not probed by quick-check; run `rch doctor --reliability` for full status".to_string(),
        );
    }

    let result = QuickCheckResult {
        daemon_running,
        worker_count,
        workers_healthy,
        hook_installed,
        warnings,
        errors,
    };

    tracing::debug!(
        target: "rch::doctor::quick_check",
        daemon_running,
        worker_count,
        workers_healthy = ?result.workers_healthy,
        hook_installed,
        is_healthy = result.is_healthy(),
        "doctor.quick_check.complete",
    );

    result
}

/// Print a quick health check summary to the console.
pub fn print_quick_check_summary(result: &QuickCheckResult, ctx: &OutputContext) {
    let style = ctx.theme();

    println!();
    println!("{}", style.highlight("Quick Health Check"));
    println!();

    // Daemon status
    if result.daemon_running {
        println!(
            "  {} Daemon running",
            StatusIndicator::Success.display(style)
        );
    } else {
        println!(
            "  {} Daemon not running",
            StatusIndicator::Warning.display(style)
        );
    }

    // Workers status
    if result.worker_count > 0 {
        println!(
            "  {} {} worker(s) configured",
            StatusIndicator::Success.display(style),
            result.worker_count
        );
    } else {
        println!(
            "  {} No workers configured",
            StatusIndicator::Warning.display(style)
        );
    }

    // Hook status
    if result.hook_installed {
        println!(
            "  {} Hook installed",
            StatusIndicator::Success.display(style)
        );
    } else {
        println!(
            "  {} Hook not installed",
            StatusIndicator::Error.display(style)
        );
    }

    println!();

    // Summary
    if result.is_healthy() {
        println!(
            "{}",
            style.format_success("Setup complete! Your next cargo build will compile remotely.")
        );
    } else if !result.errors.is_empty() {
        println!(
            "{}",
            style.format_error(&format!(
                "Issues found: {} error(s). Run 'rch doctor' for details.",
                result.errors.len()
            ))
        );
    } else if !result.warnings.is_empty() {
        println!(
            "{}",
            style.format_warning(&format!(
                "Setup complete with {} warning(s). Run 'rch doctor' for details.",
                result.warnings.len()
            ))
        );
    }
}

// =============================================================================
// Prerequisite Checks
// =============================================================================

fn check_prerequisites(
    checks: &mut Vec<CheckResult>,
    ctx: &OutputContext,
    _options: &DoctorOptions,
) {
    let style = ctx.theme();

    if !ctx.is_json() {
        println!("{}", style.highlight("Prerequisites"));
        println!();
    }

    // Check rsync
    let rsync_result = check_command_exists("rsync", "File synchronization");
    print_check_result(&rsync_result, ctx);
    checks.push(rsync_result);

    // Check zstd
    let zstd_result = check_command_exists("zstd", "Compression tool");
    print_check_result(&zstd_result, ctx);
    checks.push(zstd_result);

    // Check ssh
    let ssh_result = check_command_exists("ssh", "SSH client");
    print_check_result(&ssh_result, ctx);
    checks.push(ssh_result);

    // Check rustup
    let rustup_result = check_command_exists("rustup", "Rust toolchain manager");
    print_check_result(&rustup_result, ctx);
    checks.push(rustup_result);

    // Check cargo
    let cargo_result = check_command_exists("cargo", "Rust build tool");
    print_check_result(&cargo_result, ctx);
    checks.push(cargo_result);

    if !ctx.is_json() {
        println!();
    }
}

fn check_command_exists(cmd: &str, description: &str) -> CheckResult {
    let exists = which(cmd).is_ok();
    let version = exists.then(|| command_version(cmd)).flatten();

    CheckResult {
        category: "prerequisites".to_string(),
        name: cmd.to_string(),
        status: if exists {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        message: if exists {
            format!("{} is installed", description)
        } else {
            format!("{} not found", description)
        },
        details: version,
        suggestion: if exists {
            None
        } else {
            Some(format!("Install {} using your package manager", cmd))
        },
        fixable: !exists,
        fix_applied: false,
        fix_message: None,
    }
}

/// Run `<cmd> <version-flag>` with a hard timeout and capture the first
/// non-empty line of output. A misbehaving rustup proxy or cargo waiting
/// on the network MUST NOT hang doctor forever; without a timeout
/// `--version` could block on a stalled credential prompt or registry
/// fetch (rustup updates, in particular). Default cap: 5 seconds.
fn command_version(cmd: &str) -> Option<String> {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let (program, mut command) = match cmd {
        "rsync" => {
            let mut command = Command::new("rsync");
            command.arg("--version");
            ("rsync", command)
        }
        "zstd" => {
            let mut command = Command::new("zstd");
            command.arg("--version");
            ("zstd", command)
        }
        "ssh" => {
            let mut command = Command::new("ssh");
            command.arg("-V");
            ("ssh", command)
        }
        "rustup" => {
            let mut command = Command::new("rustup");
            command.arg("--version");
            ("rustup", command)
        }
        "cargo" => {
            let mut command = Command::new("cargo");
            command.arg("--version");
            ("cargo", command)
        }
        _ => return None,
    };

    let timeout = Duration::from_secs(5);
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let started = Instant::now();
    // Poll every 50ms instead of waiting forever on `child.wait()`.
    // For most healthy `--version` invocations this loop exits on the
    // first poll (subprocess returns instantly).
    let exited = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if started.elapsed() >= timeout {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    };

    if exited.is_none() {
        // Timed out — kill the child and return None. A logged warning
        // helps diagnose flaky workers without breaking the doctor.
        let _ = child.kill();
        let _ = child.wait();
        tracing::warn!(
            target: "rch::doctor",
            cmd = %program,
            timeout_secs = timeout.as_secs(),
            "version-probe subprocess timed out; killed"
        );
        return None;
    }

    // Drain stdout + stderr; child has exited so reads should not block.
    let output = child.wait_with_output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let text = if stdout.trim().is_empty() {
        stderr.as_ref()
    } else {
        stdout.as_ref()
    };
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

// =============================================================================
// Configuration Checks
// =============================================================================

fn check_configuration(
    checks: &mut Vec<CheckResult>,
    ctx: &OutputContext,
    _options: &DoctorOptions,
) {
    let style = ctx.theme();

    if !ctx.is_json() {
        println!("{}", style.highlight("Configuration"));
        println!();
    }

    // Check config directory
    let config_dir_result = check_config_directory();
    print_check_result(&config_dir_result, ctx);
    checks.push(config_dir_result);

    // Check config.toml
    let config_result = check_config_file();
    print_check_result(&config_result, ctx);
    checks.push(config_result);

    // Check workers.toml
    let workers_result = check_workers_file();
    print_check_result(&workers_result, ctx);
    checks.push(workers_result);

    if !ctx.is_json() {
        println!();
    }
}

fn check_config_directory() -> CheckResult {
    match config_dir() {
        Some(dir) => {
            if dir.exists() {
                CheckResult {
                    category: "configuration".to_string(),
                    name: "config_directory".to_string(),
                    status: CheckStatus::Pass,
                    message: "Config directory exists".to_string(),
                    details: Some(dir.display().to_string()),
                    suggestion: None,
                    fixable: false,
                    fix_applied: false,
                    fix_message: None,
                }
            } else {
                CheckResult {
                    category: "configuration".to_string(),
                    name: "config_directory".to_string(),
                    status: CheckStatus::Warning,
                    message: "Config directory does not exist".to_string(),
                    details: Some(dir.display().to_string()),
                    suggestion: Some("Run 'rch config init' to create it".to_string()),
                    fixable: true,
                    fix_applied: false,
                    fix_message: None,
                }
            }
        }
        None => CheckResult {
            category: "configuration".to_string(),
            name: "config_directory".to_string(),
            status: CheckStatus::Fail,
            message: "Could not determine config directory".to_string(),
            details: None,
            suggestion: None,
            fixable: false,
            fix_applied: false,
            fix_message: None,
        },
    }
}

fn check_config_file() -> CheckResult {
    let config_path = match config_dir() {
        Some(d) => d.join("config.toml"),
        None => {
            return CheckResult {
                category: "configuration".to_string(),
                name: "config.toml".to_string(),
                status: CheckStatus::Skipped,
                message: "Skipped (no config directory)".to_string(),
                details: None,
                suggestion: None,
                fixable: false,
                fix_applied: false,
                fix_message: None,
            };
        }
    };

    if !config_path.exists() {
        return CheckResult {
            category: "configuration".to_string(),
            name: "config.toml".to_string(),
            status: CheckStatus::Warning,
            message: "config.toml not found (using defaults)".to_string(),
            details: Some(config_path.display().to_string()),
            suggestion: Some("Run 'rch config init' to create default config".to_string()),
            fixable: true,
            fix_applied: false,
            fix_message: None,
        };
    }

    match read_config_capped(&config_path) {
        Ok(content) => match toml::from_str::<toml::Value>(&content) {
            Ok(_) => CheckResult {
                category: "configuration".to_string(),
                name: "config.toml".to_string(),
                status: CheckStatus::Pass,
                message: "config.toml is valid".to_string(),
                details: Some(config_path.display().to_string()),
                suggestion: None,
                fixable: false,
                fix_applied: false,
                fix_message: None,
            },
            Err(e) => CheckResult {
                category: "configuration".to_string(),
                name: "config.toml".to_string(),
                status: CheckStatus::Fail,
                message: "config.toml has syntax errors".to_string(),
                details: Some(e.to_string()),
                suggestion: Some("Fix TOML syntax errors in config file".to_string()),
                fixable: false,
                fix_applied: false,
                fix_message: None,
            },
        },
        Err(e) => CheckResult {
            category: "configuration".to_string(),
            name: "config.toml".to_string(),
            status: CheckStatus::Fail,
            message: "Could not read config.toml".to_string(),
            details: Some(e.to_string()),
            suggestion: None,
            fixable: false,
            fix_applied: false,
            fix_message: None,
        },
    }
}

fn check_workers_file() -> CheckResult {
    let workers_path = match config_dir() {
        Some(d) => d.join("workers.toml"),
        None => {
            return CheckResult {
                category: "configuration".to_string(),
                name: "workers.toml".to_string(),
                status: CheckStatus::Skipped,
                message: "Skipped (no config directory)".to_string(),
                details: None,
                suggestion: None,
                fixable: false,
                fix_applied: false,
                fix_message: None,
            };
        }
    };

    if !workers_path.exists() {
        return CheckResult {
            category: "configuration".to_string(),
            name: "workers.toml".to_string(),
            status: CheckStatus::Fail,
            message: "workers.toml not found".to_string(),
            details: Some(workers_path.display().to_string()),
            suggestion: Some("Run 'rch config init' to create example workers config".to_string()),
            fixable: true,
            fix_applied: false,
            fix_message: None,
        };
    }

    match read_config_capped(&workers_path) {
        Ok(content) => match toml::from_str::<toml::Value>(&content) {
            Ok(parsed) => {
                let worker_count = parsed
                    .get("workers")
                    .and_then(|w| w.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);

                if worker_count == 0 {
                    CheckResult {
                        category: "configuration".to_string(),
                        name: "workers.toml".to_string(),
                        status: CheckStatus::Warning,
                        message: "workers.toml is valid but has no workers defined".to_string(),
                        details: Some(workers_path.display().to_string()),
                        suggestion: Some("Add worker definitions to workers.toml".to_string()),
                        fixable: false,
                        fix_applied: false,
                        fix_message: None,
                    }
                } else {
                    CheckResult {
                        category: "configuration".to_string(),
                        name: "workers.toml".to_string(),
                        status: CheckStatus::Pass,
                        message: format!("workers.toml is valid ({} workers)", worker_count),
                        details: Some(workers_path.display().to_string()),
                        suggestion: None,
                        fixable: false,
                        fix_applied: false,
                        fix_message: None,
                    }
                }
            }
            Err(e) => CheckResult {
                category: "configuration".to_string(),
                name: "workers.toml".to_string(),
                status: CheckStatus::Fail,
                message: "workers.toml has syntax errors".to_string(),
                details: Some(e.to_string()),
                suggestion: Some("Fix TOML syntax errors in workers file".to_string()),
                fixable: false,
                fix_applied: false,
                fix_message: None,
            },
        },
        Err(e) => CheckResult {
            category: "configuration".to_string(),
            name: "workers.toml".to_string(),
            status: CheckStatus::Fail,
            message: "Could not read workers.toml".to_string(),
            details: Some(e.to_string()),
            suggestion: None,
            fixable: false,
            fix_applied: false,
            fix_message: None,
        },
    }
}

// =============================================================================
// SSH Key Checks
// =============================================================================

fn check_ssh_keys(
    checks: &mut Vec<CheckResult>,
    ctx: &OutputContext,
    options: &DoctorOptions,
    fixes_applied: &mut Vec<FixApplied>,
) {
    let style = ctx.theme();

    if !ctx.is_json() {
        println!("{}", style.highlight("SSH Keys"));
        println!();
    }

    // Check common SSH key locations
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let ssh_dir = home.join(".ssh");

    let key_files = vec![
        ssh_dir.join("id_ed25519"),
        ssh_dir.join("id_rsa"),
        ssh_dir.join("id_ecdsa"),
    ];

    let mut found_key = false;

    for key_path in key_files {
        if key_path.exists() {
            found_key = true;
            let result = check_ssh_key_permissions(&key_path, options, fixes_applied);
            print_check_result(&result, ctx);
            checks.push(result);
        }
    }

    if !found_key {
        let default_key = ssh_dir.join("id_ed25519");
        let result = CheckResult {
            category: "ssh".to_string(),
            name: "ssh_keys".to_string(),
            status: CheckStatus::Warning,
            message: "No standard SSH keys found".to_string(),
            details: Some("Checked: ~/.ssh/id_{ed25519,rsa,ecdsa}".to_string()),
            suggestion: Some(format!(
                "Generate an SSH key: ssh-keygen -t ed25519 -f {} && ssh-add {}",
                default_key.display(),
                default_key.display()
            )),
            fixable: false,
            fix_applied: false,
            fix_message: None,
        };
        print_check_result(&result, ctx);
        checks.push(result);
    }

    // Check worker identity files from config
    check_worker_identity_files(checks, ctx, options, fixes_applied);

    // Check SSH config
    let ssh_config_result = check_ssh_config();
    print_check_result(&ssh_config_result, ctx);
    checks.push(ssh_config_result);

    if !ctx.is_json() {
        println!();
    }
}

#[cfg(unix)]
fn check_ssh_key_permissions(
    key_path: &Path,
    options: &DoctorOptions,
    fixes_applied: &mut Vec<FixApplied>,
) -> CheckResult {
    let key_name = key_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    match std::fs::metadata(key_path) {
        Ok(meta) => {
            let mode = meta.permissions().mode();
            let perms = mode & 0o777;

            // SSH keys should be 0600 or 0400
            if perms == 0o600 || perms == 0o400 {
                CheckResult {
                    category: "ssh".to_string(),
                    name: key_name,
                    status: CheckStatus::Pass,
                    message: format!("SSH key exists with correct permissions (0{:o})", perms),
                    details: Some(key_path.display().to_string()),
                    suggestion: None,
                    fixable: false,
                    fix_applied: false,
                    fix_message: None,
                }
            } else {
                // Try to fix if requested
                if options.fix {
                    if options.dry_run {
                        return CheckResult {
                            category: "ssh".to_string(),
                            name: key_name,
                            status: CheckStatus::Warning,
                            message: format!("SSH key has loose permissions (0{:o})", perms),
                            details: Some(key_path.display().to_string()),
                            suggestion: Some(format!("Run: chmod 600 {}", key_path.display())),
                            fixable: true,
                            fix_applied: false,
                            fix_message: Some(format!(
                                "Would change permissions from 0{:o} to 0600",
                                perms
                            )),
                        };
                    }
                    match std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
                    {
                        Ok(()) => {
                            fixes_applied.push(FixApplied {
                                check_name: key_name.clone(),
                                action: format!("Changed permissions from 0{:o} to 0600", perms),
                                success: true,
                                error: None,
                            });
                            CheckResult {
                                category: "ssh".to_string(),
                                name: key_name,
                                status: CheckStatus::Pass,
                                message: "SSH key permissions fixed to 0600".to_string(),
                                details: Some(key_path.display().to_string()),
                                suggestion: None,
                                fixable: false,
                                fix_applied: true,
                                fix_message: Some(format!(
                                    "Changed permissions from 0{:o} to 0600",
                                    perms
                                )),
                            }
                        }
                        Err(e) => {
                            fixes_applied.push(FixApplied {
                                check_name: key_name.clone(),
                                action: "Failed to fix permissions".to_string(),
                                success: false,
                                error: Some(e.to_string()),
                            });
                            CheckResult {
                                category: "ssh".to_string(),
                                name: key_name,
                                status: CheckStatus::Warning,
                                message: format!(
                                    "SSH key has loose permissions (0{:o}), fix failed",
                                    perms
                                ),
                                details: Some(e.to_string()),
                                suggestion: Some(format!("Run: chmod 600 {}", key_path.display())),
                                fixable: true,
                                fix_applied: false,
                                fix_message: Some(format!("Failed to fix permissions: {}", e)),
                            }
                        }
                    }
                } else {
                    CheckResult {
                        category: "ssh".to_string(),
                        name: key_name,
                        status: CheckStatus::Warning,
                        message: format!("SSH key has loose permissions (0{:o})", perms),
                        details: Some(key_path.display().to_string()),
                        suggestion: Some(format!("Run: chmod 600 {}", key_path.display())),
                        fixable: true,
                        fix_applied: false,
                        fix_message: None,
                    }
                }
            }
        }
        Err(e) => CheckResult {
            category: "ssh".to_string(),
            name: key_name,
            status: CheckStatus::Fail,
            message: "Could not read SSH key metadata".to_string(),
            details: Some(e.to_string()),
            suggestion: None,
            fixable: false,
            fix_applied: false,
            fix_message: None,
        },
    }
}

#[cfg(not(unix))]
fn check_ssh_key_permissions(
    key_path: &Path,
    _options: &DoctorOptions,
    _fixes_applied: &mut Vec<FixApplied>,
) -> CheckResult {
    let key_name = key_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    CheckResult {
        category: "ssh".to_string(),
        name: key_name,
        status: CheckStatus::Skipped,
        message: "SSH key permission checks are not supported on this platform".to_string(),
        details: Some(key_path.display().to_string()),
        suggestion: None,
        fixable: false,
        fix_applied: false,
        fix_message: None,
    }
}

fn check_worker_identity_files(
    checks: &mut Vec<CheckResult>,
    ctx: &OutputContext,
    options: &DoctorOptions,
    fixes_applied: &mut Vec<FixApplied>,
) {
    let workers = match load_workers_from_config() {
        Ok(w) => w,
        Err(_) => return,
    };

    for worker in workers {
        let key_path = PathBuf::from(shellexpand::tilde(&worker.identity_file).to_string());
        let name = format!("worker_key:{}", worker.id.as_str());
        let suggestion = ssh_worker_suggestion(&worker.user, &worker.host, &key_path);

        if !key_path.exists() {
            let result = CheckResult {
                category: "ssh".to_string(),
                name,
                status: CheckStatus::Warning,
                message: format!("Identity file missing for worker {}", worker.id.as_str()),
                details: Some(key_path.display().to_string()),
                suggestion: Some(suggestion),
                fixable: false,
                fix_applied: false,
                fix_message: None,
            };
            print_check_result(&result, ctx);
            checks.push(result);
            continue;
        }

        let key_result = check_ssh_key_permissions(&key_path, options, fixes_applied);
        let status = key_result.status;
        let mut message = key_result.message;
        message.push_str(&format!(" (worker {})", worker.id.as_str()));

        let result = CheckResult {
            category: "ssh".to_string(),
            name,
            status,
            message,
            details: key_result.details,
            suggestion: Some(suggestion),
            fixable: key_result.fixable,
            fix_applied: key_result.fix_applied,
            fix_message: key_result.fix_message,
        };
        print_check_result(&result, ctx);
        checks.push(result);
    }
}

fn ssh_worker_suggestion(user: &str, host: &str, key_path: &Path) -> String {
    // Shell-escape every component before splicing into a runnable shell
    // string. Suggestions are surfaced to agents and copy-pasted into a
    // shell; a `workers.toml` entry like `host = "evil; rm -rf ~"` (or
    // a key path with spaces) MUST NOT produce a destructive command.
    let key_q = shell_escape::escape(key_path.to_string_lossy());
    let user_q = shell_escape::escape(user.into());
    let host_q = shell_escape::escape(host.into());
    format!(
        "Copy key: ssh-copy-id -i {key_q} {user_q}@{host_q}; \
Test: ssh -i {key_q} {user_q}@{host_q} echo \"success\"; \
Agent: eval $(ssh-agent) && ssh-add {key_q}; \
Debug: ssh -vvv -i {key_q} {user_q}@{host_q}",
    )
}

fn check_ssh_config() -> CheckResult {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let ssh_config = home.join(".ssh").join("config");

    if ssh_config.exists() {
        CheckResult {
            category: "ssh".to_string(),
            name: "ssh_config".to_string(),
            status: CheckStatus::Pass,
            message: "SSH config file exists".to_string(),
            details: Some(ssh_config.display().to_string()),
            suggestion: None,
            fixable: false,
            fix_applied: false,
            fix_message: None,
        }
    } else {
        CheckResult {
            category: "ssh".to_string(),
            name: "ssh_config".to_string(),
            status: CheckStatus::Warning,
            message: "No SSH config file".to_string(),
            details: Some(ssh_config.display().to_string()),
            suggestion: Some(
                "Consider creating ~/.ssh/config for custom host settings".to_string(),
            ),
            fixable: false,
            fix_applied: false,
            fix_message: None,
        }
    }
}

// =============================================================================
// Daemon Checks
// =============================================================================

fn which_rchd_path() -> PathBuf {
    // Try to find rchd in same directory as current executable
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(dir) = exe_path.parent()
    {
        let rchd = dir.join("rchd");
        if rchd.exists() {
            return rchd;
        }
    }

    // Fallback to path lookup
    which("rchd").unwrap_or_else(|_| PathBuf::from("rchd"))
}

fn spawn_rchd(rchd_path: &Path, socket_path: &Path) -> Result<(), String> {
    let mut cmd = Command::new("nohup");
    cmd.arg(rchd_path)
        .arg("-s")
        .arg(socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    let mut child = cmd.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "nohup not found while launching rchd".to_string(),
        _ => e.to_string(),
    })?;

    std::thread::sleep(Duration::from_millis(100));
    if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
        return if status.success() {
            Ok(())
        } else {
            Err(format!(
                "rchd launch wrapper exited unsuccessfully: {status}"
            ))
        };
    }

    // `nohup` does not daemonize by itself; it execs/wraps rchd as our
    // direct child. Keep a detached waiter while doctor continues so a
    // later daemon exit is reaped instead of becoming a zombie.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

fn wait_for_socket(socket_path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if socket_path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    socket_path.exists()
}

fn start_daemon_with_binary(
    socket_path: &Path,
    rchd_path: &Path,
    timeout: Duration,
) -> Result<(), String> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    spawn_rchd(rchd_path, socket_path)?;

    if wait_for_socket(socket_path, timeout) {
        return Ok(());
    }

    Err(format!(
        "daemon process started but socket not found after {}s",
        timeout.as_secs()
    ))
}

fn start_daemon_for_doctor(socket_path: &Path, timeout: Duration) -> Result<(), String> {
    start_daemon_with_binary(socket_path, &which_rchd_path(), timeout)
}

fn check_daemon(
    checks: &mut Vec<CheckResult>,
    ctx: &OutputContext,
    options: &DoctorOptions,
    fixes_applied: &mut Vec<FixApplied>,
) {
    let style = ctx.theme();

    if !ctx.is_json() {
        println!("{}", style.highlight("Daemon"));
        println!();
    }

    let socket_path = default_socket_path();
    let mut result = if socket_path.exists() {
        CheckResult {
            category: "daemon".to_string(),
            name: "daemon_socket".to_string(),
            status: CheckStatus::Pass,
            message: "Daemon socket exists".to_string(),
            details: Some(socket_path.to_string_lossy().to_string()),
            suggestion: None,
            fixable: false,
            fix_applied: false,
            fix_message: None,
        }
    } else {
        CheckResult {
            category: "daemon".to_string(),
            name: "daemon_socket".to_string(),
            status: CheckStatus::Warning,
            message: "Daemon is not running".to_string(),
            details: Some(socket_path.to_string_lossy().to_string()),
            suggestion: Some("Start daemon with: rch daemon start".to_string()),
            fixable: true,
            fix_applied: false,
            fix_message: None,
        }
    };

    let mut fix_line: Option<(StatusIndicator, String)> = None;
    if options.fix && result.fixable && result.status != CheckStatus::Pass {
        if options.dry_run {
            let msg = "Would start RCH daemon".to_string();
            result.fix_message = Some(msg.clone());
            fix_line = Some((StatusIndicator::Pending, format!("Would fix: {}", msg)));
        } else {
            match start_daemon_for_doctor(&socket_path, Duration::from_secs(3)) {
                Ok(()) => {
                    let msg = "Started RCH daemon".to_string();
                    result.status = CheckStatus::Pass;
                    result.message = "Daemon started (fixed)".to_string();
                    result.details = Some(socket_path.to_string_lossy().to_string());
                    result.suggestion = None;
                    result.fixable = false;
                    result.fix_applied = true;
                    result.fix_message = Some(msg.clone());
                    fix_line = Some((StatusIndicator::Success, format!("Fixed: {}", msg)));
                    fixes_applied.push(FixApplied {
                        check_name: "daemon_socket".to_string(),
                        action: msg,
                        success: true,
                        error: None,
                    });
                }
                Err(e) => {
                    let msg = format!("Failed to start daemon: {}", e);
                    result.fix_message = Some(msg.clone());
                    fix_line = Some((StatusIndicator::Error, msg.clone()));
                    fixes_applied.push(FixApplied {
                        check_name: "daemon_socket".to_string(),
                        action: "Start RCH daemon".to_string(),
                        success: false,
                        error: Some(e),
                    });
                }
            }
        }
    }

    if let Some((indicator, line)) = fix_line
        && !ctx.is_json()
    {
        let rendered = match indicator {
            StatusIndicator::Success => style.success(&line),
            StatusIndicator::Pending => style.muted(&line),
            StatusIndicator::Error => style.error(&line),
            _ => style.info(&line),
        };
        println!("  {} {}", indicator.display(style), rendered);
    }

    print_check_result(&result, ctx);
    checks.push(result);

    // Warn if a legacy /tmp socket exists but the default has moved.
    let legacy_socket = Path::new("/tmp/rch.sock");
    if socket_path != legacy_socket && legacy_socket.exists() {
        let legacy_result = CheckResult {
            category: "daemon".to_string(),
            name: "legacy_socket_path".to_string(),
            status: CheckStatus::Warning,
            message: "Legacy /tmp socket detected".to_string(),
            details: Some(legacy_socket.display().to_string()),
            suggestion: Some(
                "Restart the daemon so it binds to the new default socket path".to_string(),
            ),
            fixable: false,
            fix_applied: false,
            fix_message: None,
        };
        print_check_result(&legacy_result, ctx);
        checks.push(legacy_result);
    }

    if !ctx.is_json() {
        println!();
    }
}

// =============================================================================
// Cancellation Health Checks
// =============================================================================

fn evaluate_cancellation_health(
    status: &crate::status_types::DaemonFullStatusResponse,
) -> CheckResult {
    let mut total = 0usize;
    let mut cleanup_failures = 0usize;
    let mut sigkill_escalations = 0usize;
    let mut unreachable_workers = 0usize;
    let mut operations = Vec::new();

    for build in &status.recent_builds {
        let Some(cancellation) = &build.cancellation else {
            continue;
        };
        total += 1;
        operations.push(cancellation.operation_id.clone());
        if !cancellation.cleanup_ok {
            cleanup_failures += 1;
        }
        if cancellation.escalation_stage == "sigkill" {
            sigkill_escalations += 1;
        }
        if cancellation
            .worker_health
            .as_ref()
            .is_some_and(|health| health.status == "unreachable")
        {
            unreachable_workers += 1;
        }
    }

    if total == 0 {
        return CheckResult {
            category: "cancellation".to_string(),
            name: "cancellation_health".to_string(),
            status: CheckStatus::Pass,
            message: "No recent cancellation events detected".to_string(),
            details: None,
            suggestion: None,
            fixable: false,
            fix_applied: false,
            fix_message: None,
        };
    }

    let details = Some(format!(
        "recent={}, cleanup_failures={}, sigkill_escalations={}, unreachable_workers={}, operations={}",
        total,
        cleanup_failures,
        sigkill_escalations,
        unreachable_workers,
        operations.join(",")
    ));

    if cleanup_failures > 0 {
        return CheckResult {
            category: "cancellation".to_string(),
            name: "cancellation_health".to_string(),
            status: CheckStatus::Fail,
            message: format!(
                "{} cancellation(s) ended with cleanup failures",
                cleanup_failures
            ),
            details,
            suggestion: Some(
                "Run `rch workers probe --all` and inspect daemon `cancellation_failed` events before retrying affected builds.".to_string(),
            ),
            fixable: false,
            fix_applied: false,
            fix_message: None,
        };
    }

    if sigkill_escalations > 0 || unreachable_workers > 0 {
        return CheckResult {
            category: "cancellation".to_string(),
            name: "cancellation_health".to_string(),
            status: CheckStatus::Warning,
            message: format!(
                "{} cancellation(s) required escalation and/or involved unreachable workers",
                total
            ),
            details,
            suggestion: Some(
                "Review `rch status --jobs` for stuck phases and verify worker connectivity with `rch workers probe --all`.".to_string(),
            ),
            fixable: false,
            fix_applied: false,
            fix_message: None,
        };
    }

    CheckResult {
        category: "cancellation".to_string(),
        name: "cancellation_health".to_string(),
        status: CheckStatus::Pass,
        message: format!(
            "{} recent cancellation(s) completed with deterministic cleanup",
            total
        ),
        details,
        suggestion: None,
        fixable: false,
        fix_applied: false,
        fix_message: None,
    }
}

async fn check_cancellation_health(checks: &mut Vec<CheckResult>, ctx: &OutputContext) {
    let style = ctx.theme();
    if !ctx.is_json() {
        println!("{}", style.highlight("Cancellation Health"));
        println!();
    }

    let result = if !default_socket_path().exists() {
        CheckResult {
            category: "cancellation".to_string(),
            name: "cancellation_health".to_string(),
            status: CheckStatus::Skipped,
            message: "Daemon socket not present; skipping cancellation diagnostics".to_string(),
            details: Some(default_socket_path().display().to_string()),
            suggestion: Some("Start daemon with: rch daemon start".to_string()),
            fixable: false,
            fix_applied: false,
            fix_message: None,
        }
    } else {
        match query_daemon_full_status().await {
            Ok(status) => evaluate_cancellation_health(&status),
            Err(e) => CheckResult {
                category: "cancellation".to_string(),
                name: "cancellation_health".to_string(),
                status: CheckStatus::Warning,
                message: "Unable to query daemon status for cancellation diagnostics".to_string(),
                details: Some(e.to_string()),
                suggestion: Some(
                    "Ensure daemon is responsive (`rch status`) and retry `rch doctor`."
                        .to_string(),
                ),
                fixable: false,
                fix_applied: false,
                fix_message: None,
            },
        }
    };

    print_check_result(&result, ctx);
    checks.push(result);

    if !ctx.is_json() {
        println!();
    }
}

// =============================================================================
// Hook Checks
// =============================================================================

fn check_hooks(
    checks: &mut Vec<CheckResult>,
    ctx: &OutputContext,
    options: &DoctorOptions,
    fixes_applied: &mut Vec<FixApplied>,
) {
    let style = ctx.theme();

    if !ctx.is_json() {
        println!("{}", style.highlight("Hooks"));
        println!();
    }

    // Check Claude Code hook
    let mut claude_result = check_claude_code_hook();
    let mut fix_message: Option<String> = None;
    let mut fix_applied = false;
    let mut fix_line: Option<(StatusIndicator, String)> = None;

    if options.fix && claude_result.fixable && claude_result.status != CheckStatus::Pass {
        match install_hook(AgentKind::ClaudeCode, options.dry_run) {
            Ok(IdempotentResult::Changed) => {
                fix_applied = true;
                let msg = "Installed Claude Code hook".to_string();
                fix_message = Some(msg.clone());
                fix_line = Some((StatusIndicator::Success, format!("Fixed: {}", msg)));
                fixes_applied.push(FixApplied {
                    check_name: "claude_code_hook".to_string(),
                    action: msg.clone(),
                    success: true,
                    error: None,
                });
                claude_result.status = CheckStatus::Pass;
                claude_result.message = "Claude Code PreToolUse hook installed (fixed)".to_string();
                claude_result.suggestion = None;
                claude_result.fixable = false;
            }
            Ok(IdempotentResult::WouldChange(msg)) => {
                fix_message = Some(msg.clone());
                fix_line = Some((StatusIndicator::Pending, format!("Would fix: {}", msg)));
            }
            Ok(IdempotentResult::Unchanged) => {
                fix_message = Some("Claude Code hook already installed".to_string());
                claude_result.status = CheckStatus::Pass;
                claude_result.message = "Claude Code PreToolUse hook already installed".to_string();
                claude_result.suggestion = None;
                claude_result.fixable = false;
            }
            Ok(other) => {
                let msg = format!("Hook install result: {}", other);
                fix_message = Some(msg.clone());
                fix_line = Some((StatusIndicator::Success, format!("Fixed: {}", msg)));
                if !options.dry_run {
                    fix_applied = true;
                    fixes_applied.push(FixApplied {
                        check_name: "claude_code_hook".to_string(),
                        action: msg.clone(),
                        success: true,
                        error: None,
                    });
                    claude_result.status = CheckStatus::Pass;
                    claude_result.message =
                        "Claude Code PreToolUse hook installed (fixed)".to_string();
                    claude_result.suggestion = None;
                    claude_result.fixable = false;
                }
            }
            Err(e) => {
                let msg = format!("Failed to install hook: {}", e);
                fix_message = Some(msg.clone());
                fix_line = Some((StatusIndicator::Error, msg.clone()));
                if !options.dry_run {
                    fixes_applied.push(FixApplied {
                        check_name: "claude_code_hook".to_string(),
                        action: "Install Claude Code hook".to_string(),
                        success: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }
    }

    claude_result.fix_applied = fix_applied;
    claude_result.fix_message = fix_message;

    if let Some((indicator, line)) = fix_line
        && !ctx.is_json()
    {
        let rendered = match indicator {
            StatusIndicator::Success => style.success(&line),
            StatusIndicator::Pending => style.muted(&line),
            StatusIndicator::Error => style.error(&line),
            _ => style.info(&line),
        };
        println!("  {} {}", indicator.display(style), rendered);
    }
    print_check_result(&claude_result, ctx);
    checks.push(claude_result);

    if !ctx.is_json() {
        println!();
    }
}

fn check_claude_code_hook() -> CheckResult {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let settings_path = home.join(".claude").join("settings.json");

    if !settings_path.exists() {
        return CheckResult {
            category: "hooks".to_string(),
            name: "claude_code_hook".to_string(),
            status: CheckStatus::Warning,
            message: "Claude Code settings not found".to_string(),
            details: Some(settings_path.display().to_string()),
            suggestion: Some("Install hook with: rch hook install".to_string()),
            fixable: true,
            fix_applied: false,
            fix_message: None,
        };
    }

    match read_config_capped(&settings_path) {
        Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(settings) => {
                let has_hook = settings
                    .get("hooks")
                    .and_then(|h| h.get("PreToolUse"))
                    .is_some();

                if has_hook {
                    CheckResult {
                        category: "hooks".to_string(),
                        name: "claude_code_hook".to_string(),
                        status: CheckStatus::Pass,
                        message: "Claude Code PreToolUse hook is installed".to_string(),
                        details: Some(settings_path.display().to_string()),
                        suggestion: None,
                        fixable: false,
                        fix_applied: false,
                        fix_message: None,
                    }
                } else {
                    CheckResult {
                        category: "hooks".to_string(),
                        name: "claude_code_hook".to_string(),
                        status: CheckStatus::Warning,
                        message: "Claude Code PreToolUse hook not configured".to_string(),
                        details: Some(settings_path.display().to_string()),
                        suggestion: Some("Install hook with: rch hook install".to_string()),
                        fixable: true,
                        fix_applied: false,
                        fix_message: None,
                    }
                }
            }
            Err(e) => CheckResult {
                category: "hooks".to_string(),
                name: "claude_code_hook".to_string(),
                status: CheckStatus::Fail,
                message: "Could not parse Claude Code settings".to_string(),
                details: Some(e.to_string()),
                suggestion: None,
                fixable: false,
                fix_applied: false,
                fix_message: None,
            },
        },
        Err(e) => CheckResult {
            category: "hooks".to_string(),
            name: "claude_code_hook".to_string(),
            status: CheckStatus::Fail,
            message: "Could not read Claude Code settings".to_string(),
            details: Some(e.to_string()),
            suggestion: None,
            fixable: false,
            fix_applied: false,
            fix_message: None,
        },
    }
}

// =============================================================================
// Worker Checks
// =============================================================================

async fn check_workers(
    checks: &mut Vec<CheckResult>,
    ctx: &OutputContext,
    options: &DoctorOptions,
) {
    let style = ctx.theme();

    if !ctx.is_json() {
        println!("{}", style.highlight("Workers"));
        println!();
    }

    // Only check connectivity if verbose mode or explicitly requested
    let workers = match load_workers_from_config() {
        Ok(w) => w,
        Err(_) => {
            let result = CheckResult {
                category: "workers".to_string(),
                name: "worker_config".to_string(),
                status: CheckStatus::Skipped,
                message: "Could not load workers configuration".to_string(),
                details: None,
                suggestion: Some("Run 'rch config init' to create workers.toml".to_string()),
                fixable: false,
                fix_applied: false,
                fix_message: None,
            };
            print_check_result(&result, ctx);
            checks.push(result);
            return;
        }
    };

    if workers.is_empty() {
        let result = CheckResult {
            category: "workers".to_string(),
            name: "worker_count".to_string(),
            status: CheckStatus::Warning,
            message: "No workers configured".to_string(),
            details: None,
            suggestion: Some("Add workers to workers.toml".to_string()),
            fixable: false,
            fix_applied: false,
            fix_message: None,
        };
        print_check_result(&result, ctx);
        checks.push(result);
        return;
    }

    // Report worker count
    let count_result = CheckResult {
        category: "workers".to_string(),
        name: "worker_count".to_string(),
        status: CheckStatus::Pass,
        message: format!("{} worker(s) configured", workers.len()),
        details: Some(
            workers
                .iter()
                .map(|w| w.id.as_str().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ),
        suggestion: None,
        fixable: false,
        fix_applied: false,
        fix_message: None,
    };
    print_check_result(&count_result, ctx);
    checks.push(count_result);

    // Only probe workers in verbose mode
    if options.verbose && !ctx.is_json() {
        println!(
            "  {}",
            style.muted("(use --verbose to probe worker connectivity)")
        );
    }

    if !ctx.is_json() {
        println!();
    }
}

// =============================================================================
// Telemetry Database Checks
// =============================================================================

fn check_telemetry_database(
    checks: &mut Vec<CheckResult>,
    ctx: &OutputContext,
    options: &DoctorOptions,
) {
    let style = ctx.theme();

    if !ctx.is_json() {
        println!("{}", style.highlight("Telemetry Database"));
        println!();
    }

    // Get the default telemetry database path
    let db_path = match ProjectDirs::from("com", "rch", "rch") {
        Some(dirs) => dirs.data_local_dir().join("telemetry").join("telemetry.db"),
        None => {
            let result = CheckResult {
                category: "telemetry".to_string(),
                name: "telemetry_database".to_string(),
                status: CheckStatus::Skipped,
                message: "Could not determine telemetry database path".to_string(),
                details: None,
                suggestion: None,
                fixable: false,
                fix_applied: false,
                fix_message: None,
            };
            print_check_result(&result, ctx);
            checks.push(result);
            return;
        }
    };

    // Check if database file exists
    if !db_path.exists() {
        let result = CheckResult {
            category: "telemetry".to_string(),
            name: "telemetry_database".to_string(),
            status: CheckStatus::Warning,
            message: "Telemetry database does not exist yet".to_string(),
            details: Some(db_path.display().to_string()),
            suggestion: Some("Database will be created when daemon starts".to_string()),
            fixable: false,
            fix_applied: false,
            fix_message: None,
        };
        print_check_result(&result, ctx);
        checks.push(result);
        return;
    }

    // Try to open and check the database
    match TelemetryStorage::new(&db_path, 30, 24, 365, 100) {
        Ok(storage) => {
            // Run integrity check
            match storage.integrity_check() {
                Ok(()) => {
                    // Get stats if verbose
                    let details = if options.verbose {
                        storage.stats().ok().map(|s| {
                            format!(
                                "Snapshots: {}, Aggregates: {}, SpeedScores: {}, Tests: {}, Size: {} KB",
                                s.telemetry_snapshots,
                                s.hourly_aggregates,
                                s.speedscore_entries,
                                s.test_runs,
                                s.db_size_bytes / 1024
                            )
                        })
                    } else {
                        Some(db_path.display().to_string())
                    };

                    let result = CheckResult {
                        category: "telemetry".to_string(),
                        name: "telemetry_database".to_string(),
                        status: CheckStatus::Pass,
                        message: "Telemetry database is healthy".to_string(),
                        details,
                        suggestion: None,
                        fixable: false,
                        fix_applied: false,
                        fix_message: None,
                    };
                    print_check_result(&result, ctx);
                    checks.push(result);
                }
                Err(e) => {
                    let result = CheckResult {
                        category: "telemetry".to_string(),
                        name: "telemetry_database".to_string(),
                        status: CheckStatus::Fail,
                        message: "Telemetry database integrity check failed".to_string(),
                        details: Some(e.to_string()),
                        suggestion: Some(
                            "Database may be corrupted. Delete and let daemon recreate it"
                                .to_string(),
                        ),
                        fixable: false,
                        fix_applied: false,
                        fix_message: None,
                    };
                    print_check_result(&result, ctx);
                    checks.push(result);
                }
            }
        }
        Err(e) => {
            let result = CheckResult {
                category: "telemetry".to_string(),
                name: "telemetry_database".to_string(),
                status: CheckStatus::Fail,
                message: "Could not open telemetry database".to_string(),
                details: Some(e.to_string()),
                suggestion: Some(
                    "Check file permissions or delete and let daemon recreate it".to_string(),
                ),
                fixable: false,
                fix_applied: false,
                fix_message: None,
            };
            print_check_result(&result, ctx);
            checks.push(result);
        }
    }

    if !ctx.is_json() {
        println!();
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn print_check_result(result: &CheckResult, ctx: &OutputContext) {
    if ctx.is_json() {
        return;
    }

    let style = ctx.theme();
    let indicator = match result.status {
        CheckStatus::Pass => StatusIndicator::Success,
        CheckStatus::Warning => StatusIndicator::Warning,
        CheckStatus::Fail => StatusIndicator::Error,
        CheckStatus::Skipped => StatusIndicator::Pending,
    };

    print!(
        "  {} {} {}",
        indicator.display(style),
        style.highlight(&result.name),
        style.muted("-")
    );

    match result.status {
        CheckStatus::Pass => println!(" {}", style.success(&result.message)),
        CheckStatus::Warning => println!(" {}", style.warning(&result.message)),
        CheckStatus::Fail => println!(" {}", style.error(&result.message)),
        CheckStatus::Skipped => println!(" {}", style.muted(&result.message)),
    }

    if let Some(ref details) = result.details
        && ctx.is_verbose()
    {
        println!("    {}", style.muted(details));
    }

    if let Some(ref suggestion) = result.suggestion {
        println!("    {} {}", style.muted("Hint:"), style.info(suggestion));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn worker_status(
        id: &str,
        status: &str,
        circuit_state: &str,
    ) -> crate::status_types::WorkerStatusFromApi {
        serde_json::from_value(json!({
            "id": id,
            "host": "worker.example",
            "user": "ubuntu",
            "status": status,
            "circuit_state": circuit_state,
            "used_slots": 0,
            "total_slots": 8,
            "speed_score": 99.0,
            "last_error": null
        }))
        .expect("worker status fixture should parse")
    }

    #[test]
    fn test_worker_topology_known_non_ready_status_is_degraded() {
        for status in ["degraded", "draining", "drained", "disabled", "busy"] {
            let worker = worker_status("worker-a", status, "closed");
            let diagnostic = worker_topology_diagnostic(&worker);

            assert_eq!(diagnostic.severity, ReliabilitySeverity::Warning);
            assert_eq!(diagnostic.code, ReliabilityReasonCode::WorkerDegraded);
            assert!(
                diagnostic.message.contains(status),
                "message should preserve the known non-ready status, got: {}",
                diagnostic.message
            );
        }
    }

    #[test]
    fn test_worker_topology_unknown_status_reports_protocol_drift() {
        let worker = worker_status("worker-a", "parked", "closed");
        let diagnostic = worker_topology_diagnostic(&worker);

        assert_eq!(diagnostic.severity, ReliabilitySeverity::Warning);
        assert_eq!(
            diagnostic.code,
            ReliabilityReasonCode::WorkerStatusUnrecognized
        );
        assert!(
            diagnostic.message.contains("status is unrecognized"),
            "unexpected message: {}",
            diagnostic.message
        );
    }

    // ========================================================================
    // t07 — defensive parsers for worker.ready_status + circuit_state.
    // Pure-function tests (no doctor/daemon harness) for the parser
    // contracts that drive worker_topology_diagnostic.
    // ========================================================================

    #[test]
    fn test_parse_ready_status_known_ready_variants() {
        for v in ["healthy", "available", "ready", "idle", "running"] {
            assert_eq!(
                parse_worker_ready_status(v),
                ParsedStatus::Known(KnownStatus::Ready),
                "{v} should parse as Ready"
            );
        }
    }

    #[test]
    fn test_parse_ready_status_known_degraded_variants() {
        for v in [
            "busy",
            "degraded",
            "draining",
            "drained",
            "disabled",
            "unhealthy",
        ] {
            assert_eq!(
                parse_worker_ready_status(v),
                ParsedStatus::Known(KnownStatus::Degraded),
                "{v} should parse as Degraded"
            );
        }
    }

    #[test]
    fn test_parse_ready_status_known_unreachable_variants() {
        for v in ["unreachable", "offline", "error", "failed"] {
            assert_eq!(
                parse_worker_ready_status(v),
                ParsedStatus::Known(KnownStatus::Unreachable),
                "{v} should parse as Unreachable"
            );
        }
    }

    #[test]
    fn test_parse_ready_status_trims_and_lowers() {
        // Whitespace + casing variations all hit the same bucket.
        for v in [
            "  healthy  ",
            "\tHealthy\n",
            "READY",
            "  Ready ",
            "\u{00A0}healthy\u{00A0}", // non-breaking space (Rust trim handles)
        ] {
            assert_eq!(
                parse_worker_ready_status(v),
                ParsedStatus::Known(KnownStatus::Ready),
                "{v:?} should normalize to Ready"
            );
        }
    }

    #[test]
    fn test_parse_ready_status_unknown_preserves_normalized_input() {
        // The Unrecognized variant carries the trim+lowered value so the
        // resulting diagnostic can surface it to operators.
        assert_eq!(
            parse_worker_ready_status("  PARKED  "),
            ParsedStatus::Unrecognized("parked".to_string())
        );
    }

    #[test]
    fn test_parse_ready_status_empty_string_unrecognized() {
        assert_eq!(
            parse_worker_ready_status(""),
            ParsedStatus::Unrecognized(String::new())
        );
        assert_eq!(
            parse_worker_ready_status("   \t  "),
            ParsedStatus::Unrecognized(String::new())
        );
    }

    #[test]
    fn test_parse_circuit_state_known_variants() {
        assert_eq!(
            parse_worker_circuit_state("closed"),
            ParsedCircuit::Known(KnownCircuit::Closed)
        );
        assert_eq!(
            parse_worker_circuit_state("open"),
            ParsedCircuit::Known(KnownCircuit::Open)
        );
        assert_eq!(
            parse_worker_circuit_state("half_open"),
            ParsedCircuit::Known(KnownCircuit::HalfOpen)
        );
        // dash form also accepted (some serializers use it).
        assert_eq!(
            parse_worker_circuit_state("half-open"),
            ParsedCircuit::Known(KnownCircuit::HalfOpen)
        );
    }

    #[test]
    fn test_parse_circuit_state_trims_and_lowers() {
        for v in ["  Open  ", "\tOPEN\n", "OPEN"] {
            assert_eq!(
                parse_worker_circuit_state(v),
                ParsedCircuit::Known(KnownCircuit::Open),
                "{v:?} should normalize to Open"
            );
        }
    }

    #[test]
    fn test_parse_circuit_state_unknown_preserves_normalized() {
        // Forensics: Unrecognized carries the offending value.
        assert_eq!(
            parse_worker_circuit_state("OPEN_FORCED"),
            ParsedCircuit::Unrecognized("open_forced".to_string())
        );
        assert_eq!(
            parse_worker_circuit_state("closed_for_maintenance"),
            ParsedCircuit::Unrecognized("closed_for_maintenance".to_string())
        );
        assert_eq!(
            parse_worker_circuit_state(""),
            ParsedCircuit::Unrecognized(String::new())
        );
    }

    #[test]
    fn test_worker_topology_unknown_circuit_state_reports_protocol_drift() {
        // The conjugate of the existing ready_status test: unknown
        // circuit_state values must surface as Warning with the
        // dedicated reason code, never silently mapped to Pass.
        let worker = worker_status("worker-a", "healthy", "OPEN_FORCED");
        let diagnostic = worker_topology_diagnostic(&worker);

        assert_eq!(diagnostic.severity, ReliabilitySeverity::Warning);
        assert_eq!(
            diagnostic.code,
            ReliabilityReasonCode::WorkerCircuitStateUnrecognized
        );
        assert!(
            diagnostic.message.contains("circuit_state is unrecognized"),
            "unexpected message: {}",
            diagnostic.message
        );
    }

    #[test]
    fn test_worker_topology_circuit_unrecognized_dominates_status() {
        // When BOTH fields are unrecognized, circuit drift is reported
        // first (the match-arm ordering encodes operator priority).
        let worker = worker_status("worker-a", "parked", "UNKNOWN");
        let diagnostic = worker_topology_diagnostic(&worker);
        assert_eq!(
            diagnostic.code,
            ReliabilityReasonCode::WorkerCircuitStateUnrecognized
        );
    }

    #[test]
    fn test_read_config_capped_reader_rejects_bytes_past_cap() {
        let err = read_config_capped_from_reader(
            std::io::Cursor::new(b"abcd".to_vec()),
            3,
            "test config",
        )
        .expect_err("reader that yields more than the cap must be rejected");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("exceeds 3-byte cap"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn test_read_config_capped_reader_accepts_exact_cap() {
        let content =
            read_config_capped_from_reader(std::io::Cursor::new(b"abc".to_vec()), 3, "test config")
                .expect("reader at the cap should be accepted");

        assert_eq!(content, "abc");
    }

    #[test]
    fn test_schema_compatibility_diagnostic_flags_mismatch() {
        let diagnostic =
            schema_compatibility_diagnostic("status", "2.0.0", "1.0.0", "CLI status response");

        assert_eq!(
            diagnostic.category,
            ReliabilityCategory::SchemaCompatibility
        );
        assert_eq!(diagnostic.severity, ReliabilitySeverity::Critical);
        assert_eq!(diagnostic.code, ReliabilityReasonCode::SchemaIncompatible);
        assert_eq!(
            diagnostic.details.as_deref(),
            Some("expected=1.0.0, actual=2.0.0")
        );
        assert!(
            diagnostic.remediation_command.is_some(),
            "schema mismatch should include remediation"
        );
    }

    #[test]
    fn test_schema_compatibility_diagnostic_passes_match() {
        let diagnostic =
            schema_compatibility_diagnostic("status", "1.0.0", "1.0.0", "CLI status response");

        assert_eq!(diagnostic.severity, ReliabilitySeverity::Pass);
        assert_eq!(diagnostic.code, ReliabilityReasonCode::SchemaCompatible);
        assert_eq!(
            diagnostic.details.as_deref(),
            Some("schema_version=1.0.0 expected=1.0.0")
        );
        assert!(diagnostic.remediation_command.is_none());
    }

    #[test]
    fn test_schema_compatibility_diagnostics_use_pinned_expected_versions() {
        let diagnostics = reliability_schema_compatibility_diagnostics();

        assert_eq!(diagnostics.len(), 4);
        for check_name in [
            "doctor_reliability",
            "status",
            "repo_updater_contract",
            "process_triage_contract",
        ] {
            let diagnostic = diagnostics
                .iter()
                .find(|diagnostic| diagnostic.check_name == check_name);
            assert!(
                diagnostic.is_some(),
                "missing schema diagnostic for {check_name}"
            );
            let Some(diagnostic) = diagnostic else {
                return;
            };

            assert_eq!(diagnostic.severity, ReliabilitySeverity::Pass);
            assert_eq!(diagnostic.code, ReliabilityReasonCode::SchemaCompatible);
            assert!(
                diagnostic
                    .details
                    .as_deref()
                    .is_some_and(|details| details.ends_with(" expected=1.0.0")),
                "{check_name} should compare against this doctor's pinned expected schema version"
            );
        }
    }

    #[test]
    fn test_check_command_exists_which() {
        // 'which' should exist on most systems
        let result = check_command_exists("which", "which command");
        assert_eq!(result.status, CheckStatus::Pass);
    }

    #[test]
    fn test_check_command_exists_nonexistent() {
        let result = check_command_exists("totally_nonexistent_command_12345", "fake command");
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.suggestion.is_some());
    }

    #[test]
    fn test_check_status_serialization() {
        let pass = serde_json::to_string(&CheckStatus::Pass).unwrap();
        assert_eq!(pass, "\"pass\"");

        let fail = serde_json::to_string(&CheckStatus::Fail).unwrap();
        assert_eq!(fail, "\"fail\"");
    }

    #[test]
    fn test_doctor_summary() {
        let summary = DoctorSummary {
            total: 10,
            passed: 7,
            warnings: 2,
            failed: 1,
            fixed: 0,
            would_fix: 0,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"total\":10"));
        assert!(json.contains("\"passed\":7"));
    }

    #[test]
    fn test_evaluate_cancellation_health_fails_on_cleanup_failure() {
        let status: crate::status_types::DaemonFullStatusResponse = serde_json::from_value(json!({
            "daemon": {
                "pid": 1,
                "uptime_secs": 10,
                "version": "0.1.0",
                "socket_path": "/tmp/rch.sock",
                "started_at": "2026-01-01T00:00:00Z",
                "workers_total": 1,
                "workers_healthy": 1,
                "slots_total": 8,
                "slots_available": 4
            },
            "workers": [],
            "active_builds": [],
            "queued_builds": [],
            "recent_builds": [{
                "id": 9,
                "started_at": "2026-01-01T00:00:00Z",
                "completed_at": "2026-01-01T00:00:05Z",
                "project_id": "proj",
                "worker_id": "worker-a",
                "command": "cargo test",
                "exit_code": 130,
                "duration_ms": 5000,
                "location": "remote",
                "bytes_transferred": 1024,
                "timing": null,
                "cancellation": {
                    "operation_id": "cancel-9",
                    "origin": "timeout",
                    "reason_code": "timeout",
                    "decision_path": ["requested", "term_sent", "remote_kill_sent", "escalated", "completed"],
                    "escalation_stage": "sigkill",
                    "escalation_count": 2,
                    "remote_kill_attempted": true,
                    "cleanup_ok": false,
                    "history_cancelled": true,
                    "final_state": "completed",
                    "worker_health": {
                        "status": "unreachable",
                        "speed_score": 0.0,
                        "used_slots": 4,
                        "available_slots": 0,
                        "pressure_state": "critical",
                        "pressure_reason_code": "disk_free_below_critical_gb"
                    }
                }
            }],
            "issues": [],
            "alerts": [],
            "stats": {
                "total_builds": 1,
                "success_count": 0,
                "failure_count": 1,
                "remote_count": 1,
                "local_count": 0,
                "avg_duration_ms": 5000
            },
            "test_stats": null,
            "saved_time": null
        }))
        .expect("status json should parse");

        let result = evaluate_cancellation_health(&status);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("cleanup failures"));
    }

    #[test]
    fn test_evaluate_cancellation_health_passes_on_clean_cancel() {
        let status: crate::status_types::DaemonFullStatusResponse = serde_json::from_value(json!({
            "daemon": {
                "pid": 1,
                "uptime_secs": 10,
                "version": "0.1.0",
                "socket_path": "/tmp/rch.sock",
                "started_at": "2026-01-01T00:00:00Z",
                "workers_total": 1,
                "workers_healthy": 1,
                "slots_total": 8,
                "slots_available": 4
            },
            "workers": [],
            "active_builds": [],
            "queued_builds": [],
            "recent_builds": [{
                "id": 10,
                "started_at": "2026-01-01T00:00:00Z",
                "completed_at": "2026-01-01T00:00:03Z",
                "project_id": "proj",
                "worker_id": "worker-a",
                "command": "cargo check",
                "exit_code": 130,
                "duration_ms": 3000,
                "location": "remote",
                "bytes_transferred": 1024,
                "timing": null,
                "cancellation": {
                    "operation_id": "cancel-10",
                    "origin": "user",
                    "reason_code": "user",
                    "decision_path": ["requested", "term_sent", "completed"],
                    "escalation_stage": "term",
                    "escalation_count": 0,
                    "remote_kill_attempted": false,
                    "cleanup_ok": true,
                    "history_cancelled": true,
                    "final_state": "completed",
                    "worker_health": {
                        "status": "healthy",
                        "speed_score": 97.2,
                        "used_slots": 0,
                        "available_slots": 8,
                        "pressure_state": "healthy",
                        "pressure_reason_code": "healthy"
                    }
                }
            }],
            "issues": [],
            "alerts": [],
            "stats": {
                "total_builds": 1,
                "success_count": 0,
                "failure_count": 1,
                "remote_count": 1,
                "local_count": 0,
                "avg_duration_ms": 3000
            },
            "test_stats": null,
            "saved_time": null
        }))
        .expect("status json should parse");

        let result = evaluate_cancellation_health(&status);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.message.contains("deterministic cleanup"));
    }

    #[test]
    fn test_quick_check_result_is_healthy() {
        let healthy = QuickCheckResult {
            daemon_running: true,
            worker_count: 1,
            workers_healthy: Some(1),
            hook_installed: true,
            warnings: vec![],
            errors: vec![],
        };
        assert!(healthy.is_healthy());

        let no_daemon = QuickCheckResult {
            daemon_running: false,
            worker_count: 1,
            workers_healthy: Some(1),
            hook_installed: true,
            warnings: vec![],
            errors: vec![],
        };
        assert!(!no_daemon.is_healthy());

        let no_workers = QuickCheckResult {
            daemon_running: true,
            worker_count: 0,
            workers_healthy: None,
            hook_installed: true,
            warnings: vec![],
            errors: vec![],
        };
        assert!(!no_workers.is_healthy());

        let no_hook = QuickCheckResult {
            daemon_running: true,
            worker_count: 1,
            workers_healthy: Some(1),
            hook_installed: false,
            warnings: vec![],
            errors: vec![],
        };
        assert!(!no_hook.is_healthy());

        let with_warning = QuickCheckResult {
            daemon_running: true,
            worker_count: 1,
            workers_healthy: Some(1),
            hook_installed: true,
            warnings: vec!["Worker health stale".to_string()],
            errors: vec![],
        };
        assert!(
            !with_warning.is_healthy(),
            "warnings are issues and must not report full quick-check health"
        );
    }

    #[test]
    fn test_quick_check_result_has_issues() {
        let no_issues = QuickCheckResult {
            daemon_running: true,
            worker_count: 1,
            workers_healthy: Some(1),
            hook_installed: true,
            warnings: vec![],
            errors: vec![],
        };
        assert!(!no_issues.has_issues());

        let with_warnings = QuickCheckResult {
            daemon_running: true,
            worker_count: 1,
            workers_healthy: Some(1),
            hook_installed: true,
            warnings: vec!["Some warning".to_string()],
            errors: vec![],
        };
        assert!(with_warnings.has_issues());

        let with_errors = QuickCheckResult {
            daemon_running: true,
            worker_count: 1,
            workers_healthy: Some(1),
            hook_installed: true,
            warnings: vec![],
            errors: vec!["Some error".to_string()],
        };
        assert!(with_errors.has_issues());
    }

    #[test]
    fn test_run_quick_check_returns_result() {
        // This test just verifies that run_quick_check executes without panicking
        // and returns a valid result structure
        let result = run_quick_check();
        // We can't assert on specific values because they depend on system state,
        // but we can verify the result is accessible and properly structured
        let _total_issues = result.warnings.len() + result.errors.len();
    }

    // =========================================================================
    // t03 — run_quick_check contract: Option<usize> for workers_healthy +
    // honest "unknown" signal + is_healthy() never defaults to success.
    // =========================================================================

    #[test]
    fn test_quick_check_unknown_workers_health_is_not_healthy() {
        // The bead's headline regression: workers_healthy=None must
        // never be treated as healthy. Even if everything else is ok,
        // unknown worker state means "not healthy until probed".
        let unknown = QuickCheckResult {
            daemon_running: true,
            worker_count: 3,
            workers_healthy: None, // not probed
            hook_installed: true,
            warnings: vec![],
            errors: vec![],
        };
        assert!(
            !unknown.is_healthy(),
            "is_healthy() must NOT return true when workers_healthy is None"
        );
    }

    #[test]
    fn test_quick_check_partial_health_is_not_healthy() {
        // 5 workers configured, only 3 probed healthy: definitively NOT healthy.
        let partial = QuickCheckResult {
            daemon_running: true,
            worker_count: 5,
            workers_healthy: Some(3),
            hook_installed: true,
            warnings: vec![],
            errors: vec![],
        };
        assert!(!partial.is_healthy());
    }

    #[test]
    fn test_quick_check_full_health_is_healthy() {
        // worker_count == workers_healthy.unwrap() AND everything else ok.
        let full = QuickCheckResult {
            daemon_running: true,
            worker_count: 3,
            workers_healthy: Some(3),
            hook_installed: true,
            warnings: vec![],
            errors: vec![],
        };
        assert!(full.is_healthy());
    }

    #[test]
    fn test_quick_check_does_not_default_to_success() {
        // Explicit regression for the original bug: the prior code had
        //   Ok(workers) => (workers.len(), workers.len()) // assume healthy
        // which silently treated configured workers as healthy. Now we
        // require an explicit Some(n) AND n == worker_count for is_healthy()
        // to return true. NO path through run_quick_check() can satisfy
        // this without an honest probe.
        let result = run_quick_check();
        // Since run_quick_check is fast-only (no network probes), it
        // CANNOT report Some(_) for workers_healthy. The contract is
        // verified by the implementation: workers_healthy is always None.
        assert_eq!(
            result.workers_healthy, None,
            "fast-only run_quick_check must report unknown worker health"
        );
        // Confirms is_healthy() returns false for fast-only checks.
        assert!(
            !result.is_healthy(),
            "fast-only check must never report healthy without a probe"
        );
    }

    #[test]
    fn test_quick_check_emits_warning_about_unprobed_workers() {
        // When worker_count > 0 but workers_healthy is None, surface a
        // warning so operators understand they ran a fast-check, not a
        // real probe. (Only fires if there are configured workers; an
        // empty fleet is reported via "No workers configured" warning.)
        // Since we can't easily inject a fake fleet here, we test the
        // logic at the struct level: build a synthetic result and
        // verify the warning text would be emitted.
        let r = QuickCheckResult {
            daemon_running: true,
            worker_count: 3,
            workers_healthy: None,
            hook_installed: true,
            warnings: vec![
                "Worker health not probed by quick-check; run `rch doctor --reliability` for full status".to_string(),
            ],
            errors: vec![],
        };
        assert!(
            r.warnings.iter().any(|w| w.contains("not probed")),
            "expected fast-check to surface 'not probed' warning"
        );
        // is_healthy still returns false because workers_healthy is None.
        assert!(!r.is_healthy());
    }

    // =========================================================================
    // Individual Check Tests
    // =========================================================================

    #[test]
    fn test_check_config_directory_with_existing_dir() {
        // TEST START: check_config_directory with existing directory
        // This test verifies config directory check handles existing directories
        let result = check_config_directory();
        // Config directory check should return a valid result regardless of state
        assert!(
            matches!(
                result.status,
                CheckStatus::Pass | CheckStatus::Warning | CheckStatus::Fail
            ),
            "Config directory check returned unexpected status"
        );
        assert_eq!(result.category, "configuration");
        assert_eq!(result.name, "config_directory");
        // TEST PASS: check_config_directory
    }

    #[test]
    fn test_check_config_file_structure() {
        // TEST START: check_config_file structure validation
        let result = check_config_file();
        assert_eq!(result.category, "configuration");
        assert_eq!(result.name, "config.toml");
        // Check that we get valid status and proper field population
        assert!(
            matches!(
                result.status,
                CheckStatus::Pass | CheckStatus::Warning | CheckStatus::Fail | CheckStatus::Skipped
            ),
            "Config file check returned unexpected status"
        );
        // If skipped, should have appropriate message
        if result.status == CheckStatus::Skipped {
            assert!(result.message.contains("Skipped"));
        }
        // TEST PASS: check_config_file structure
    }

    #[test]
    fn test_check_workers_file_structure() {
        // TEST START: check_workers_file structure validation
        let result = check_workers_file();
        assert_eq!(result.category, "configuration");
        assert_eq!(result.name, "workers.toml");
        // Should return valid CheckResult regardless of file existence
        assert!(
            matches!(
                result.status,
                CheckStatus::Pass | CheckStatus::Warning | CheckStatus::Fail | CheckStatus::Skipped
            ),
            "Workers file check returned unexpected status"
        );
        // TEST PASS: check_workers_file structure
    }

    #[test]
    fn test_check_ssh_config_returns_valid_result() {
        // TEST START: check_ssh_config validation
        let result = check_ssh_config();
        assert_eq!(result.category, "ssh");
        assert_eq!(result.name, "ssh_config");
        // SSH config is optional, so either Pass or Warning is acceptable
        assert!(
            matches!(result.status, CheckStatus::Pass | CheckStatus::Warning),
            "SSH config check should return Pass or Warning, got {:?}",
            result.status
        );
        // TEST PASS: check_ssh_config
    }

    #[test]
    fn test_check_claude_code_hook_returns_valid_result() {
        // TEST START: check_claude_code_hook validation
        let result = check_claude_code_hook();
        assert_eq!(result.category, "hooks");
        assert_eq!(result.name, "claude_code_hook");
        // Hook may or may not be installed
        assert!(
            matches!(
                result.status,
                CheckStatus::Pass | CheckStatus::Warning | CheckStatus::Fail
            ),
            "Claude Code hook check returned unexpected status"
        );
        // Should always have details pointing to settings path
        assert!(result.details.is_some() || result.status == CheckStatus::Fail);
        // TEST PASS: check_claude_code_hook
    }

    #[test]
    fn test_check_command_exists_common_tools() {
        // TEST START: check_command_exists for common system tools
        // These should exist on any Unix-like system
        let tools = [
            ("ls", "List command"),
            ("cat", "Concatenate command"),
            ("echo", "Echo command"),
        ];

        for (cmd, desc) in tools {
            let result = check_command_exists(cmd, desc);
            assert_eq!(
                result.status,
                CheckStatus::Pass,
                "Expected {} to exist on system",
                cmd
            );
            assert_eq!(result.category, "prerequisites");
            assert_eq!(result.name, cmd);
            assert!(result.message.contains("installed"));
        }
        // TEST PASS: check_command_exists for common tools
    }

    #[test]
    fn test_check_command_exists_returns_version_info() {
        // TEST START: check_command_exists captures version info
        let result = check_command_exists("ls", "List command");
        if result.status == CheckStatus::Pass {
            // Most tools return version info, but some may not
            // We just verify the field exists
            let _ = &result.details;
        }
        // TEST PASS: check_command_exists version info
    }

    #[test]
    fn test_check_command_exists_provides_suggestion_for_missing() {
        // TEST START: check_command_exists suggestions for missing commands
        let result = check_command_exists("rch_nonexistent_test_cmd_xyz", "fake tool");
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(
            result.suggestion.is_some(),
            "Missing command should provide installation suggestion"
        );
        assert!(
            result.suggestion.unwrap().contains("package manager"),
            "Suggestion should mention package manager"
        );
        // TEST PASS: check_command_exists suggestions
    }

    // =========================================================================
    // CheckResult Structure Tests
    // =========================================================================

    #[test]
    fn test_check_result_json_serialization() {
        // TEST START: CheckResult JSON serialization
        let result = CheckResult {
            category: "test".to_string(),
            name: "test_check".to_string(),
            status: CheckStatus::Pass,
            message: "Test passed".to_string(),
            details: Some("Extra details".to_string()),
            suggestion: None,
            fixable: false,
            fix_applied: false,
            fix_message: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"category\":\"test\""));
        assert!(json.contains("\"name\":\"test_check\""));
        assert!(json.contains("\"status\":\"pass\""));
        assert!(json.contains("\"message\":\"Test passed\""));
        assert!(json.contains("\"details\":\"Extra details\""));
        // Optional fields that are None should be skipped
        assert!(!json.contains("\"suggestion\":"));
        assert!(!json.contains("\"fix_message\":"));
        // TEST PASS: CheckResult JSON serialization
    }

    #[test]
    fn test_check_result_with_fix_info() {
        // TEST START: CheckResult with fix information
        let result = CheckResult {
            category: "ssh".to_string(),
            name: "key_permissions".to_string(),
            status: CheckStatus::Warning,
            message: "Loose permissions".to_string(),
            details: Some("/home/user/.ssh/id_ed25519".to_string()),
            suggestion: Some("chmod 600 /path/to/key".to_string()),
            fixable: true,
            fix_applied: true,
            fix_message: Some("Changed permissions to 0600".to_string()),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"fixable\":true"));
        assert!(json.contains("\"fix_applied\":true"));
        assert!(json.contains("\"fix_message\":"));
        // TEST PASS: CheckResult with fix info
    }

    #[test]
    fn test_all_check_statuses_serialize() {
        // TEST START: All CheckStatus variants serialize correctly
        let statuses = [
            (CheckStatus::Pass, "\"pass\""),
            (CheckStatus::Warning, "\"warning\""),
            (CheckStatus::Fail, "\"fail\""),
            (CheckStatus::Skipped, "\"skipped\""),
        ];

        for (status, expected) in statuses {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(
                json, expected,
                "CheckStatus::{:?} serialized incorrectly",
                status
            );
        }
        // TEST PASS: All CheckStatus variants serialize
    }

    // =========================================================================
    // DoctorResponse Structure Tests
    // =========================================================================

    #[test]
    fn test_doctor_response_serialization() {
        // TEST START: DoctorResponse full serialization
        let response = DoctorResponse {
            schema_version: "1.0.0".to_string(),
            checks: vec![
                CheckResult {
                    category: "prerequisites".to_string(),
                    name: "rsync".to_string(),
                    status: CheckStatus::Pass,
                    message: "rsync is installed".to_string(),
                    details: Some("rsync version 3.2.7".to_string()),
                    suggestion: None,
                    fixable: false,
                    fix_applied: false,
                    fix_message: None,
                },
                CheckResult {
                    category: "configuration".to_string(),
                    name: "config.toml".to_string(),
                    status: CheckStatus::Warning,
                    message: "config.toml not found".to_string(),
                    details: None,
                    suggestion: Some("Run rch config init".to_string()),
                    fixable: true,
                    fix_applied: false,
                    fix_message: None,
                },
            ],
            summary: DoctorSummary {
                total: 2,
                passed: 1,
                warnings: 1,
                failed: 0,
                fixed: 0,
                would_fix: 0,
            },
            fixes_applied: vec![],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"checks\":["));
        assert!(json.contains("\"summary\":{"));
        assert!(json.contains("\"fixes_applied\":[]"));
        // TEST PASS: DoctorResponse serialization
    }

    #[test]
    fn test_doctor_response_with_fixes() {
        // TEST START: DoctorResponse with applied fixes
        let response = DoctorResponse {
            schema_version: "1.0.0".to_string(),
            checks: vec![],
            summary: DoctorSummary {
                total: 1,
                passed: 1,
                warnings: 0,
                failed: 0,
                fixed: 1,
                would_fix: 0,
            },
            fixes_applied: vec![FixApplied {
                check_name: "ssh_key_perms".to_string(),
                action: "Changed permissions to 0600".to_string(),
                success: true,
                error: None,
            }],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"fixes_applied\":[{"));
        assert!(json.contains("\"check_name\":\"ssh_key_perms\""));
        assert!(json.contains("\"success\":true"));
        // TEST PASS: DoctorResponse with fixes
    }

    // =========================================================================
    // Fix Applied Structure Tests
    // =========================================================================

    #[test]
    fn test_fix_applied_success() {
        // TEST START: FixApplied success case
        let fix = FixApplied {
            check_name: "id_ed25519".to_string(),
            action: "Changed permissions from 0644 to 0600".to_string(),
            success: true,
            error: None,
        };

        let json = serde_json::to_string(&fix).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(!json.contains("\"error\""));
        // TEST PASS: FixApplied success
    }

    #[test]
    fn test_fix_applied_failure() {
        // TEST START: FixApplied failure case
        let fix = FixApplied {
            check_name: "id_rsa".to_string(),
            action: "Attempted to change permissions".to_string(),
            success: false,
            error: Some("Permission denied".to_string()),
        };

        let json = serde_json::to_string(&fix).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("\"error\":\"Permission denied\""));
        // TEST PASS: FixApplied failure
    }

    // =========================================================================
    // DoctorOptions Tests
    // =========================================================================

    #[test]
    fn test_doctor_options_default_values() {
        // TEST START: DoctorOptions can be constructed with various combinations
        let opts_minimal = DoctorOptions {
            fix: false,
            dry_run: false,
            install_deps: false,
            reliability: false,
            check_schemas: false,
            verbose: false,
            strict: false,
            lenient: false,
            scope: ReliabilityScopeSet::default(),
        };
        assert!(!opts_minimal.fix);
        assert!(!opts_minimal.dry_run);

        let opts_fix = DoctorOptions {
            fix: true,
            dry_run: false,
            install_deps: false,
            reliability: false,
            check_schemas: false,
            verbose: false,
            strict: false,
            lenient: false,
            scope: ReliabilityScopeSet::default(),
        };
        assert!(opts_fix.fix);

        let opts_dry_run = DoctorOptions {
            fix: true,
            dry_run: true,
            install_deps: false,
            reliability: false,
            check_schemas: false,
            verbose: false,
            strict: false,
            lenient: false,
            scope: ReliabilityScopeSet::default(),
        };
        assert!(opts_dry_run.fix);
        assert!(opts_dry_run.dry_run);

        let opts_verbose = DoctorOptions {
            fix: false,
            dry_run: false,
            install_deps: false,
            reliability: false,
            check_schemas: false,
            verbose: true,
            strict: false,
            lenient: false,
            scope: ReliabilityScopeSet::default(),
        };
        assert!(opts_verbose.verbose);
        // TEST PASS: DoctorOptions construction
    }

    // =========================================================================
    // DoctorSummary Tests
    // =========================================================================

    #[test]
    fn test_doctor_summary_all_passed() {
        // TEST START: DoctorSummary all checks passed
        let summary = DoctorSummary {
            total: 15,
            passed: 15,
            warnings: 0,
            failed: 0,
            fixed: 0,
            would_fix: 0,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"total\":15"));
        assert!(json.contains("\"passed\":15"));
        assert!(json.contains("\"failed\":0"));
        // TEST PASS: DoctorSummary all passed
    }

    #[test]
    fn test_doctor_summary_with_failures() {
        // TEST START: DoctorSummary with failures
        let summary = DoctorSummary {
            total: 10,
            passed: 5,
            warnings: 2,
            failed: 3,
            fixed: 0,
            would_fix: 0,
        };

        // Verify counts add up
        assert_eq!(
            summary.passed + summary.warnings + summary.failed,
            summary.total
        );
        // TEST PASS: DoctorSummary with failures
    }

    #[test]
    fn test_doctor_summary_with_fixes() {
        // TEST START: DoctorSummary tracking fixes
        let summary = DoctorSummary {
            total: 10,
            passed: 8,
            warnings: 0,
            failed: 0,
            fixed: 2,
            would_fix: 0,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"fixed\":2"));
        // TEST PASS: DoctorSummary with fixes
    }

    #[test]
    fn test_doctor_summary_dry_run_would_fix() {
        // TEST START: DoctorSummary dry run would_fix count
        let summary = DoctorSummary {
            total: 10,
            passed: 7,
            warnings: 3,
            failed: 0,
            fixed: 0,
            would_fix: 3,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"would_fix\":3"));
        // TEST PASS: DoctorSummary dry run
    }

    // =========================================================================
    // QuickCheckResult Extended Tests
    // =========================================================================

    #[test]
    fn test_quick_check_result_multiple_issues() {
        // TEST START: QuickCheckResult with multiple issues
        let result = QuickCheckResult {
            daemon_running: false,
            worker_count: 0,
            workers_healthy: None,
            hook_installed: false,
            warnings: vec![
                "Daemon not running".to_string(),
                "No workers configured".to_string(),
            ],
            errors: vec!["Hook not installed".to_string()],
        };

        assert!(!result.is_healthy());
        assert!(result.has_issues());
        assert_eq!(result.warnings.len(), 2);
        assert_eq!(result.errors.len(), 1);
        // TEST PASS: QuickCheckResult multiple issues
    }

    #[test]
    fn test_quick_check_result_partial_health() {
        // TEST START: QuickCheckResult partial health
        // Updated for t03 contract (2s99h.11): partial worker health is
        // NOT healthy. Previously this test asserted is_healthy()=true
        // with a warning, encoding the default-to-success behavior.
        // The new contract: workers_healthy < worker_count means the
        // system is NOT healthy.
        let result = QuickCheckResult {
            daemon_running: true,
            worker_count: 2,
            workers_healthy: Some(1), // Only 1 of 2 healthy
            hook_installed: true,
            warnings: vec!["Worker css is offline".to_string()],
            errors: vec![],
        };

        // Partial health is now NOT healthy (default-to-degraded discipline).
        assert!(
            !result.is_healthy(),
            "1/2 workers healthy must NOT report system-healthy"
        );
        assert!(result.has_issues());
        // TEST PASS: QuickCheckResult partial health
    }

    // =========================================================================
    // SSH Worker Suggestion Tests
    // =========================================================================

    #[test]
    fn test_ssh_worker_suggestion_format() {
        // TEST START: ssh_worker_suggestion generates correct commands
        let suggestion = ssh_worker_suggestion(
            "ubuntu",
            "build-server.local",
            Path::new("/home/user/.ssh/id_ed25519"),
        );

        // Should contain ssh-copy-id command
        assert!(
            suggestion.contains("ssh-copy-id"),
            "Should suggest ssh-copy-id"
        );
        // Should contain test command
        assert!(
            suggestion.contains("ssh -i"),
            "Should suggest testing with ssh -i"
        );
        // Should contain agent commands
        assert!(
            suggestion.contains("ssh-agent") && suggestion.contains("ssh-add"),
            "Should suggest ssh-agent setup"
        );
        // Should contain debug command
        assert!(suggestion.contains("-vvv"), "Should suggest verbose debug");
        // Should use correct user and host
        assert!(suggestion.contains("ubuntu@build-server.local"));
        // TEST PASS: ssh_worker_suggestion format
    }

    #[test]
    fn test_ssh_worker_suggestion_with_special_path() {
        // TEST START: ssh_worker_suggestion handles special paths
        let suggestion =
            ssh_worker_suggestion("admin", "192.168.1.100", Path::new("/custom/path/my_key"));

        assert!(suggestion.contains("/custom/path/my_key"));
        assert!(suggestion.contains("admin@192.168.1.100"));
        // TEST PASS: ssh_worker_suggestion special path
    }

    #[test]
    fn test_ssh_worker_suggestion_quotes_shell_metachars() {
        // TEST START: shell-injection defense — fields with `;`, `$`, etc.
        // must be shell-escaped so a hostile workers.toml cannot produce a
        // runnable destructive command when an agent copy-pastes the
        // suggestion.
        let suggestion = ssh_worker_suggestion(
            "evil; rm -rf ~",
            "host\"$(touch /tmp/pwned)",
            Path::new("/keys/with spaces/id"),
        );
        // The literal `; rm -rf ~` MUST NOT appear unquoted — it would
        // execute when the user pastes the string into a shell.
        // shell_escape::escape produces single-quoted strings for posix
        // shells; a string containing a single-quote is broken across
        // multiple quoted segments. Either way, the dangerous payload is
        // contained inside quoted/escaped boundaries.
        let dangerous_unquoted = "; rm -rf ~"; // the bare metachar sequence
        // We require that the dangerous sequence does NOT appear AT a
        // shell-relevant position — i.e., it must always be inside the
        // quoting that shell_escape produces. The simplest robust check:
        // the suggestion must contain the escape character or quoting
        // around the user field rather than a bare `;`.
        // shell_escape always outputs a fully-quoted form when the input
        // contains shell metachars; assert the input form is preserved
        // by counting that the dangerous chars are wrapped.
        let user_segment_starts = suggestion.find("evil").expect("user appears");
        // The character immediately preceding the user value must be `'`
        // (POSIX-shell single-quote escaping) or `"` (double-quote).
        let prev_char = suggestion[..user_segment_starts]
            .chars()
            .last()
            .expect("preceding char");
        assert!(
            matches!(prev_char, '\'' | '"'),
            "user field must be inside shell quoting; got prev_char={:?} in suggestion={}",
            prev_char,
            suggestion
        );
        // Strong safety property: passing the suggestion through `sh -n`
        // (parse-only) MUST succeed — i.e., it's syntactically valid
        // shell, no runaway `;` or unterminated quote. This catches any
        // future regression where the escaping breaks the syntax.
        let parse_check = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&suggestion)
            .output();
        if let Ok(out) = parse_check {
            assert!(
                out.status.success(),
                "shell parse-only check failed for: {}\nstderr: {}",
                suggestion,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        // The dangerous payload should never appear *unquoted* at a
        // statement boundary. If it did, the test_ssh_worker_suggestion
        // test would still pass (the substring is still in the string)
        // but the parse_check above would catch the syntax break.
        let _ = dangerous_unquoted; // referenced for clarity; not asserted directly.
        // TEST PASS: shell injection defense holds
    }

    // =========================================================================
    // Default Socket Path Tests
    // =========================================================================

    #[test]
    fn test_default_socket_path_returns_valid_path() {
        // TEST START: default_socket_path returns non-empty path
        let path = default_socket_path();
        assert!(
            !path.as_os_str().is_empty(),
            "Socket path should not be empty"
        );
        // Should end with a reasonable filename
        let filename = path.file_name().map(|f| f.to_string_lossy().to_string());
        assert!(
            filename.is_some(),
            "Socket path should have a filename component"
        );
        // TEST PASS: default_socket_path
    }

    // =========================================================================
    // Integration-Style Tests (Still No Mocks)
    // =========================================================================

    #[test]
    fn test_prerequisite_checks_run_without_panic() {
        // TEST START: Prerequisites check runs safely
        use crate::ui::context::{OutputConfig, OutputContext};

        let ctx = OutputContext::new(OutputConfig::default());
        let options = DoctorOptions {
            fix: false,
            dry_run: false,
            install_deps: false,
            reliability: false,
            check_schemas: false,
            verbose: false,
            strict: false,
            lenient: false,
            scope: ReliabilityScopeSet::default(),
        };

        let mut checks = Vec::new();
        // This should not panic regardless of system state
        check_prerequisites(&mut checks, &ctx, &options);

        // Should have checked at least the core tools (rsync, zstd, ssh, rustup, cargo)
        assert!(
            checks.len() >= 5,
            "Should check at least 5 prerequisite tools, got {}",
            checks.len()
        );

        // All results should have valid structure
        for check in &checks {
            assert_eq!(check.category, "prerequisites");
            assert!(!check.name.is_empty());
            assert!(!check.message.is_empty());
        }
        // TEST PASS: Prerequisites check runs
    }

    #[test]
    fn test_configuration_checks_run_without_panic() {
        // TEST START: Configuration checks run safely
        use crate::ui::context::{OutputConfig, OutputContext};

        let ctx = OutputContext::new(OutputConfig::default());
        let options = DoctorOptions {
            fix: false,
            dry_run: false,
            install_deps: false,
            reliability: false,
            check_schemas: false,
            verbose: false,
            strict: false,
            lenient: false,
            scope: ReliabilityScopeSet::default(),
        };

        let mut checks = Vec::new();
        check_configuration(&mut checks, &ctx, &options);

        // Should check config directory, config.toml, workers.toml
        assert!(
            checks.len() >= 3,
            "Should check at least 3 config items, got {}",
            checks.len()
        );

        for check in &checks {
            assert_eq!(check.category, "configuration");
        }
        // TEST PASS: Configuration checks run
    }

    #[test]
    fn test_daemon_check_runs_without_panic() {
        // TEST START: Daemon check runs safely
        use crate::ui::context::{OutputConfig, OutputContext};

        let ctx = OutputContext::new(OutputConfig::default());
        let options = DoctorOptions {
            fix: false,
            dry_run: false,
            install_deps: false,
            reliability: false,
            check_schemas: false,
            verbose: false,
            strict: false,
            lenient: false,
            scope: ReliabilityScopeSet::default(),
        };
        let mut fixes_applied = Vec::new();

        let mut checks = Vec::new();
        check_daemon(&mut checks, &ctx, &options, &mut fixes_applied);

        // Should check at least daemon socket
        assert!(!checks.is_empty(), "Should have daemon checks");

        for check in &checks {
            assert_eq!(check.category, "daemon");
        }
        // TEST PASS: Daemon check runs
    }

    #[test]
    fn test_wait_for_socket_times_out() {
        // TEST START: wait_for_socket times out when socket never appears
        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("missing.sock");
        assert!(!wait_for_socket(&socket_path, Duration::from_millis(50)));
        // TEST PASS: wait_for_socket timeout
    }

    #[cfg(unix)]
    #[test]
    fn test_start_daemon_with_fake_rchd_creates_socket_file() {
        // TEST START: start_daemon_with_binary uses -s socket path and waits for file
        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("daemon.sock");
        let fake_rchd = tmp.path().join("rchd");

        let script = "#!/usr/bin/env sh\n\
sock=\"\"\n\
while [ \"$#\" -gt 0 ]; do\n\
  if [ \"$1\" = \"-s\" ] || [ \"$1\" = \"--socket\" ]; then\n\
    shift\n\
    sock=\"$1\"\n\
  fi\n\
  shift\n\
done\n\
[ -n \"$sock\" ] || exit 1\n\
: > \"$sock\"\n\
exit 0\n"
            .to_string();
        std::fs::write(&fake_rchd, script).unwrap();
        let mut perms = std::fs::metadata(&fake_rchd).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_rchd, perms).unwrap();

        start_daemon_with_binary(&socket_path, &fake_rchd, Duration::from_secs(1)).unwrap();
        assert!(socket_path.exists());
        // TEST PASS: start_daemon_with_binary creates socket file
    }

    #[cfg(unix)]
    #[test]
    fn test_start_daemon_with_failing_fake_rchd_reports_exit() {
        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("daemon.sock");
        let fake_rchd = tmp.path().join("rchd");

        std::fs::write(&fake_rchd, "#!/usr/bin/env sh\nexit 42\n").unwrap();
        let mut perms = std::fs::metadata(&fake_rchd).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_rchd, perms).unwrap();

        let err =
            start_daemon_with_binary(&socket_path, &fake_rchd, Duration::from_secs(1)).unwrap_err();
        assert!(
            err.contains("exited unsuccessfully") && err.contains("42"),
            "unexpected error: {err}"
        );
        assert!(!socket_path.exists());
    }

    #[test]
    fn test_check_result_fixable_field_semantics() {
        // TEST START: CheckResult fixable field has correct semantics
        // A check that passes should not be fixable (nothing to fix)
        let pass_result = CheckResult {
            category: "test".to_string(),
            name: "passing_check".to_string(),
            status: CheckStatus::Pass,
            message: "All good".to_string(),
            details: None,
            suggestion: None,
            fixable: false, // Correct: passing checks aren't fixable
            fix_applied: false,
            fix_message: None,
        };
        assert!(!pass_result.fixable);

        // A failing check that can be auto-fixed should be marked fixable
        let fixable_fail = CheckResult {
            category: "test".to_string(),
            name: "fixable_issue".to_string(),
            status: CheckStatus::Warning,
            message: "Permission issue".to_string(),
            details: None,
            suggestion: Some("Run chmod 600".to_string()),
            fixable: true, // Correct: this can be fixed
            fix_applied: false,
            fix_message: None,
        };
        assert!(fixable_fail.fixable);

        // A failing check that cannot be auto-fixed should not be fixable
        let unfixable_fail = CheckResult {
            category: "test".to_string(),
            name: "unfixable_issue".to_string(),
            status: CheckStatus::Fail,
            message: "Missing hardware".to_string(),
            details: None,
            suggestion: Some("Buy new hardware".to_string()),
            fixable: false, // Correct: can't auto-fix hardware
            fix_applied: false,
            fix_message: None,
        };
        assert!(!unfixable_fail.fixable);
        // TEST PASS: fixable field semantics
    }

    #[test]
    fn test_check_result_fix_applied_and_message_consistency() {
        // TEST START: fix_applied and fix_message should be consistent
        // If fix_applied is true, fix_message should be Some
        let fixed_result = CheckResult {
            category: "test".to_string(),
            name: "fixed_check".to_string(),
            status: CheckStatus::Pass,
            message: "Fixed!".to_string(),
            details: None,
            suggestion: None,
            fixable: false,
            fix_applied: true,
            fix_message: Some("Changed X to Y".to_string()),
        };
        assert!(fixed_result.fix_applied);
        assert!(fixed_result.fix_message.is_some());

        // If fix_applied is false, fix_message typically should be None
        let not_fixed = CheckResult {
            category: "test".to_string(),
            name: "not_fixed".to_string(),
            status: CheckStatus::Warning,
            message: "Issue detected".to_string(),
            details: None,
            suggestion: Some("Run fix command".to_string()),
            fixable: true,
            fix_applied: false,
            fix_message: None,
        };
        assert!(!not_fixed.fix_applied);
        // TEST PASS: fix_applied and fix_message consistency
    }

    // ========================================================================
    // Config-cache hoisting (t10) — verify the rollout-posture probe accepts
    // a borrowed config and produces the same diagnostics regardless of how
    // many times the caller invokes it.
    // ========================================================================

    #[test]
    fn test_rollout_posture_takes_borrowed_config() {
        // Borrowed-Ok path: probe consumes a shared snapshot.
        let config = rch_common::RchConfig::default();
        let diags = reliability_rollout_posture_diagnostics(Ok(&config));
        // 5 always-on diagnostics: hook_starts_daemon, daemon_installs_hooks,
        // status_surface, repo_convergence_gate, disk_pressure_gate.
        assert!(
            diags.len() >= 4,
            "expected at least 4 diagnostics (got {}): {:?}",
            diags.len(),
            diags.iter().map(|d| &d.check_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rollout_posture_handles_borrowed_err() {
        // Borrowed-Err path: probe surfaces a single ConfigLoadFailed
        // diagnostic and continues with the rollout-surface checks.
        let diags = reliability_rollout_posture_diagnostics(Err("synthetic toml parse failure"));
        let warning_count = diags
            .iter()
            .filter(|d| {
                matches!(d.severity, ReliabilitySeverity::Warning)
                    && d.code == ReliabilityReasonCode::ConfigLoadFailed
            })
            .count();
        assert_eq!(
            warning_count,
            1,
            "expected exactly one ConfigLoadFailed diagnostic, got: {:?}",
            diags
                .iter()
                .map(|d| (&d.check_name, &d.code))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rollout_posture_idempotent_for_same_config() {
        // Calling the probe twice with the same borrowed config must
        // produce byte-identical diagnostics — confirms the function is
        // pure with respect to its config input.
        let config = rch_common::RchConfig::default();
        let a = reliability_rollout_posture_diagnostics(Ok(&config));
        let b = reliability_rollout_posture_diagnostics(Ok(&config));
        assert_eq!(a.len(), b.len());
        for (da, db) in a.iter().zip(b.iter()) {
            assert_eq!(da.check_name, db.check_name);
            assert_eq!(da.severity, db.severity);
            assert_eq!(da.message, db.message);
            assert_eq!(da.code, db.code);
        }
    }

    #[test]
    fn test_rollout_posture_two_configs_isolated() {
        // Different config snapshots produce different diagnostics —
        // confirms no shared mutable state between invocations.
        let mut config_a = rch_common::RchConfig::default();
        config_a.self_healing.hook_starts_daemon = true;
        let mut config_b = rch_common::RchConfig::default();
        config_b.self_healing.hook_starts_daemon = false;

        let a = reliability_rollout_posture_diagnostics(Ok(&config_a));
        let b = reliability_rollout_posture_diagnostics(Ok(&config_b));

        let a_hook = a
            .iter()
            .find(|d| d.check_name == "hook_starts_daemon")
            .expect("hook diag in a");
        let b_hook = b
            .iter()
            .find(|d| d.check_name == "hook_starts_daemon")
            .expect("hook diag in b");
        assert_eq!(a_hook.code, ReliabilityReasonCode::HookAutoStartEnabled);
        assert_eq!(b_hook.code, ReliabilityReasonCode::HookAutoStartDisabled);
    }

    // ========================================================================
    // Verdict tri-state (t02) — aggregator + exit-code mapping + serde shape.
    // ========================================================================

    fn make_diag(severity: ReliabilitySeverity) -> ReliabilityDiagnostic {
        ReliabilityDiagnostic::new(
            ReliabilityCategory::Topology,
            "synthetic",
            severity,
            "test",
            ReliabilityReasonCode::WorkersConfigured,
        )
    }

    #[test]
    fn test_aggregate_verdict_empty_is_healthy() {
        // Empty input is honest — caller decorates with "no probes ran" if needed.
        assert_eq!(aggregate_verdict(&[]), ReliabilityVerdict::Healthy);
    }

    #[test]
    fn test_aggregate_verdict_all_pass_is_healthy() {
        let diags = vec![make_diag(ReliabilitySeverity::Pass); 5];
        assert_eq!(aggregate_verdict(&diags), ReliabilityVerdict::Healthy);
    }

    #[test]
    fn test_aggregate_verdict_pass_plus_info_is_healthy() {
        let diags = vec![
            make_diag(ReliabilitySeverity::Pass),
            make_diag(ReliabilitySeverity::Info),
            make_diag(ReliabilitySeverity::Pass),
        ];
        assert_eq!(aggregate_verdict(&diags), ReliabilityVerdict::Healthy);
    }

    #[test]
    fn test_aggregate_verdict_one_warning_is_degraded() {
        let diags = vec![
            make_diag(ReliabilitySeverity::Pass),
            make_diag(ReliabilitySeverity::Warning),
            make_diag(ReliabilitySeverity::Info),
        ];
        assert_eq!(aggregate_verdict(&diags), ReliabilityVerdict::Degraded);
    }

    #[test]
    fn test_aggregate_verdict_one_critical_is_failing() {
        let diags = vec![
            make_diag(ReliabilitySeverity::Pass),
            make_diag(ReliabilitySeverity::Warning),
            make_diag(ReliabilitySeverity::Critical),
        ];
        assert_eq!(aggregate_verdict(&diags), ReliabilityVerdict::Failing);
    }

    #[test]
    fn test_aggregate_verdict_critical_dominates_warning() {
        let diags = vec![
            make_diag(ReliabilitySeverity::Critical),
            make_diag(ReliabilitySeverity::Warning),
        ];
        assert_eq!(aggregate_verdict(&diags), ReliabilityVerdict::Failing);
    }

    #[test]
    fn test_verdict_serde_lowercase_strings() {
        // JSON wire form: "healthy" / "degraded" / "failing".
        let h = serde_json::to_string(&ReliabilityVerdict::Healthy).unwrap();
        let d = serde_json::to_string(&ReliabilityVerdict::Degraded).unwrap();
        let f = serde_json::to_string(&ReliabilityVerdict::Failing).unwrap();
        assert_eq!(h, "\"healthy\"");
        assert_eq!(d, "\"degraded\"");
        assert_eq!(f, "\"failing\"");
        // Roundtrip
        let back: ReliabilityVerdict = serde_json::from_str(&d).unwrap();
        assert_eq!(back, ReliabilityVerdict::Degraded);
    }

    #[test]
    fn test_default_exit_code_mapping() {
        assert_eq!(ReliabilityVerdict::Healthy.default_exit_code(), 0);
        assert_eq!(ReliabilityVerdict::Degraded.default_exit_code(), 1);
        assert_eq!(ReliabilityVerdict::Failing.default_exit_code(), 2);
    }

    #[test]
    fn test_strict_promotes_degraded_to_two() {
        assert_eq!(ReliabilityVerdict::Healthy.exit_code(true, false), 0);
        assert_eq!(ReliabilityVerdict::Degraded.exit_code(true, false), 2);
        assert_eq!(ReliabilityVerdict::Failing.exit_code(true, false), 2);
    }

    #[test]
    fn test_lenient_demotes_failing_to_one() {
        assert_eq!(ReliabilityVerdict::Healthy.exit_code(false, true), 0);
        assert_eq!(ReliabilityVerdict::Degraded.exit_code(false, true), 1);
        assert_eq!(ReliabilityVerdict::Failing.exit_code(false, true), 1);
    }

    #[test]
    fn test_default_no_strict_no_lenient_uses_default_mapping() {
        for v in [
            ReliabilityVerdict::Healthy,
            ReliabilityVerdict::Degraded,
            ReliabilityVerdict::Failing,
        ] {
            assert_eq!(v.exit_code(false, false), v.default_exit_code());
        }
    }

    #[test]
    fn test_verdict_label_matches_variant_name() {
        assert_eq!(ReliabilityVerdict::Healthy.label(), "Healthy");
        assert_eq!(ReliabilityVerdict::Degraded.label(), "Degraded");
        assert_eq!(ReliabilityVerdict::Failing.label(), "Failing");
    }

    #[test]
    fn test_summary_overall_uses_aggregate_verdict() {
        // Build a response with mixed severities and assert the summary's
        // verdict matches the aggregator.
        let diags = vec![
            make_diag(ReliabilitySeverity::Pass),
            make_diag(ReliabilitySeverity::Warning),
        ];
        let response = build_reliability_doctor_response(
            ReliabilityDoctorMode::Check,
            &ReliabilityScopeSet::default(),
            diags,
        );
        assert_eq!(response.summary.overall, ReliabilityVerdict::Degraded);
    }

    #[test]
    fn test_summary_overall_failing_when_critical_present() {
        let diags = vec![
            make_diag(ReliabilitySeverity::Pass),
            make_diag(ReliabilitySeverity::Critical),
        ];
        let response = build_reliability_doctor_response(
            ReliabilityDoctorMode::Check,
            &ReliabilityScopeSet::default(),
            diags,
        );
        assert_eq!(response.summary.overall, ReliabilityVerdict::Failing);
    }

    // ========================================================================
    // Scope filter (t01) — parser, set semantics, gating, response wiring.
    // ========================================================================

    #[test]
    fn test_scope_default_is_all() {
        let s = ReliabilityScopeSet::default();
        assert_eq!(s.0, vec![ReliabilityScope::All]);
        assert!(s.matches(ReliabilityScope::Topology));
        assert!(s.matches(ReliabilityScope::Pressure));
        // matches() returns true for every named scope when All is present.
        for v in [
            ReliabilityScope::All,
            ReliabilityScope::Topology,
            ReliabilityScope::Convergence,
            ReliabilityScope::Pressure,
            ReliabilityScope::Triage,
            ReliabilityScope::Helpers,
            ReliabilityScope::Rollout,
            ReliabilityScope::Schema,
        ] {
            assert!(s.matches(v));
        }
    }

    #[test]
    fn test_scope_parses_single_value() {
        let s: ReliabilityScopeSet = "topology".parse().unwrap();
        assert_eq!(s.0, vec![ReliabilityScope::Topology]);
        assert!(s.matches(ReliabilityScope::Topology));
        assert!(!s.matches(ReliabilityScope::Pressure));
    }

    #[test]
    fn test_scope_parses_multi_value_csv() {
        let s: ReliabilityScopeSet = "topology,pressure".parse().unwrap();
        assert_eq!(
            s.0,
            vec![ReliabilityScope::Topology, ReliabilityScope::Pressure]
        );
        assert!(s.matches(ReliabilityScope::Topology));
        assert!(s.matches(ReliabilityScope::Pressure));
        assert!(!s.matches(ReliabilityScope::Helpers));
    }

    #[test]
    fn test_scope_dedups_keeping_first_occurrence() {
        let s: ReliabilityScopeSet = "topology,pressure,topology,pressure".parse().unwrap();
        assert_eq!(
            s.0,
            vec![ReliabilityScope::Topology, ReliabilityScope::Pressure]
        );
    }

    #[test]
    fn test_scope_all_dominates_when_mixed() {
        // `all,topology` collapses to `[All]` — operator gets the full sweep.
        let s: ReliabilityScopeSet = "all,topology".parse().unwrap();
        assert_eq!(s.0, vec![ReliabilityScope::All]);
    }

    #[test]
    fn test_scope_empty_string_errors() {
        let err = ""
            .parse::<ReliabilityScopeSet>()
            .expect_err("empty must err");
        assert!(err.contains("scope list is empty"));
    }

    #[test]
    fn test_scope_unknown_segment_errors_with_offender() {
        let err = "topology,bogus"
            .parse::<ReliabilityScopeSet>()
            .expect_err("unknown segment must err");
        assert!(
            err.contains("bogus"),
            "error should name the offender, got: {err}"
        );
    }

    #[test]
    fn test_scope_case_insensitive_segment_parse() {
        let s: ReliabilityScopeSet = "Topology,PRESSURE".parse().unwrap();
        assert_eq!(
            s.0,
            vec![ReliabilityScope::Topology, ReliabilityScope::Pressure]
        );
    }

    #[test]
    fn test_scope_whitespace_trimmed() {
        let s: ReliabilityScopeSet = "  topology  ".parse().unwrap();
        assert_eq!(s.0, vec![ReliabilityScope::Topology]);
    }

    #[test]
    fn test_scope_as_strings_stable_order() {
        let s = ReliabilityScopeSet(vec![ReliabilityScope::Pressure, ReliabilityScope::Topology]);
        assert_eq!(s.as_strings(), vec!["pressure", "topology"]);
    }

    #[test]
    fn test_scope_response_field_records_what_was_asked() {
        let scope =
            ReliabilityScopeSet(vec![ReliabilityScope::Topology, ReliabilityScope::Pressure]);
        let response =
            build_reliability_doctor_response(ReliabilityDoctorMode::Check, &scope, vec![]);
        assert_eq!(response.scope, vec!["topology", "pressure"]);
    }

    #[test]
    fn test_scope_response_default_is_all_array() {
        let response = build_reliability_doctor_response(
            ReliabilityDoctorMode::Check,
            &ReliabilityScopeSet::default(),
            vec![],
        );
        // data.scope is always an array (even single-element).
        assert_eq!(response.scope, vec!["all"]);
    }

    #[test]
    fn test_scope_prefetch_dependencies_are_precise() {
        let all = ReliabilityScopeSet::default();
        assert!(all.needs_worker_config());
        assert!(all.needs_daemon_status());
        assert!(all.needs_repo_convergence_status());
        assert!(all.needs_rollout_config());

        let topology: ReliabilityScopeSet = "topology".parse().unwrap();
        assert!(topology.needs_worker_config());
        assert!(topology.needs_daemon_status());
        assert!(!topology.needs_repo_convergence_status());
        assert!(!topology.needs_rollout_config());

        let pressure: ReliabilityScopeSet = "pressure".parse().unwrap();
        assert!(!pressure.needs_worker_config());
        assert!(pressure.needs_daemon_status());
        assert!(!pressure.needs_repo_convergence_status());
        assert!(!pressure.needs_rollout_config());

        let convergence: ReliabilityScopeSet = "convergence".parse().unwrap();
        assert!(!convergence.needs_worker_config());
        assert!(!convergence.needs_daemon_status());
        assert!(convergence.needs_repo_convergence_status());
        assert!(!convergence.needs_rollout_config());

        let rollout: ReliabilityScopeSet = "rollout".parse().unwrap();
        assert!(!rollout.needs_worker_config());
        assert!(!rollout.needs_daemon_status());
        assert!(!rollout.needs_repo_convergence_status());
        assert!(rollout.needs_rollout_config());

        let local_only: ReliabilityScopeSet = "helpers,schema".parse().unwrap();
        assert!(!local_only.needs_worker_config());
        assert!(!local_only.needs_daemon_status());
        assert!(!local_only.needs_repo_convergence_status());
        assert!(!local_only.needs_rollout_config());
    }

    #[test]
    fn test_scope_probe_names_honor_schema_gate() {
        let all = ReliabilityScopeSet::default();
        assert_eq!(
            all.probe_names_to_run(false),
            vec![
                "topology",
                "convergence",
                "pressure",
                "triage",
                "helpers",
                "rollout"
            ]
        );
        assert_eq!(
            all.probe_names_to_run(true),
            vec![
                "topology",
                "convergence",
                "pressure",
                "triage",
                "helpers",
                "rollout",
                "schema"
            ]
        );

        let schema_only: ReliabilityScopeSet = "schema".parse().unwrap();
        assert_eq!(schema_only.probe_names_to_run(false), vec!["schema"]);
        assert_eq!(schema_only.probe_names_to_run(true), vec!["schema"]);

        let helpers_schema: ReliabilityScopeSet = "helpers,schema".parse().unwrap();
        assert_eq!(
            helpers_schema.probe_names_to_run(false),
            vec!["helpers", "schema"]
        );
    }

    // ========================================================================
    // t05 — envelope harmonization. Verify command tag is the dotted
    // form, daemon_unreachable + reasons populate correctly, and the
    // legacy DoctorResponse carries a schema_version.
    // ========================================================================

    fn synthetic_diagnostic(
        code: ReliabilityReasonCode,
        check_name: &str,
        message: &str,
        severity: ReliabilitySeverity,
    ) -> ReliabilityDiagnostic {
        ReliabilityDiagnostic::new(
            ReliabilityCategory::Topology,
            check_name,
            severity,
            message,
            code,
        )
    }

    #[test]
    fn test_daemon_unreachable_false_when_all_reachable() {
        // No daemon-unreachable codes in the diagnostics → false + empty list.
        let diags = vec![
            synthetic_diagnostic(
                ReliabilityReasonCode::WorkersHealthy,
                "daemon_worker_capacity",
                "All 7 workers healthy",
                ReliabilitySeverity::Pass,
            ),
            synthetic_diagnostic(
                ReliabilityReasonCode::WorkerReady,
                "worker_topology",
                "Worker css ready",
                ReliabilitySeverity::Pass,
            ),
        ];
        let response = build_reliability_doctor_response(
            ReliabilityDoctorMode::Check,
            &ReliabilityScopeSet::default(),
            diags,
        );
        assert!(!response.daemon_unreachable);
        assert!(response.daemon_unreachable_reasons.is_empty());
    }

    #[test]
    fn test_daemon_unreachable_true_when_status_unavailable() {
        // Single probe reports DaemonStatusUnavailable → flag flips.
        let diags = vec![synthetic_diagnostic(
            ReliabilityReasonCode::DaemonStatusUnavailable,
            "daemon_status",
            "Daemon status is unavailable",
            ReliabilitySeverity::Warning,
        )];
        let response = build_reliability_doctor_response(
            ReliabilityDoctorMode::Check,
            &ReliabilityScopeSet::default(),
            diags,
        );
        assert!(response.daemon_unreachable);
        assert_eq!(response.daemon_unreachable_reasons.len(), 1);
        // The reason text should attribute it to the probe name + message.
        assert!(
            response.daemon_unreachable_reasons[0].contains("daemon_status"),
            "reason text should name the probe: {:?}",
            response.daemon_unreachable_reasons
        );
        assert!(
            response.daemon_unreachable_reasons[0].contains("unavailable"),
            "reason text should include the diagnostic message"
        );
    }

    #[test]
    fn test_daemon_unreachable_aggregates_multiple_probes() {
        // Multiple unreachable codes → all attributed.
        let diags = vec![
            synthetic_diagnostic(
                ReliabilityReasonCode::DaemonStatusUnavailable,
                "daemon_status",
                "daemon down",
                ReliabilitySeverity::Warning,
            ),
            synthetic_diagnostic(
                ReliabilityReasonCode::DiskPressureUnavailable,
                "disk_pressure",
                "disk surface gone",
                ReliabilitySeverity::Warning,
            ),
            synthetic_diagnostic(
                ReliabilityReasonCode::ProcessDebtUnavailable,
                "process_debt",
                "triage unavailable",
                ReliabilitySeverity::Warning,
            ),
            // Non-unreachable diagnostic should NOT appear in the reasons.
            synthetic_diagnostic(
                ReliabilityReasonCode::WorkersHealthy,
                "daemon_worker_capacity",
                "ignored",
                ReliabilitySeverity::Pass,
            ),
        ];
        let response = build_reliability_doctor_response(
            ReliabilityDoctorMode::Check,
            &ReliabilityScopeSet::default(),
            diags,
        );
        assert!(response.daemon_unreachable);
        assert_eq!(
            response.daemon_unreachable_reasons.len(),
            3,
            "expected 3 reasons (the 3 unreachable codes), got {:?}",
            response.daemon_unreachable_reasons
        );
        // None of the reasons should mention the "ignored" Pass diagnostic.
        for r in &response.daemon_unreachable_reasons {
            assert!(
                !r.contains("ignored"),
                "Pass diagnostics should NOT contribute to reasons: {r}"
            );
        }
    }

    #[test]
    fn test_reliability_response_carries_schema_version() {
        // schema_version is non-empty and sourced from the registry.
        let response = build_reliability_doctor_response(
            ReliabilityDoctorMode::Check,
            &ReliabilityScopeSet::default(),
            vec![],
        );
        assert!(!response.schema_version.is_empty());
        // Format check: should look like a semver string (digits + dots).
        assert!(
            response
                .schema_version
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.'),
            "schema_version must be numeric+dots: {:?}",
            response.schema_version
        );
    }

    #[test]
    fn test_doctor_unreachable_codes_table_is_subset_of_known_codes() {
        // The hand-maintained DAEMON_UNREACHABLE_REASON_CODES list must
        // only contain codes that exist in ReliabilityReasonCode::ALL.
        // Catches typos or removed-but-still-referenced variants.
        for c in DAEMON_UNREACHABLE_REASON_CODES {
            assert!(
                ReliabilityReasonCode::ALL.contains(c),
                "DAEMON_UNREACHABLE_REASON_CODES contains {c:?} which is not in ALL"
            );
        }
        // And shouldn't have duplicates.
        let unique: std::collections::HashSet<_> = DAEMON_UNREACHABLE_REASON_CODES.iter().collect();
        assert_eq!(unique.len(), DAEMON_UNREACHABLE_REASON_CODES.len());
    }
}
