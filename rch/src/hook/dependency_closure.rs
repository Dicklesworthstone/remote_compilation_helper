//! Dependency-closure sync planning and remote dependency preflight for the hook.
//!
//! This submodule owns the planning + verification layer that sits *between*
//! command classification and the remote-build pipeline (`transfer_orchestration`),
//! extracted from `hook.rs` per bead `remote_compilation_helper-zcecy.14`:
//!
//! - **Sync-closure planning** — given the dependency sync roots resolved by the
//!   runtime planner, [`build_sync_closure_plan`] canonicalizes each root against
//!   the worker path-topology policy, filters out-of-topology roots, dedupes
//!   aliases, and orders the plan deterministically; [`build_sync_closure_manifest`]
//!   renders the plan as a serializable [`SyncClosureManifest`]. [`merge_sync_result`]
//!   folds the per-root [`SyncResult`]s that `transfer_orchestration` accumulates.
//! - **Sync-topology predicates** — `effective_sync_topology_roots` /
//!   [`is_within_sync_topology`] / `map_sync_root_to_remote_root` encode the
//!   `/data/projects` + `/dp` canonical-root conventions.
//! - **Dependency preflight** — once the closure is synced,
//!   [`verify_remote_dependency_manifests`] probes each remote root over SSH (via
//!   the sibling `ssh` submodule's `run_offload_ssh_command`) to confirm every
//!   required `Cargo.toml` plus source entrypoint exists remotely, producing a
//!   [`DependencyPreflightReport`]; a failed verification surfaces as a
//!   [`DependencyPreflightFailure`] that forces a local fallback. The cargo
//!   manifest/workspace parsers (`cargo_package_source_entrypoints`,
//!   `cargo_workspace_member_source_entrypoints`, …) compute the required-path
//!   set from each package's `Cargo.toml`.
//!
//! It reaches its support layer from the parent via `use super::*` (the
//! path-topology types, `WorkerConfig` / `HookReporter`, and the `rch_common`
//! types/consts) and the offload SSH primitives from the sibling `ssh` submodule.
//! Symbols consumed by the parent (`build_dependency_runtime_fail_open_report` and
//! the error downcasts in `run_hook` / `run_exec`) and by the sibling
//! `transfer_orchestration` are `pub(super)`; the manifest/probe parsers and the
//! status/evidence helpers stay private. The cluster's unit tests remain in
//! `hook::tests` and reach the test-only items through an explicit
//! `use super::dependency_closure::{…}` (matching the sibling-import convention),
//! while the preflight types/consts that `hook` itself re-exports arrive via the
//! test module's `use super::*`.

use super::ssh::{run_offload_ssh_command, should_skip_remote_preflight};
use super::*;

pub(super) fn merge_sync_result(base: &SyncResult, extra: &SyncResult) -> SyncResult {
    SyncResult {
        bytes_transferred: base
            .bytes_transferred
            .saturating_add(extra.bytes_transferred),
        files_transferred: base
            .files_transferred
            .saturating_add(extra.files_transferred),
        duration_ms: base.duration_ms.saturating_add(extra.duration_ms),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SyncClosurePlanEntry {
    pub(super) local_root: PathBuf,
    pub(super) remote_root: String,
    pub(super) project_id: String,
    pub(super) root_hash: String,
    pub(super) is_primary: bool,
    pub(super) mode: SyncClosureMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SyncClosureMode {
    Full,
    WorkspaceMetadata,
}

/// Outcome of syncing a single closure root during multi-root transfer.
///
/// Used to collect per-root results and enable partial failure diagnostics
/// instead of aborting the entire sync on the first dependency root failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SyncRootOutcome {
    /// Root synced successfully.
    Synced,
    /// Dependency root sync was skipped (transfer estimation indicated skip).
    Skipped { reason: String },
    /// Dependency root sync failed (non-fatal for non-primary roots).
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SyncClosureManifest {
    pub(super) schema_version: &'static str,
    pub(super) generated_at_unix_ms: i64,
    pub(super) project_root: String,
    pub(super) entries: Vec<SyncClosureManifestEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SyncClosureManifestEntry {
    pub(super) order: usize,
    pub(super) local_root: String,
    pub(super) remote_root: String,
    pub(super) project_id: String,
    pub(super) root_hash: String,
    pub(super) is_primary: bool,
    mode: SyncClosureMode,
}

pub(super) const DEPENDENCY_PREFLIGHT_SCHEMA_VERSION: &str = "rch.dependency_preflight.v1";
const DEPENDENCY_PREFLIGHT_CODE_PRESENT: &str = "RCH-I410";
pub(super) const DEPENDENCY_PREFLIGHT_CODE_MISSING: &str = "RCH-E410";
pub(super) const DEPENDENCY_PREFLIGHT_CODE_STALE: &str = "RCH-E411";
pub(super) const DEPENDENCY_PREFLIGHT_CODE_UNKNOWN: &str = "RCH-E412";
pub(super) const DEPENDENCY_PREFLIGHT_CODE_POLICY: &str = "RCH-E413";
pub(super) const DEPENDENCY_PREFLIGHT_CODE_TIMEOUT: &str = "RCH-E414";
pub(super) const DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING: &str = "Ensure every dependency root in the closure is synced and Cargo.toml plus required source entrypoints exist remotely.";
pub(super) const DEPENDENCY_PREFLIGHT_REMEDIATION_STALE: &str = "One or more dependency roots were not refreshed; rerun after successful sync of skipped roots.";
pub(super) const DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN: &str =
    "Dependency verification could not determine remote state; inspect sync/SSH logs and retry.";
pub(super) const DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY: &str = "Path dependency topology policy failed; move dependencies under /data/projects (or /dp) and retry.";
pub(super) const DEPENDENCY_PREFLIGHT_REMEDIATION_TIMEOUT: &str = "Dependency planner timed out; rerun after system load decreases or investigate cargo metadata latency.";
pub(super) const DEPENDENCY_PREFLIGHT_PROBE_BATCH_SIZE: usize = 128;
const WORKSPACE_METADATA_SYNC_PATTERNS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain",
    "rust-toolchain.toml",
    ".cargo/",
    ".cargo/**",
];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum DependencyPreflightStatus {
    Present,
    Missing,
    Stale,
    PolicyViolation,
    Timeout,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct DependencyPreflightEvidence {
    pub(super) root: String,
    pub(super) manifest: String,
    pub(super) required_path: String,
    pub(super) required_kind: &'static str,
    pub(super) status: DependencyPreflightStatus,
    pub(super) reason_code: &'static str,
    pub(super) detail: String,
    pub(super) is_primary: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct DependencyPreflightReport {
    pub(super) schema_version: &'static str,
    pub(super) worker: String,
    pub(super) verified: bool,
    pub(super) reason_code: Option<&'static str>,
    pub(super) remediation: Option<&'static str>,
    pub(super) evidence: Vec<DependencyPreflightEvidence>,
}

#[derive(Debug, thiserror::Error)]
#[error("dependency preflight verification failed [{reason_code}]")]
pub(super) struct DependencyPreflightFailure {
    pub(super) reason_code: &'static str,
    pub(super) remediation: &'static str,
    report: DependencyPreflightReport,
}

impl DependencyPreflightFailure {
    pub(super) fn from_report(report: DependencyPreflightReport) -> Self {
        let reason_code = report
            .reason_code
            .unwrap_or(DEPENDENCY_PREFLIGHT_CODE_UNKNOWN);
        let remediation = report
            .remediation
            .unwrap_or(DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN);
        Self {
            reason_code,
            remediation,
            report,
        }
    }

    pub(super) fn report_json(&self) -> String {
        serde_json::to_string(&self.report).unwrap_or_else(|err| {
            format!(
                "{{\"schema_version\":\"{}\",\"verified\":false,\"reason_code\":\"{}\",\"serialization_error\":\"{}\"}}",
                DEPENDENCY_PREFLIGHT_SCHEMA_VERSION, self.reason_code, err
            )
        })
    }

    pub(super) fn evidence_summary(&self) -> String {
        dependency_preflight_evidence_summary(&self.report.evidence)
    }
}

fn dependency_preflight_status_label(status: DependencyPreflightStatus) -> &'static str {
    match status {
        DependencyPreflightStatus::Present => "present",
        DependencyPreflightStatus::Missing => "missing",
        DependencyPreflightStatus::Stale => "stale",
        DependencyPreflightStatus::PolicyViolation => "policy_violation",
        DependencyPreflightStatus::Timeout => "timeout",
        DependencyPreflightStatus::Unknown => "unknown",
    }
}

fn dependency_preflight_evidence_summary(evidence: &[DependencyPreflightEvidence]) -> String {
    let selected = evidence
        .iter()
        .find(|item| item.status != DependencyPreflightStatus::Present)
        .or_else(|| evidence.first());

    match selected {
        Some(item) => format!(
            "{} {} {}: {}",
            dependency_preflight_status_label(item.status),
            item.required_kind,
            item.required_path,
            item.detail
        ),
        None => "no dependency preflight evidence rows".to_string(),
    }
}

pub(super) fn parse_dependency_preflight_probe_output(
    stdout: &str,
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
) {
    let mut present = std::collections::BTreeSet::new();
    let mut missing = std::collections::BTreeSet::new();

    for line in stdout.lines() {
        if let Some(path) = line.strip_prefix("RCH_DEP_PRESENT:") {
            present.insert(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("RCH_DEP_MISSING:") {
            missing.insert(path.trim().to_string());
        }
    }

    (present, missing)
}

fn dependency_preflight_failure_reason(
    evidence: &[DependencyPreflightEvidence],
) -> Option<(&'static str, &'static str)> {
    // For Cargo dependency-closure builds, every synchronized root must reflect
    // the current local state. Proceeding when any non-primary dependency root
    // is stale or missing can silently compile against an older sibling checkout
    // on the worker, which is worse than falling back to a local build.
    if evidence
        .iter()
        .any(|item| item.status == DependencyPreflightStatus::Missing)
    {
        return Some((
            DEPENDENCY_PREFLIGHT_CODE_MISSING,
            DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING,
        ));
    }
    if evidence
        .iter()
        .any(|item| item.status == DependencyPreflightStatus::Stale)
    {
        return Some((
            DEPENDENCY_PREFLIGHT_CODE_STALE,
            DEPENDENCY_PREFLIGHT_REMEDIATION_STALE,
        ));
    }
    if evidence
        .iter()
        .any(|item| item.status == DependencyPreflightStatus::Unknown)
    {
        return Some((
            DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
            DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN,
        ));
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DependencyPreflightCheck {
    pub(super) root: String,
    pub(super) manifest: String,
    pub(super) required_path: String,
    pub(super) required_kind: &'static str,
    pub(super) is_primary: bool,
}

fn clean_relative_cargo_path(raw: &str) -> Option<PathBuf> {
    let path = Path::new(raw);
    if path.is_absolute() {
        return None;
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return None;
    }
    Some(path.to_path_buf())
}

fn table_path_value(table: &toml::Table, key: &str) -> Option<PathBuf> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .and_then(clean_relative_cargo_path)
}

fn target_array_paths(table: &toml::Table, key: &str) -> Vec<PathBuf> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
        .filter_map(|target| table_path_value(target, "path"))
        .collect()
}

fn table_string_array(table: &toml::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(str::to_string)
        .collect()
}

fn package_auto_discovery_enabled(table: &toml::Table, key: &str) -> bool {
    table
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get(key))
        .and_then(toml::Value::as_bool)
        .unwrap_or(true)
}

fn insert_existing_relative_entrypoint(
    paths: &mut std::collections::BTreeSet<PathBuf>,
    package_root: &Path,
    relative_path: impl Into<PathBuf>,
) {
    let relative_path = relative_path.into();
    if package_root.join(&relative_path).is_file() {
        paths.insert(relative_path);
    }
}

fn insert_auto_discovered_target_entrypoints(
    paths: &mut std::collections::BTreeSet<PathBuf>,
    package_root: &Path,
    relative_dir: &str,
) {
    let Ok(entries) = std::fs::read_dir(package_root.join(relative_dir)) else {
        return;
    };

    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let file_name = entry.file_name();
        if file_type.is_file() {
            if entry.path().extension().is_some_and(|ext| ext == "rs") {
                paths.insert(PathBuf::from(relative_dir).join(file_name));
            }
        } else if file_type.is_dir() {
            insert_existing_relative_entrypoint(
                paths,
                package_root,
                PathBuf::from(relative_dir).join(file_name).join("main.rs"),
            );
        }
    }
}

pub(super) fn cargo_package_source_entrypoints(package_root: &Path) -> Vec<PathBuf> {
    let manifest_path = package_root.join("Cargo.toml");
    let Ok(contents) = std::fs::read_to_string(&manifest_path) else {
        return Vec::new();
    };
    let Ok(table) = toml::from_str::<toml::Table>(&contents) else {
        return Vec::new();
    };
    if !table.contains_key("package") {
        return Vec::new();
    }

    let mut paths = std::collections::BTreeSet::<PathBuf>::new();

    if let Some(lib_path) = table
        .get("lib")
        .and_then(toml::Value::as_table)
        .and_then(|lib| table_path_value(lib, "path"))
    {
        paths.insert(lib_path);
    } else if package_auto_discovery_enabled(&table, "autolib") || table.contains_key("lib") {
        insert_existing_relative_entrypoint(&mut paths, package_root, "src/lib.rs");
    }

    if package_auto_discovery_enabled(&table, "autobins") {
        insert_existing_relative_entrypoint(&mut paths, package_root, "src/main.rs");
        insert_auto_discovered_target_entrypoints(&mut paths, package_root, "src/bin");
    }
    if package_auto_discovery_enabled(&table, "autoexamples") {
        insert_auto_discovered_target_entrypoints(&mut paths, package_root, "examples");
    }
    if package_auto_discovery_enabled(&table, "autotests") {
        insert_auto_discovered_target_entrypoints(&mut paths, package_root, "tests");
    }
    if package_auto_discovery_enabled(&table, "autobenches") {
        insert_auto_discovered_target_entrypoints(&mut paths, package_root, "benches");
    }

    for key in ["bin", "example", "test", "bench"] {
        paths.extend(target_array_paths(&table, key));
    }

    paths.into_iter().collect()
}

fn cargo_manifest_table(package_root: &Path) -> Option<toml::Table> {
    let manifest_path = package_root.join("Cargo.toml");
    let contents = std::fs::read_to_string(&manifest_path).ok()?;
    toml::from_str::<toml::Table>(&contents).ok()
}

fn has_glob_meta(pattern: &str) -> bool {
    pattern
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
}

fn path_slash_string(path: &Path) -> Option<String> {
    Some(
        path.to_str()?
            .trim_start_matches("./")
            .replace(std::path::MAIN_SEPARATOR, "/"),
    )
}

fn workspace_exclude_matches(relative_member: &Path, exclude_patterns: &[String]) -> bool {
    let Some(relative_member) = path_slash_string(relative_member) else {
        return false;
    };

    exclude_patterns.iter().any(|pattern| {
        let Some(pattern_path) = clean_relative_cargo_path(pattern) else {
            return false;
        };
        let Some(pattern_slash) = path_slash_string(&pattern_path) else {
            return false;
        };
        if has_glob_meta(&pattern_slash) {
            glob::Pattern::new(&pattern_slash)
                .map(|compiled| compiled.matches(&relative_member))
                .unwrap_or(false)
        } else {
            relative_member == pattern_slash
                || relative_member
                    .strip_prefix(&pattern_slash)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }
    })
}

fn workspace_member_manifest_paths(workspace_root: &Path) -> Vec<PathBuf> {
    let Some(table) = cargo_manifest_table(workspace_root) else {
        return Vec::new();
    };
    let Some(workspace) = table.get("workspace").and_then(toml::Value::as_table) else {
        return Vec::new();
    };

    let members = table_string_array(workspace, "members");
    let exclude_patterns = table_string_array(workspace, "exclude");
    let mut manifests = std::collections::BTreeSet::<PathBuf>::new();

    for member in members {
        let Some(member_path) = clean_relative_cargo_path(&member) else {
            continue;
        };
        if has_glob_meta(&member) {
            let glob_path = workspace_root.join(&member_path).join("Cargo.toml");
            let Some(glob_pattern) = glob_path.to_str() else {
                continue;
            };
            let Ok(entries) = glob::glob(glob_pattern) else {
                continue;
            };
            for entry in entries.flatten() {
                if !entry.is_file() {
                    continue;
                }
                let Ok(relative_manifest) = entry.strip_prefix(workspace_root) else {
                    continue;
                };
                let Some(relative_member) = relative_manifest.parent() else {
                    continue;
                };
                if !workspace_exclude_matches(relative_member, &exclude_patterns) {
                    manifests.insert(relative_manifest.to_path_buf());
                }
            }
        } else {
            let relative_manifest = member_path.join("Cargo.toml");
            if workspace_root.join(&relative_manifest).is_file()
                && !workspace_exclude_matches(&member_path, &exclude_patterns)
            {
                manifests.insert(relative_manifest);
            }
        }
    }

    manifests.into_iter().collect()
}

pub(super) fn cargo_workspace_member_source_entrypoints(workspace_root: &Path) -> Vec<PathBuf> {
    let mut paths = std::collections::BTreeSet::<PathBuf>::new();
    for manifest_path in workspace_member_manifest_paths(workspace_root) {
        paths.insert(manifest_path.clone());
        if let Some(member_root) = manifest_path.parent() {
            paths.extend(
                cargo_package_source_entrypoints(&workspace_root.join(member_root))
                    .into_iter()
                    .map(|entrypoint| member_root.join(entrypoint)),
            );
        }
    }

    paths.into_iter().collect()
}

pub(super) fn dependency_preflight_checks_for_entry(
    entry: &SyncClosurePlanEntry,
) -> Vec<DependencyPreflightCheck> {
    let remote_root = PathBuf::from(&entry.remote_root);
    let manifest = remote_root.join("Cargo.toml").to_string_lossy().to_string();
    let mut checks = Vec::new();
    checks.push(DependencyPreflightCheck {
        root: entry.remote_root.clone(),
        manifest: manifest.clone(),
        required_path: manifest.clone(),
        required_kind: "manifest",
        is_primary: entry.is_primary,
    });

    if entry.mode == SyncClosureMode::Full {
        checks.extend(
            cargo_package_source_entrypoints(&entry.local_root)
                .into_iter()
                .map(|relative_path| DependencyPreflightCheck {
                    root: entry.remote_root.clone(),
                    manifest: manifest.clone(),
                    required_path: remote_root
                        .join(relative_path)
                        .to_string_lossy()
                        .to_string(),
                    required_kind: "source_entrypoint",
                    is_primary: entry.is_primary,
                }),
        );
        checks.extend(
            cargo_workspace_member_source_entrypoints(&entry.local_root)
                .into_iter()
                .map(|relative_path| DependencyPreflightCheck {
                    root: entry.remote_root.clone(),
                    manifest: manifest.clone(),
                    required_path: remote_root
                        .join(relative_path)
                        .to_string_lossy()
                        .to_string(),
                    required_kind: "source_entrypoint",
                    is_primary: entry.is_primary,
                }),
        );
    }

    checks.sort_by(|left, right| {
        (&left.required_path, left.required_kind).cmp(&(&right.required_path, right.required_kind))
    });
    checks.dedup_by(|left, right| {
        left.required_path == right.required_path && left.required_kind == right.required_kind
    });
    checks
}

pub(super) fn synced_dependency_preflight_checks(
    root_outcomes: &[(SyncClosurePlanEntry, SyncRootOutcome)],
) -> Vec<DependencyPreflightCheck> {
    root_outcomes
        .iter()
        .filter(|(_, outcome)| matches!(outcome, SyncRootOutcome::Synced))
        .flat_map(|(entry, _)| dependency_preflight_checks_for_entry(entry))
        .collect()
}

pub(super) fn build_dependency_preflight_report(
    worker: &WorkerConfig,
    root_outcomes: &[(SyncClosurePlanEntry, SyncRootOutcome)],
    present_paths: &std::collections::BTreeSet<String>,
    missing_paths: &std::collections::BTreeSet<String>,
    probe_failure: Option<&str>,
) -> DependencyPreflightReport {
    let mut evidence = Vec::new();
    let mut unknown_probe_samples = std::collections::BTreeSet::<(String, &'static str)>::new();

    for (entry, outcome) in root_outcomes {
        for check in dependency_preflight_checks_for_entry(entry) {
            let (status, reason_code, detail) = match outcome {
                SyncRootOutcome::Synced => {
                    if missing_paths.contains(&check.required_path) {
                        let detail = match check.required_kind {
                            "manifest" => "required Cargo.toml is missing on remote worker",
                            "source_entrypoint" => {
                                "required package source entrypoint is missing on remote worker"
                            }
                            _ => "required dependency path is missing on remote worker",
                        };
                        (
                            DependencyPreflightStatus::Missing,
                            DEPENDENCY_PREFLIGHT_CODE_MISSING,
                            format!("{detail}: {}", check.required_path),
                        )
                    } else if present_paths.contains(&check.required_path) {
                        (
                            DependencyPreflightStatus::Present,
                            DEPENDENCY_PREFLIGHT_CODE_PRESENT,
                            format!(
                                "required {} present after current sync: {}",
                                check.required_kind, check.required_path
                            ),
                        )
                    } else {
                        let detail = probe_failure
                            .map(|failure| {
                                format!(
                                    "dependency probe unavailable for {} under {}; sample required_path={}; additional unreported paths for this root/kind share this failure; {}",
                                    check.required_kind,
                                    check.root,
                                    check.required_path,
                                    failure
                                )
                            })
                            .unwrap_or_else(|| {
                                format!(
                                    "probe output omitted status for synced required path: {}",
                                    check.required_path
                                )
                            });
                        (
                            DependencyPreflightStatus::Unknown,
                            DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
                            detail,
                        )
                    }
                }
                SyncRootOutcome::Skipped { reason } => (
                    DependencyPreflightStatus::Stale,
                    DEPENDENCY_PREFLIGHT_CODE_STALE,
                    format!(
                        "dependency root skipped before verification for {}: {}",
                        check.required_path, reason
                    ),
                ),
                SyncRootOutcome::Failed { error } => (
                    DependencyPreflightStatus::Unknown,
                    DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
                    format!(
                        "dependency root sync failed before verification for {}: {}",
                        check.required_path, error
                    ),
                ),
            };

            if probe_failure.is_some()
                && status == DependencyPreflightStatus::Unknown
                && matches!(outcome, SyncRootOutcome::Synced)
                && !unknown_probe_samples.insert((check.root.clone(), check.required_kind))
            {
                continue;
            }

            evidence.push(DependencyPreflightEvidence {
                root: check.root,
                manifest: check.manifest,
                required_path: check.required_path,
                required_kind: check.required_kind,
                status,
                reason_code,
                detail,
                is_primary: check.is_primary,
            });
        }
    }

    if evidence.is_empty() {
        for (entry, outcome) in root_outcomes {
            let manifest = PathBuf::from(&entry.remote_root)
                .join("Cargo.toml")
                .to_string_lossy()
                .to_string();
            let (status, reason_code, detail) = match outcome {
                SyncRootOutcome::Synced => (
                    DependencyPreflightStatus::Unknown,
                    DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
                    "dependency preflight had no required paths to verify".to_string(),
                ),
                SyncRootOutcome::Skipped { reason } => (
                    DependencyPreflightStatus::Stale,
                    DEPENDENCY_PREFLIGHT_CODE_STALE,
                    format!("dependency root skipped before verification: {}", reason),
                ),
                SyncRootOutcome::Failed { error } => (
                    DependencyPreflightStatus::Unknown,
                    DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
                    format!("dependency root sync failed before verification: {}", error),
                ),
            };
            evidence.push(DependencyPreflightEvidence {
                root: entry.remote_root.clone(),
                manifest: manifest.clone(),
                required_path: manifest,
                required_kind: "manifest",
                status,
                reason_code,
                detail,
                is_primary: entry.is_primary,
            });
        }
    }

    let (verified, reason_code, remediation) = match dependency_preflight_failure_reason(&evidence)
    {
        Some((reason_code, remediation)) => (false, Some(reason_code), Some(remediation)),
        None => (true, None, None),
    };

    DependencyPreflightReport {
        schema_version: DEPENDENCY_PREFLIGHT_SCHEMA_VERSION,
        worker: worker.id.as_str().to_string(),
        verified,
        reason_code,
        remediation,
        evidence,
    }
}

pub(super) fn canonicalize_sync_root_for_plan(root: &Path, policy: &PathTopologyPolicy) -> PathBuf {
    normalize_dependency_root_for_runtime(root, policy)
        .or_else(|| std::fs::canonicalize(root).ok())
        .unwrap_or_else(|| root.to_path_buf())
}

fn manifest_declares_workspace(manifest_path: &Path) -> bool {
    let Ok(contents) = std::fs::read_to_string(manifest_path) else {
        return false;
    };
    let Ok(table) = toml::from_str::<toml::Table>(&contents) else {
        return false;
    };
    table.contains_key("workspace")
}

fn enclosing_workspace_root_for_sync_root(
    root: &Path,
    policy: &PathTopologyPolicy,
) -> Option<PathBuf> {
    for candidate in root.ancestors() {
        if !is_within_sync_topology(candidate, policy) {
            break;
        }
        let manifest_path = candidate.join("Cargo.toml");
        if manifest_path.is_file() && manifest_declares_workspace(&manifest_path) {
            return (candidate != root).then(|| candidate.to_path_buf());
        }
    }

    None
}

pub(super) fn workspace_metadata_sync_patterns() -> Vec<String> {
    WORKSPACE_METADATA_SYNC_PATTERNS
        .iter()
        .map(|pattern| (*pattern).to_string())
        .collect()
}

fn effective_sync_topology_roots(policy: &PathTopologyPolicy) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    roots.push(policy.canonical_root().to_path_buf());
    roots.push(policy.alias_root().to_path_buf());

    if !policy.canonical_root().exists()
        && let Ok(alias_target) = std::fs::canonicalize(policy.alias_root())
    {
        roots.push(alias_target);
    }

    roots.sort();
    roots.dedup();
    roots
}

/// Returns `true` if `path` is within the allowed topology roots.
pub(super) fn is_within_sync_topology(path: &Path, policy: &PathTopologyPolicy) -> bool {
    effective_sync_topology_roots(policy)
        .into_iter()
        .any(|root| path.starts_with(&root))
}

fn map_sync_root_to_remote_root(path: &Path, policy: &PathTopologyPolicy) -> String {
    // The remote canonical root comes from the same policy the rest of the
    // hook uses, never the compile-time `DEFAULT_CANONICAL_PROJECT_ROOT`,
    // because hosts that don't ship `/data/projects` (which is most of them)
    // configure their own canonical via `~/.config/rch/config.toml` and
    // would otherwise see their `[path_topology]` setting silently ignored
    // for the sync-target translation step. See rch#15.
    let remote_root = policy.canonical_root();

    for root in effective_sync_topology_roots(policy) {
        if let Ok(relative) = path.strip_prefix(&root) {
            return remote_root.join(relative).to_string_lossy().to_string();
        }
    }

    path.to_string_lossy().to_string()
}

pub(super) fn build_sync_closure_plan(
    sync_roots: &[PathBuf],
    normalized_project_root: &Path,
    project_hash: &str,
    topology_policy: &PathTopologyPolicy,
) -> Vec<SyncClosurePlanEntry> {
    let mut ordered_entries = std::collections::BTreeSet::<(PathBuf, SyncClosureMode)>::new();
    for root in sync_roots {
        let canonicalized = canonicalize_sync_root_for_plan(root, topology_policy);
        if !is_within_sync_topology(&canonicalized, topology_policy) {
            warn!(
                "Dependency root {} (canonicalized: {}) is outside allowed topology ({} / {}); skipping from sync closure",
                root.display(),
                canonicalized.display(),
                topology_policy.canonical_root().display(),
                topology_policy.alias_root().display(),
            );
            continue;
        }
        ordered_entries.insert((canonicalized.clone(), SyncClosureMode::Full));
        if let Some(workspace_root) =
            enclosing_workspace_root_for_sync_root(&canonicalized, topology_policy)
        {
            ordered_entries.insert((workspace_root, SyncClosureMode::WorkspaceMetadata));
        }
    }

    let primary_root = canonicalize_sync_root_for_plan(normalized_project_root, topology_policy);
    ordered_entries.insert((primary_root.clone(), SyncClosureMode::Full));
    let full_roots: Vec<PathBuf> = ordered_entries
        .iter()
        .filter(|(_, mode)| *mode == SyncClosureMode::Full)
        .map(|(root, _)| root.clone())
        .collect();
    for root in full_roots {
        ordered_entries.remove(&(root, SyncClosureMode::WorkspaceMetadata));
    }

    ordered_entries
        .into_iter()
        .map(|(root, mode)| {
            let is_primary = root == primary_root && mode == SyncClosureMode::Full;
            let root_hash = if is_primary {
                project_hash.to_string()
            } else {
                compute_project_hash_with_dependency_roots_and_policy(&root, &[], topology_policy)
            };
            SyncClosurePlanEntry {
                remote_root: map_sync_root_to_remote_root(&root, topology_policy),
                project_id: project_id_from_path(&root),
                root_hash,
                is_primary,
                mode,
                local_root: root,
            }
        })
        .collect()
}

pub(super) fn build_sync_closure_manifest(
    plan: &[SyncClosurePlanEntry],
    normalized_project_root: &Path,
) -> SyncClosureManifest {
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default();
    let entries = plan
        .iter()
        .enumerate()
        .map(|(idx, entry)| SyncClosureManifestEntry {
            order: idx + 1,
            local_root: entry.local_root.to_string_lossy().to_string(),
            remote_root: entry.remote_root.clone(),
            project_id: entry.project_id.clone(),
            root_hash: entry.root_hash.clone(),
            is_primary: entry.is_primary,
            mode: entry.mode,
        })
        .collect();
    SyncClosureManifest {
        schema_version: "rch.sync_closure_manifest.v2",
        generated_at_unix_ms,
        project_root: normalized_project_root.to_string_lossy().to_string(),
        entries,
    }
}

pub(super) async fn verify_remote_dependency_manifests(
    worker: &WorkerConfig,
    root_outcomes: &[(SyncClosurePlanEntry, SyncRootOutcome)],
    reporter: &HookReporter,
) -> anyhow::Result<()> {
    if should_skip_remote_preflight(worker) {
        reporter.verbose("[RCH] remote dependency preflight skipped in mock mode");
        return Ok(());
    }
    if root_outcomes.is_empty() {
        return Ok(());
    }

    let synced_checks = synced_dependency_preflight_checks(root_outcomes);

    let mut present_paths = std::collections::BTreeSet::new();
    let mut missing_paths = std::collections::BTreeSet::new();
    let mut probe_failure: Option<String> = None;

    for verify_cmd in build_remote_dependency_preflight_commands(&synced_checks) {
        match run_offload_ssh_command(worker, &verify_cmd, Duration::from_secs(20)).await {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let (present, missing) = parse_dependency_preflight_probe_output(&stdout);
                let batch_had_missing = !missing.is_empty();
                present_paths.extend(present);
                missing_paths.extend(missing);
                if !output.status.success() && !batch_had_missing {
                    probe_failure = Some(format!(
                        "probe exited with status {:?}; stdout='{}'; stderr='{}'",
                        output.status.code(),
                        stdout,
                        stderr
                    ));
                }
            }
            Err(err) => {
                probe_failure = Some(err.to_string());
            }
        }
        if probe_failure.is_some() {
            break;
        }
    }

    let report = build_dependency_preflight_report(
        worker,
        root_outcomes,
        &present_paths,
        &missing_paths,
        probe_failure.as_deref(),
    );
    let report_json = serde_json::to_string(&report).unwrap_or_else(|err| {
        format!(
            "{{\"schema_version\":\"{}\",\"verified\":false,\"reason_code\":\"{}\",\"serialization_error\":\"{}\"}}",
            DEPENDENCY_PREFLIGHT_SCHEMA_VERSION, DEPENDENCY_PREFLIGHT_CODE_UNKNOWN, err
        )
    });
    reporter.verbose(&format!(
        "[RCH] dependency preflight report: {}",
        report_json
    ));
    if report.verified {
        reporter.verbose(&format!(
            "[RCH] remote dependency preflight verified {} roots on {}",
            report.evidence.len(),
            worker.id
        ));
        return Ok(());
    }

    let failure = DependencyPreflightFailure::from_report(report);
    let evidence_summary = failure.evidence_summary();
    warn!(
        "Remote dependency preflight blocked remote execution on {} [{}] remediation='{}' evidence='{}'",
        worker.id, failure.reason_code, failure.remediation, evidence_summary
    );
    reporter.verbose(&format!(
        "[RCH] dependency preflight remediation [{}]: {}",
        failure.reason_code, failure.remediation
    ));
    Err(failure.into())
}

pub(super) fn build_remote_dependency_preflight_command(
    checks: &[DependencyPreflightCheck],
) -> Option<String> {
    if checks.is_empty() {
        return None;
    }

    let commands = checks
        .iter()
        .map(|check| {
            let escaped = shell_escape::escape(check.required_path.clone().into());
            escaped.to_string()
        })
        .collect::<Vec<_>>()
        .join(" ");

    Some(format!(
        "missing=0; for required in {commands}; do if [ -f \"$required\" ]; then printf 'RCH_DEP_PRESENT:%s\\n' \"$required\"; else printf 'RCH_DEP_MISSING:%s\\n' \"$required\"; missing=1; fi; done; if [ \"$missing\" -ne 0 ]; then exit 43; fi; echo RCH_REMOTE_DEPENDENCIES_OK"
    ))
}

pub(super) fn build_remote_dependency_preflight_commands(
    checks: &[DependencyPreflightCheck],
) -> Vec<String> {
    checks
        .chunks(DEPENDENCY_PREFLIGHT_PROBE_BATCH_SIZE)
        .filter_map(build_remote_dependency_preflight_command)
        .collect()
}
