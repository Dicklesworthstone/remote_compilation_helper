//! E2E Test Harness Framework
//!
//! Provides infrastructure for running end-to-end tests including:
//! - Process lifecycle management (start/stop daemon, workers)
//! - Temporary directory and file management
//! - Command execution with output capture
//! - Assertions and matchers for test validation

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::logging::{
    LogLevel, LogSource, RELIABILITY_EVENT_SCHEMA_VERSION, ReliabilityContext,
    ReliabilityEventInput, ReliabilityPhase, TestLogger, TestLoggerBuilder,
};

/// Error type for test harness operations
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("Process failed to start: {0}")]
    ProcessStartFailed(String),

    #[error("Process exited with non-zero status: {0}")]
    ProcessFailed(i32),

    #[error("Process timed out after {0:?}")]
    Timeout(Duration),

    #[error("Process not found: {0}")]
    ProcessNotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Assertion failed: {0}")]
    AssertionFailed(String),

    #[error("Setup failed: {0}")]
    SetupFailed(String),

    #[error("Cleanup failed: {0}")]
    CleanupFailed(String),
}

/// Result type for harness operations
pub type HarnessResult<T> = Result<T, HarnessError>;

/// Information about a managed process
#[derive(Debug)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub started_at: Instant,
    child: Child,
}

impl ProcessInfo {
    /// Check if the process is still running
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Get the process exit status (non-blocking)
    pub fn try_exit_status(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    /// Kill the process
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }

    /// Wait for the process to exit
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.wait()
    }

    /// Take stdout for reading (can only be called once)
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }

    /// Take stderr for reading (can only be called once)
    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.stderr.take()
    }
}

/// Result of a command execution
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
}

impl CommandResult {
    /// Check if the command succeeded (exit code 0)
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    /// Check if stdout contains a pattern
    pub fn stdout_contains(&self, pattern: &str) -> bool {
        self.stdout.contains(pattern)
    }

    /// Check if stderr contains a pattern
    pub fn stderr_contains(&self, pattern: &str) -> bool {
        self.stderr.contains(pattern)
    }

    /// Get combined output (stdout + stderr)
    pub fn combined_output(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

/// Configuration for the test harness
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    /// Base temporary directory for test artifacts
    pub temp_dir: PathBuf,
    /// Default timeout for commands
    pub default_timeout: Duration,
    /// Whether to clean up temp files on success
    pub cleanup_on_success: bool,
    /// Whether to clean up temp files on failure
    pub cleanup_on_failure: bool,
    /// Path to the rch binary
    pub rch_binary: PathBuf,
    /// Path to the rchd binary
    pub rchd_binary: PathBuf,
    /// Path to the rch-wkr binary
    pub rch_wkr_binary: PathBuf,
    /// Environment variables to set for all processes
    pub env_vars: HashMap<String, String>,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        fn cargo_bin_exe(candidates: &[&str]) -> Option<PathBuf> {
            for candidate in candidates {
                let key = format!("CARGO_BIN_EXE_{candidate}");
                if let Ok(value) = std::env::var(&key) {
                    let trimmed = value.trim();
                    if !trimmed.is_empty() {
                        return Some(PathBuf::from(trimmed));
                    }
                }
            }
            None
        }

        // Find binaries in target/debug or target/release.
        //
        // NOTE: The harness spawns processes with `current_dir = test_dir`, so we must resolve
        // binary paths relative to the workspace root (not the per-test temp dir).
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
        let manifest_dir = manifest_dir.canonicalize().unwrap_or(manifest_dir);
        let workspace_root = manifest_dir
            .parent()
            .unwrap_or(manifest_dir.as_path())
            .to_path_buf();
        let cargo_target = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| workspace_root.join("target"));
        let cargo_target = if cargo_target.is_absolute() {
            cargo_target
        } else {
            workspace_root.join(cargo_target)
        };

        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };

        let default_bin_dir = cargo_target.join(profile);
        let bin_dir = if std::env::var("LLVM_PROFILE_FILE")
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        {
            let llvm_cov_dir = cargo_target.join("llvm-cov-target").join(profile);
            if llvm_cov_dir.is_dir() {
                llvm_cov_dir
            } else {
                default_bin_dir.clone()
            }
        } else {
            default_bin_dir.clone()
        };

        let mut env_vars = HashMap::new();
        if std::env::var("CI")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            env_vars.insert("RCH_MOCK_SSH".to_string(), "1".to_string());
        }

        Self {
            temp_dir: std::env::temp_dir().join("rch_e2e_tests"),
            default_timeout: Duration::from_secs(30),
            cleanup_on_success: true,
            cleanup_on_failure: false,
            rch_binary: cargo_bin_exe(&["rch"])
                .map(|path| {
                    if path.is_relative() {
                        workspace_root.join(path)
                    } else {
                        path
                    }
                })
                .unwrap_or_else(|| bin_dir.join("rch")),
            rchd_binary: cargo_bin_exe(&["rchd"])
                .map(|path| {
                    if path.is_relative() {
                        workspace_root.join(path)
                    } else {
                        path
                    }
                })
                .unwrap_or_else(|| bin_dir.join("rchd")),
            rch_wkr_binary: cargo_bin_exe(&["rch-wkr", "rch_wkr"])
                .map(|path| {
                    if path.is_relative() {
                        workspace_root.join(path)
                    } else {
                        path
                    }
                })
                .unwrap_or_else(|| bin_dir.join("rch-wkr")),
            env_vars,
        }
    }
}

/// Failure hooks that can be explicitly injected into reliability scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReliabilityFailureHook {
    NetworkCut,
    SyncTimeout,
    PartialUpdate,
    DaemonRestart,
}

impl std::fmt::Display for ReliabilityFailureHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::NetworkCut => "network_cut",
            Self::SyncTimeout => "sync_timeout",
            Self::PartialUpdate => "partial_update",
            Self::DaemonRestart => "daemon_restart",
        };
        write!(f, "{label}")
    }
}

/// Explicit allowlist for failure hooks. Hooks are denied unless enabled here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReliabilityFailureHookFlags {
    pub allow_network_cut: bool,
    pub allow_sync_timeout: bool,
    pub allow_partial_update: bool,
    pub allow_daemon_restart: bool,
}

impl ReliabilityFailureHookFlags {
    /// Enable all hooks for explicit high-risk test scenarios.
    pub fn allow_all() -> Self {
        Self {
            allow_network_cut: true,
            allow_sync_timeout: true,
            allow_partial_update: true,
            allow_daemon_restart: true,
        }
    }

    /// Returns true when the provided hook is explicitly enabled.
    pub fn allows(&self, hook: ReliabilityFailureHook) -> bool {
        match hook {
            ReliabilityFailureHook::NetworkCut => self.allow_network_cut,
            ReliabilityFailureHook::SyncTimeout => self.allow_sync_timeout,
            ReliabilityFailureHook::PartialUpdate => self.allow_partial_update,
            ReliabilityFailureHook::DaemonRestart => self.allow_daemon_restart,
        }
    }
}

fn default_required_success() -> bool {
    true
}

/// One deterministic lifecycle command invoked by the reliability scenario runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliabilityLifecycleCommand {
    pub name: String,
    pub program: String,
    pub args: Vec<String>,
    pub timeout_secs: Option<u64>,
    #[serde(default = "default_required_success")]
    pub required_success: bool,
    #[serde(default)]
    pub via_rch_exec: bool,
}

impl ReliabilityLifecycleCommand {
    /// Build a command with required-success semantics.
    pub fn new(
        name: impl Into<String>,
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            timeout_secs: None,
            required_success: true,
            via_rch_exec: false,
        }
    }

    /// Override timeout in seconds for this command.
    pub fn with_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = Some(timeout_secs);
        self
    }

    /// Marks this command optional; failures are logged but do not fail the scenario.
    pub fn optional(mut self) -> Self {
        self.required_success = false;
        self
    }

    /// Run command via `rch exec -- <program> <args...>`.
    pub fn via_rch_exec(mut self) -> Self {
        self.via_rch_exec = true;
        self
    }
}

/// Worker lifecycle hooks consumed by reliability scenario suites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReliabilityWorkerLifecycleHooks {
    pub pre_checks: Vec<ReliabilityLifecycleCommand>,
    pub remote_probes: Vec<ReliabilityLifecycleCommand>,
    pub post_checks: Vec<ReliabilityLifecycleCommand>,
    pub cleanup_verification: Vec<ReliabilityLifecycleCommand>,
}

/// Full reliability scenario definition used by the deterministic runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliabilityScenarioSpec {
    pub scenario_id: String,
    pub worker_id: Option<String>,
    pub repo_set: Vec<String>,
    pub pressure_state: Option<String>,
    pub triage_actions: Vec<String>,
    pub lifecycle: ReliabilityWorkerLifecycleHooks,
    pub execute_commands: Vec<ReliabilityLifecycleCommand>,
    pub requested_failure_hooks: Vec<ReliabilityFailureHook>,
    pub failure_hook_flags: ReliabilityFailureHookFlags,
}

impl ReliabilityScenarioSpec {
    /// Creates a new scenario with deterministic defaults.
    pub fn new(scenario_id: impl Into<String>) -> Self {
        Self {
            scenario_id: scenario_id.into(),
            worker_id: None,
            repo_set: Vec::new(),
            pressure_state: None,
            triage_actions: Vec::new(),
            lifecycle: ReliabilityWorkerLifecycleHooks::default(),
            execute_commands: Vec::new(),
            requested_failure_hooks: Vec::new(),
            failure_hook_flags: ReliabilityFailureHookFlags::default(),
        }
    }

    pub fn with_worker_id(mut self, worker_id: impl Into<String>) -> Self {
        self.worker_id = Some(worker_id.into());
        self
    }

    pub fn with_repo_set(mut self, repos: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.repo_set = repos.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_pressure_state(mut self, pressure_state: impl Into<String>) -> Self {
        self.pressure_state = Some(pressure_state.into());
        self
    }

    pub fn add_triage_action(mut self, action: impl Into<String>) -> Self {
        self.triage_actions.push(action.into());
        self
    }

    pub fn add_pre_check(mut self, command: ReliabilityLifecycleCommand) -> Self {
        self.lifecycle.pre_checks.push(command);
        self
    }

    pub fn add_remote_probe(mut self, command: ReliabilityLifecycleCommand) -> Self {
        self.lifecycle.remote_probes.push(command);
        self
    }

    pub fn add_post_check(mut self, command: ReliabilityLifecycleCommand) -> Self {
        self.lifecycle.post_checks.push(command);
        self
    }

    pub fn add_cleanup_verification(mut self, command: ReliabilityLifecycleCommand) -> Self {
        self.lifecycle.cleanup_verification.push(command);
        self
    }

    pub fn add_execute_command(mut self, command: ReliabilityLifecycleCommand) -> Self {
        self.execute_commands.push(command);
        self
    }

    pub fn request_failure_hook(mut self, hook: ReliabilityFailureHook) -> Self {
        self.requested_failure_hooks.push(hook);
        self
    }

    pub fn with_failure_hook_flags(mut self, flags: ReliabilityFailureHookFlags) -> Self {
        self.failure_hook_flags = flags;
        self
    }
}

/// Recorded result of one lifecycle command execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliabilityCommandRecord {
    pub phase: ReliabilityPhase,
    pub stage: String,
    pub command_name: String,
    pub invoked_program: String,
    pub invoked_args: Vec<String>,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub required_success: bool,
    pub succeeded: bool,
    pub artifact_paths: Vec<String>,
}

/// Replay-focused artifact index for one scenario run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliabilityScenarioReport {
    pub schema_version: String,
    pub scenario_id: String,
    pub phase_order: Vec<ReliabilityPhase>,
    pub activated_failure_hooks: Vec<ReliabilityFailureHook>,
    pub command_records: Vec<ReliabilityCommandRecord>,
    pub artifact_paths: Vec<String>,
    pub manifest_path: Option<PathBuf>,
}

impl ReliabilityScenarioReport {
    fn new(scenario_id: &str) -> Self {
        Self {
            schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
            scenario_id: scenario_id.to_string(),
            phase_order: Vec::new(),
            activated_failure_hooks: Vec::new(),
            command_records: Vec::new(),
            artifact_paths: Vec::new(),
            manifest_path: None,
        }
    }
}

/// Clean up stale sockets and test directories from previous test runs.
///
/// This function should be called during test harness setup to prevent
/// leftover sockets from causing connection failures in new tests.
///
/// # Arguments
/// * `base_dir` - The base directory containing test artifacts (e.g., `/tmp/rch_e2e_tests`)
/// * `max_age` - Maximum age of directories to keep (default: 1 hour)
pub fn cleanup_stale_test_artifacts(base_dir: &Path, max_age: Duration) {
    if !base_dir.exists() {
        return;
    }

    let now = std::time::SystemTime::now();
    let mut cleaned_sockets = 0;
    let mut cleaned_dirs = 0;

    // First pass: clean up stale sockets in all test directories
    if let Ok(entries) = std::fs::read_dir(base_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Check if the directory is old enough to clean
            let is_stale = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|modified| {
                    now.duration_since(modified)
                        .map(|age| age > max_age)
                        .unwrap_or(false)
                })
                .unwrap_or(false);

            // Clean up sockets in stale directories
            if is_stale {
                // Look for socket files
                if let Ok(dir_entries) = std::fs::read_dir(&path) {
                    for file_entry in dir_entries.flatten() {
                        let file_path = file_entry.path();
                        if file_path.extension().is_some_and(|e| e == "sock")
                            && std::fs::remove_file(&file_path).is_ok()
                        {
                            cleaned_sockets += 1;
                        }
                    }
                }

                // Try to remove the stale directory
                if std::fs::remove_dir_all(&path).is_ok() {
                    cleaned_dirs += 1;
                }
            }
        }
    }

    if cleaned_sockets > 0 || cleaned_dirs > 0 {
        eprintln!(
            "[e2e::harness] Pre-test cleanup: removed {} stale sockets, {} stale directories",
            cleaned_sockets, cleaned_dirs
        );
    }
}

/// E2E Test Harness for managing test execution
pub struct TestHarness {
    pub config: HarnessConfig,
    pub logger: TestLogger,
    test_dir: PathBuf,
    managed_processes: Arc<Mutex<HashMap<String, ProcessInfo>>>,
    created_files: Arc<Mutex<Vec<PathBuf>>>,
    created_dirs: Arc<Mutex<Vec<PathBuf>>>,
    test_passed: Arc<Mutex<bool>>,
}

impl TestHarness {
    /// Create a new test harness with the given configuration
    pub fn new(test_name: &str, config: HarnessConfig) -> HarnessResult<Self> {
        // Clean up stale artifacts from previous test runs (older than 1 hour)
        cleanup_stale_test_artifacts(&config.temp_dir, Duration::from_secs(3600));

        // Create unique test directory
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f");
        let test_dir =
            config
                .temp_dir
                .join(format!("{}_{}", test_name.replace("::", "_"), timestamp));

        std::fs::create_dir_all(&test_dir)?;

        // Create logger with log dir in test directory
        let logger = TestLoggerBuilder::new(test_name)
            .log_dir(test_dir.join("logs"))
            .build();

        logger.info(format!("Test harness initialized: {test_name}"));
        logger.debug(format!("Test directory: {}", test_dir.display()));
        logger.log_reliability_event(ReliabilityEventInput {
            level: LogLevel::Info,
            phase: ReliabilityPhase::Setup,
            scenario_id: test_name.to_string(),
            message: "Test harness initialized".to_string(),
            context: ReliabilityContext {
                worker_id: None,
                repo_set: vec![test_dir.display().to_string()],
                pressure_state: None,
                triage_actions: Vec::new(),
                decision_code: "HARNESS_INIT".to_string(),
                fallback_reason: None,
            },
            artifact_paths: Vec::new(),
        });

        Ok(Self {
            config,
            logger,
            test_dir,
            managed_processes: Arc::new(Mutex::new(HashMap::new())),
            created_files: Arc::new(Mutex::new(Vec::new())),
            created_dirs: Arc::new(Mutex::new(vec![])),
            test_passed: Arc::new(Mutex::new(false)),
        })
    }

    /// Create a harness with default configuration
    pub fn default_for_test(test_name: &str) -> HarnessResult<Self> {
        Self::new(test_name, HarnessConfig::default())
    }

    /// Get the test directory path
    pub fn test_dir(&self) -> &Path {
        &self.test_dir
    }

    /// Run a reliability scenario with deterministic setup/execute/verify/cleanup phases.
    ///
    /// This is the shared foundation consumed by scenario-specific suites (path dependencies,
    /// repo convergence, disk pressure, and process triage) so they can reuse one orchestration
    /// engine instead of bespoke scaffolding.
    pub fn run_reliability_scenario(
        &self,
        scenario: &ReliabilityScenarioSpec,
    ) -> HarnessResult<ReliabilityScenarioReport> {
        let mut report = ReliabilityScenarioReport::new(&scenario.scenario_id);
        let mut triage_actions = scenario.triage_actions.clone();

        report.phase_order.push(ReliabilityPhase::Setup);
        self.log_scenario_event(
            scenario,
            ReliabilityPhase::Setup,
            LogLevel::Info,
            "Reliability setup phase started",
            "SCENARIO_SETUP_START",
            &triage_actions,
            None,
            Vec::new(),
        );

        let setup_result: HarnessResult<()> = (|| {
            report.activated_failure_hooks =
                self.activate_failure_hooks(scenario, &mut report, &mut triage_actions)?;

            self.run_phase_lifecycle_commands(
                scenario,
                ReliabilityPhase::Setup,
                "pre_checks",
                &scenario.lifecycle.pre_checks,
                &mut report,
                &mut triage_actions,
            )
        })();

        if let Err(error) = setup_result.as_ref() {
            self.log_scenario_event(
                scenario,
                ReliabilityPhase::Setup,
                LogLevel::Error,
                format!("Reliability setup phase failed: {error}"),
                "SCENARIO_SETUP_FAIL",
                &triage_actions,
                Some(error.to_string()),
                Vec::new(),
            );
        } else {
            self.log_scenario_event(
                scenario,
                ReliabilityPhase::Setup,
                LogLevel::Info,
                "Reliability setup phase completed",
                "SCENARIO_SETUP_DONE",
                &triage_actions,
                None,
                Vec::new(),
            );
        }

        report.phase_order.push(ReliabilityPhase::Execute);
        let execute_result: HarnessResult<()> = if setup_result.is_ok() {
            self.log_scenario_event(
                scenario,
                ReliabilityPhase::Execute,
                LogLevel::Info,
                "Reliability execute phase started",
                "SCENARIO_EXECUTE_START",
                &triage_actions,
                None,
                Vec::new(),
            );

            let result = (|| {
                self.run_phase_lifecycle_commands(
                    scenario,
                    ReliabilityPhase::Execute,
                    "execute",
                    &scenario.execute_commands,
                    &mut report,
                    &mut triage_actions,
                )?;
                self.run_phase_lifecycle_commands(
                    scenario,
                    ReliabilityPhase::Execute,
                    "remote_probes",
                    &scenario.lifecycle.remote_probes,
                    &mut report,
                    &mut triage_actions,
                )
            })();

            if let Err(error) = result.as_ref() {
                self.log_scenario_event(
                    scenario,
                    ReliabilityPhase::Execute,
                    LogLevel::Error,
                    format!("Reliability execute phase failed: {error}"),
                    "SCENARIO_EXECUTE_FAIL",
                    &triage_actions,
                    Some(error.to_string()),
                    Vec::new(),
                );
            } else {
                self.log_scenario_event(
                    scenario,
                    ReliabilityPhase::Execute,
                    LogLevel::Info,
                    "Reliability execute phase completed",
                    "SCENARIO_EXECUTE_DONE",
                    &triage_actions,
                    None,
                    Vec::new(),
                );
            }

            result
        } else {
            self.log_scenario_event(
                scenario,
                ReliabilityPhase::Execute,
                LogLevel::Warn,
                "Reliability execute phase skipped due setup failure",
                "SCENARIO_EXECUTE_SKIPPED",
                &triage_actions,
                Some("setup phase failed".to_string()),
                Vec::new(),
            );
            Ok(())
        };

        report.phase_order.push(ReliabilityPhase::Verify);
        let verify_result: HarnessResult<()> = if setup_result.is_ok() && execute_result.is_ok() {
            self.log_scenario_event(
                scenario,
                ReliabilityPhase::Verify,
                LogLevel::Info,
                "Reliability verify phase started",
                "SCENARIO_VERIFY_START",
                &triage_actions,
                None,
                Vec::new(),
            );

            let result = self.run_phase_lifecycle_commands(
                scenario,
                ReliabilityPhase::Verify,
                "post_checks",
                &scenario.lifecycle.post_checks,
                &mut report,
                &mut triage_actions,
            );

            if let Err(error) = result.as_ref() {
                self.log_scenario_event(
                    scenario,
                    ReliabilityPhase::Verify,
                    LogLevel::Error,
                    format!("Reliability verify phase failed: {error}"),
                    "SCENARIO_VERIFY_FAIL",
                    &triage_actions,
                    Some(error.to_string()),
                    Vec::new(),
                );
            } else {
                self.log_scenario_event(
                    scenario,
                    ReliabilityPhase::Verify,
                    LogLevel::Info,
                    "Reliability verify phase completed",
                    "SCENARIO_VERIFY_DONE",
                    &triage_actions,
                    None,
                    Vec::new(),
                );
            }

            result
        } else {
            self.log_scenario_event(
                scenario,
                ReliabilityPhase::Verify,
                LogLevel::Warn,
                "Reliability verify phase skipped due earlier failure",
                "SCENARIO_VERIFY_SKIPPED",
                &triage_actions,
                Some("setup or execute phase failed".to_string()),
                Vec::new(),
            );
            Ok(())
        };

        report.phase_order.push(ReliabilityPhase::Cleanup);
        self.log_scenario_event(
            scenario,
            ReliabilityPhase::Cleanup,
            LogLevel::Info,
            "Reliability cleanup phase started",
            "SCENARIO_CLEANUP_START",
            &triage_actions,
            None,
            Vec::new(),
        );

        let cleanup_result = self.run_phase_lifecycle_commands(
            scenario,
            ReliabilityPhase::Cleanup,
            "cleanup_verification",
            &scenario.lifecycle.cleanup_verification,
            &mut report,
            &mut triage_actions,
        );

        let manifest_payload = serde_json::json!({
            "schema_version": report.schema_version,
            "scenario_id": report.scenario_id,
            "phase_order": report.phase_order.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "activated_failure_hooks": report
                .activated_failure_hooks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "command_records": report.command_records,
            "artifact_paths": report.artifact_paths,
        });
        let mut cleanup_artifacts = Vec::new();
        if let Ok(path) = self.logger.capture_artifact_json(
            &scenario.scenario_id,
            "scenario_artifact_index",
            &manifest_payload,
        ) {
            let as_string = path.display().to_string();
            report.manifest_path = Some(path);
            Self::push_unique_string(&mut report.artifact_paths, as_string.clone());
            cleanup_artifacts.push(as_string);
        }

        if let Err(error) = cleanup_result.as_ref() {
            self.log_scenario_event(
                scenario,
                ReliabilityPhase::Cleanup,
                LogLevel::Error,
                format!("Reliability cleanup phase failed: {error}"),
                "SCENARIO_CLEANUP_FAIL",
                &triage_actions,
                Some(error.to_string()),
                cleanup_artifacts,
            );
        } else {
            self.log_scenario_event(
                scenario,
                ReliabilityPhase::Cleanup,
                LogLevel::Info,
                "Reliability cleanup phase completed",
                "SCENARIO_CLEANUP_DONE",
                &triage_actions,
                None,
                cleanup_artifacts,
            );
        }

        setup_result?;
        execute_result?;
        verify_result?;
        cleanup_result?;

        Ok(report)
    }

    fn run_phase_lifecycle_commands(
        &self,
        scenario: &ReliabilityScenarioSpec,
        phase: ReliabilityPhase,
        stage: &str,
        commands: &[ReliabilityLifecycleCommand],
        report: &mut ReliabilityScenarioReport,
        triage_actions: &mut Vec<String>,
    ) -> HarnessResult<()> {
        for command in commands {
            self.execute_lifecycle_command(
                scenario,
                phase,
                stage,
                command,
                report,
                triage_actions,
            )?;
        }
        Ok(())
    }

    fn execute_lifecycle_command(
        &self,
        scenario: &ReliabilityScenarioSpec,
        phase: ReliabilityPhase,
        stage: &str,
        command: &ReliabilityLifecycleCommand,
        report: &mut ReliabilityScenarioReport,
        triage_actions: &mut Vec<String>,
    ) -> HarnessResult<()> {
        let mut invoked_args = command.args.clone();
        let invoked_program = if command.via_rch_exec {
            let mut wrapped = vec![
                "exec".to_string(),
                "--".to_string(),
                command.program.clone(),
            ];
            wrapped.extend(invoked_args);
            invoked_args = wrapped;
            "rch".to_string()
        } else {
            command.program.clone()
        };

        let timeout = command
            .timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(self.config.default_timeout);
        let result = self.exec_with_timeout(
            &invoked_program,
            invoked_args.iter().map(String::as_str),
            timeout,
        )?;

        let artifact_prefix = format!(
            "{}_{}_{}",
            Self::sanitize_artifact_component(stage),
            Self::sanitize_artifact_component(&command.name),
            chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f")
        );
        let mut command_artifacts = Vec::new();
        let trace_payload = serde_json::json!({
            "scenario_id": scenario.scenario_id,
            "phase": phase.to_string(),
            "stage": stage,
            "command_name": command.name,
            "invoked_program": invoked_program,
            "invoked_args": invoked_args,
            "required_success": command.required_success,
            "exit_code": result.exit_code,
            "duration_ms": result.duration.as_millis(),
        });
        if let Ok(path) = self.logger.capture_artifact_json(
            &scenario.scenario_id,
            &format!("{artifact_prefix}_trace"),
            &trace_payload,
        ) {
            command_artifacts.push(path.display().to_string());
        }
        if !result.stdout.is_empty()
            && let Ok(path) = self.logger.capture_artifact_text(
                &scenario.scenario_id,
                &format!("{artifact_prefix}_stdout"),
                &result.stdout,
            )
        {
            command_artifacts.push(path.display().to_string());
        }
        if !result.stderr.is_empty()
            && let Ok(path) = self.logger.capture_artifact_text(
                &scenario.scenario_id,
                &format!("{artifact_prefix}_stderr"),
                &result.stderr,
            )
        {
            command_artifacts.push(path.display().to_string());
        }

        for artifact_path in &command_artifacts {
            Self::push_unique_string(&mut report.artifact_paths, artifact_path.clone());
        }

        let mut event_triage = triage_actions.clone();
        if result.success() {
            Self::push_unique_string(
                &mut event_triage,
                format!("{}_{}_pass", stage, command.name),
            );
        } else {
            Self::push_unique_string(
                &mut event_triage,
                format!("{}_{}_fail", stage, command.name),
            );
        }

        let decision_code = format!(
            "{}_{}",
            Self::sanitize_decision_token(stage),
            if result.success() { "PASS" } else { "FAIL" }
        );

        self.log_scenario_event(
            scenario,
            phase,
            if result.success() {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
            format!(
                "Lifecycle command '{}' in stage '{}' finished with exit {}",
                command.name, stage, result.exit_code
            ),
            decision_code,
            &event_triage,
            if result.success() {
                None
            } else {
                Some(format!(
                    "lifecycle command '{}' failed with exit {}",
                    command.name, result.exit_code
                ))
            },
            command_artifacts.clone(),
        );

        report.command_records.push(ReliabilityCommandRecord {
            phase,
            stage: stage.to_string(),
            command_name: command.name.clone(),
            invoked_program: invoked_program.clone(),
            invoked_args: invoked_args.clone(),
            exit_code: result.exit_code,
            duration_ms: result.duration.as_millis() as u64,
            required_success: command.required_success,
            succeeded: result.success(),
            artifact_paths: command_artifacts,
        });

        if !result.success() && command.required_success {
            return Err(HarnessError::AssertionFailed(format!(
                "required lifecycle command '{}' failed in stage '{}' (exit={})",
                command.name, stage, result.exit_code
            )));
        }
        if !result.success() && !command.required_success {
            Self::push_unique_string(
                triage_actions,
                format!("optional_command_failed:{}:{}", stage, command.name),
            );
        }

        Ok(())
    }

    fn activate_failure_hooks(
        &self,
        scenario: &ReliabilityScenarioSpec,
        report: &mut ReliabilityScenarioReport,
        triage_actions: &mut Vec<String>,
    ) -> HarnessResult<Vec<ReliabilityFailureHook>> {
        let mut activated = Vec::new();
        if scenario.requested_failure_hooks.is_empty() {
            return Ok(activated);
        }

        let marker_dir = self.test_dir.join(".reliability-hooks");
        std::fs::create_dir_all(&marker_dir)?;

        for hook in &scenario.requested_failure_hooks {
            if !scenario.failure_hook_flags.allows(*hook) {
                self.log_scenario_event(
                    scenario,
                    ReliabilityPhase::Setup,
                    LogLevel::Error,
                    format!("Failure hook denied: {hook}"),
                    "FAILURE_HOOK_DENIED",
                    triage_actions,
                    Some(format!("hook {hook} requested without explicit allow flag")),
                    Vec::new(),
                );
                return Err(HarnessError::SetupFailed(format!(
                    "failure hook '{hook}' requested but not enabled"
                )));
            }

            let marker_path = marker_dir.join(format!("{hook}.enabled"));
            std::fs::write(
                &marker_path,
                format!(
                    "scenario_id={}\nhook={hook}\narmed_at={}\n",
                    scenario.scenario_id,
                    chrono::Utc::now().to_rfc3339()
                ),
            )?;

            let mut hook_artifacts = Vec::new();
            if let Ok(path) = self.logger.capture_artifact_text(
                &scenario.scenario_id,
                &format!("failure_hook_{hook}_marker"),
                &format!("marker_path={}", marker_path.display()),
            ) {
                hook_artifacts.push(path.display().to_string());
            }
            let hook_payload = serde_json::json!({
                "scenario_id": scenario.scenario_id,
                "hook": hook.to_string(),
                "marker_path": marker_path.display().to_string(),
                "armed_at": chrono::Utc::now().to_rfc3339(),
            });
            if let Ok(path) = self.logger.capture_artifact_json(
                &scenario.scenario_id,
                &format!("failure_hook_{hook}_payload"),
                &hook_payload,
            ) {
                hook_artifacts.push(path.display().to_string());
            }

            for artifact_path in &hook_artifacts {
                Self::push_unique_string(&mut report.artifact_paths, artifact_path.clone());
            }

            Self::push_unique_string(triage_actions, format!("failure_hook:{hook}:armed"));

            self.log_scenario_event(
                scenario,
                ReliabilityPhase::Setup,
                LogLevel::Info,
                format!("Failure hook armed: {hook}"),
                "FAILURE_HOOK_ARMED",
                triage_actions,
                None,
                hook_artifacts,
            );

            activated.push(*hook);
        }

        Ok(activated)
    }

    #[allow(clippy::too_many_arguments)]
    fn log_scenario_event(
        &self,
        scenario: &ReliabilityScenarioSpec,
        phase: ReliabilityPhase,
        level: LogLevel,
        message: impl Into<String>,
        decision_code: impl Into<String>,
        triage_actions: &[String],
        fallback_reason: Option<String>,
        artifact_paths: Vec<String>,
    ) {
        let repo_set = if scenario.repo_set.is_empty() {
            vec![self.test_dir.display().to_string()]
        } else {
            scenario.repo_set.clone()
        };

        self.logger.log_reliability_event(ReliabilityEventInput {
            level,
            phase,
            scenario_id: scenario.scenario_id.clone(),
            message: message.into(),
            context: ReliabilityContext {
                worker_id: scenario.worker_id.clone(),
                repo_set,
                pressure_state: scenario.pressure_state.clone(),
                triage_actions: triage_actions.to_vec(),
                decision_code: decision_code.into(),
                fallback_reason,
            },
            artifact_paths,
        });
    }

    fn push_unique_string(values: &mut Vec<String>, value: String) {
        if !values.iter().any(|existing| existing == &value) {
            values.push(value);
        }
    }

    fn sanitize_decision_token(raw: &str) -> String {
        let mut token = String::with_capacity(raw.len());
        for ch in raw.chars() {
            if ch.is_ascii_alphanumeric() {
                token.push(ch.to_ascii_uppercase());
            } else {
                token.push('_');
            }
        }
        if token.is_empty() {
            "PHASE".to_string()
        } else {
            token
        }
    }

    /// Create a subdirectory in the test directory
    pub fn create_dir(&self, name: &str) -> HarnessResult<PathBuf> {
        let path = self.test_dir.join(name);
        std::fs::create_dir_all(&path)?;
        self.created_dirs.lock().unwrap().push(path.clone());
        self.logger
            .debug(format!("Created directory: {}", path.display()));
        Ok(path)
    }

    /// Create a file in the test directory
    pub fn create_file(&self, name: &str, content: &str) -> HarnessResult<PathBuf> {
        let path = self.test_dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content)?;
        self.created_files.lock().unwrap().push(path.clone());
        self.logger
            .debug(format!("Created file: {}", path.display()));
        Ok(path)
    }

    /// Create a config file for the daemon
    pub fn create_daemon_config(&self, config_content: &str) -> HarnessResult<PathBuf> {
        let config_dir = self.create_dir("config")?;
        let config_path = config_dir.join("daemon.toml");
        std::fs::write(&config_path, config_content)?;
        self.logger
            .info(format!("Created daemon config: {}", config_path.display()));
        Ok(config_path)
    }

    /// Create a workers config file
    pub fn create_workers_config(&self, config_content: &str) -> HarnessResult<PathBuf> {
        let config_dir = self.test_dir.join("config");
        std::fs::create_dir_all(&config_dir)?;
        let config_path = config_dir.join("workers.toml");
        std::fs::write(&config_path, config_content)?;
        self.logger
            .info(format!("Created workers config: {}", config_path.display()));
        Ok(config_path)
    }

    /// Spawn a managed process
    pub fn spawn_process<I, S>(
        &self,
        name: &str,
        program: &Path,
        args: I,
        env: Option<&HashMap<String, String>>,
    ) -> HarnessResult<u32>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut cmd = Command::new(program);
        // Use Stdio::null() to prevent pipe buffer blocking. Long-running
        // daemon processes can fill the 64KB pipe buffer on Linux, blocking
        // on write and becoming unresponsive to socket requests. Since no
        // test reads from the daemon's piped stdout/stderr, null is correct.
        cmd.args(args)
            .current_dir(&self.test_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        // Set default environment variables
        for (k, v) in &self.config.env_vars {
            cmd.env(k, v);
        }

        // Set additional environment variables
        if let Some(env_vars) = env {
            for (k, v) in env_vars {
                cmd.env(k, v);
            }
        }

        self.logger.info(format!(
            "Spawning process: {} {:?}",
            name,
            program.display()
        ));

        let child = cmd.spawn().map_err(|e| {
            HarnessError::ProcessStartFailed(format!("{}: {}", program.display(), e))
        })?;

        let pid = child.id();
        let info = ProcessInfo {
            name: name.to_string(),
            pid,
            started_at: Instant::now(),
            child,
        };

        self.managed_processes
            .lock()
            .unwrap()
            .insert(name.to_string(), info);

        self.logger.log_with_context(
            LogLevel::Info,
            LogSource::Harness,
            format!("Process spawned: {name}"),
            vec![("pid".to_string(), pid.to_string())],
        );

        Ok(pid)
    }

    /// Start the daemon process
    pub fn start_daemon(&self, extra_args: &[&str]) -> HarnessResult<u32> {
        let workers_config = self.test_dir.join("config").join("workers.toml");
        let workers_config_str: String = workers_config.to_string_lossy().into_owned();
        let mut args: Vec<&str> = vec!["--workers-config", &workers_config_str];
        args.extend(extra_args);

        self.spawn_process("daemon", &self.config.rchd_binary, &args, None)
    }

    /// Stop a managed process by name
    pub fn stop_process(&self, name: &str) -> HarnessResult<()> {
        let mut processes = self.managed_processes.lock().unwrap();
        if let Some(mut info) = processes.remove(name) {
            self.logger
                .info(format!("Stopping process: {} (pid={})", name, info.pid));
            info.kill()?;
            let status = info.wait()?;
            self.logger
                .debug(format!("Process {} exited with status: {:?}", name, status));
            Ok(())
        } else {
            Err(HarnessError::ProcessNotFound(name.to_string()))
        }
    }

    /// Stop all managed processes
    pub fn stop_all_processes(&self) {
        let mut processes = self.managed_processes.lock().unwrap();
        for (name, mut info) in processes.drain() {
            self.logger
                .info(format!("Stopping process: {} (pid={})", name, info.pid));
            if let Err(e) = info.kill() {
                self.logger.warn(format!("Failed to kill {}: {}", name, e));
            }
            match info.wait() {
                Ok(status) => {
                    self.logger
                        .debug(format!("Process {} exited: {:?}", name, status));
                }
                Err(e) => {
                    self.logger
                        .warn(format!("Failed to wait for {}: {}", name, e));
                }
            }
        }
    }

    /// Execute a command and capture output
    pub fn exec<I, S>(&self, program: &str, args: I) -> HarnessResult<CommandResult>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.exec_with_timeout(program, args, self.config.default_timeout)
    }

    /// Execute a command with a specific timeout
    ///
    /// Terminates the process if it exceeds the provided timeout.
    pub fn exec_with_timeout<I, S>(
        &self,
        program: &str,
        args: I,
        timeout: Duration,
    ) -> HarnessResult<CommandResult>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args: Vec<_> = args.into_iter().collect();
        let args_display: Vec<_> = args.iter().map(|s| s.as_ref().to_string_lossy()).collect();

        self.logger
            .debug(format!("Executing: {} {}", program, args_display.join(" ")));

        let start = Instant::now();

        let mut cmd = Command::new(program);
        cmd.args(&args)
            .current_dir(&self.test_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set default environment variables
        for (k, v) in &self.config.env_vars {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn()?;
        let stdout_handle = child
            .stdout
            .take()
            .map(|mut stdout| thread::spawn(move || Self::read_to_string(&mut stdout)));
        let stderr_handle = child
            .stderr
            .take()
            .map(|mut stderr| thread::spawn(move || Self::read_to_string(&mut stderr)));

        let mut timed_out = false;
        let exit_status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }

            if start.elapsed() >= timeout {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }

            thread::sleep(Duration::from_millis(10));
        };

        let duration = start.elapsed();
        let stdout = Self::join_output(stdout_handle);
        let mut stderr = Self::join_output(stderr_handle);
        if timed_out {
            if !stderr.is_empty() {
                stderr.push('\n');
            }
            stderr.push_str(&format!("Process timed out after {:?}.", timeout));
        }

        let exit_code = exit_status
            .and_then(|status| status.code())
            .unwrap_or(if timed_out { 124 } else { -1 });

        let result = CommandResult {
            exit_code,
            stdout,
            stderr,
            duration,
        };

        let command_line = format!("{} {}", program, args_display.join(" "));
        let artifact_prefix = format!(
            "{}_{}",
            Self::sanitize_artifact_component(program),
            chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f")
        );
        let mut artifact_paths = Vec::new();
        let trace_payload = serde_json::json!({
            "command": command_line,
            "program": program,
            "args": args_display,
            "exit_code": result.exit_code,
            "duration_ms": duration.as_millis(),
            "timed_out": timed_out,
            "stdout_len_bytes": result.stdout.len(),
            "stderr_len_bytes": result.stderr.len(),
        });
        if let Ok(path) = self.logger.capture_artifact_json(
            self.logger.test_name(),
            &format!("{artifact_prefix}_trace"),
            &trace_payload,
        ) {
            artifact_paths.push(path.display().to_string());
        }
        if !result.stdout.is_empty()
            && let Ok(path) = self.logger.capture_artifact_text(
                self.logger.test_name(),
                &format!("{artifact_prefix}_stdout"),
                &result.stdout,
            )
        {
            artifact_paths.push(path.display().to_string());
        }
        if !result.stderr.is_empty()
            && let Ok(path) = self.logger.capture_artifact_text(
                self.logger.test_name(),
                &format!("{artifact_prefix}_stderr"),
                &result.stderr,
            )
        {
            artifact_paths.push(path.display().to_string());
        }

        self.logger.log_with_context(
            if result.success() {
                LogLevel::Debug
            } else {
                LogLevel::Warn
            },
            LogSource::Harness,
            format!("Command completed: {program}"),
            vec![
                ("exit_code".to_string(), result.exit_code.to_string()),
                ("duration_ms".to_string(), duration.as_millis().to_string()),
                ("timed_out".to_string(), timed_out.to_string()),
            ],
        );

        let decision_code = if timed_out {
            "CMD_TIMEOUT"
        } else if result.success() {
            "CMD_SUCCESS"
        } else {
            "CMD_FAILURE"
        };
        self.logger.log_reliability_event(ReliabilityEventInput {
            level: if result.success() {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
            phase: ReliabilityPhase::Execute,
            scenario_id: self.logger.test_name().to_string(),
            message: format!("Command execution finished: {program}"),
            context: ReliabilityContext {
                worker_id: None,
                repo_set: vec![self.test_dir.display().to_string()],
                pressure_state: None,
                triage_actions: if timed_out {
                    vec!["process_killed_after_timeout".to_string()]
                } else {
                    Vec::new()
                },
                decision_code: decision_code.to_string(),
                fallback_reason: if timed_out {
                    Some(format!("command exceeded timeout {:?}", timeout))
                } else {
                    None
                },
            },
            artifact_paths,
        });

        if !result.stdout.is_empty() {
            for line in result.stdout.lines() {
                self.logger.log(
                    LogLevel::Trace,
                    LogSource::Custom(program.to_string()),
                    line,
                );
            }
        }

        if !result.stderr.is_empty() {
            for line in result.stderr.lines() {
                self.logger.log(
                    LogLevel::Trace,
                    LogSource::Custom(format!("{program}:stderr")),
                    line,
                );
            }
        }

        Ok(result)
    }

    fn read_to_string<R: Read>(reader: &mut R) -> String {
        let mut buffer = Vec::new();
        if reader.read_to_end(&mut buffer).is_ok() {
            String::from_utf8_lossy(&buffer).to_string()
        } else {
            String::new()
        }
    }

    fn join_output(handle: Option<thread::JoinHandle<String>>) -> String {
        match handle {
            Some(handle) => handle.join().unwrap_or_default(),
            None => String::new(),
        }
    }

    fn sanitize_artifact_component(raw: &str) -> String {
        let mut sanitized = String::with_capacity(raw.len());
        for ch in raw.chars() {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                sanitized.push(ch);
            } else {
                sanitized.push('_');
            }
        }
        if sanitized.is_empty() {
            "artifact".to_string()
        } else {
            sanitized
        }
    }

    /// Execute the rch binary
    pub fn exec_rch<I, S>(&self, args: I) -> HarnessResult<CommandResult>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let binary = self.config.rch_binary.to_string_lossy().to_string();
        self.exec(&binary, args)
    }

    /// Execute the rchd binary
    pub fn exec_rchd<I, S>(&self, args: I) -> HarnessResult<CommandResult>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let binary = self.config.rchd_binary.to_string_lossy().to_string();
        self.exec(&binary, args)
    }

    /// Execute the rch-wkr binary
    pub fn exec_rch_wkr<I, S>(&self, args: I) -> HarnessResult<CommandResult>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let binary = self.config.rch_wkr_binary.to_string_lossy().to_string();
        self.exec(&binary, args)
    }

    /// Wait for a condition to become true
    pub fn wait_for<F>(
        &self,
        description: &str,
        timeout: Duration,
        interval: Duration,
        condition: F,
    ) -> HarnessResult<()>
    where
        F: Fn() -> bool,
    {
        self.logger
            .debug(format!("Waiting for: {description} (timeout: {timeout:?})"));

        let start = Instant::now();
        while start.elapsed() < timeout {
            if condition() {
                self.logger.debug(format!(
                    "Condition satisfied: {description} after {:?}",
                    start.elapsed()
                ));
                return Ok(());
            }
            std::thread::sleep(interval);
        }

        self.logger.error(format!(
            "Timeout waiting for: {description} after {timeout:?}"
        ));
        Err(HarnessError::Timeout(timeout))
    }

    /// Wait for a file to exist
    pub fn wait_for_file(&self, path: &Path, timeout: Duration) -> HarnessResult<()> {
        let path_display = path.display().to_string();
        self.wait_for(
            &format!("file to exist: {path_display}"),
            timeout,
            Duration::from_millis(100),
            || path.exists(),
        )
    }

    /// Wait for a socket to be available
    pub fn wait_for_socket(&self, socket_path: &Path, timeout: Duration) -> HarnessResult<()> {
        self.wait_for_socket_with_backoff(socket_path, timeout)
    }

    /// Wait for a socket using exponential backoff for more reliable detection.
    ///
    /// Starts with a 10ms delay and doubles up to a maximum of 500ms per iteration.
    /// This reduces CPU usage while maintaining responsiveness for fast-starting daemons.
    pub fn wait_for_socket_with_backoff(
        &self,
        socket_path: &Path,
        max_wait: Duration,
    ) -> HarnessResult<()> {
        let socket_display = socket_path.display().to_string();
        self.logger.debug(format!(
            "Waiting for socket with backoff: {socket_display} (timeout: {max_wait:?})"
        ));

        let start = std::time::Instant::now();
        let mut delay = Duration::from_millis(10);
        let max_delay = Duration::from_millis(500);

        while start.elapsed() < max_wait {
            if socket_path.exists() {
                #[cfg(unix)]
                {
                    // A socket file can exist while the daemon is not yet accepting connections
                    // (or after a previous process died). Prefer probing connect() to avoid flakes.
                    match std::os::unix::net::UnixStream::connect(socket_path) {
                        Ok(stream) => {
                            drop(stream);
                            self.logger.info(format!(
                                "Socket ready after {:?}: {socket_display}",
                                start.elapsed()
                            ));
                            return Ok(());
                        }
                        Err(err) => {
                            self.logger.debug(format!(
                                "Socket exists but not connectable yet ({err}); retrying..."
                            ));
                        }
                    }
                }

                #[cfg(not(unix))]
                {
                    self.logger.info(format!(
                        "Socket ready after {:?}: {socket_display}",
                        start.elapsed()
                    ));
                    return Ok(());
                }
            }
            std::thread::sleep(delay);
            delay = (delay * 2).min(max_delay);
        }

        self.logger.error(format!(
            "Socket timeout after {:?}: {socket_display}",
            max_wait
        ));
        Err(HarnessError::Timeout(max_wait))
    }

    /// Mark the test as passed
    pub fn mark_passed(&self) {
        *self.test_passed.lock().unwrap() = true;
        self.logger.info("Test marked as PASSED");
    }

    /// Mark the test as failed with a reason
    pub fn mark_failed(&self, reason: &str) {
        *self.test_passed.lock().unwrap() = false;
        self.logger
            .error(format!("Test marked as FAILED: {reason}"));
    }

    /// Check if the test passed
    pub fn passed(&self) -> bool {
        *self.test_passed.lock().unwrap()
    }

    /// Assert that a condition is true
    pub fn assert(&self, condition: bool, message: &str) -> HarnessResult<()> {
        if condition {
            self.logger.debug(format!("Assertion passed: {message}"));
            self.logger
                .log_reliability_event(ReliabilityEventInput::with_decision(
                    ReliabilityPhase::Verify,
                    self.logger.test_name().to_string(),
                    format!("Assertion passed: {message}"),
                    "ASSERT_PASS",
                ));
            Ok(())
        } else {
            self.logger.error(format!("Assertion failed: {message}"));
            self.logger
                .log_reliability_event(ReliabilityEventInput::with_decision(
                    ReliabilityPhase::Verify,
                    self.logger.test_name().to_string(),
                    format!("Assertion failed: {message}"),
                    "ASSERT_FAIL",
                ));
            Err(HarnessError::AssertionFailed(message.to_string()))
        }
    }

    /// Assert that two values are equal
    pub fn assert_eq<T: PartialEq + std::fmt::Debug>(
        &self,
        actual: T,
        expected: T,
        message: &str,
    ) -> HarnessResult<()> {
        if actual == expected {
            self.logger.debug(format!("Assertion passed: {message}"));
            self.logger
                .log_reliability_event(ReliabilityEventInput::with_decision(
                    ReliabilityPhase::Verify,
                    self.logger.test_name().to_string(),
                    format!("Equality assertion passed: {message}"),
                    "ASSERT_EQ_PASS",
                ));
            Ok(())
        } else {
            let msg = format!("{}: expected {:?}, got {:?}", message, expected, actual);
            self.logger.error(format!("Assertion failed: {msg}"));
            self.logger
                .log_reliability_event(ReliabilityEventInput::with_decision(
                    ReliabilityPhase::Verify,
                    self.logger.test_name().to_string(),
                    format!("Equality assertion failed: {msg}"),
                    "ASSERT_EQ_FAIL",
                ));
            Err(HarnessError::AssertionFailed(msg))
        }
    }

    /// Assert that a command result succeeded
    pub fn assert_success(&self, result: &CommandResult, context: &str) -> HarnessResult<()> {
        if result.success() {
            self.logger.debug(format!("Command succeeded: {context}"));
            self.logger
                .log_reliability_event(ReliabilityEventInput::with_decision(
                    ReliabilityPhase::Verify,
                    self.logger.test_name().to_string(),
                    format!("Command success assertion passed: {context}"),
                    "CMD_ASSERT_SUCCESS",
                ));
            Ok(())
        } else {
            let msg = format!(
                "{}: command failed with exit code {} - stdout: {}, stderr: {}",
                context,
                result.exit_code,
                result.stdout.trim(),
                result.stderr.trim()
            );
            self.logger.error(&msg);
            self.logger
                .log_reliability_event(ReliabilityEventInput::with_decision(
                    ReliabilityPhase::Verify,
                    self.logger.test_name().to_string(),
                    format!("Command success assertion failed: {msg}"),
                    "CMD_ASSERT_FAIL",
                ));
            Err(HarnessError::AssertionFailed(msg))
        }
    }

    /// Assert that a command result contains expected output
    pub fn assert_stdout_contains(
        &self,
        result: &CommandResult,
        pattern: &str,
        context: &str,
    ) -> HarnessResult<()> {
        if result.stdout_contains(pattern) {
            self.logger.debug(format!(
                "Stdout contains expected pattern: {context} -> {pattern}"
            ));
            self.logger
                .log_reliability_event(ReliabilityEventInput::with_decision(
                    ReliabilityPhase::Verify,
                    self.logger.test_name().to_string(),
                    format!("Stdout assertion passed for pattern '{pattern}'"),
                    "STDOUT_PATTERN_PASS",
                ));
            Ok(())
        } else {
            let msg = format!(
                "{}: stdout does not contain '{}'. Actual stdout: {}",
                context,
                pattern,
                result.stdout.trim()
            );
            self.logger.error(&msg);
            self.logger
                .log_reliability_event(ReliabilityEventInput::with_decision(
                    ReliabilityPhase::Verify,
                    self.logger.test_name().to_string(),
                    format!("Stdout assertion failed for pattern '{pattern}'"),
                    "STDOUT_PATTERN_FAIL",
                ));
            Err(HarnessError::AssertionFailed(msg))
        }
    }

    /// Perform cleanup
    pub fn cleanup(&self) {
        self.logger.info("Starting cleanup");
        self.logger
            .log_reliability_event(ReliabilityEventInput::with_decision(
                ReliabilityPhase::Cleanup,
                self.logger.test_name().to_string(),
                "Cleanup started",
                "CLEANUP_START",
            ));

        // Stop all managed processes
        self.stop_all_processes();

        // Determine if we should clean up files
        let should_cleanup = if *self.test_passed.lock().unwrap() {
            self.config.cleanup_on_success
        } else {
            self.config.cleanup_on_failure
        };

        if should_cleanup {
            self.logger.debug(format!(
                "Removing test directory: {}",
                self.test_dir.display()
            ));
            if let Err(e) = std::fs::remove_dir_all(&self.test_dir) {
                self.logger
                    .warn(format!("Failed to remove test directory: {}", e));
            }
        } else {
            self.logger.info(format!(
                "Preserving test directory for inspection: {}",
                self.test_dir.display()
            ));
        }

        self.logger
            .log_reliability_event(ReliabilityEventInput::with_decision(
                ReliabilityPhase::Cleanup,
                self.logger.test_name().to_string(),
                "Cleanup finished",
                "CLEANUP_DONE",
            ));

        self.logger.print_summary();
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Builder for creating a TestHarness with custom configuration
pub struct TestHarnessBuilder {
    test_name: String,
    config: HarnessConfig,
}

impl TestHarnessBuilder {
    /// Create a new builder for the given test name
    pub fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            config: HarnessConfig::default(),
        }
    }

    /// Set the temp directory
    pub fn temp_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config.temp_dir = dir.into();
        self
    }

    /// Set the default command timeout
    pub fn default_timeout(mut self, timeout: Duration) -> Self {
        self.config.default_timeout = timeout;
        self
    }

    /// Set whether to cleanup on success
    pub fn cleanup_on_success(mut self, cleanup: bool) -> Self {
        self.config.cleanup_on_success = cleanup;
        self
    }

    /// Set whether to cleanup on failure
    pub fn cleanup_on_failure(mut self, cleanup: bool) -> Self {
        self.config.cleanup_on_failure = cleanup;
        self
    }

    /// Set the rch binary path
    pub fn rch_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.rch_binary = path.into();
        self
    }

    /// Set the rchd binary path
    pub fn rchd_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.rchd_binary = path.into();
        self
    }

    /// Set the rch-wkr binary path
    pub fn rch_wkr_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.rch_wkr_binary = path.into();
        self
    }

    /// Add an environment variable
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.config
            .env_vars
            .insert(key.to_string(), value.to_string());
        self
    }

    /// Build the TestHarness
    pub fn build(self) -> HarnessResult<TestHarness> {
        TestHarness::new(&self.test_name, self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harness_creation() {
        let harness = TestHarnessBuilder::new("test_creation")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        assert!(harness.test_dir().exists());
        // Will cleanup on drop
    }

    #[test]
    fn test_harness_file_creation() {
        let harness = TestHarnessBuilder::new("test_files")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        let file_path = harness.create_file("test.txt", "hello world").unwrap();
        assert!(file_path.exists());

        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_harness_exec() {
        let harness = TestHarnessBuilder::new("test_exec")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        let result = harness.exec("echo", ["hello"]).unwrap();
        assert!(result.success());
        assert!(result.stdout_contains("hello"));
    }

    #[cfg(unix)]
    #[test]
    fn test_harness_exec_timeout() {
        let harness = TestHarnessBuilder::new("test_exec_timeout")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        let result = harness
            .exec_with_timeout("sleep", ["1"], Duration::from_millis(50))
            .unwrap();

        assert!(!result.success());
        assert_eq!(result.exit_code, 124);
        assert!(result.stderr_contains("timed out"));
    }

    #[test]
    fn test_command_result() {
        let result = CommandResult {
            exit_code: 0,
            stdout: "hello world\n".to_string(),
            stderr: "".to_string(),
            duration: Duration::from_millis(10),
        };

        assert!(result.success());
        assert!(result.stdout_contains("hello"));
        assert!(!result.stderr_contains("error"));
    }

    #[test]
    fn test_harness_assertions() {
        let harness = TestHarnessBuilder::new("test_assertions")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        harness.assert(true, "should pass").unwrap();
        harness.assert_eq(1, 1, "numbers equal").unwrap();

        let result = CommandResult {
            exit_code: 0,
            stdout: "success".to_string(),
            stderr: "".to_string(),
            duration: Duration::from_millis(1),
        };
        harness.assert_success(&result, "echo command").unwrap();

        harness.mark_passed();
        assert!(harness.passed());
    }

    #[test]
    fn test_reliability_harness_phase_order_and_manifest_index() {
        let harness = TestHarnessBuilder::new("reliability_harness_phase_order")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        let scenario = ReliabilityScenarioSpec::new("reliability_harness_phase_order")
            .with_worker_id("worker-a")
            .with_repo_set([harness.test_dir().display().to_string()])
            .with_pressure_state("disk:normal,memory:normal")
            .add_triage_action("initial_context")
            .add_pre_check(ReliabilityLifecycleCommand::new(
                "pre-check",
                "echo",
                ["pre-check"],
            ))
            .add_execute_command(ReliabilityLifecycleCommand::new(
                "execute-build",
                "echo",
                ["execute-build"],
            ))
            .add_remote_probe(ReliabilityLifecycleCommand::new(
                "remote-probe",
                "echo",
                ["remote-probe"],
            ))
            .add_post_check(ReliabilityLifecycleCommand::new(
                "post-check",
                "echo",
                ["post-check"],
            ))
            .add_cleanup_verification(ReliabilityLifecycleCommand::new(
                "cleanup-check",
                "echo",
                ["cleanup-check"],
            ));

        let report = harness.run_reliability_scenario(&scenario).unwrap();
        assert_eq!(
            report.phase_order,
            vec![
                ReliabilityPhase::Setup,
                ReliabilityPhase::Execute,
                ReliabilityPhase::Verify,
                ReliabilityPhase::Cleanup
            ]
        );
        let stages: Vec<_> = report
            .command_records
            .iter()
            .map(|record| record.stage.as_str())
            .collect();
        assert_eq!(
            stages,
            vec![
                "pre_checks",
                "execute",
                "remote_probes",
                "post_checks",
                "cleanup_verification"
            ]
        );

        let manifest_path = report.manifest_path.expect("manifest path should exist");
        assert!(manifest_path.exists());
        let manifest = std::fs::read_to_string(manifest_path).unwrap();
        assert!(manifest.contains("\"scenario_id\": \"reliability_harness_phase_order\""));
    }

    #[test]
    fn test_reliability_harness_denies_unflagged_failure_hooks() {
        let harness = TestHarnessBuilder::new("reliability_harness_hook_denied")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        let scenario = ReliabilityScenarioSpec::new("reliability_harness_hook_denied")
            .request_failure_hook(ReliabilityFailureHook::NetworkCut);

        let err = harness
            .run_reliability_scenario(&scenario)
            .expect_err("unflagged failure hook must be rejected");
        assert!(matches!(err, HarnessError::SetupFailed(_)));
        assert!(err.to_string().contains("not enabled"));
    }

    #[test]
    fn test_reliability_harness_arms_explicit_failure_hooks() {
        let harness = TestHarnessBuilder::new("reliability_harness_hook_enabled")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        let flags = ReliabilityFailureHookFlags::allow_all();

        let scenario = ReliabilityScenarioSpec::new("reliability_harness_hook_enabled")
            .with_repo_set([harness.test_dir().display().to_string()])
            .request_failure_hook(ReliabilityFailureHook::NetworkCut)
            .request_failure_hook(ReliabilityFailureHook::SyncTimeout)
            .request_failure_hook(ReliabilityFailureHook::PartialUpdate)
            .request_failure_hook(ReliabilityFailureHook::DaemonRestart)
            .with_failure_hook_flags(flags)
            .add_cleanup_verification(ReliabilityLifecycleCommand::new(
                "cleanup-check",
                "echo",
                ["cleanup-check"],
            ));

        let report = harness.run_reliability_scenario(&scenario).unwrap();
        assert_eq!(
            report.activated_failure_hooks,
            vec![
                ReliabilityFailureHook::NetworkCut,
                ReliabilityFailureHook::SyncTimeout,
                ReliabilityFailureHook::PartialUpdate,
                ReliabilityFailureHook::DaemonRestart
            ]
        );
        assert!(
            report
                .artifact_paths
                .iter()
                .any(|path| path.contains("failure_hook_network_cut"))
        );
        assert!(
            harness
                .test_dir()
                .join(".reliability-hooks/network_cut.enabled")
                .exists()
        );
        assert!(
            harness
                .test_dir()
                .join(".reliability-hooks/sync_timeout.enabled")
                .exists()
        );
        assert!(
            harness
                .test_dir()
                .join(".reliability-hooks/partial_update.enabled")
                .exists()
        );
        assert!(
            harness
                .test_dir()
                .join(".reliability-hooks/daemon_restart.enabled")
                .exists()
        );
    }

    #[test]
    fn test_reliability_harness_primitives_cover_downstream_scenarios() {
        let harness = TestHarnessBuilder::new("reliability_harness_downstream")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        let scenario_ids = ["bd-vvmd.2.8", "bd-vvmd.3.6", "bd-vvmd.4.6", "bd-vvmd.5.6"];
        for scenario_id in scenario_ids {
            let scenario = ReliabilityScenarioSpec::new(scenario_id)
                .with_repo_set([harness.test_dir().display().to_string()])
                .add_execute_command(ReliabilityLifecycleCommand::new(
                    "smoke",
                    "echo",
                    [format!("scenario={scenario_id}")],
                ));

            let report = harness
                .run_reliability_scenario(&scenario)
                .unwrap_or_else(|error| panic!("scenario {scenario_id} failed: {error}"));
            assert!(
                report.manifest_path.is_some(),
                "missing manifest for {scenario_id}"
            );
            assert!(
                report
                    .command_records
                    .iter()
                    .any(|record| record.stage == "execute"),
                "missing execute stage record for {scenario_id}"
            );
        }
    }
}
