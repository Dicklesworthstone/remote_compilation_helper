//! State detection and idempotent configuration primitives.
//!
//! This module provides the foundational building blocks for RCH's setup,
//! configuration, and state management. It ensures all operations are:
//!
//! - **Idempotent**: Can be called repeatedly without side effects
//! - **Atomic**: File operations use write-to-temp-then-rename
//! - **Safe**: Lock files prevent concurrent modifications
//! - **Traceable**: Clear exit codes and error messages
//!
//! # Module Structure
//!
//! - [`exit_codes`]: Exit codes following sysexits.h conventions
//! - [`primitives`]: Atomic, idempotent file operations
//! - [`lock`]: File-based locking with timeout support
//!
//! # Example
//!
//! ```no_run
//! use rch::state::{RchState, detect_state};
//!
//! // Detect current installation state
//! let state = detect_state()?;
//! match state.status {
//!     InstallStatus::Ready => println!("RCH is fully configured"),
//!     InstallStatus::NeedsSetup => println!("Run: rch setup"),
//!     _ => println!("Issues detected: {:?}", state.issues),
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```

pub mod exit_codes;
pub mod lock;
pub mod primitives;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use exit_codes::{
    ALREADY_CURRENT, CONFIG, DAEMON_DOWN, ERROR, LOCKED, NEEDS_MIGRATION, NEEDS_SETUP,
    NO_WORKERS, OK, USAGE,
};
pub use lock::ConfigLock;
pub use primitives::{
    append_line_if_missing, atomic_write, create_backup, create_if_missing, ensure_directory,
    ensure_symlink, update_if_changed, IdempotentResult,
};

/// Complete RCH installation state.
///
/// This struct captures the entire state of an RCH installation, including
/// all components, configuration files, and any detected issues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RchState {
    /// Global state assessment.
    pub status: InstallStatus,

    /// Individual component states.
    pub components: ComponentStates,

    /// Detected issues with remediation hints.
    pub issues: Vec<StateIssue>,

    /// Timestamp of state detection.
    pub detected_at: chrono::DateTime<chrono::Utc>,

    /// RCH version that performed this detection.
    pub rch_version: String,
}

/// Overall installation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallStatus {
    /// Fully configured and operational.
    Ready,
    /// Partially configured, needs setup.
    NeedsSetup,
    /// Not installed or critically broken.
    NotInstalled,
    /// Running but with warnings.
    Degraded,
    /// Config from older version, needs migration.
    NeedsMigration,
}

impl std::fmt::Display for InstallStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallStatus::Ready => write!(f, "ready"),
            InstallStatus::NeedsSetup => write!(f, "needs setup"),
            InstallStatus::NotInstalled => write!(f, "not installed"),
            InstallStatus::Degraded => write!(f, "degraded"),
            InstallStatus::NeedsMigration => write!(f, "needs migration"),
        }
    }
}

/// State of all RCH components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStates {
    /// User-level configuration state.
    pub user_config: ConfigState,
    /// Project-level configuration state (if in a project).
    pub project_config: ConfigState,
    /// Workers configuration state.
    pub workers: WorkersState,
    /// Daemon state.
    pub daemon: DaemonState,
    /// Registered agent hooks.
    pub hooks: Vec<AgentHookState>,
    /// Binary installation state.
    pub binaries: BinaryState,
}

/// State of a configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigState {
    /// Path to the configuration file.
    pub path: PathBuf,
    /// Whether the file exists.
    pub exists: bool,
    /// Whether the file is valid TOML/JSON.
    pub valid: bool,
    /// Version string from the config, if present.
    pub version: Option<String>,
    /// Whether the config needs migration.
    pub needs_migration: bool,
    /// Where this config's values came from.
    pub source: ConfigSource,
}

/// Source of a configuration value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    /// Built-in default value.
    Default,
    /// User configuration file (~/.config/rch/config.toml).
    UserConfig,
    /// Project configuration file (.rch/config.toml).
    ProjectConfig,
    /// Environment variable.
    Environment,
    /// Command line argument.
    CommandLine,
}

/// State of worker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkersState {
    /// Path to workers.toml.
    pub config_path: PathBuf,
    /// Whether the workers file exists.
    pub exists: bool,
    /// Whether the workers file is valid.
    pub valid: bool,
    /// Number of configured workers.
    pub worker_count: usize,
    /// Number of reachable workers (if checked).
    pub reachable_count: Option<usize>,
}

/// State of the RCH daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonState {
    /// Whether the daemon is running.
    pub running: bool,
    /// Process ID if running.
    pub pid: Option<u32>,
    /// Socket path.
    pub socket_path: PathBuf,
    /// Whether the socket exists and is responsive.
    pub socket_responsive: bool,
    /// Daemon version (if running).
    pub version: Option<String>,
}

/// State of an agent hook registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHookState {
    /// Agent name (e.g., "claude-code", "codex").
    pub agent: String,
    /// Hook configuration path.
    pub hook_path: PathBuf,
    /// Whether the hook is properly registered.
    pub registered: bool,
    /// Hook version.
    pub version: Option<String>,
}

/// State of binary installations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryState {
    /// Path to rch binary.
    pub rch_path: Option<PathBuf>,
    /// Path to rchd binary.
    pub rchd_path: Option<PathBuf>,
    /// Path to rch-wkr binary.
    pub rch_wkr_path: Option<PathBuf>,
    /// Version of installed binaries.
    pub version: Option<String>,
    /// Whether binaries are in PATH.
    pub in_path: bool,
}

/// A detected issue with remediation hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateIssue {
    /// Issue severity.
    pub severity: IssueSeverity,
    /// Component with the issue.
    pub component: String,
    /// Issue description.
    pub message: String,
    /// Suggested fix.
    pub remediation: String,
    /// Exit code associated with this issue.
    pub exit_code: i32,
}

/// Severity of a detected issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueSeverity {
    /// Critical issue preventing operation.
    Critical,
    /// Warning that may affect operation.
    Warning,
    /// Informational notice.
    Info,
}

/// Detect the current RCH installation state.
///
/// This function examines all RCH components and configuration files
/// to determine the overall installation status.
///
/// # Returns
///
/// An `RchState` struct containing:
/// - Overall status (Ready, NeedsSetup, etc.)
/// - Individual component states
/// - Any detected issues with remediation hints
///
/// # Example
///
/// ```no_run
/// use rch::state::detect_state;
///
/// let state = detect_state()?;
/// if state.status == rch::state::InstallStatus::Ready {
///     println!("RCH is ready to use");
/// } else {
///     for issue in &state.issues {
///         println!("Issue: {} - Fix: {}", issue.message, issue.remediation);
///     }
/// }
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn detect_state() -> Result<RchState> {
    let mut issues = Vec::new();

    // Detect user config state
    let user_config = detect_user_config(&mut issues)?;

    // Detect project config state
    let project_config = detect_project_config(&mut issues)?;

    // Detect workers state
    let workers = detect_workers_state(&mut issues)?;

    // Detect daemon state
    let daemon = detect_daemon_state(&mut issues)?;

    // Detect hooks state
    let hooks = detect_hooks_state(&mut issues)?;

    // Detect binary state
    let binaries = detect_binary_state(&mut issues)?;

    let components = ComponentStates {
        user_config,
        project_config,
        workers,
        daemon,
        hooks,
        binaries,
    };

    // Determine overall status
    let status = determine_overall_status(&components, &issues);

    Ok(RchState {
        status,
        components,
        issues,
        detected_at: chrono::Utc::now(),
        rch_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Detect user configuration state.
fn detect_user_config(issues: &mut Vec<StateIssue>) -> Result<ConfigState> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?;
    let config_path = config_dir.join("rch/config.toml");

    let exists = config_path.exists();
    let mut valid = false;
    let mut version = None;
    let needs_migration = false;

    if exists {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => {
                match toml::from_str::<toml::Value>(&content) {
                    Ok(value) => {
                        valid = true;
                        // Try to extract version from config
                        if let Some(v) = value.get("version").and_then(|v| v.as_str()) {
                            version = Some(v.to_string());
                        }
                    }
                    Err(e) => {
                        issues.push(StateIssue {
                            severity: IssueSeverity::Critical,
                            component: "user_config".to_string(),
                            message: format!("Invalid TOML in config.toml: {}", e),
                            remediation: "Fix the syntax error or run: rch config init --force"
                                .to_string(),
                            exit_code: exit_codes::CONFIG,
                        });
                    }
                }
            }
            Err(e) => {
                issues.push(StateIssue {
                    severity: IssueSeverity::Critical,
                    component: "user_config".to_string(),
                    message: format!("Cannot read config.toml: {}", e),
                    remediation: "Check file permissions".to_string(),
                    exit_code: exit_codes::CONFIG,
                });
            }
        }
    }

    Ok(ConfigState {
        path: config_path,
        exists,
        valid,
        version,
        needs_migration,
        source: if exists {
            ConfigSource::UserConfig
        } else {
            ConfigSource::Default
        },
    })
}

/// Detect project configuration state.
fn detect_project_config(_issues: &mut Vec<StateIssue>) -> Result<ConfigState> {
    let cwd = std::env::current_dir().context("Cannot determine current directory")?;
    let config_path = cwd.join(".rch/config.toml");

    let exists = config_path.exists();
    let mut valid = false;
    let mut version = None;

    if exists {
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Ok(value) = toml::from_str::<toml::Value>(&content) {
                valid = true;
                if let Some(v) = value.get("version").and_then(|v| v.as_str()) {
                    version = Some(v.to_string());
                }
            }
        }
    }

    Ok(ConfigState {
        path: config_path,
        exists,
        valid,
        version,
        needs_migration: false,
        source: if exists {
            ConfigSource::ProjectConfig
        } else {
            ConfigSource::Default
        },
    })
}

/// Detect workers configuration state.
fn detect_workers_state(issues: &mut Vec<StateIssue>) -> Result<WorkersState> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?;
    let config_path = config_dir.join("rch/workers.toml");

    let exists = config_path.exists();
    let mut valid = false;
    let mut worker_count = 0;

    if exists {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => {
                match toml::from_str::<toml::Value>(&content) {
                    Ok(value) => {
                        valid = true;
                        // Count workers
                        if let Some(workers) = value.get("workers").and_then(|w| w.as_array()) {
                            worker_count = workers.len();
                        }
                    }
                    Err(e) => {
                        issues.push(StateIssue {
                            severity: IssueSeverity::Critical,
                            component: "workers".to_string(),
                            message: format!("Invalid TOML in workers.toml: {}", e),
                            remediation: "Fix the syntax error in workers.toml".to_string(),
                            exit_code: exit_codes::CONFIG,
                        });
                    }
                }
            }
            Err(e) => {
                issues.push(StateIssue {
                    severity: IssueSeverity::Critical,
                    component: "workers".to_string(),
                    message: format!("Cannot read workers.toml: {}", e),
                    remediation: "Check file permissions".to_string(),
                    exit_code: exit_codes::CONFIG,
                });
            }
        }
    } else {
        issues.push(StateIssue {
            severity: IssueSeverity::Warning,
            component: "workers".to_string(),
            message: "No workers.toml found".to_string(),
            remediation: "Create ~/.config/rch/workers.toml or run: rch setup workers".to_string(),
            exit_code: exit_codes::NO_WORKERS,
        });
    }

    if exists && valid && worker_count == 0 {
        issues.push(StateIssue {
            severity: IssueSeverity::Warning,
            component: "workers".to_string(),
            message: "workers.toml exists but has no workers configured".to_string(),
            remediation: "Add worker entries to workers.toml".to_string(),
            exit_code: exit_codes::NO_WORKERS,
        });
    }

    Ok(WorkersState {
        config_path,
        exists,
        valid,
        worker_count,
        reachable_count: None, // Would require network check
    })
}

/// Detect daemon state.
fn detect_daemon_state(issues: &mut Vec<StateIssue>) -> Result<DaemonState> {
    let socket_path = PathBuf::from("/tmp/rch.sock");
    let socket_exists = socket_path.exists();

    // Try to check if daemon is responsive
    let socket_responsive = if socket_exists {
        // A simple check - try to connect
        std::os::unix::net::UnixStream::connect(&socket_path).is_ok()
    } else {
        false
    };

    let running = socket_responsive;
    let pid = None; // Would need to query daemon

    if !running {
        issues.push(StateIssue {
            severity: IssueSeverity::Warning,
            component: "daemon".to_string(),
            message: "RCH daemon is not running".to_string(),
            remediation: "Start the daemon with: rchd or rch daemon start".to_string(),
            exit_code: exit_codes::DAEMON_DOWN,
        });
    }

    Ok(DaemonState {
        running,
        pid,
        socket_path,
        socket_responsive,
        version: None,
    })
}

/// Detect hooks state.
fn detect_hooks_state(_issues: &mut Vec<StateIssue>) -> Result<Vec<AgentHookState>> {
    // Check for Claude Code hook
    let mut hooks = Vec::new();

    // Claude Code settings location
    let claude_settings = dirs::config_dir()
        .map(|p| p.join("claude-code/settings.json"));

    if let Some(path) = claude_settings {
        let registered = path.exists();
        // Could parse the settings to verify hook registration
        hooks.push(AgentHookState {
            agent: "claude-code".to_string(),
            hook_path: path,
            registered,
            version: None,
        });
    }

    Ok(hooks)
}

/// Detect binary installation state.
fn detect_binary_state(issues: &mut Vec<StateIssue>) -> Result<BinaryState> {
    let rch_path = which::which("rch").ok();
    let rchd_path = which::which("rchd").ok();
    let rch_wkr_path = which::which("rch-wkr").ok();

    let in_path = rch_path.is_some();

    if rch_path.is_none() {
        issues.push(StateIssue {
            severity: IssueSeverity::Warning,
            component: "binaries".to_string(),
            message: "rch binary not found in PATH".to_string(),
            remediation: "Add ~/.local/bin to PATH or install with: cargo install --path rch"
                .to_string(),
            exit_code: exit_codes::NEEDS_SETUP,
        });
    }

    Ok(BinaryState {
        rch_path,
        rchd_path,
        rch_wkr_path,
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
        in_path,
    })
}

/// Determine overall status from component states and issues.
fn determine_overall_status(components: &ComponentStates, issues: &[StateIssue]) -> InstallStatus {
    // Check for critical issues
    let has_critical = issues.iter().any(|i| i.severity == IssueSeverity::Critical);
    if has_critical {
        return InstallStatus::NotInstalled;
    }

    // Check if needs migration
    if components.user_config.needs_migration {
        return InstallStatus::NeedsMigration;
    }

    // Check for basic setup requirements
    let config_ready = components.user_config.exists && components.user_config.valid;
    let workers_ready =
        components.workers.exists && components.workers.valid && components.workers.worker_count > 0;

    if !config_ready || !workers_ready {
        return InstallStatus::NeedsSetup;
    }

    // Check for warnings (degraded state)
    let has_warnings = issues.iter().any(|i| i.severity == IssueSeverity::Warning);
    if has_warnings {
        return InstallStatus::Degraded;
    }

    InstallStatus::Ready
}

/// Get the exit code for the current state.
///
/// This is useful for scripting: `rch state --check` can return
/// an exit code indicating the installation status.
pub fn state_to_exit_code(state: &RchState) -> i32 {
    // Return the most severe issue's exit code
    if let Some(issue) = state
        .issues
        .iter()
        .filter(|i| i.severity == IssueSeverity::Critical)
        .next()
    {
        return issue.exit_code;
    }

    match state.status {
        InstallStatus::Ready => exit_codes::OK,
        InstallStatus::NeedsSetup => exit_codes::NEEDS_SETUP,
        InstallStatus::NotInstalled => exit_codes::NEEDS_SETUP,
        InstallStatus::Degraded => exit_codes::OK, // Degraded is still usable
        InstallStatus::NeedsMigration => exit_codes::NEEDS_MIGRATION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_status_display() {
        assert_eq!(format!("{}", InstallStatus::Ready), "ready");
        assert_eq!(format!("{}", InstallStatus::NeedsSetup), "needs setup");
        assert_eq!(format!("{}", InstallStatus::NotInstalled), "not installed");
        assert_eq!(format!("{}", InstallStatus::Degraded), "degraded");
        assert_eq!(format!("{}", InstallStatus::NeedsMigration), "needs migration");
    }

    #[test]
    fn test_state_serialization() {
        let state = RchState {
            status: InstallStatus::Ready,
            components: ComponentStates {
                user_config: ConfigState {
                    path: PathBuf::from("/test"),
                    exists: true,
                    valid: true,
                    version: Some("1.0".to_string()),
                    needs_migration: false,
                    source: ConfigSource::UserConfig,
                },
                project_config: ConfigState {
                    path: PathBuf::from("/test/.rch"),
                    exists: false,
                    valid: false,
                    version: None,
                    needs_migration: false,
                    source: ConfigSource::Default,
                },
                workers: WorkersState {
                    config_path: PathBuf::from("/test/workers.toml"),
                    exists: true,
                    valid: true,
                    worker_count: 2,
                    reachable_count: None,
                },
                daemon: DaemonState {
                    running: true,
                    pid: Some(12345),
                    socket_path: PathBuf::from("/tmp/rch.sock"),
                    socket_responsive: true,
                    version: Some("0.1.0".to_string()),
                },
                hooks: vec![],
                binaries: BinaryState {
                    rch_path: Some(PathBuf::from("/usr/local/bin/rch")),
                    rchd_path: Some(PathBuf::from("/usr/local/bin/rchd")),
                    rch_wkr_path: None,
                    version: Some("0.1.0".to_string()),
                    in_path: true,
                },
            },
            issues: vec![],
            detected_at: chrono::Utc::now(),
            rch_version: "0.1.0".to_string(),
        };

        // Should serialize to JSON without error
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("ready"));
        assert!(json.contains("user_config"));
    }

    #[test]
    fn test_state_to_exit_code() {
        let ready_state = RchState {
            status: InstallStatus::Ready,
            components: ComponentStates {
                user_config: ConfigState {
                    path: PathBuf::new(),
                    exists: true,
                    valid: true,
                    version: None,
                    needs_migration: false,
                    source: ConfigSource::Default,
                },
                project_config: ConfigState {
                    path: PathBuf::new(),
                    exists: false,
                    valid: false,
                    version: None,
                    needs_migration: false,
                    source: ConfigSource::Default,
                },
                workers: WorkersState {
                    config_path: PathBuf::new(),
                    exists: true,
                    valid: true,
                    worker_count: 1,
                    reachable_count: None,
                },
                daemon: DaemonState {
                    running: true,
                    pid: None,
                    socket_path: PathBuf::new(),
                    socket_responsive: true,
                    version: None,
                },
                hooks: vec![],
                binaries: BinaryState {
                    rch_path: None,
                    rchd_path: None,
                    rch_wkr_path: None,
                    version: None,
                    in_path: false,
                },
            },
            issues: vec![],
            detected_at: chrono::Utc::now(),
            rch_version: "0.1.0".to_string(),
        };

        assert_eq!(state_to_exit_code(&ready_state), exit_codes::OK);
    }
}
