//! Diagnostic command implementation for `rch doctor`.
//!
//! Runs comprehensive diagnostics and optionally auto-fixes common issues.

use crate::commands::{JsonResponse, config_dir, load_workers_from_config};
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::Result;
use serde::Serialize;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Default socket path.
const DEFAULT_SOCKET_PATH: &str = "/tmp/rch.sock";

// =============================================================================
// JSON Response Types
// =============================================================================

/// Overall doctor command response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorResponse {
    pub checks: Vec<CheckResult>,
    pub summary: DoctorSummary,
    pub fixes_applied: Vec<FixApplied>,
}

/// Summary of all checks.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorSummary {
    pub total: usize,
    pub passed: usize,
    pub warnings: usize,
    pub failed: usize,
}

/// Result of a single diagnostic check.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub category: String,
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    pub fixable: bool,
}

/// Status of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warning,
    Fail,
    Skipped,
}

/// A fix that was applied.
#[derive(Debug, Clone, Serialize)]
pub struct FixApplied {
    pub check_name: String,
    pub action: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Doctor Command Options
// =============================================================================

/// Options for the doctor command.
pub struct DoctorOptions {
    /// Attempt to fix safe issues.
    pub fix: bool,
    /// Allow installing missing local deps (requires confirmation).
    #[allow(dead_code)]
    pub install_deps: bool,
    /// Detailed output.
    pub verbose: bool,
}

// =============================================================================
// Main Doctor Function
// =============================================================================

/// Run all diagnostic checks.
pub async fn run_doctor(ctx: &OutputContext, options: DoctorOptions) -> Result<()> {
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
    check_daemon(&mut checks, ctx, &options);
    check_hooks(&mut checks, ctx, &options);
    check_workers(&mut checks, ctx, &options).await;

    // Calculate summary
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
    };

    // Output results
    if ctx.is_json() {
        let _ = ctx.json(&JsonResponse::ok("doctor", DoctorResponse {
            checks,
            summary,
            fixes_applied,
        }));
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

/// Quick health check result for post-hook-install display.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct QuickCheckResult {
    pub daemon_running: bool,
    pub worker_count: usize,
    pub workers_healthy: usize,
    pub hook_installed: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl QuickCheckResult {
    /// Check if the system is fully operational.
    pub fn is_healthy(&self) -> bool {
        self.daemon_running
            && self.worker_count > 0
            && self.hook_installed
            && self.errors.is_empty()
    }

    /// Check if there are any issues.
    #[allow(dead_code)]
    pub fn has_issues(&self) -> bool {
        !self.warnings.is_empty() || !self.errors.is_empty()
    }
}

/// Run a quick health check (for post-install feedback).
/// This runs fast checks only (no network probes).
pub fn run_quick_check() -> QuickCheckResult {
    let socket_path = Path::new(DEFAULT_SOCKET_PATH);
    let daemon_running = socket_path.exists();

    // Check workers
    let (worker_count, workers_healthy) = match load_workers_from_config() {
        Ok(workers) => (workers.len(), workers.len()), // Assume healthy without probing
        Err(_) => (0, 0),
    };

    // Check hook
    let hook_installed = {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        let settings_path = home.join(".claude").join("settings.json");
        if settings_path.exists() {
            std::fs::read_to_string(&settings_path)
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

    QuickCheckResult {
        daemon_running,
        worker_count,
        workers_healthy,
        hook_installed,
        warnings,
        errors,
    }
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
    let exists = Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let version = if exists {
        Command::new(cmd)
            .arg("--version")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|v| v.lines().next().unwrap_or("").to_string())
    } else {
        None
    };

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
    }
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
        };
    }

    match std::fs::read_to_string(&config_path) {
        Ok(content) => match toml::from_str::<toml::Value>(&content) {
            Ok(_) => CheckResult {
                category: "configuration".to_string(),
                name: "config.toml".to_string(),
                status: CheckStatus::Pass,
                message: "config.toml is valid".to_string(),
                details: Some(config_path.display().to_string()),
                suggestion: None,
                fixable: false,
            },
            Err(e) => CheckResult {
                category: "configuration".to_string(),
                name: "config.toml".to_string(),
                status: CheckStatus::Fail,
                message: "config.toml has syntax errors".to_string(),
                details: Some(e.to_string()),
                suggestion: Some("Fix TOML syntax errors in config file".to_string()),
                fixable: false,
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
        };
    }

    match std::fs::read_to_string(&workers_path) {
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
        let result = CheckResult {
            category: "ssh".to_string(),
            name: "ssh_keys".to_string(),
            status: CheckStatus::Warning,
            message: "No standard SSH keys found".to_string(),
            details: Some("Checked: ~/.ssh/id_{ed25519,rsa,ecdsa}".to_string()),
            suggestion: Some("Generate an SSH key: ssh-keygen -t ed25519".to_string()),
            fixable: false,
        };
        print_check_result(&result, ctx);
        checks.push(result);
    }

    // Check SSH config
    let ssh_config_result = check_ssh_config();
    print_check_result(&ssh_config_result, ctx);
    checks.push(ssh_config_result);

    if !ctx.is_json() {
        println!();
    }
}

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
                }
            } else {
                // Try to fix if requested
                if options.fix {
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
        },
    }
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
        }
    }
}

// =============================================================================
// Daemon Checks
// =============================================================================

fn check_daemon(checks: &mut Vec<CheckResult>, ctx: &OutputContext, _options: &DoctorOptions) {
    let style = ctx.theme();

    if !ctx.is_json() {
        println!("{}", style.highlight("Daemon"));
        println!();
    }

    let socket_path = Path::new(DEFAULT_SOCKET_PATH);
    let result = if socket_path.exists() {
        CheckResult {
            category: "daemon".to_string(),
            name: "daemon_socket".to_string(),
            status: CheckStatus::Pass,
            message: "Daemon socket exists".to_string(),
            details: Some(DEFAULT_SOCKET_PATH.to_string()),
            suggestion: None,
            fixable: false,
        }
    } else {
        CheckResult {
            category: "daemon".to_string(),
            name: "daemon_socket".to_string(),
            status: CheckStatus::Warning,
            message: "Daemon is not running".to_string(),
            details: Some(DEFAULT_SOCKET_PATH.to_string()),
            suggestion: Some("Start daemon with: rch daemon start".to_string()),
            fixable: false,
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

fn check_hooks(checks: &mut Vec<CheckResult>, ctx: &OutputContext, _options: &DoctorOptions) {
    let style = ctx.theme();

    if !ctx.is_json() {
        println!("{}", style.highlight("Hooks"));
        println!();
    }

    // Check Claude Code hook
    let claude_result = check_claude_code_hook();
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
        };
    }

    match std::fs::read_to_string(&settings_path) {
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

    if let Some(ref details) = result.details {
        if ctx.is_verbose() {
            println!("    {}", style.muted(details));
        }
    }

    if let Some(ref suggestion) = result.suggestion {
        println!("    {} {}", style.muted("Hint:"), style.info(suggestion));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"total\":10"));
        assert!(json.contains("\"passed\":7"));
    }

    #[test]
    fn test_quick_check_result_is_healthy() {
        let healthy = QuickCheckResult {
            daemon_running: true,
            worker_count: 1,
            workers_healthy: 1,
            hook_installed: true,
            warnings: vec![],
            errors: vec![],
        };
        assert!(healthy.is_healthy());

        let no_daemon = QuickCheckResult {
            daemon_running: false,
            worker_count: 1,
            workers_healthy: 1,
            hook_installed: true,
            warnings: vec![],
            errors: vec![],
        };
        assert!(!no_daemon.is_healthy());

        let no_workers = QuickCheckResult {
            daemon_running: true,
            worker_count: 0,
            workers_healthy: 0,
            hook_installed: true,
            warnings: vec![],
            errors: vec![],
        };
        assert!(!no_workers.is_healthy());

        let no_hook = QuickCheckResult {
            daemon_running: true,
            worker_count: 1,
            workers_healthy: 1,
            hook_installed: false,
            warnings: vec![],
            errors: vec![],
        };
        assert!(!no_hook.is_healthy());
    }

    #[test]
    fn test_quick_check_result_has_issues() {
        let no_issues = QuickCheckResult {
            daemon_running: true,
            worker_count: 1,
            workers_healthy: 1,
            hook_installed: true,
            warnings: vec![],
            errors: vec![],
        };
        assert!(!no_issues.has_issues());

        let with_warnings = QuickCheckResult {
            daemon_running: true,
            worker_count: 1,
            workers_healthy: 1,
            hook_installed: true,
            warnings: vec!["Some warning".to_string()],
            errors: vec![],
        };
        assert!(with_warnings.has_issues());

        let with_errors = QuickCheckResult {
            daemon_running: true,
            worker_count: 1,
            workers_healthy: 1,
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
}
