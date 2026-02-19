//! Diagnostic command implementation for `rch doctor`.
//!
//! Runs comprehensive diagnostics and optionally auto-fixes common issues.

use crate::agent::{AgentKind, install_hook};
use crate::commands::{
    DoctorCheck, DoctorCheckStatus, DoctorFixApplied, DoctorResponse, DoctorSummary, config_dir,
    load_workers_from_config,
};
use crate::state::primitives::IdempotentResult;
use crate::status_display::query_daemon_full_status;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::Result;
use directories::ProjectDirs;
use rch_common::ApiResponse;
use rch_telemetry::TelemetryStorage;
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

// Type aliases for backward compatibility within this module
type CheckResult = DoctorCheck;
type CheckStatus = DoctorCheckStatus;
type FixApplied = DoctorFixApplied;

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
    let socket_path = default_socket_path();
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
        fix_applied: false,
        fix_message: None,
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
    let key = key_path.display();
    format!(
        "Copy key: ssh-copy-id -i {key} {user}@{host}; \
Test: ssh -i {key} {user}@{host} echo \"success\"; \
Agent: eval $(ssh-agent) && ssh-add {key}; \
Debug: ssh -vvv -i {key} {user}@{host}",
        key = key,
        user = user,
        host = host
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

    cmd.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "rchd not found in PATH".to_string(),
        _ => e.to_string(),
    })?;
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
            verbose: false,
        };
        assert!(!opts_minimal.fix);
        assert!(!opts_minimal.dry_run);

        let opts_fix = DoctorOptions {
            fix: true,
            dry_run: false,
            install_deps: false,
            verbose: false,
        };
        assert!(opts_fix.fix);

        let opts_dry_run = DoctorOptions {
            fix: true,
            dry_run: true,
            install_deps: false,
            verbose: false,
        };
        assert!(opts_dry_run.fix);
        assert!(opts_dry_run.dry_run);

        let opts_verbose = DoctorOptions {
            fix: false,
            dry_run: false,
            install_deps: false,
            verbose: true,
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
            workers_healthy: 0,
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
        // TEST START: QuickCheckResult partial health (some components working)
        let result = QuickCheckResult {
            daemon_running: true,
            worker_count: 2,
            workers_healthy: 1, // Only 1 of 2 healthy
            hook_installed: true,
            warnings: vec!["Worker css is offline".to_string()],
            errors: vec![],
        };

        // System is "healthy" from base criteria but has warnings
        assert!(result.is_healthy());
        assert!(result.has_issues()); // Still has issues due to warning
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
            verbose: false,
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
            verbose: false,
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
            verbose: false,
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
}
