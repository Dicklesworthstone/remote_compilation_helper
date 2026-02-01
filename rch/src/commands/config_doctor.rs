//! Configuration doctor command for diagnosing issues.
//!
//! This module handles the `rch config doctor` command, which performs
//! deeper health checks than `config lint`.

use anyhow::Result;
use rch_common::RchConfig;
use schemars::JsonSchema;
use serde::Serialize;
use std::path::PathBuf;

use crate::config;
use crate::ui::context::OutputContext;

use super::helpers::{config_dir, load_workers_from_config};

// =============================================================================
// Config Doctor Command
// =============================================================================

/// Severity levels for doctor diagnostics.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DoctorSeverity {
    Error,
    Warning,
    Info,
}

/// A single diagnostic from config doctor.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DoctorDiagnostic {
    pub severity: DoctorSeverity,
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Response type for config doctor command.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigDoctorResponse {
    pub diagnostics: Vec<DoctorDiagnostic>,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub healthy: bool,
}

/// Diagnose configuration and system health issues.
///
/// Performs deeper checks than `config lint`:
/// - Socket path writability
/// - SSH identity file existence and permissions
/// - Remote path format validation
/// - Glob pattern syntax
/// - File permission issues
pub fn config_doctor(ctx: &OutputContext) -> Result<()> {
    let mut diagnostics = Vec::new();

    // Load configuration
    let config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            diagnostics.push(DoctorDiagnostic {
                severity: DoctorSeverity::Error,
                code: "DOC-E001".to_string(),
                message: "Failed to load configuration".to_string(),
                detail: Some(e.to_string()),
                remediation: Some("Run 'rch config init' to create configuration".to_string()),
            });
            // Can't continue without config
            return output_doctor_results(ctx, diagnostics);
        }
    };

    // Check 1: Socket path writability
    check_socket_path(&config, &mut diagnostics);

    // Check 2: SSH identity files
    check_identity_files(&mut diagnostics);

    // Check 3: Remote paths are absolute
    check_remote_paths(&mut diagnostics);

    // Check 4: Glob pattern syntax
    check_glob_patterns(&config, &mut diagnostics);

    // Check 5: File permissions
    check_file_permissions(&mut diagnostics);

    // Check 6: Daemon status
    check_daemon_status(&mut diagnostics);

    output_doctor_results(ctx, diagnostics)
}

fn check_socket_path(config: &RchConfig, diagnostics: &mut Vec<DoctorDiagnostic>) {
    let socket_path = PathBuf::from(&config.general.socket_path);

    // Check if parent directory exists and is writable
    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            diagnostics.push(DoctorDiagnostic {
                severity: DoctorSeverity::Error,
                code: "DOC-E010".to_string(),
                message: format!("Socket directory does not exist: {}", parent.display()),
                detail: None,
                remediation: Some(format!("Create directory: mkdir -p {}", parent.display())),
            });
        } else {
            // Check writability by attempting to create a temp file
            let test_file = parent.join(".rch_write_test");
            match std::fs::File::create(&test_file) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&test_file);
                }
                Err(e) => {
                    diagnostics.push(DoctorDiagnostic {
                        severity: DoctorSeverity::Error,
                        code: "DOC-E011".to_string(),
                        message: format!("Socket directory is not writable: {}", parent.display()),
                        detail: Some(e.to_string()),
                        remediation: Some(format!(
                            "Fix permissions: chmod u+w {}",
                            parent.display()
                        )),
                    });
                }
            }
        }
    }

    // Check if socket already exists (stale socket)
    if socket_path.exists() {
        // Try to determine if it's a valid socket or stale
        diagnostics.push(DoctorDiagnostic {
            severity: DoctorSeverity::Info,
            code: "DOC-I010".to_string(),
            message: format!("Socket file exists: {}", socket_path.display()),
            detail: Some("This may be from a running daemon or a stale socket".to_string()),
            remediation: Some(
                "If daemon is not running, remove with: rm -f <socket_path>".to_string(),
            ),
        });
    }
}

fn check_identity_files(diagnostics: &mut Vec<DoctorDiagnostic>) {
    let workers = match load_workers_from_config() {
        Ok(w) => w,
        Err(_) => return, // Skip if workers can't be loaded
    };

    for worker in workers {
        let identity_path = expand_tilde(&worker.identity_file);

        if !identity_path.exists() {
            diagnostics.push(DoctorDiagnostic {
                severity: DoctorSeverity::Error,
                code: "DOC-E020".to_string(),
                message: format!(
                    "SSH identity file not found for worker '{}': {}",
                    worker.id, worker.identity_file
                ),
                detail: None,
                remediation: Some(format!(
                    "Generate key: ssh-keygen -t ed25519 -f {}",
                    worker.identity_file
                )),
            });
        } else {
            // Check permissions (should be 600 or 400)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = identity_path.metadata() {
                    let mode = metadata.permissions().mode() & 0o777;
                    if mode != 0o600 && mode != 0o400 {
                        diagnostics.push(DoctorDiagnostic {
                            severity: DoctorSeverity::Warning,
                            code: "DOC-W020".to_string(),
                            message: format!(
                                "Identity file has insecure permissions for worker '{}': {:o}",
                                worker.id, mode
                            ),
                            detail: Some(
                                "SSH may refuse to use keys with permissions too open".to_string(),
                            ),
                            remediation: Some(format!(
                                "Fix permissions: chmod 600 {}",
                                worker.identity_file
                            )),
                        });
                    }
                }
            }
        }
    }
}

fn check_remote_paths(_diagnostics: &mut Vec<DoctorDiagnostic>) {
    // WorkerConfig currently doesn't have optional remote path fields.
    // This check is a placeholder for when those fields are added.
    // Future checks could validate:
    // - remote_home is absolute
    // - remote_work_dir is absolute or ~-prefixed
}

fn check_glob_patterns(config: &RchConfig, diagnostics: &mut Vec<DoctorDiagnostic>) {
    use glob::Pattern;

    for (i, pattern) in config.transfer.exclude_patterns.iter().enumerate() {
        if let Err(e) = Pattern::new(pattern) {
            diagnostics.push(DoctorDiagnostic {
                severity: DoctorSeverity::Error,
                code: "DOC-E040".to_string(),
                message: format!(
                    "Invalid glob pattern in exclude_patterns[{}]: {}",
                    i, pattern
                ),
                detail: Some(e.to_string()),
                remediation: Some("Fix the pattern syntax in your configuration".to_string()),
            });
        }
    }
}

fn check_file_permissions(diagnostics: &mut Vec<DoctorDiagnostic>) {
    // Check config directory permissions
    if let Some(config_dir) = config_dir()
        && config_dir.exists()
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = config_dir.metadata() {
                let mode = metadata.permissions().mode() & 0o777;
                // Config dir should not be world-readable if it contains sensitive data
                if mode & 0o007 != 0 {
                    diagnostics.push(DoctorDiagnostic {
                        severity: DoctorSeverity::Warning,
                        code: "DOC-W050".to_string(),
                        message: format!("Config directory is world-accessible: {:o}", mode),
                        detail: Some(format!(
                            "Directory {} may contain sensitive configuration",
                            config_dir.display()
                        )),
                        remediation: Some(format!(
                            "Restrict access: chmod 700 {}",
                            config_dir.display()
                        )),
                    });
                }
            }
        }
    }

    // Check workers.toml permissions
    if let Some(workers_path) = config_dir().map(|d| d.join("workers.toml"))
        && workers_path.exists()
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = workers_path.metadata() {
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    diagnostics.push(DoctorDiagnostic {
                        severity: DoctorSeverity::Info,
                        code: "DOC-I050".to_string(),
                        message: format!("workers.toml is group/world accessible: {:o}", mode),
                        detail: Some(
                            "Consider restricting if it contains sensitive paths".to_string(),
                        ),
                        remediation: Some(format!(
                            "Restrict access: chmod 600 {}",
                            workers_path.display()
                        )),
                    });
                }
            }
        }
    }
}

fn check_daemon_status(diagnostics: &mut Vec<DoctorDiagnostic>) {
    // Try to connect to daemon socket
    let config = match config::load_config() {
        Ok(c) => c,
        Err(_) => return,
    };

    let socket_path = PathBuf::from(&config.general.socket_path);

    #[cfg(unix)]
    {
        if socket_path.exists() {
            // Socket exists, try a quick connection test
            match std::os::unix::net::UnixStream::connect(&socket_path) {
                Ok(_) => {
                    diagnostics.push(DoctorDiagnostic {
                        severity: DoctorSeverity::Info,
                        code: "DOC-I060".to_string(),
                        message: "Daemon is running and accepting connections".to_string(),
                        detail: None,
                        remediation: None,
                    });
                }
                Err(e) => {
                    diagnostics.push(DoctorDiagnostic {
                        severity: DoctorSeverity::Warning,
                        code: "DOC-W060".to_string(),
                        message: "Socket exists but connection failed".to_string(),
                        detail: Some(e.to_string()),
                        remediation: Some("Try: rch daemon restart".to_string()),
                    });
                }
            }
        } else {
            diagnostics.push(DoctorDiagnostic {
                severity: DoctorSeverity::Warning,
                code: "DOC-W061".to_string(),
                message: "Daemon does not appear to be running".to_string(),
                detail: Some(format!("No socket at {}", socket_path.display())),
                remediation: Some("Start daemon with: rch daemon start".to_string()),
            });
        }
    }

    #[cfg(not(unix))]
    {
        let _ = socket_path;
        diagnostics.push(DoctorDiagnostic {
            severity: DoctorSeverity::Info,
            code: "DOC-I062".to_string(),
            message: "Daemon status check skipped (Unix sockets not available on this platform)"
                .to_string(),
            detail: None,
            remediation: None,
        });
    }
}

fn output_doctor_results(ctx: &OutputContext, diagnostics: Vec<DoctorDiagnostic>) -> Result<()> {
    let style = ctx.theme();

    let error_count = diagnostics
        .iter()
        .filter(|d| matches!(d.severity, DoctorSeverity::Error))
        .count();
    let warning_count = diagnostics
        .iter()
        .filter(|d| matches!(d.severity, DoctorSeverity::Warning))
        .count();
    let info_count = diagnostics
        .iter()
        .filter(|d| matches!(d.severity, DoctorSeverity::Info))
        .count();

    let response = ConfigDoctorResponse {
        diagnostics: diagnostics.clone(),
        error_count,
        warning_count,
        info_count,
        healthy: error_count == 0,
    };

    if ctx.is_json() {
        let _ = ctx.json(&response);
        if error_count > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Human-readable output
    println!();
    println!("{}", style.format_header("Configuration Doctor"));
    println!();

    if diagnostics.is_empty() {
        println!("  {} All checks passed!", style.success("✓"));
    } else {
        for diag in &diagnostics {
            let (icon, _severity_style) = match diag.severity {
                DoctorSeverity::Error => (style.error("✗"), "error"),
                DoctorSeverity::Warning => (style.warning("!"), "warning"),
                DoctorSeverity::Info => (style.info("i"), "info"),
            };

            println!("  {} [{}] {}", icon, diag.code, diag.message);
            if let Some(ref detail) = diag.detail {
                println!("      {}", style.muted(detail));
            }
            if let Some(ref remediation) = diag.remediation {
                println!("      {}", style.highlight(&format!("→ {}", remediation)));
            }
            println!();
        }

        // Summary
        let mut summary_parts = Vec::new();
        if error_count > 0 {
            summary_parts.push(format!(
                "{} error{}",
                error_count,
                if error_count == 1 { "" } else { "s" }
            ));
        }
        if warning_count > 0 {
            summary_parts.push(format!(
                "{} warning{}",
                warning_count,
                if warning_count == 1 { "" } else { "s" }
            ));
        }
        if info_count > 0 {
            summary_parts.push(format!("{} info", info_count));
        }

        let status = if error_count > 0 {
            style.error("unhealthy")
        } else if warning_count > 0 {
            style.warning("healthy with warnings")
        } else {
            style.success("healthy")
        };

        println!("  Status: {} ({})", status, summary_parts.join(", "));
    }

    if error_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Expand ~ to home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    } else if path == "~"
        && let Some(home) = dirs::home_dir()
    {
        return home;
    }
    PathBuf::from(path)
}
