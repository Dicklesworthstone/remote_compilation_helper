//! Configuration doctor command for diagnosing issues.
//!
//! This module handles the `rch config doctor` command, which performs
//! deeper health checks than `config lint`.

use anyhow::Result;
use rch_common::RchConfig;
use schemars::JsonSchema;
use serde::Serialize;
use std::path::{Path, PathBuf};

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
/// - Built-in transfer exclusions omitted by replacement lists
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
    check_transfer_defaults(&config, &mut diagnostics);

    // Check 5: File permissions
    check_file_permissions(&mut diagnostics);

    // Check 6: Daemon status
    check_daemon_status(&config, &mut diagnostics);

    // Check 7: Remediation knobs (bd-...remediation-ocv9i.17.2)
    check_remediation_config(&config, &mut diagnostics);

    output_doctor_results(ctx, diagnostics)
}

/// Check 7: validate the central remediation knobs
/// (bd-...remediation-ocv9i.17.2).
///
/// Maps each `RemediationConfig::validate()` finding to a doctor diagnostic so
/// unsafe, contradictory, or out-of-range remediation settings are reported
/// here with a concrete next step. When everything validates, emit one Info so
/// operators can see the section was checked (defaults apply where unset).
fn check_remediation_config(config: &RchConfig, diagnostics: &mut Vec<DoctorDiagnostic>) {
    let issues = config.remediation.validate();
    if issues.is_empty() {
        diagnostics.push(DoctorDiagnostic {
            severity: DoctorSeverity::Info,
            code: "DOC-I100".to_string(),
            message: "Remediation settings are valid".to_string(),
            detail: Some(
                "All [remediation] knobs are within safe ranges (defaults apply where unset)."
                    .to_string(),
            ),
            remediation: None,
        });
        return;
    }
    for issue in issues {
        let (severity, code) = match issue.severity {
            rch_common::remediation_config::IssueSeverity::Error => {
                (DoctorSeverity::Error, "DOC-E100")
            }
            rch_common::remediation_config::IssueSeverity::Warning => {
                (DoctorSeverity::Warning, "DOC-W100")
            }
        };
        diagnostics.push(DoctorDiagnostic {
            severity,
            code: code.to_string(),
            message: format!("{}: {}", issue.field, issue.message),
            detail: None,
            remediation: Some(format!(
                "Adjust `{}` under [remediation] (or the matching RCH_REMEDIATION_* env var).",
                issue.field
            )),
        });
    }
}

fn configured_socket_path(config: &RchConfig) -> PathBuf {
    PathBuf::from(shellexpand::tilde(&config.general.socket_path).into_owned())
}

fn probe_socket_directory(parent: &Path) -> std::io::Result<()> {
    use std::io::Write;

    // Never open a predictable shared pathname with truncation. Besides
    // clobbering an existing file, that followed .rch_write_test symlinks and
    // could block on a FIFO. An anonymous tempfile owns only its own inode,
    // including when concurrent doctors inspect the same socket directory.
    let mut probe = tempfile::tempfile_in(parent)?;
    // Creating an empty inode alone does not detect block quotas or delayed
    // write failures. Flush only this private probe, never the filesystem.
    probe.write_all(b"RCH_SOCKET_DIRECTORY_PROBE\n")?;
    probe.sync_all()
}

fn check_socket_path(config: &RchConfig, diagnostics: &mut Vec<DoctorDiagnostic>) {
    let socket_path = configured_socket_path(config);

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
            match probe_socket_directory(parent) {
                Ok(()) => {}
                Err(e) => {
                    diagnostics.push(DoctorDiagnostic {
                        severity: DoctorSeverity::Error,
                        code: "DOC-E011".to_string(),
                        message: format!(
                            "Socket directory write probe failed: {}",
                            parent.display()
                        ),
                        detail: Some(e.to_string()),
                        remediation: Some(
                            "Check directory permissions, free space, and user quotas".to_string(),
                        ),
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
                "Check ownership with 'rch daemon status' before changing the socket".to_string(),
            ),
        });
    }
}

fn check_identity_files(diagnostics: &mut Vec<DoctorDiagnostic>) {
    let workers = match load_workers_from_config() {
        Ok(w) => w,
        Err(_) => return, // Skip if workers can't be loaded
    };

    // Group workers by (expanded) identity_file so a shared missing key only
    // produces one diagnostic that names every referencing worker.
    let mut by_identity: std::collections::BTreeMap<PathBuf, Vec<String>> =
        std::collections::BTreeMap::new();

    for worker in &workers {
        let identity_path = match shellexpand::full(&worker.identity_file) {
            Ok(expanded) => PathBuf::from(expanded.into_owned()),
            Err(err) => {
                diagnostics.push(DoctorDiagnostic {
                    severity: DoctorSeverity::Error,
                    code: "RCH-E009".to_string(),
                    message: format!(
                        "identity_file {:?} for worker '{}' is unresolvable: {}",
                        worker.identity_file, worker.id, err
                    ),
                    detail: None,
                    remediation: Some(
                        "Set the referenced environment variable, or replace the reference \
                        with an absolute path / ~-relative path in workers.toml"
                            .to_string(),
                    ),
                });
                continue;
            }
        };
        by_identity
            .entry(identity_path)
            .or_default()
            .push(worker.id.as_str().to_string());
    }

    for (identity_path, worker_ids) in &by_identity {
        if !identity_path.exists() {
            let referencing = worker_ids.join(", ");
            diagnostics.push(DoctorDiagnostic {
                severity: DoctorSeverity::Error,
                code: "RCH-E009".to_string(),
                message: format!(
                    "SSH identity file not found: {} (referenced by workers: {})",
                    identity_path.display(),
                    referencing
                ),
                detail: None,
                remediation: Some(format!(
                    "Generate key: ssh-keygen -t ed25519 -f {}",
                    identity_path.display()
                )),
            });
            continue;
        }
        check_shared_identity_file_permissions(identity_path, worker_ids, diagnostics);
    }
}

/// Emit at most one permissions warning per unique identity_file, listing
/// every worker that references it. Keeps `rch config doctor` output short
/// when many workers share a single key.
fn check_shared_identity_file_permissions(
    identity_path: &Path,
    worker_ids: &[String],
    diagnostics: &mut Vec<DoctorDiagnostic>,
) {
    #[cfg(not(unix))]
    {
        let _ = (identity_path, worker_ids, diagnostics);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(metadata) = identity_path.metadata() else {
            return;
        };
        let mode = metadata.permissions().mode() & 0o777;
        if mode == 0o600 || mode == 0o400 {
            return;
        }
        diagnostics.push(DoctorDiagnostic {
            severity: DoctorSeverity::Warning,
            code: "DOC-W020".to_string(),
            message: format!(
                "Identity file {} has insecure permissions {:o} (referenced by workers: {})",
                identity_path.display(),
                mode,
                worker_ids.join(", ")
            ),
            detail: Some("SSH may refuse to use keys with permissions too open".to_string()),
            remediation: Some(format!(
                "Fix permissions: chmod 600 {}",
                identity_path.display()
            )),
        });
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

/// An explicit exclusion list replaces, rather than extends, built-in defaults.
/// Audit the effective list so old user/project lists cannot silently hide newly
/// added protections (bd-rqjaj). This is a literal default-presence check, not a
/// second rsync matcher or a claim that any particular file was transferred.
fn check_transfer_defaults(config: &RchConfig, diagnostics: &mut Vec<DoctorDiagnostic>) {
    let missing = config.transfer.unacknowledged_omitted_default_excludes();
    if missing.is_empty() {
        return;
    }
    diagnostics.push(DoctorDiagnostic {
        severity: DoctorSeverity::Warning,
        code: "DOC-W041".to_string(),
        message: format!(
            "Effective transfer exclusions omit {} built-in default pattern(s)",
            missing.len()
        ),
        // Only built-in pattern names are reported. Do not read source files
        // or echo unrelated custom patterns, paths, or credential contents.
        detail: Some(format!(
            "Missing defaults: {missing:?}. Custom [transfer] exclude_patterns replace \
             defaults, including later credential and agent-state protections. Other \
             rules may cover the same files; this is not a transfer inventory."
        )),
        remediation: Some(
            "Review and add the missing patterns to the effective [transfer] exclude_patterns \
             list, or remove the overriding list to inherit current defaults; list deliberate \
             omissions in [transfer] exclude_defaults_acknowledged. Check both user and \
             project configuration. No exclusions or worker files were changed."
                .to_string(),
        ),
    });
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

fn check_daemon_status(config: &RchConfig, diagnostics: &mut Vec<DoctorDiagnostic>) {
    let socket_path = configured_socket_path(config);

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
        ctx.json(&response)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_defaults_and_reordered_supersets_are_quiet() {
        let mut config = RchConfig::default();
        for customized in [false, true] {
            if customized {
                config.transfer.exclude_patterns.reverse();
                config
                    .transfer
                    .exclude_patterns
                    .push("private-fixture/".into());
                config.transfer.exclude_patterns.push(".env".into());
            }
            let original = config.transfer.exclude_patterns.clone();
            let mut diagnostics = Vec::new();
            check_transfer_defaults(&config, &mut diagnostics);
            assert!(diagnostics.is_empty());
            assert_eq!(config.transfer.exclude_patterns, original);
        }
    }

    #[test]
    fn stale_custom_exclusions_name_credential_and_agent_state_defaults() {
        let mut config = RchConfig::default();
        for pattern in [".env", ".ntm/"] {
            assert!(
                config
                    .transfer
                    .exclude_patterns
                    .iter()
                    .any(|p| p == pattern)
            );
        }
        config
            .transfer
            .exclude_patterns
            .retain(|p| p != ".env" && p != ".ntm/");
        config
            .transfer
            .exclude_patterns
            .push("tenant-private-name".into());
        let original = config.transfer.exclude_patterns.clone();
        let mut diagnostics = Vec::new();
        check_transfer_defaults(&config, &mut diagnostics);
        assert_eq!(diagnostics.len(), 1);
        let warning = &diagnostics[0];
        assert!(matches!(warning.severity, DoctorSeverity::Warning));
        assert_eq!(warning.code, "DOC-W041");
        assert!(warning.message.contains("2 built-in"));
        let detail = warning.detail.as_deref().unwrap();
        assert!(detail.contains("\".env\"") && detail.contains("\".ntm/\""));
        assert!(!detail.contains("tenant-private-name"));
        assert!(warning.remediation.as_deref().unwrap().contains("project"));
        assert_eq!(config.transfer.exclude_patterns, original);
    }

    #[test]
    fn exclusion_audit_tracks_every_default_without_hardcoded_security_subsets() {
        let defaults = rch_common::TransferConfig::default().exclude_patterns;
        assert!(!defaults.is_empty());
        for omitted in &defaults {
            let mut config = RchConfig::default();
            config.transfer.exclude_patterns.retain(|p| p != omitted);
            let mut diagnostics = Vec::new();
            check_transfer_defaults(&config, &mut diagnostics);
            assert_eq!(diagnostics.len(), 1, "{omitted}");
            assert!(diagnostics[0].message.contains("1 built-in"), "{omitted}");
            assert!(diagnostics[0].detail.as_deref().unwrap().contains(omitted));
        }
    }

    #[test]
    fn acknowledged_omissions_are_quiet_and_others_still_warn() {
        let mut config = RchConfig::default();
        config
            .transfer
            .exclude_patterns
            .retain(|p| p != "*.pem" && p != "*.key" && p != ".env");
        config.transfer.exclude_defaults_acknowledged = vec!["*.pem".into(), "*.key".into()];
        let mut diagnostics = Vec::new();
        check_transfer_defaults(&config, &mut diagnostics);
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.contains("1 built-in"));
        let detail = diagnostics[0].detail.as_deref().unwrap();
        assert!(detail.contains("\".env\""));
        assert!(!detail.contains("*.pem") && !detail.contains("*.key"));

        config.transfer.exclude_patterns.push(".env".into());
        diagnostics.clear();
        check_transfer_defaults(&config, &mut diagnostics);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn empty_and_alternate_rules_do_not_masquerade_as_default_lists() {
        for patterns in [Vec::new(), vec!["*".to_string(), "/.env".to_string()]] {
            let mut config = RchConfig::default();
            config.transfer.exclude_patterns = patterns.clone();
            let mut diagnostics = Vec::new();
            check_transfer_defaults(&config, &mut diagnostics);
            assert_eq!(diagnostics.len(), 1);
            assert!(
                diagnostics[0]
                    .detail
                    .as_deref()
                    .unwrap()
                    .contains("not a transfer inventory")
            );
            assert_eq!(config.transfer.exclude_patterns, patterns);
        }
    }

    #[test]
    fn socket_probe_never_truncates_or_removes_the_legacy_probe_name() {
        let root = tempfile::tempdir().unwrap().keep();
        let legacy = root.join(".rch_write_test");
        let content = b"pre-existing operator data must survive";
        std::fs::write(&legacy, content).unwrap();
        for _ in 0..3 {
            probe_socket_directory(&root).unwrap();
            assert_eq!(std::fs::read(&legacy).unwrap(), content);
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn socket_probe_does_not_follow_legacy_symlinks_or_modify_hardlinks() {
        use std::os::unix::fs::{MetadataExt, symlink};

        let root = tempfile::tempdir().unwrap().keep();
        let victim = root.join("operator-state");
        std::fs::write(&victim, b"retained bytes").unwrap();
        for linked in [false, true] {
            let directory = root.join(if linked { "hardlink" } else { "symlink" });
            std::fs::create_dir(&directory).unwrap();
            let legacy = directory.join(".rch_write_test");
            if linked {
                std::fs::hard_link(&victim, &legacy).unwrap();
            } else {
                symlink(&victim, &legacy).unwrap();
            }
            let before = std::fs::metadata(&victim).unwrap();
            probe_socket_directory(&directory).unwrap();
            let after = std::fs::metadata(&victim).unwrap();
            assert_eq!(std::fs::read(&victim).unwrap(), b"retained bytes");
            assert_eq!(before.ino(), after.ino());
            assert_eq!(before.nlink(), after.nlink());
            assert_eq!(
                std::fs::symlink_metadata(&legacy)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                !linked
            );
        }
    }

    #[test]
    fn socket_probe_handles_concurrent_checks_and_non_directory_failures() {
        let root = tempfile::tempdir().unwrap().keep();
        std::thread::scope(|scope| {
            let checks: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| probe_socket_directory(&root)))
                .collect();
            for check in checks {
                check.join().unwrap().unwrap();
            }
        });
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        let file = root.join("not-a-directory");
        std::fs::write(&file, b"unchanged").unwrap();
        assert!(probe_socket_directory(&file).is_err());
        assert!(probe_socket_directory(&root.join("missing")).is_err());
        assert_eq!(std::fs::read(file).unwrap(), b"unchanged");
    }

    #[test]
    fn socket_probe_failures_reach_diagnostics_without_changing_existing_paths() {
        let root = tempfile::tempdir().unwrap().keep();
        let existing_file = root.join("file");
        std::fs::write(&existing_file, b"retain").unwrap();
        for (parent, expected) in [
            (root.join("missing"), "DOC-E010"),
            (existing_file.clone(), "DOC-E011"),
        ] {
            let mut config = RchConfig::default();
            config.general.socket_path = parent.join("rch.sock").to_string_lossy().into_owned();
            let mut diagnostics = Vec::new();
            check_socket_path(&config, &mut diagnostics);
            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].code, expected);
            assert!(matches!(diagnostics[0].severity, DoctorSeverity::Error));
        }
        assert_eq!(std::fs::read(existing_file).unwrap(), b"retain");
        assert!(!root.join("missing").exists());
    }

    #[test]
    fn transfer_default_warnings_reach_json_and_toon_without_becoming_errors() {
        use crate::ui::context::{ColorChoice, OutputConfig, OutputFormat, OutputMode};
        use crate::ui::writer::OutputWriter;

        let root = tempfile::tempdir().unwrap().keep();
        for format in [OutputFormat::Json, OutputFormat::Toon] {
            let path = root.join(format!("{format:?}.output"));
            let ctx = OutputContext::with_writers(
                OutputConfig {
                    force_mode: Some(OutputMode::Json),
                    color: ColorChoice::Never,
                    format,
                    ..Default::default()
                },
                OutputWriter::new(std::fs::File::create_new(&path).unwrap(), false),
                OutputWriter::stderr(),
            );
            let mut config = RchConfig::default();
            config.transfer.exclude_patterns.retain(|p| p != ".env");
            let mut diagnostics = Vec::new();
            check_transfer_defaults(&config, &mut diagnostics);
            output_doctor_results(&ctx, diagnostics).unwrap();
            let bytes = std::fs::read(path).unwrap();
            let report: serde_json::Value = if format == OutputFormat::Toon {
                serde_json::from_str(
                    &toon_rust::toon_to_json(std::str::from_utf8(&bytes).unwrap()).unwrap(),
                )
                .unwrap()
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            assert_eq!(report["healthy"], true);
            assert_eq!(report["error_count"].as_f64(), Some(0.0));
            assert_eq!(report["warning_count"].as_f64(), Some(1.0));
            assert_eq!(report["diagnostics"][0]["severity"], "warning");
            assert_eq!(report["diagnostics"][0]["code"], "DOC-W041");
            assert!(
                report["diagnostics"][0]["detail"]
                    .as_str()
                    .unwrap()
                    .contains(".env")
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn doctor_reporter_delivers_formats_and_propagates_real_output_failures() {
        use crate::ui::context::{
            ColorChoice, OutputConfig, OutputError, OutputFormat, OutputMode,
        };
        use crate::ui::writer::OutputWriter;
        use std::os::unix::net::UnixStream;

        let retained = tempfile::tempdir().unwrap().keep();
        for format in [OutputFormat::Json, OutputFormat::Toon] {
            for closed in [false, true] {
                let path = retained.join(format!("{format:?}-{closed}.output"));
                let stdout = if closed {
                    let (socket, peer) = UnixStream::pair().unwrap();
                    socket
                        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                        .unwrap();
                    drop(peer);
                    OutputWriter::new(socket, false)
                } else {
                    OutputWriter::new(std::fs::File::create_new(&path).unwrap(), false)
                };
                let ctx = OutputContext::with_writers(
                    OutputConfig {
                        force_mode: Some(OutputMode::Json),
                        color: ColorChoice::Never,
                        format,
                        ..Default::default()
                    },
                    stdout,
                    OutputWriter::stderr(),
                );
                // Reporter-only test: an empty diagnostic set is not a claim
                // about actual configuration, daemon or worker health.
                let result = output_doctor_results(&ctx, Vec::new());
                if closed {
                    let error = result.unwrap_err();
                    assert!(matches!(
                        error.downcast_ref::<OutputError>(),
                        Some(OutputError::Delivery(cause))
                            if cause.kind() == std::io::ErrorKind::BrokenPipe
                    ));
                    assert!(!path.exists());
                } else {
                    result.unwrap();
                    let bytes = std::fs::read(path).unwrap();
                    let report = if format == OutputFormat::Toon {
                        serde_json::from_str::<serde_json::Value>(
                            &toon_rust::toon_to_json(std::str::from_utf8(&bytes).unwrap()).unwrap(),
                        )
                        .unwrap()
                    } else {
                        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
                    };
                    assert_eq!(report["healthy"], true);
                    assert_eq!(report["diagnostics"], serde_json::json!([]));
                    // TOON decodes every number as f64, so compare numerically.
                    for count in ["error_count", "warning_count", "info_count"] {
                        assert_eq!(report[count].as_f64(), Some(0.0), "{format:?} {count}");
                    }
                }
            }
        }
    }

    #[test]
    fn configured_socket_path_expands_tilde() {
        let mut config = RchConfig::default();
        config.general.socket_path = "~/rch-config-doctor.sock".to_string();

        let socket_path = configured_socket_path(&config);

        assert_ne!(socket_path, PathBuf::from("~/rch-config-doctor.sock"));
        assert!(socket_path.ends_with("rch-config-doctor.sock"));
    }
}
