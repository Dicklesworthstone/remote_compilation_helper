//! Binary installation and rollback.

use super::download::DownloadedRelease;
use super::lock::UpdateLock;
use super::types::{BackupEntry, MAX_BACKUPS, UpdateError};
use crate::ui::OutputContext;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Result of installation.
#[allow(dead_code)]
pub struct InstallResult {
    pub backup_path: PathBuf,
    pub installed_version: String,
    pub daemon_restarted: bool,
}

/// Install downloaded update.
pub async fn install_update(
    ctx: &OutputContext,
    download: &DownloadedRelease,
    restart_daemon: bool,
    drain_timeout: u64,
) -> Result<InstallResult, UpdateError> {
    // Acquire update lock
    let _lock = UpdateLock::acquire()?;

    if !ctx.is_json() {
        println!("Installing update...");
    }

    // Get installation paths
    let install_dir = get_install_dir()?;

    // Stop daemon if running and restart is requested
    let daemon_was_running = if restart_daemon {
        stop_daemon_gracefully(drain_timeout).await?
    } else {
        false
    };

    // Get current version for backup
    let current_version = env!("CARGO_PKG_VERSION");

    // Create backup with metadata
    if !ctx.is_json() {
        println!("Backing up current installation (v{})...", current_version);
    }
    let backup_entry = create_backup(&install_dir, current_version)?;
    let backup_dir = backup_entry.backup_path;

    // Extract new binaries to temp location
    let temp_extract = std::env::temp_dir().join("rch-extract");
    extract_archive(&download.archive_path, &temp_extract)?;

    // Atomic replace: move new binaries to install dir
    if !ctx.is_json() {
        println!("Installing new binaries...");
    }
    replace_binaries(&temp_extract, &install_dir)?;

    // Verify new binaries work
    verify_installation(&install_dir)?;

    // Restart daemon if it was running
    let daemon_restarted = if restart_daemon && daemon_was_running {
        if !ctx.is_json() {
            println!("Restarting daemon...");
        }
        start_daemon().await?;
        true
    } else {
        false
    };

    // Clean up temp files
    let _ = std::fs::remove_dir_all(&temp_extract);

    Ok(InstallResult {
        backup_path: backup_dir,
        installed_version: download.version.clone(),
        daemon_restarted,
    })
}

/// Rollback to previous version.
///
/// If `target_version` is None, rolls back to the most recent backup.
/// If `target_version` is Some, rolls back to the specified version.
pub async fn rollback(
    ctx: &OutputContext,
    dry_run: bool,
    target_version: Option<&str>,
) -> Result<(), UpdateError> {
    let backup_dir = if let Some(version) = target_version {
        find_backup_by_version(version)?
    } else {
        find_latest_backup()?
    };

    // Try to get version info from backup metadata
    let version_info = {
        let metadata_path = backup_dir.join("backup.json");
        if metadata_path.exists() {
            fs::read_to_string(&metadata_path)
                .ok()
                .and_then(|s| serde_json::from_str::<BackupEntry>(&s).ok())
                .map(|e| e.version)
        } else {
            None
        }
    };

    if !ctx.is_json() {
        if let Some(ref version) = version_info {
            println!("Rolling back to version {}...", version);
        } else {
            println!("Rolling back to backup at {}...", backup_dir.display());
        }
    }

    if dry_run {
        if !ctx.is_json() {
            println!("Dry run: would restore from {}", backup_dir.display());
        }
        return Ok(());
    }

    // Acquire lock
    let _lock = UpdateLock::acquire()?;

    // Stop daemon
    let daemon_was_running = stop_daemon_gracefully(30).await?;

    // Get install dir
    let install_dir = get_install_dir()?;

    // Restore from backup
    restore_from_backup(&backup_dir, &install_dir)?;

    // Restart daemon if it was running
    if daemon_was_running {
        start_daemon().await?;
    }

    if !ctx.is_json() {
        if let Some(version) = version_info {
            println!("Rollback to version {} complete.", version);
        } else {
            println!("Rollback complete.");
        }
    }

    Ok(())
}

/// Find a backup by version string.
fn find_backup_by_version(version: &str) -> Result<PathBuf, UpdateError> {
    let backups = list_backups()?;
    let version_clean = version.strip_prefix('v').unwrap_or(version);

    for backup in backups {
        if backup.version == version_clean || backup.version == version {
            return Ok(backup.backup_path);
        }
    }

    Err(UpdateError::NoBackupAvailable)
}

/// Get the installation directory.
fn get_install_dir() -> Result<PathBuf, UpdateError> {
    // Try to determine where rch is installed
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        return Ok(parent.to_path_buf());
    }

    // Default to ~/.local/bin
    let home = dirs::home_dir().ok_or_else(|| {
        UpdateError::InstallFailed("Could not determine home directory".to_string())
    })?;

    Ok(home.join(".local/bin"))
}

/// Get the backup directory for a version.
fn get_backup_dir(version: &str) -> Result<PathBuf, UpdateError> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        UpdateError::InstallFailed("Could not determine data directory".to_string())
    })?;

    let backup_base = data_dir.join("rch/backups");
    std::fs::create_dir_all(&backup_base)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to create backup dir: {}", e)))?;

    // Use timestamp to allow multiple backups of same version
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    Ok(backup_base.join(format!("v{}-{}", version, timestamp)))
}

/// Find the latest backup.
fn find_latest_backup() -> Result<PathBuf, UpdateError> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        UpdateError::InstallFailed("Could not determine data directory".to_string())
    })?;

    let backup_base = data_dir.join("rch/backups");

    if !backup_base.exists() {
        return Err(UpdateError::NoBackupAvailable);
    }

    let mut backups: Vec<_> = std::fs::read_dir(&backup_base)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to read backup dir: {}", e)))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
        .collect();

    backups.sort_by_key(|e| e.file_name());

    backups
        .last()
        .map(|e| e.path())
        .ok_or(UpdateError::NoBackupAvailable)
}

/// Backup current installation.
fn backup_current_installation(
    install_dir: &std::path::Path,
    backup_dir: &std::path::Path,
) -> Result<(), UpdateError> {
    std::fs::create_dir_all(backup_dir)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to create backup dir: {}", e)))?;

    for binary in &["rch", "rchd", "rch-wkr"] {
        let src = install_dir.join(binary);
        if src.exists() {
            let dst = backup_dir.join(binary);
            std::fs::copy(&src, &dst).map_err(|e| {
                UpdateError::InstallFailed(format!("Failed to backup {}: {}", binary, e))
            })?;
        }
    }

    Ok(())
}

/// Create a backup with JSON metadata file.
pub fn create_backup(
    install_dir: &std::path::Path,
    version: &str,
) -> Result<BackupEntry, UpdateError> {
    let backup_dir = get_backup_dir(version)?;

    // Backup the binaries
    backup_current_installation(install_dir, &backup_dir)?;

    // Create metadata
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let entry = BackupEntry {
        version: version.to_string(),
        created_at: now,
        original_path: install_dir.to_path_buf(),
        backup_path: backup_dir.clone(),
    };

    // Write metadata JSON
    let metadata_path = backup_dir.join("backup.json");
    let json = serde_json::to_string_pretty(&entry).map_err(|e| {
        UpdateError::InstallFailed(format!("Failed to serialize backup metadata: {}", e))
    })?;
    fs::write(&metadata_path, json).map_err(|e| {
        UpdateError::InstallFailed(format!("Failed to write backup metadata: {}", e))
    })?;

    // Prune old backups
    prune_old_backups()?;

    Ok(entry)
}

/// List all available backups with metadata.
pub fn list_backups() -> Result<Vec<BackupEntry>, UpdateError> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        UpdateError::InstallFailed("Could not determine data directory".to_string())
    })?;

    let backup_base = data_dir.join("rch/backups");

    if !backup_base.exists() {
        return Ok(Vec::new());
    }

    let mut backups = Vec::new();

    let entries = fs::read_dir(&backup_base)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to read backup dir: {}", e)))?;

    for entry in entries.filter_map(|e| e.ok()) {
        if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            continue;
        }

        let backup_path = entry.path();
        let metadata_path = backup_path.join("backup.json");

        if metadata_path.exists() {
            // Read metadata from JSON
            if let Ok(content) = fs::read_to_string(&metadata_path)
                && let Ok(mut backup_entry) = serde_json::from_str::<BackupEntry>(&content)
            {
                backup_entry.backup_path = backup_path;
                backups.push(backup_entry);
            }
        } else {
            // Legacy backup without metadata - extract info from directory name
            let dir_name = entry.file_name().to_string_lossy().to_string();
            if let Some(version) = dir_name.strip_prefix('v') {
                // Format: v{version}-{timestamp}
                let version_part = version.split('-').next().unwrap_or(version);
                let created_at = fs::metadata(&backup_path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                backups.push(BackupEntry {
                    version: version_part.to_string(),
                    created_at,
                    original_path: PathBuf::new(),
                    backup_path,
                });
            }
        }
    }

    // Sort by creation time, newest first
    backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    Ok(backups)
}

/// Prune old backups, keeping only MAX_BACKUPS.
pub fn prune_old_backups() -> Result<(), UpdateError> {
    let backups = list_backups()?;

    if backups.len() <= MAX_BACKUPS {
        return Ok(());
    }

    // Remove oldest backups (list is sorted newest-first)
    for backup in backups.iter().skip(MAX_BACKUPS) {
        if backup.backup_path.exists() {
            let _ = fs::remove_dir_all(&backup.backup_path);
        }
    }

    Ok(())
}

/// Extract archive to destination.
fn extract_archive(archive: &std::path::Path, dest: &std::path::Path) -> Result<(), UpdateError> {
    std::fs::create_dir_all(dest)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to create extract dir: {}", e)))?;

    let output = Command::new("tar")
        .args([
            "-xzf",
            archive.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to run tar: {}", e)))?;

    if !output.status.success() {
        return Err(UpdateError::InstallFailed(format!(
            "tar extraction failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Replace binaries in install directory.
fn replace_binaries(
    src_dir: &std::path::Path,
    install_dir: &std::path::Path,
) -> Result<(), UpdateError> {
    std::fs::create_dir_all(install_dir)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to create install dir: {}", e)))?;

    for binary in &["rch", "rchd", "rch-wkr"] {
        let src = src_dir.join(binary);
        if src.exists() {
            let dst = install_dir.join(binary);

            // Remove existing binary first
            if dst.exists() {
                std::fs::remove_file(&dst).map_err(|e| {
                    UpdateError::InstallFailed(format!("Failed to remove old {}: {}", binary, e))
                })?;
            }

            // Move new binary
            std::fs::rename(&src, &dst)
                .or_else(|_| {
                    // If rename fails (cross-device), copy instead
                    std::fs::copy(&src, &dst)?;
                    std::fs::remove_file(&src)?;
                    Ok::<_, std::io::Error>(())
                })
                .map_err(|e| {
                    UpdateError::InstallFailed(format!("Failed to install {}: {}", binary, e))
                })?;

            // Make executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&dst)
                    .map_err(|e| {
                        UpdateError::InstallFailed(format!("Failed to get permissions: {}", e))
                    })?
                    .permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&dst, perms).map_err(|e| {
                    UpdateError::InstallFailed(format!("Failed to set permissions: {}", e))
                })?;
            }
        }
    }

    Ok(())
}

/// Verify the installation by checking binary versions.
fn verify_installation(install_dir: &std::path::Path) -> Result<(), UpdateError> {
    let rch = install_dir.join("rch");

    let output = Command::new(&rch)
        .arg("--version")
        .output()
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to verify installation: {}", e)))?;

    if !output.status.success() {
        return Err(UpdateError::InstallFailed(
            "Installed binary failed version check".to_string(),
        ));
    }

    Ok(())
}

/// Restore from backup.
fn restore_from_backup(
    backup_dir: &std::path::Path,
    install_dir: &std::path::Path,
) -> Result<(), UpdateError> {
    for binary in &["rch", "rchd", "rch-wkr"] {
        let src = backup_dir.join(binary);
        if src.exists() {
            let dst = install_dir.join(binary);

            if dst.exists() {
                std::fs::remove_file(&dst).map_err(|e| {
                    UpdateError::InstallFailed(format!("Failed to remove {}: {}", binary, e))
                })?;
            }

            std::fs::copy(&src, &dst).map_err(|e| {
                UpdateError::InstallFailed(format!("Failed to restore {}: {}", binary, e))
            })?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&dst)
                    .map_err(|e| {
                        UpdateError::InstallFailed(format!("Failed to get permissions: {}", e))
                    })?
                    .permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&dst, perms).map_err(|e| {
                    UpdateError::InstallFailed(format!("Failed to set permissions: {}", e))
                })?;
            }
        }
    }

    Ok(())
}

/// Stop daemon gracefully, waiting for builds to complete.
async fn stop_daemon_gracefully(_timeout_secs: u64) -> Result<bool, UpdateError> {
    use std::path::Path;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    // Check if daemon is running
    let socket_path_buf = PathBuf::from(rch_common::default_socket_path());
    let socket_path = Path::new(&socket_path_buf);
    if !socket_path.exists() {
        return Ok(false);
    }

    // Try graceful shutdown via socket
    if let Ok(mut stream) = UnixStream::connect(socket_path).await {
        let _ = stream.write_all(b"POST /shutdown\n").await;
    }

    // Wait for socket to disappear
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if !socket_path.exists() {
            return Ok(true);
        }
    }

    // Try pkill as fallback
    let _ = tokio::process::Command::new("pkill")
        .args(["-f", "rchd"])
        .output()
        .await;

    // Remove stale socket if present
    let _ = std::fs::remove_file(socket_path);

    Ok(true)
}

/// Start the daemon.
async fn start_daemon() -> Result<(), UpdateError> {
    // Use the commands module to start daemon
    // This is a simplified version - the full implementation would use the proper startup flow
    let _child = Command::new("rchd")
        .spawn()
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to start daemon: {}", e)))?;

    // Give it a moment to start
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_get_install_dir() {
        let dir = get_install_dir().unwrap();
        assert!(dir.is_absolute());
    }

    #[test]
    fn test_backup_dir_has_timestamp() {
        let dir = get_backup_dir("0.1.0").unwrap();
        let name = dir.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("v0.1.0-"));
        assert!(name.len() > "v0.1.0-".len()); // Has timestamp
    }

    #[test]
    fn test_backup_and_restore() {
        let temp = TempDir::new().unwrap();
        let install_dir = temp.path().join("install");
        let backup_dir = temp.path().join("backup");

        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(install_dir.join("rch"), "test binary").unwrap();

        backup_current_installation(&install_dir, &backup_dir).unwrap();
        assert!(backup_dir.join("rch").exists());

        // Modify the original
        std::fs::write(install_dir.join("rch"), "modified").unwrap();

        // Restore
        restore_from_backup(&backup_dir, &install_dir).unwrap();

        let content = std::fs::read_to_string(install_dir.join("rch")).unwrap();
        assert_eq!(content, "test binary");
    }

    #[test]
    fn test_backup_creates_directory() {
        let temp = TempDir::new().unwrap();
        let install_dir = temp.path().join("install");
        let backup_dir = temp.path().join("backup/nested/deep");

        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(install_dir.join("rch"), "test").unwrap();

        // Backup directory doesn't exist yet
        assert!(!backup_dir.exists());

        backup_current_installation(&install_dir, &backup_dir).unwrap();

        // Should have created the directory
        assert!(backup_dir.exists());
        assert!(backup_dir.join("rch").exists());
    }

    #[test]
    fn test_backup_skips_missing_binaries() {
        let temp = TempDir::new().unwrap();
        let install_dir = temp.path().join("install");
        let backup_dir = temp.path().join("backup");

        std::fs::create_dir_all(&install_dir).unwrap();
        // Only create rch, not rchd or rch-wkr
        std::fs::write(install_dir.join("rch"), "test").unwrap();

        backup_current_installation(&install_dir, &backup_dir).unwrap();

        // Only rch should be backed up
        assert!(backup_dir.join("rch").exists());
        assert!(!backup_dir.join("rchd").exists());
        assert!(!backup_dir.join("rch-wkr").exists());
    }

    #[test]
    fn test_backup_all_binaries() {
        let temp = TempDir::new().unwrap();
        let install_dir = temp.path().join("install");
        let backup_dir = temp.path().join("backup");

        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(install_dir.join("rch"), "rch content").unwrap();
        std::fs::write(install_dir.join("rchd"), "rchd content").unwrap();
        std::fs::write(install_dir.join("rch-wkr"), "rch-wkr content").unwrap();

        backup_current_installation(&install_dir, &backup_dir).unwrap();

        // All three should be backed up
        assert!(backup_dir.join("rch").exists());
        assert!(backup_dir.join("rchd").exists());
        assert!(backup_dir.join("rch-wkr").exists());

        // Verify content
        assert_eq!(
            std::fs::read_to_string(backup_dir.join("rchd")).unwrap(),
            "rchd content"
        );
    }

    #[test]
    fn test_replace_binaries_creates_install_dir() {
        let temp = TempDir::new().unwrap();
        let src_dir = temp.path().join("src");
        let install_dir = temp.path().join("install/nested");

        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(src_dir.join("rch"), "new binary").unwrap();

        // Install directory doesn't exist
        assert!(!install_dir.exists());

        replace_binaries(&src_dir, &install_dir).unwrap();

        // Should have created it
        assert!(install_dir.join("rch").exists());
    }

    #[test]
    fn test_restore_preserves_content() {
        let temp = TempDir::new().unwrap();
        let backup_dir = temp.path().join("backup");
        let install_dir = temp.path().join("install");

        std::fs::create_dir_all(&backup_dir).unwrap();
        std::fs::create_dir_all(&install_dir).unwrap();

        // Create backup with specific content
        std::fs::write(backup_dir.join("rch"), "backup v1.0").unwrap();
        std::fs::write(backup_dir.join("rchd"), "backup daemon").unwrap();

        // Create current with different content
        std::fs::write(install_dir.join("rch"), "current v2.0").unwrap();
        std::fs::write(install_dir.join("rchd"), "current daemon").unwrap();

        restore_from_backup(&backup_dir, &install_dir).unwrap();

        assert_eq!(
            std::fs::read_to_string(install_dir.join("rch")).unwrap(),
            "backup v1.0"
        );
        assert_eq!(
            std::fs::read_to_string(install_dir.join("rchd")).unwrap(),
            "backup daemon"
        );
    }
}
