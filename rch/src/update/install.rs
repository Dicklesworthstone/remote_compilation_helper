//! Binary installation and rollback.

use super::download::DownloadedRelease;
use super::lock::UpdateLock;
use super::types::{BackupEntry, MAX_BACKUPS, UpdateError};
use crate::commands::{configured_socket_path, send_daemon_command};
use crate::ui::OutputContext;
use flate2::read::GzDecoder;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[cfg(not(windows))]
const UPDATE_BINARIES: &[&str] = &["rch", "rchd", "rch-wkr"];
#[cfg(windows)]
const UPDATE_BINARIES: &[&str] = &["rch.exe", "rchd.exe", "rch-wkr.exe"];

#[cfg(not(windows))]
const REQUIRED_UPDATE_BINARY: &str = "rch";
#[cfg(windows)]
const REQUIRED_UPDATE_BINARY: &str = "rch.exe";

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
    let temp_extract = UpdateExtractDir::new();
    extract_archive(&download.archive_path, temp_extract.path())?;

    // Atomic replace: move new binaries to install dir
    if !ctx.is_json() {
        println!("Installing new binaries...");
    }
    let _installed_binaries = replace_binaries(temp_extract.path(), &install_dir)?;

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

    // Include a nonce so rapid same-version backups cannot alias each other.
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S_%f");
    Ok(backup_base.join(format!(
        "v{}-{}-{}",
        version,
        timestamp,
        uuid::Uuid::new_v4()
    )))
}

/// Find the latest backup.
///
/// Previously sorted directory entries by filename, which made `v1.0.10-...`
/// appear *older* than `v1.0.9-...` (lexicographic `0` < `9`). Worse, any
/// version with ten or more digits in any segment would land in the wrong
/// bucket entirely. We now delegate to `list_backups`, which reads each
/// backup's `backup.json` metadata and sorts by the recorded creation time,
/// so "latest" really means "most recently created" regardless of version
/// formatting.
fn find_latest_backup() -> Result<PathBuf, UpdateError> {
    let backups = list_backups()?;
    backups
        .into_iter()
        .next()
        .map(|b| b.backup_path)
        .ok_or(UpdateError::NoBackupAvailable)
}

/// Backup current installation.
fn backup_current_installation(
    install_dir: &std::path::Path,
    backup_dir: &std::path::Path,
) -> Result<(), UpdateError> {
    std::fs::create_dir_all(backup_dir)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to create backup dir: {}", e)))?;

    for binary in UPDATE_BINARIES {
        let src = install_dir.join(binary);
        if binary_path_exists(&src, binary, "installed binary")? {
            let dst = backup_dir.join(binary);
            copy_regular_binary_payload(&src, &dst, binary, "backup")?;
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

    // Sort by creation time, newest first. Use the path as a deterministic
    // tie-breaker because metadata stores seconds, while backup names carry
    // subsecond time and a nonce.
    backups.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.backup_path.cmp(&left.backup_path))
    });

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

fn new_update_extract_dir() -> PathBuf {
    std::env::temp_dir().join(format!("rch-extract-{}", uuid::Uuid::new_v4()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdateArchiveFormat {
    TarGz,
    Zip,
}

struct UpdateExtractDir {
    path: PathBuf,
}

impl UpdateExtractDir {
    fn new() -> Self {
        Self {
            path: new_update_extract_dir(),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for UpdateExtractDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Extract archive to destination.
fn extract_archive(archive: &std::path::Path, dest: &std::path::Path) -> Result<(), UpdateError> {
    let format = update_archive_format(archive)?;

    std::fs::create_dir(dest)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to create extract dir: {}", e)))?;

    let archive_file = fs::File::open(archive).map_err(|e| {
        UpdateError::InstallFailed(format!(
            "Failed to open update archive {}: {}",
            archive.display(),
            e
        ))
    })?;

    match format {
        UpdateArchiveFormat::TarGz => extract_tar_gz_archive(archive_file, dest),
        UpdateArchiveFormat::Zip => extract_zip_archive(archive_file, dest),
    }
}

fn update_archive_format(archive: &Path) -> Result<UpdateArchiveFormat, UpdateError> {
    let Some(file_name) = archive.file_name().and_then(|name| name.to_str()) else {
        return Err(UpdateError::InstallFailed(format!(
            "Unsupported update archive path: {}",
            archive.display()
        )));
    };

    if file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") {
        Ok(UpdateArchiveFormat::TarGz)
    } else if file_name.ends_with(".zip") {
        Ok(UpdateArchiveFormat::Zip)
    } else {
        Err(UpdateError::InstallFailed(format!(
            "Unsupported update archive format: {}",
            archive.display()
        )))
    }
}

fn extract_tar_gz_archive(archive_file: fs::File, dest: &Path) -> Result<(), UpdateError> {
    let decoder = GzDecoder::new(archive_file);
    let mut tar = tar::Archive::new(decoder);
    let entries = tar
        .entries()
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to read archive: {}", e)))?;

    for entry in entries {
        let mut entry = entry
            .map_err(|e| UpdateError::InstallFailed(format!("Invalid archive entry: {}", e)))?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry
            .path()
            .map_err(|e| UpdateError::InstallFailed(format!("Invalid archive path: {}", e)))?;
        let relative_path = safe_archive_entry_path(&entry_path)?;
        let destination = dest.join(&relative_path);

        if entry_type.is_dir() {
            fs::create_dir_all(&destination).map_err(|e| {
                UpdateError::InstallFailed(format!(
                    "Failed to create extracted directory {}: {}",
                    relative_path.display(),
                    e
                ))
            })?;
        } else if entry_type.is_file() {
            unpack_regular_file(&mut entry, &relative_path, &destination)?;
        } else {
            return Err(UpdateError::InstallFailed(format!(
                "Unsupported update archive entry type for {}",
                relative_path.display()
            )));
        }
    }

    Ok(())
}

fn extract_zip_archive(archive_file: fs::File, dest: &Path) -> Result<(), UpdateError> {
    let mut zip = zip::ZipArchive::new(archive_file)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to read zip archive: {}", e)))?;

    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|e| UpdateError::InstallFailed(format!("Invalid zip archive entry: {}", e)))?;
        let entry_name = entry.name().to_string();
        let relative_path = safe_archive_entry_path(Path::new(&entry_name))?;
        let destination = dest.join(&relative_path);

        if entry.is_dir() {
            fs::create_dir_all(&destination).map_err(|e| {
                UpdateError::InstallFailed(format!(
                    "Failed to create extracted directory {}: {}",
                    relative_path.display(),
                    e
                ))
            })?;
        } else if entry.is_file() {
            unpack_regular_file(&mut entry, &relative_path, &destination)?;
        } else {
            return Err(UpdateError::InstallFailed(format!(
                "Unsupported update zip entry type for {}",
                relative_path.display()
            )));
        }
    }

    Ok(())
}

fn safe_archive_entry_path(path: &Path) -> Result<PathBuf, UpdateError> {
    let mut safe_path = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let Some(part) = part.to_str() else {
                    return Err(UpdateError::InstallFailed(format!(
                        "Archive entry path is not UTF-8: {}",
                        path.display()
                    )));
                };
                if part.contains('\\') || part.contains('\0') {
                    return Err(UpdateError::InstallFailed(format!(
                        "Unsafe archive entry path: {}",
                        path.display()
                    )));
                }
                safe_path.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(UpdateError::InstallFailed(format!(
                    "Unsafe archive entry path: {}",
                    path.display()
                )));
            }
        }
    }

    if safe_path.as_os_str().is_empty() {
        return Err(UpdateError::InstallFailed(
            "Archive entry path is empty".to_string(),
        ));
    }

    Ok(safe_path)
}

fn unpack_regular_file<R: Read>(
    entry: &mut R,
    relative_path: &Path,
    destination: &Path,
) -> Result<(), UpdateError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            UpdateError::InstallFailed(format!(
                "Failed to create extracted parent for {}: {}",
                relative_path.display(),
                e
            ))
        })?;
    }

    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|e| {
            UpdateError::InstallFailed(format!(
                "Failed to create extracted file {}: {}",
                relative_path.display(),
                e
            ))
        })?;
    io::copy(entry, &mut output).map_err(|e| {
        UpdateError::InstallFailed(format!(
            "Failed to extract file {}: {}",
            relative_path.display(),
            e
        ))
    })?;

    Ok(())
}

fn discover_extracted_update_binaries(
    src_dir: &std::path::Path,
) -> Result<Vec<&'static str>, UpdateError> {
    let mut found = Vec::new();
    for binary in UPDATE_BINARIES {
        let src = src_dir.join(binary);
        match std::fs::symlink_metadata(&src) {
            Ok(metadata) if metadata.file_type().is_file() => found.push(*binary),
            Ok(_) => {
                return Err(UpdateError::InstallFailed(format!(
                    "Extracted update entry '{}' is not a regular file",
                    src.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(UpdateError::InstallFailed(format!(
                    "Failed to inspect extracted {}: {}",
                    binary, e
                )));
            }
        }
    }

    if !found.contains(&REQUIRED_UPDATE_BINARY) {
        return Err(UpdateError::InstallFailed(format!(
            "Extracted update archive did not contain required '{}' binary in {}",
            REQUIRED_UPDATE_BINARY,
            src_dir.display()
        )));
    }

    Ok(found)
}

/// Replace binaries in install directory.
fn replace_binaries(
    src_dir: &std::path::Path,
    install_dir: &std::path::Path,
) -> Result<Vec<&'static str>, UpdateError> {
    let binaries = discover_extracted_update_binaries(src_dir)?;

    std::fs::create_dir_all(install_dir)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to create install dir: {}", e)))?;

    for binary in &binaries {
        let src = src_dir.join(binary);
        let dst = install_dir.join(binary);
        install_binary_from_payload(&src, &dst, binary)?;
    }

    Ok(binaries)
}

fn install_binary_from_payload(src: &Path, dst: &Path, binary: &str) -> Result<(), UpdateError> {
    let staged = dst.with_file_name(format!(".{binary}.rch-update-{}", uuid::Uuid::new_v4()));

    if let Err(error) = copy_regular_binary_payload(src, &staged, binary, "stage") {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }

    if let Err(error) = set_update_binary_permissions(&staged) {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    replace_staged_binary(&staged, dst, binary)
}

#[cfg(unix)]
fn replace_staged_binary(staged: &Path, dst: &Path, binary: &str) -> Result<(), UpdateError> {
    std::fs::rename(staged, dst).map_err(|e| {
        let _ = std::fs::remove_file(staged);
        UpdateError::InstallFailed(format!("Failed to install {}: {}", binary, e))
    })
}

#[cfg(windows)]
fn replace_staged_binary(staged: &Path, dst: &Path, binary: &str) -> Result<(), UpdateError> {
    if dst.exists() {
        std::fs::remove_file(dst).map_err(|e| {
            let _ = std::fs::remove_file(staged);
            UpdateError::InstallFailed(format!("Failed to remove old {}: {}", binary, e))
        })?;
    }

    std::fs::rename(staged, dst).map_err(|e| {
        let _ = std::fs::remove_file(staged);
        UpdateError::InstallFailed(format!("Failed to install {}: {}", binary, e))
    })
}

#[cfg(unix)]
fn set_update_binary_permissions(path: &Path) -> Result<(), UpdateError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to get permissions: {}", e)))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to set permissions: {}", e)))
}

#[cfg(windows)]
fn set_update_binary_permissions(_path: &Path) -> Result<(), UpdateError> {
    Ok(())
}

/// Verify the installation by checking binary versions.
fn verify_installation(install_dir: &std::path::Path) -> Result<(), UpdateError> {
    let rch = install_dir.join(REQUIRED_UPDATE_BINARY);

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
    for binary in UPDATE_BINARIES {
        let src = backup_dir.join(binary);
        if binary_path_exists(&src, binary, "backup payload")? {
            let dst = install_dir.join(binary);
            install_binary_from_payload(&src, &dst, binary)?;
        }
    }

    Ok(())
}

fn binary_path_exists(path: &Path, binary: &str, source_name: &str) -> Result<bool, UpdateError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(UpdateError::InstallFailed(format!(
            "Failed to inspect {} {} at {}: {}",
            source_name,
            binary,
            path.display(),
            e
        ))),
    }
}

fn copy_regular_binary_payload(
    src: &Path,
    dst: &Path,
    binary: &str,
    action: &str,
) -> Result<(), UpdateError> {
    let metadata = std::fs::symlink_metadata(src).map_err(|e| {
        UpdateError::InstallFailed(format!(
            "Failed to inspect {} at {} before {}: {}",
            binary,
            src.display(),
            action,
            e
        ))
    })?;

    if !metadata.file_type().is_file() {
        return Err(UpdateError::InstallFailed(format!(
            "Refusing to {} {} from non-regular file {}",
            action,
            binary,
            src.display()
        )));
    }

    std::fs::copy(src, dst).map_err(|e| {
        UpdateError::InstallFailed(format!("Failed to {} {}: {}", action, binary, e))
    })?;

    Ok(())
}

/// Stop daemon gracefully, waiting for builds to complete.
#[cfg(not(unix))]
async fn stop_daemon_gracefully(_timeout_secs: u64) -> Result<bool, UpdateError> {
    Ok(false)
}

/// Stop daemon gracefully, waiting for builds to complete.
#[cfg(unix)]
async fn stop_daemon_gracefully(timeout_secs: u64) -> Result<bool, UpdateError> {
    let socket_path = configured_update_socket_path()?;
    if !socket_path.exists() {
        return Ok(false);
    }

    // Try graceful shutdown via socket
    let _ = send_daemon_command("POST /shutdown\n").await;

    // Wait for socket to disappear
    for _ in 0..shutdown_poll_attempts(timeout_secs) {
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
    let _ = tokio::fs::remove_file(&socket_path).await;

    Ok(true)
}

/// Start the daemon.
async fn start_daemon() -> Result<(), UpdateError> {
    let socket_path = configured_update_socket_path()?;
    let mut command = daemon_start_command();

    // Preserve custom socket configuration across update and rollback restarts.
    let _child = command
        .args(daemon_start_args(&socket_path))
        .spawn()
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to start daemon: {}", e)))?;

    // Give it a moment to start
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    Ok(())
}

#[cfg(not(windows))]
fn daemon_start_command() -> Command {
    Command::new("rchd")
}

#[cfg(windows)]
fn daemon_start_command() -> Command {
    Command::new("rchd.exe")
}

fn configured_update_socket_path() -> Result<PathBuf, UpdateError> {
    configured_socket_path()
        .map(PathBuf::from)
        .map_err(|e| UpdateError::InstallFailed(format!("Failed to resolve daemon socket: {e}")))
}

fn daemon_start_args(socket_path: &Path) -> [&std::ffi::OsStr; 2] {
    [std::ffi::OsStr::new("--socket"), socket_path.as_os_str()]
}

fn shutdown_poll_attempts(timeout_secs: u64) -> u64 {
    timeout_secs.saturating_mul(10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Cursor;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_tar_gz_with_entries(
        archive_path: &Path,
        entries: &[(&str, &[u8])],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let file = fs::File::create(archive_path)?;
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(encoder);

        for (path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(path)?;
            header.set_size(u64::try_from(content.len())?);
            header.set_cksum();
            builder.append(&header, Cursor::new(*content))?;
        }

        builder.finish()?;
        let encoder = builder.into_inner()?;
        encoder.finish()?;
        Ok(())
    }

    fn create_zip_with_entries(
        archive_path: &Path,
        entries: &[(&str, &[u8])],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let file = fs::File::create(archive_path)?;
        let mut writer = zip::ZipWriter::new(file);

        for (path, content) in entries {
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            writer.start_file(*path, options)?;
            writer.write_all(content)?;
        }

        writer.finish()?;
        Ok(())
    }

    fn optional_update_binary() -> &'static str {
        UPDATE_BINARIES
            .iter()
            .copied()
            .find(|binary| *binary != REQUIRED_UPDATE_BINARY)
            .expect("update binary list should include at least one optional binary")
    }

    fn create_tar_gz_with_raw_path(
        archive_path: &Path,
        raw_path: &[u8],
        content: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let file = fs::File::create(archive_path)?;
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(u64::try_from(content.len())?);
        header.set_mode(0o755);
        let path_field = header
            .as_mut_bytes()
            .get_mut(0..raw_path.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "raw tar path too long"))?;
        path_field.copy_from_slice(raw_path);
        header.set_cksum();
        builder.append(&header, Cursor::new(content))?;
        builder.finish()?;
        let encoder = builder.into_inner()?;
        encoder.finish()?;
        Ok(())
    }

    fn create_tar_gz_with_symlink(
        archive_path: &Path,
        link_path: &str,
        target_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let file = fs::File::create(archive_path)?;
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_path(link_path)?;
        header.set_link_name(target_path)?;
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, io::empty())?;
        builder.finish()?;
        let encoder = builder.into_inner()?;
        encoder.finish()?;
        Ok(())
    }

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
    fn test_backup_dir_is_unique_for_same_version() {
        let first = get_backup_dir("0.1.0").unwrap();
        let second = get_backup_dir("0.1.0").unwrap();

        assert_ne!(
            first, second,
            "same-version backups created in rapid succession must not share a directory"
        );
    }

    #[test]
    fn test_backup_and_restore() {
        let temp = TempDir::new().unwrap();
        let install_dir = temp.path().join("install");
        let backup_dir = temp.path().join("backup");

        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(install_dir.join(REQUIRED_UPDATE_BINARY), "test binary").unwrap();

        backup_current_installation(&install_dir, &backup_dir).unwrap();
        assert!(backup_dir.join(REQUIRED_UPDATE_BINARY).exists());

        // Modify the original
        std::fs::write(install_dir.join(REQUIRED_UPDATE_BINARY), "modified").unwrap();

        // Restore
        restore_from_backup(&backup_dir, &install_dir).unwrap();

        let content = std::fs::read_to_string(install_dir.join(REQUIRED_UPDATE_BINARY)).unwrap();
        assert_eq!(content, "test binary");
    }

    #[test]
    fn test_backup_creates_directory() {
        let temp = TempDir::new().unwrap();
        let install_dir = temp.path().join("install");
        let backup_dir = temp.path().join("backup/nested/deep");

        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(install_dir.join(REQUIRED_UPDATE_BINARY), "test").unwrap();

        // Backup directory doesn't exist yet
        assert!(!backup_dir.exists());

        backup_current_installation(&install_dir, &backup_dir).unwrap();

        // Should have created the directory
        assert!(backup_dir.exists());
        assert!(backup_dir.join(REQUIRED_UPDATE_BINARY).exists());
    }

    #[test]
    fn test_backup_skips_missing_binaries() {
        let temp = TempDir::new().unwrap();
        let install_dir = temp.path().join("install");
        let backup_dir = temp.path().join("backup");

        std::fs::create_dir_all(&install_dir).unwrap();
        // Only create the required binary, not the optional companions.
        std::fs::write(install_dir.join(REQUIRED_UPDATE_BINARY), "test").unwrap();

        backup_current_installation(&install_dir, &backup_dir).unwrap();

        // Only rch should be backed up
        assert!(backup_dir.join(REQUIRED_UPDATE_BINARY).exists());
        for binary in UPDATE_BINARIES
            .iter()
            .copied()
            .filter(|binary| *binary != REQUIRED_UPDATE_BINARY)
        {
            assert!(!backup_dir.join(binary).exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_backup_rejects_symlinked_installed_binary() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let install_dir = temp.path().join("install");
        let backup_dir = temp.path().join("backup");
        let external_binary = temp.path().join("external-rch");

        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(&external_binary, "external binary").unwrap();
        symlink(&external_binary, install_dir.join(REQUIRED_UPDATE_BINARY)).unwrap();

        let result = backup_current_installation(&install_dir, &backup_dir);

        assert!(matches!(result, Err(UpdateError::InstallFailed(_))));
        assert!(
            !backup_dir.join(REQUIRED_UPDATE_BINARY).exists(),
            "backup must not follow installed binary symlinks"
        );
    }

    #[test]
    fn test_backup_all_binaries() {
        let temp = TempDir::new().unwrap();
        let install_dir = temp.path().join("install");
        let backup_dir = temp.path().join("backup");

        std::fs::create_dir_all(&install_dir).unwrap();
        for binary in UPDATE_BINARIES {
            std::fs::write(install_dir.join(binary), format!("content for {binary}")).unwrap();
        }

        backup_current_installation(&install_dir, &backup_dir).unwrap();

        // All three should be backed up
        for binary in UPDATE_BINARIES {
            assert!(backup_dir.join(binary).exists());
        }

        // Verify content
        assert_eq!(
            std::fs::read_to_string(backup_dir.join(REQUIRED_UPDATE_BINARY)).unwrap(),
            format!("content for {REQUIRED_UPDATE_BINARY}")
        );
    }

    #[test]
    fn test_replace_binaries_creates_install_dir() {
        let temp = TempDir::new().unwrap();
        let src_dir = temp.path().join("src");
        let install_dir = temp.path().join("install/nested");

        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(src_dir.join(REQUIRED_UPDATE_BINARY), "new binary").unwrap();

        // Install directory doesn't exist
        assert!(!install_dir.exists());

        let installed = replace_binaries(&src_dir, &install_dir).unwrap();

        // Should have created it
        assert_eq!(installed, vec![REQUIRED_UPDATE_BINARY]);
        assert!(install_dir.join(REQUIRED_UPDATE_BINARY).exists());
    }

    #[test]
    fn test_replace_binaries_requires_rch_payload() {
        let temp = TempDir::new().unwrap();
        let src_dir = temp.path().join("src");
        let install_dir = temp.path().join("install");

        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::create_dir_all(&install_dir).unwrap();
        let optional_binary = optional_update_binary();
        std::fs::write(src_dir.join(optional_binary), "new optional binary").unwrap();
        std::fs::write(
            install_dir.join(REQUIRED_UPDATE_BINARY),
            "old required binary",
        )
        .unwrap();

        let result = replace_binaries(&src_dir, &install_dir);
        assert!(matches!(result, Err(UpdateError::InstallFailed(_))));
        assert_eq!(
            std::fs::read_to_string(install_dir.join(REQUIRED_UPDATE_BINARY)).unwrap(),
            "old required binary",
            "missing required payload must fail before touching installed binaries"
        );
        assert!(
            !install_dir.join(optional_binary).exists(),
            "preflight failure must not partially install optional binaries"
        );
    }

    #[test]
    fn test_replace_binaries_replaces_existing_binary_after_staging() {
        let temp = TempDir::new().unwrap();
        let src_dir = temp.path().join("src");
        let install_dir = temp.path().join("install");

        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(src_dir.join(REQUIRED_UPDATE_BINARY), "new binary").unwrap();
        std::fs::write(install_dir.join(REQUIRED_UPDATE_BINARY), "old binary").unwrap();

        let installed = replace_binaries(&src_dir, &install_dir).unwrap();

        assert_eq!(installed, vec![REQUIRED_UPDATE_BINARY]);
        assert_eq!(
            std::fs::read_to_string(install_dir.join(REQUIRED_UPDATE_BINARY)).unwrap(),
            "new binary"
        );
        assert!(
            std::fs::read_dir(&install_dir)
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().contains(".rch-update-")),
            "successful replacement should not leave staged update files"
        );
    }

    #[test]
    fn test_replace_binaries_rejects_non_file_payload() {
        let temp = TempDir::new().unwrap();
        let src_dir = temp.path().join("src");
        let install_dir = temp.path().join("install");

        std::fs::create_dir_all(src_dir.join(REQUIRED_UPDATE_BINARY)).unwrap();

        let result = replace_binaries(&src_dir, &install_dir);
        assert!(matches!(result, Err(UpdateError::InstallFailed(_))));
        assert!(
            !install_dir.exists(),
            "invalid payload must fail before creating the install dir"
        );
    }

    #[test]
    fn test_new_update_extract_dir_is_unique() {
        let first = new_update_extract_dir();
        let second = new_update_extract_dir();
        assert_ne!(first, second);
        assert!(
            first
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("rch-extract-")
        );
    }

    #[test]
    fn test_update_extract_dir_cleans_on_drop() {
        let path = {
            let dir = UpdateExtractDir::new();
            fs::create_dir(dir.path()).unwrap();
            fs::write(dir.path().join("partial"), "partial extraction").unwrap();
            dir.path().to_path_buf()
        };

        assert!(
            !path.exists(),
            "temporary extraction directory should be removed on drop"
        );
    }

    #[test]
    fn test_update_archive_format_accepts_release_formats() {
        assert_eq!(
            update_archive_format(Path::new("rch-v1.0.0-x86_64-unknown-linux-musl.tar.gz"))
                .unwrap(),
            UpdateArchiveFormat::TarGz
        );
        assert_eq!(
            update_archive_format(Path::new("rch-v1.0.0-x86_64-pc-windows-msvc.zip")).unwrap(),
            UpdateArchiveFormat::Zip
        );
        assert!(matches!(
            update_archive_format(Path::new("rch-v1.0.0.txt")),
            Err(UpdateError::InstallFailed(_))
        ));
    }

    #[test]
    fn test_extract_archive_extracts_tar_gz_regular_files() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("rch.tar.gz");
        let dest = temp.path().join("extract");
        create_tar_gz_with_entries(
            &archive_path,
            &[("rch", b"hook binary"), ("nested/rchd", b"daemon binary")],
        )
        .unwrap();

        extract_archive(&archive_path, &dest).unwrap();

        assert_eq!(
            std::fs::read_to_string(dest.join("rch")).unwrap(),
            "hook binary"
        );
        assert_eq!(
            std::fs::read_to_string(dest.join("nested/rchd")).unwrap(),
            "daemon binary"
        );
    }

    #[test]
    fn test_extract_archive_extracts_zip_regular_files() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("rch.zip");
        let dest = temp.path().join("extract");
        create_zip_with_entries(
            &archive_path,
            &[
                (REQUIRED_UPDATE_BINARY, b"hook binary"),
                (optional_update_binary(), b"optional binary"),
            ],
        )
        .unwrap();

        extract_archive(&archive_path, &dest).unwrap();

        assert_eq!(
            std::fs::read_to_string(dest.join(REQUIRED_UPDATE_BINARY)).unwrap(),
            "hook binary"
        );
        assert_eq!(
            std::fs::read_to_string(dest.join(optional_update_binary())).unwrap(),
            "optional binary"
        );
    }

    #[test]
    fn test_extract_archive_rejects_parent_traversal() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("rch.tar.gz");
        let dest = temp.path().join("extract");
        let outside = temp.path().join("outside-rch");
        create_tar_gz_with_raw_path(&archive_path, b"../outside-rch", b"escape").unwrap();

        let result = extract_archive(&archive_path, &dest);

        assert!(matches!(result, Err(UpdateError::InstallFailed(_))));
        assert!(
            !outside.exists(),
            "traversal entry must not write outside extract root"
        );
    }

    #[test]
    fn test_extract_archive_rejects_absolute_paths() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("rch.tar.gz");
        let dest = temp.path().join("extract");
        create_tar_gz_with_raw_path(&archive_path, b"/tmp/rch-escape", b"escape").unwrap();

        let result = extract_archive(&archive_path, &dest);

        assert!(matches!(result, Err(UpdateError::InstallFailed(_))));
    }

    #[test]
    fn test_extract_archive_rejects_backslash_paths() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("rch.tar.gz");
        let dest = temp.path().join("extract");
        create_tar_gz_with_entries(&archive_path, &[("nested\\rch", b"binary")]).unwrap();

        let result = extract_archive(&archive_path, &dest);

        assert!(matches!(result, Err(UpdateError::InstallFailed(_))));
    }

    #[test]
    fn test_extract_archive_rejects_symlink_entries() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("rch.tar.gz");
        let dest = temp.path().join("extract");
        create_tar_gz_with_symlink(&archive_path, "rch", "/tmp/rch-target").unwrap();

        let result = extract_archive(&archive_path, &dest);

        assert!(matches!(result, Err(UpdateError::InstallFailed(_))));
        assert!(!dest.join("rch").exists());
    }

    #[test]
    fn test_extract_archive_rejects_preexisting_destination() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("rch.tar.gz");
        let dest = temp.path().join("extract");
        create_tar_gz_with_entries(&archive_path, &[("rch", b"binary")]).unwrap();
        fs::create_dir(&dest).unwrap();

        let result = extract_archive(&archive_path, &dest);

        assert!(matches!(result, Err(UpdateError::InstallFailed(_))));
        assert!(
            !dest.join("rch").exists(),
            "existing extraction root must not be reused"
        );
    }

    #[test]
    fn test_restore_preserves_content() {
        let temp = TempDir::new().unwrap();
        let backup_dir = temp.path().join("backup");
        let install_dir = temp.path().join("install");

        std::fs::create_dir_all(&backup_dir).unwrap();
        std::fs::create_dir_all(&install_dir).unwrap();
        let optional_binary = optional_update_binary();

        // Create backup with specific content
        std::fs::write(backup_dir.join(REQUIRED_UPDATE_BINARY), "backup v1.0").unwrap();
        std::fs::write(backup_dir.join(optional_binary), "backup optional").unwrap();

        // Create current with different content
        std::fs::write(install_dir.join(REQUIRED_UPDATE_BINARY), "current v2.0").unwrap();
        std::fs::write(install_dir.join(optional_binary), "current optional").unwrap();

        restore_from_backup(&backup_dir, &install_dir).unwrap();

        assert_eq!(
            std::fs::read_to_string(install_dir.join(REQUIRED_UPDATE_BINARY)).unwrap(),
            "backup v1.0"
        );
        assert_eq!(
            std::fs::read_to_string(install_dir.join(optional_binary)).unwrap(),
            "backup optional"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_restore_rejects_symlink_backup_payload() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let backup_dir = temp.path().join("backup");
        let install_dir = temp.path().join("install");
        let external_binary = temp.path().join("external-rch");

        std::fs::create_dir_all(&backup_dir).unwrap();
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(&external_binary, "external backup binary").unwrap();
        symlink(&external_binary, backup_dir.join(REQUIRED_UPDATE_BINARY)).unwrap();
        std::fs::write(install_dir.join(REQUIRED_UPDATE_BINARY), "current binary").unwrap();

        let result = restore_from_backup(&backup_dir, &install_dir);

        assert!(matches!(result, Err(UpdateError::InstallFailed(_))));
        assert_eq!(
            std::fs::read_to_string(install_dir.join(REQUIRED_UPDATE_BINARY)).unwrap(),
            "current binary",
            "rollback must not follow symlinked backup payloads"
        );
    }

    #[test]
    fn test_restore_failure_preserves_existing_binary() {
        let temp = TempDir::new().unwrap();
        let backup_dir = temp.path().join("backup");
        let install_dir = temp.path().join("install");

        std::fs::create_dir_all(backup_dir.join(REQUIRED_UPDATE_BINARY)).unwrap();
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(install_dir.join(REQUIRED_UPDATE_BINARY), "current binary").unwrap();

        let result = restore_from_backup(&backup_dir, &install_dir);

        assert!(matches!(result, Err(UpdateError::InstallFailed(_))));
        assert_eq!(
            std::fs::read_to_string(install_dir.join(REQUIRED_UPDATE_BINARY)).unwrap(),
            "current binary",
            "rollback must stage backup payload before replacing the installed binary"
        );
    }

    #[test]
    fn daemon_start_args_pin_configured_socket_path() {
        let socket_path = Path::new("/tmp/rch-update-custom.sock");
        let args = daemon_start_args(socket_path);

        assert_eq!(args[0], std::ffi::OsStr::new("--socket"));
        assert_eq!(args[1], socket_path.as_os_str());
    }

    #[test]
    fn shutdown_poll_attempts_respects_requested_timeout() {
        assert_eq!(shutdown_poll_attempts(0), 0);
        assert_eq!(shutdown_poll_attempts(1), 10);
        assert_eq!(shutdown_poll_attempts(30), 300);
    }
}
