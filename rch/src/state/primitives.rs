//! Idempotent file operation primitives.
//!
//! This module provides atomic, crash-safe file operations that can be called
//! repeatedly without side effects. All write operations use the write-to-temp-
//! then-rename pattern to ensure atomicity.

use anyhow::{Context, Result, anyhow};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

/// Result of an idempotent operation.
///
/// These results allow callers to distinguish between:
/// - Creating something new
/// - Finding it already exists (no action taken)
/// - Updating something that changed
/// - Finding no changes needed
/// - Dry-run mode (no action taken)
/// - Not applicable (e.g., user doesn't use this tool)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotentResult {
    /// A new file/resource was created.
    Created,
    /// The file/resource already exists (no action taken).
    AlreadyExists,
    /// The file/resource was updated with new content.
    Updated,
    /// No changes were needed (content identical).
    Unchanged,
    /// Dry-run mode: shows what would happen without doing it.
    DryRun,
    /// A change was made (alias for Updated, used by hook operations).
    Changed,
    /// Dry-run mode: describes what would change without doing it.
    WouldChange(String),
    /// Operation not applicable (e.g., user doesn't have the tool installed).
    NotApplicable(String),
}

impl std::fmt::Display for IdempotentResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdempotentResult::Created => write!(f, "created"),
            IdempotentResult::AlreadyExists => write!(f, "already exists"),
            IdempotentResult::Updated => write!(f, "updated"),
            IdempotentResult::Unchanged => write!(f, "unchanged"),
            IdempotentResult::DryRun => write!(f, "dry-run"),
            IdempotentResult::Changed => write!(f, "changed"),
            IdempotentResult::WouldChange(msg) => write!(f, "would change: {}", msg),
            IdempotentResult::NotApplicable(msg) => write!(f, "not applicable: {}", msg),
        }
    }
}

/// Atomically write content to a file using write-to-temp-then-rename.
///
/// This ensures crash safety: either the old content or the new content
/// will be present, never partial content.
///
/// # Arguments
///
/// * `path` - Destination file path
/// * `content` - Bytes to write
///
/// # Errors
///
/// Returns an error if:
/// - The parent directory doesn't exist and can't be created
/// - The temp file can't be created or written
/// - The rename operation fails
///
/// # Example
///
/// ```no_run
/// use rch::state::primitives::atomic_write;
/// use std::path::Path;
///
/// atomic_write(Path::new("/tmp/test.txt"), b"hello world")?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("No parent directory for path: {:?}", path))?;

    // Ensure parent directory exists
    if !parent.exists() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    // Generate unique temp file name using timestamp and process ID
    let temp_name = format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let temp_path = parent.join(temp_name);

    // Write to temp file
    let mut file = File::create(&temp_path)
        .with_context(|| format!("Failed to create temp file: {:?}", temp_path))?;

    file.write_all(content)
        .with_context(|| format!("Failed to write to temp file: {:?}", temp_path))?;

    // Sync data to disk
    file.sync_all()
        .with_context(|| format!("Failed to sync temp file: {:?}", temp_path))?;

    // Atomic rename
    fs::rename(&temp_path, path).with_context(|| {
        // Clean up temp file on rename failure
        let _ = fs::remove_file(&temp_path);
        format!("Failed to rename {:?} to {:?}", temp_path, path)
    })?;

    // Sync parent directory for extra safety (important on some filesystems)
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Create a file only if it doesn't exist.
///
/// This is idempotent: calling it multiple times with the same path
/// will only create the file once. Subsequent calls return `AlreadyExists`.
///
/// # Arguments
///
/// * `path` - File path to create
/// * `content` - Initial content for the file
///
/// # Returns
///
/// * `Created` - File was created
/// * `AlreadyExists` - File already exists (content not checked)
///
/// # Example
///
/// ```no_run
/// use rch::state::primitives::{create_if_missing, IdempotentResult};
/// use std::path::Path;
///
/// let result = create_if_missing(Path::new("/tmp/config.toml"), "[general]")?;
/// assert_eq!(result, IdempotentResult::Created);
///
/// // Second call returns AlreadyExists
/// let result = create_if_missing(Path::new("/tmp/config.toml"), "different")?;
/// assert_eq!(result, IdempotentResult::AlreadyExists);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn create_if_missing(path: &Path, content: &str) -> Result<IdempotentResult> {
    if path.exists() {
        return Ok(IdempotentResult::AlreadyExists);
    }

    // Ensure parent directory exists
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    atomic_write(path, content.as_bytes())?;
    Ok(IdempotentResult::Created)
}

/// Update a file only if its content has changed.
///
/// This is idempotent: if the file already contains the new content,
/// no write occurs and `Unchanged` is returned.
///
/// # Arguments
///
/// * `path` - File path to update
/// * `new_content` - New content for the file
/// * `backup` - If true, create a backup before updating
///
/// # Returns
///
/// * `Created` - File didn't exist, was created
/// * `Updated` - File existed, content changed
/// * `Unchanged` - File existed, content was identical
///
/// # Example
///
/// ```no_run
/// use rch::state::primitives::{update_if_changed, IdempotentResult};
/// use std::path::Path;
///
/// // Creates file
/// let r = update_if_changed(Path::new("/tmp/cfg.toml"), "v1", false)?;
/// assert_eq!(r, IdempotentResult::Created);
///
/// // Updates file
/// let r = update_if_changed(Path::new("/tmp/cfg.toml"), "v2", false)?;
/// assert_eq!(r, IdempotentResult::Updated);
///
/// // No change
/// let r = update_if_changed(Path::new("/tmp/cfg.toml"), "v2", false)?;
/// assert_eq!(r, IdempotentResult::Unchanged);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn update_if_changed(path: &Path, new_content: &str, backup: bool) -> Result<IdempotentResult> {
    if !path.exists() {
        atomic_write(path, new_content.as_bytes())?;
        return Ok(IdempotentResult::Created);
    }

    let existing = fs::read_to_string(path)
        .with_context(|| format!("Failed to read existing file: {:?}", path))?;

    if existing == new_content {
        return Ok(IdempotentResult::Unchanged);
    }

    if backup {
        create_backup(path)?;
    }

    atomic_write(path, new_content.as_bytes())?;
    Ok(IdempotentResult::Updated)
}

/// Create a timestamped backup of a file.
///
/// Backups are stored in `~/.local/share/rch/backups/` with the format:
/// `{filename}_{timestamp}.bak`
///
/// A retention policy keeps only the 10 most recent backups per file.
///
/// # Arguments
///
/// * `path` - Path to the file to back up
///
/// # Returns
///
/// Path to the created backup file.
pub fn create_backup(path: &Path) -> Result<std::path::PathBuf> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let backup_dir = dirs::data_dir()
        .ok_or_else(|| anyhow!("Cannot determine data directory"))?
        .join("rch/backups");

    fs::create_dir_all(&backup_dir)
        .with_context(|| format!("Failed to create backup directory: {:?}", backup_dir))?;

    let filename = path
        .file_name()
        .ok_or_else(|| anyhow!("Invalid path: no filename"))?
        .to_string_lossy();

    let backup_path = backup_dir.join(format!("{}_{}.bak", filename, timestamp));

    fs::copy(path, &backup_path)
        .with_context(|| format!("Failed to copy {:?} to {:?}", path, backup_path))?;

    // Apply retention policy (keep last 10 backups per file)
    cleanup_old_backups(&backup_dir, &filename, 10)?;

    Ok(backup_path)
}

/// Remove old backups, keeping only the N most recent.
fn cleanup_old_backups(backup_dir: &Path, prefix: &str, keep: usize) -> Result<()> {
    let mut backups: Vec<_> = fs::read_dir(backup_dir)
        .with_context(|| format!("Failed to read backup directory: {:?}", backup_dir))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
        .collect();

    // Sort by modification time (newest first)
    backups.sort_by(|a, b| {
        b.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .cmp(
                &a.metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            )
    });

    // Remove old backups beyond retention limit
    for backup in backups.into_iter().skip(keep) {
        if let Err(e) = fs::remove_file(backup.path()) {
            tracing::warn!("Failed to remove old backup {:?}: {}", backup.path(), e);
        }
    }

    Ok(())
}

/// Ensure a symlink points to the correct target.
///
/// This is idempotent: if the symlink already points to the target,
/// no action is taken. If it points elsewhere, it's updated.
///
/// # Arguments
///
/// * `link` - Path where the symlink should be created
/// * `target` - Path the symlink should point to
///
/// # Returns
///
/// * `Created` - Symlink was created
/// * `AlreadyExists` - Symlink already points to target
/// * `Updated` - Symlink was updated to point to target
#[cfg(unix)]
pub fn ensure_symlink(link: &Path, target: &Path) -> Result<IdempotentResult> {
    use std::os::unix::fs::symlink;

    // Check if link exists (either as symlink or regular file)
    if link.symlink_metadata().is_ok() {
        if let Ok(current_target) = fs::read_link(link)
            && current_target == target
        {
            return Ok(IdempotentResult::AlreadyExists);
        }
        fs::remove_file(link)
            .with_context(|| format!("Failed to remove existing link: {:?}", link))?;
    }

    // Ensure parent directory exists
    if let Some(parent) = link.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    symlink(target, link)
        .with_context(|| format!("Failed to create symlink {:?} -> {:?}", link, target))?;

    Ok(IdempotentResult::Created)
}

#[cfg(windows)]
pub fn ensure_symlink(link: &Path, target: &Path) -> Result<IdempotentResult> {
    use std::os::windows::fs::symlink_file;

    if link.symlink_metadata().is_ok() {
        if let Ok(current_target) = fs::read_link(link)
            && current_target == target
        {
            return Ok(IdempotentResult::AlreadyExists);
        }
        fs::remove_file(link)
            .with_context(|| format!("Failed to remove existing link: {:?}", link))?;
    }

    if let Some(parent) = link.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    symlink_file(target, link)
        .with_context(|| format!("Failed to create symlink {:?} -> {:?}", link, target))?;

    Ok(IdempotentResult::Created)
}

/// Append a line to a file only if it doesn't already exist.
///
/// This is useful for adding entries to PATH in shell rc files or
/// similar append-only configuration patterns.
///
/// # Arguments
///
/// * `path` - Path to the file
/// * `line` - Line to append (whitespace is trimmed for comparison)
///
/// # Returns
///
/// * `Created` - File didn't exist, was created with the line
/// * `Updated` - Line was appended
/// * `AlreadyExists` - Line already exists in file
pub fn append_line_if_missing(path: &Path, line: &str) -> Result<IdempotentResult> {
    let content = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("Failed to read file: {:?}", path))?
    } else {
        String::new()
    };

    // Check if line already exists (trim for comparison)
    if content.lines().any(|l| l.trim() == line.trim()) {
        return Ok(IdempotentResult::AlreadyExists);
    }

    // Track if we're creating or updating
    let was_empty = content.is_empty();

    // Build new content
    let mut new_content = content;
    if !new_content.ends_with('\n') && !new_content.is_empty() {
        new_content.push('\n');
    }
    new_content.push_str(line);
    new_content.push('\n');

    atomic_write(path, new_content.as_bytes())?;

    if was_empty {
        Ok(IdempotentResult::Created)
    } else {
        Ok(IdempotentResult::Updated)
    }
}

/// Ensure a directory exists.
///
/// # Returns
///
/// * `Created` - Directory was created
/// * `AlreadyExists` - Directory already exists
pub fn ensure_directory(path: &Path) -> Result<IdempotentResult> {
    if path.exists() {
        if path.is_dir() {
            return Ok(IdempotentResult::AlreadyExists);
        }
        return Err(anyhow!("Path exists but is not a directory: {:?}", path));
    }

    fs::create_dir_all(path).with_context(|| format!("Failed to create directory: {:?}", path))?;

    Ok(IdempotentResult::Created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tracing::info;

    fn log_test_start(name: &str) {
        info!("TEST START: {}", name);
    }

    fn log_test_pass(name: &str) {
        info!("TEST PASS: {}", name);
    }

    #[test]
    fn test_atomic_write_creates_file() {
        log_test_start("test_atomic_write_creates_file");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.txt");

        atomic_write(&path, b"hello").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
        log_test_pass("test_atomic_write_creates_file");
    }

    #[test]
    fn test_atomic_write_overwrites() {
        log_test_start("test_atomic_write_overwrites");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.txt");

        atomic_write(&path, b"original").unwrap();
        atomic_write(&path, b"updated").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "updated");
        log_test_pass("test_atomic_write_overwrites");
    }

    #[test]
    fn test_atomic_write_creates_parent_dirs() {
        log_test_start("test_atomic_write_creates_parent_dirs");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("a/b/c/test.txt");

        atomic_write(&path, b"nested").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "nested");
        log_test_pass("test_atomic_write_creates_parent_dirs");
    }

    #[test]
    fn test_atomic_write_no_temp_files_left() {
        log_test_start("test_atomic_write_no_temp_files_left");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.txt");

        atomic_write(&path, b"content").unwrap();

        // Check no .tmp files remain
        let tmp_files: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        assert!(tmp_files.is_empty(), "Temp files should be cleaned up");
        log_test_pass("test_atomic_write_no_temp_files_left");
    }

    #[test]
    fn test_create_if_missing_creates() {
        log_test_start("test_create_if_missing_creates");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        let result = create_if_missing(&path, "[general]").unwrap();
        assert_eq!(result, IdempotentResult::Created);
        assert_eq!(fs::read_to_string(&path).unwrap(), "[general]");
        log_test_pass("test_create_if_missing_creates");
    }

    #[test]
    fn test_create_if_missing_idempotent() {
        log_test_start("test_create_if_missing_idempotent");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        let r1 = create_if_missing(&path, "content1").unwrap();
        assert_eq!(r1, IdempotentResult::Created);

        let r2 = create_if_missing(&path, "content2").unwrap();
        assert_eq!(r2, IdempotentResult::AlreadyExists);

        // Original content preserved
        assert_eq!(fs::read_to_string(&path).unwrap(), "content1");
        log_test_pass("test_create_if_missing_idempotent");
    }

    #[test]
    fn test_update_if_changed_creates() {
        log_test_start("test_update_if_changed_creates");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        let result = update_if_changed(&path, "v1", false).unwrap();
        assert_eq!(result, IdempotentResult::Created);
        log_test_pass("test_update_if_changed_creates");
    }

    #[test]
    fn test_update_if_changed_updates() {
        log_test_start("test_update_if_changed_updates");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        update_if_changed(&path, "v1", false).unwrap();
        let result = update_if_changed(&path, "v2", false).unwrap();
        assert_eq!(result, IdempotentResult::Updated);
        assert_eq!(fs::read_to_string(&path).unwrap(), "v2");
        log_test_pass("test_update_if_changed_updates");
    }

    #[test]
    fn test_update_if_changed_unchanged() {
        log_test_start("test_update_if_changed_unchanged");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        update_if_changed(&path, "same", false).unwrap();
        let result = update_if_changed(&path, "same", false).unwrap();
        assert_eq!(result, IdempotentResult::Unchanged);
        log_test_pass("test_update_if_changed_unchanged");
    }

    #[test]
    fn test_append_line_if_missing_creates() {
        log_test_start("test_append_line_if_missing_creates");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.txt");

        let result = append_line_if_missing(&path, "line1").unwrap();
        assert_eq!(result, IdempotentResult::Created);
        assert!(fs::read_to_string(&path).unwrap().contains("line1"));
        log_test_pass("test_append_line_if_missing_creates");
    }

    #[test]
    fn test_append_line_if_missing_appends() {
        log_test_start("test_append_line_if_missing_appends");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.txt");

        fs::write(&path, "existing\n").unwrap();
        let result = append_line_if_missing(&path, "new").unwrap();
        assert_eq!(result, IdempotentResult::Updated);

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("existing"));
        assert!(content.contains("new"));
        log_test_pass("test_append_line_if_missing_appends");
    }

    #[test]
    fn test_append_line_if_missing_idempotent() {
        log_test_start("test_append_line_if_missing_idempotent");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.txt");

        append_line_if_missing(&path, "line").unwrap();
        let result = append_line_if_missing(&path, "line").unwrap();
        assert_eq!(result, IdempotentResult::AlreadyExists);

        // Should only appear once
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.matches("line").count(), 1);
        log_test_pass("test_append_line_if_missing_idempotent");
    }

    #[test]
    fn test_ensure_directory_creates() {
        log_test_start("test_ensure_directory_creates");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("new_dir");

        let result = ensure_directory(&path).unwrap();
        assert_eq!(result, IdempotentResult::Created);
        assert!(path.is_dir());
        log_test_pass("test_ensure_directory_creates");
    }

    #[test]
    fn test_ensure_directory_idempotent() {
        log_test_start("test_ensure_directory_idempotent");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("dir");

        ensure_directory(&path).unwrap();
        let result = ensure_directory(&path).unwrap();
        assert_eq!(result, IdempotentResult::AlreadyExists);
        log_test_pass("test_ensure_directory_idempotent");
    }

    #[test]
    fn test_ensure_directory_errors_on_file() {
        log_test_start("test_ensure_directory_errors_on_file");
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("not_a_dir");

        fs::write(&path, "data").unwrap();
        let result = ensure_directory(&path);
        assert!(result.is_err(), "Expected error when path is a file");
        log_test_pass("test_ensure_directory_errors_on_file");
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_symlink_creates() {
        log_test_start("test_ensure_symlink_creates");
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target");
        let link = tmp.path().join("link");

        fs::write(&target, "content").unwrap();
        let result = ensure_symlink(&link, &target).unwrap();
        assert_eq!(result, IdempotentResult::Created);
        assert_eq!(fs::read_link(&link).unwrap(), target);
        log_test_pass("test_ensure_symlink_creates");
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_symlink_idempotent() {
        log_test_start("test_ensure_symlink_idempotent");
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target");
        let link = tmp.path().join("link");

        fs::write(&target, "content").unwrap();
        ensure_symlink(&link, &target).unwrap();
        let result = ensure_symlink(&link, &target).unwrap();
        assert_eq!(result, IdempotentResult::AlreadyExists);
        log_test_pass("test_ensure_symlink_idempotent");
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_symlink_updates_target() {
        log_test_start("test_ensure_symlink_updates_target");
        let tmp = TempDir::new().unwrap();
        let target_a = tmp.path().join("target_a");
        let target_b = tmp.path().join("target_b");
        let link = tmp.path().join("link");

        fs::write(&target_a, "a").unwrap();
        fs::write(&target_b, "b").unwrap();

        let created = ensure_symlink(&link, &target_a).unwrap();
        assert_eq!(created, IdempotentResult::Created);

        let updated = ensure_symlink(&link, &target_b).unwrap();
        assert_eq!(updated, IdempotentResult::Created);
        assert_eq!(fs::read_link(&link).unwrap(), target_b);
        log_test_pass("test_ensure_symlink_updates_target");
    }

    #[test]
    fn test_idempotent_result_display() {
        log_test_start("test_idempotent_result_display");
        assert_eq!(format!("{}", IdempotentResult::Created), "created");
        assert_eq!(
            format!("{}", IdempotentResult::AlreadyExists),
            "already exists"
        );
        assert_eq!(format!("{}", IdempotentResult::Updated), "updated");
        assert_eq!(format!("{}", IdempotentResult::Unchanged), "unchanged");
        assert_eq!(format!("{}", IdempotentResult::DryRun), "dry-run");
        log_test_pass("test_idempotent_result_display");
    }
}
