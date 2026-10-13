//! Idempotent file operation primitives.
//!
//! This module provides atomic, crash-safe file operations that can be called
//! repeatedly without side effects. All write operations use the write-to-temp-
//! then-rename pattern to ensure atomicity.

use anyhow::{Context, Result, anyhow};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

/// Read a regular file relative to an already held directory. The descriptor
/// binds the namespace; NOFOLLOW and NONBLOCK reject symlinks and special
/// files without waiting for a FIFO writer. Preserve complete large receipts.
#[cfg(unix)]
pub(crate) fn read_regular_file_at(
    directory: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Read;

    let descriptor = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
        Mode::empty(),
    )
    .context("journal open without following symlinks failed")?;
    let mut file = File::from(descriptor);
    anyhow::ensure!(file.metadata()?.is_file(), "journal is not a regular file");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .context("journal read failed")?;
    Ok(bytes)
}

/// Open the journal's parent without following its final symlink, then use the
/// same descriptor-bound reader as listing. Refuse a replaced parent rather
/// than constructing a writer whose path names a different journal namespace.
#[cfg(unix)]
pub(crate) fn read_regular_file(path: &Path) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::AsFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = std::ffi::CString::new(
        path.file_name()
            .context("journal has no file name")?
            .as_bytes(),
    )?;
    let directory = File::from(
        rustix::fs::open(
            parent,
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .context("journal directory open without following symlinks failed")?,
    );
    let bytes = read_regular_file_at(directory.as_fd(), &name)?;
    let held = directory.metadata()?;
    let named = fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        named.is_dir() && held.dev() == named.dev() && held.ino() == named.ino(),
        "journal directory changed during observation"
    );
    Ok(bytes)
}

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
/// A temporary is created exclusively and retained on any failure. Unix
/// publication checks the held directory/file identities and synchronizes the
/// directory before returning success. A post-rename failure is an uncertain
/// committed state, never permission to discard evidence or claim success.
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
    let mut temporary = std::ffi::OsString::from(".");
    temporary.push(
        path.file_name()
            .context("atomic write has no destination name")?,
    );
    temporary.push(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    atomic_write_with_temporary_name(path, content, &temporary)
}

fn atomic_write_with_temporary_name(
    path: &Path,
    content: &[u8],
    temporary: &std::ffi::OsStr,
) -> Result<()> {
    let parent = path
        .parent()
        .map(|parent| {
            if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            }
        })
        .ok_or_else(|| anyhow!("No parent directory for path: {:?}", path))?;
    anyhow::ensure!(
        Path::new(temporary).components().count() == 1
            && matches!(
                Path::new(temporary).components().next(),
                Some(std::path::Component::Normal(_))
            )
            && path.file_name() != Some(temporary),
        "atomic write temporary must be a distinct directory entry"
    );

    // Ensure parent directory exists
    if !parent.exists() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    let temp_path = parent.join(temporary);
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        use std::os::fd::AsFd;
        // Preserve the caller's existing parent aliases, but retain their
        // physical directory before creation. A later alias change is refused.
        let directory = File::open(parent).context("open atomic write directory")?;
        anyhow::ensure!(
            directory.metadata()?.is_dir(),
            "atomic write parent is not a directory"
        );
        let mut file = File::from(
            rustix::fs::openat(
                directory.as_fd(),
                temporary,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_bits_truncate(0o666),
            )
            .with_context(|| format!("create exclusive temporary {temp_path:?}"))?,
        );
        file.write_all(content)
            .with_context(|| format!("write retained temporary {temp_path:?}"))?;
        file.sync_all()
            .with_context(|| format!("sync retained temporary {temp_path:?}"))?;
        publish_atomic_temporary(
            &directory,
            parent,
            temporary,
            path.file_name().context("atomic write has no name")?,
            &file,
            content,
        )
    }
    #[cfg(not(unix))]
    {
        // Retain exclusive creation and failure bytes on every platform.
        // Descriptor/checked-directory durability parity is Unix-only here.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temp_path, path)?;
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    }
}

#[cfg(unix)]
fn verify_atomic_write_name(
    directory: &File,
    parent: &Path,
    name: &std::ffi::OsStr,
    file: &File,
) -> Result<()> {
    use rustix::fs::{AtFlags, FileType};
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    let held_directory = directory.metadata()?;
    let named_directory = fs::metadata(parent)?;
    anyhow::ensure!(
        held_directory.is_dir()
            && named_directory.is_dir()
            && held_directory.dev() == named_directory.dev()
            && held_directory.ino() == named_directory.ino(),
        "atomic write directory changed; retained publication is unverified"
    );
    // Inspect the name without adding a read-permission requirement. The
    // original creation descriptor can still read a write-only-mode file.
    let named = rustix::fs::statat(directory.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)?;
    let held = rustix::fs::fstat(file.as_fd())?;
    anyhow::ensure!(
        FileType::from_raw_mode(held.st_mode) == FileType::RegularFile
            && FileType::from_raw_mode(named.st_mode) == FileType::RegularFile
            && held.st_dev == named.st_dev
            && held.st_ino == named.st_ino
            && held.st_nlink == 1
            && named.st_nlink == 1,
        "atomic write file identity or links changed; retained publication is unverified"
    );
    Ok(())
}

#[cfg(unix)]
pub(crate) fn verify_atomic_write_bytes(file: &File, expected: &[u8]) -> Result<()> {
    use std::os::unix::fs::FileExt;
    anyhow::ensure!(
        file.metadata()?.len() == expected.len() as u64,
        "atomic write length changed"
    );
    let mut offset = 0usize;
    let mut buffer = [0u8; 65536];
    while offset < expected.len() {
        let size = (expected.len() - offset).min(buffer.len());
        let count = file.read_at(&mut buffer[..size], offset as u64)?;
        anyhow::ensure!(
            count > 0 && buffer[..count] == expected[offset..offset + count],
            "atomic write bytes changed; publication unverified"
        );
        offset += count;
    }
    anyhow::ensure!(
        file.metadata()?.len() == expected.len() as u64,
        "atomic write length changed"
    );
    Ok(())
}

#[cfg(unix)]
fn publish_atomic_temporary(
    directory: &File,
    parent: &Path,
    temporary: &std::ffi::OsStr,
    destination: &std::ffi::OsStr,
    file: &File,
    expected: &[u8],
) -> Result<()> {
    use std::os::fd::AsFd;
    verify_atomic_write_name(directory, parent, temporary, file)?;
    verify_atomic_write_bytes(file, expected)?;
    rustix::fs::renameat(directory.as_fd(), temporary, directory.as_fd(), destination)
        .with_context(|| format!("rename retained temporary {temporary:?} to {destination:?}"))?;
    verify_atomic_write_name(directory, parent, destination, file)?;
    directory
        .sync_all()
        .context("sync held atomic write directory before acknowledgment")?;
    verify_atomic_write_name(directory, parent, destination, file)?;
    verify_atomic_write_bytes(file, expected)
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
///
/// Matches entries of the form `{prefix}_{timestamp}.bak` — the separator
/// is enforced so that, e.g., retention for `settings.json` doesn't
/// accidentally sweep up backups of a sibling `settings.jsona` or
/// `settings.json.old` because naive `starts_with(prefix)` would match
/// both.
fn cleanup_old_backups(backup_dir: &Path, prefix: &str, keep: usize) -> Result<()> {
    // Anchor the separator produced by `create_backup` so unrelated files
    // that merely share a prefix don't get mixed into the retention set.
    let anchor = format!("{}_", prefix);
    let mut backups: Vec<_> = fs::read_dir(backup_dir)
        .with_context(|| format!("Failed to read backup directory: {:?}", backup_dir))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with(&anchor) && name.ends_with(".bak")
        })
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

    #[cfg(unix)]
    #[test]
    fn regular_file_reader_preserves_large_bytes_and_rejects_nonregular_or_linked_roots() {
        let retained = tempfile::tempdir().unwrap().keep();
        let path = retained.join("large.json");
        let bytes = vec![b'x'; 2 * 1024 * 1024];
        fs::write(&path, &bytes).unwrap();
        assert_eq!(read_regular_file(&path).unwrap(), bytes);
        let link = retained.join("linked.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_regular_file(&link).is_err());
        assert!(read_regular_file(&retained).is_err());
        let linked_root = retained.join("linked-root");
        std::os::unix::fs::symlink(&retained, &linked_root).unwrap();
        assert!(read_regular_file(&linked_root.join("large.json")).is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
        // Retained real filesystem bytes only; no remote or recovery ownership.
    }

    #[test]
    fn test_atomic_write_creates_file() {
        log_test_start("test_atomic_write_creates_file");
        let tmp = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let path = tmp.path().join("test.txt");

        atomic_write(&path, b"hello").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
        log_test_pass("test_atomic_write_creates_file");
    }

    #[test]
    fn test_atomic_write_overwrites() {
        log_test_start("test_atomic_write_overwrites");
        let tmp = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let path = tmp.path().join("test.txt");

        atomic_write(&path, b"original").unwrap();
        atomic_write(&path, b"updated").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "updated");
        log_test_pass("test_atomic_write_overwrites");
    }

    #[test]
    fn test_atomic_write_creates_parent_dirs() {
        log_test_start("test_atomic_write_creates_parent_dirs");
        let tmp = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let path = tmp.path().join("a/b/c/test.txt");

        atomic_write(&path, b"nested").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "nested");
        log_test_pass("test_atomic_write_creates_parent_dirs");
    }

    #[test]
    fn test_atomic_write_no_temp_files_left() {
        log_test_start("test_atomic_write_no_temp_files_left");
        let tmp = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let path = tmp.path().join("test.txt");

        atomic_write(&path, b"content").unwrap();

        // Check no .tmp files remain
        let tmp_files: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        assert!(
            tmp_files.is_empty(),
            "Successful rename must consume its temporary name"
        );
        log_test_pass("test_atomic_write_no_temp_files_left");
    }

    #[test]
    fn atomic_write_retains_failed_rename_bytes_and_occupied_temporary() {
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let blocked = directory.path().join("directory-target");
        fs::create_dir(&blocked).unwrap();
        fs::write(blocked.join("original"), b"original target evidence").unwrap();
        assert!(atomic_write(&blocked, b"unpublished bytes").is_err());
        let retained: Vec<_> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "tmp"))
            .collect();
        assert_eq!(retained.len(), 1);
        assert_eq!(fs::read(&retained[0]).unwrap(), b"unpublished bytes");
        assert_eq!(
            fs::read(blocked.join("original")).unwrap(),
            b"original target evidence"
        );
        let target = directory.path().join("target");
        let occupied = std::ffi::OsStr::new("occupied.tmp");
        fs::write(&target, b"original destination").unwrap();
        fs::write(directory.path().join(occupied), b"original temporary").unwrap();
        // The same production writer takes its generated name as an argument;
        // exercise a real collision without replacing randomness or I/O.
        assert!(atomic_write_with_temporary_name(&target, b"replacement", occupied).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original destination");
        assert_eq!(
            fs::read(directory.path().join(occupied)).unwrap(),
            b"original temporary"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_preserves_parent_aliases_and_rejects_late_file_changes() {
        use std::io::Seek;
        use std::os::unix::fs::{FileExt, MetadataExt, symlink};
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let real = directory.path().join("real");
        fs::create_dir(&real).unwrap();
        let alias = directory.path().join("alias");
        symlink(&real, &alias).unwrap();
        atomic_write(&alias.join("positive"), b"published bytes").unwrap();
        assert_eq!(fs::read(real.join("positive")).unwrap(), b"published bytes");
        for change in ["links", "bytes"] {
            let parent = directory.path().join(change);
            fs::create_dir(&parent).unwrap();
            let temporary = std::ffi::OsStr::new("held.tmp");
            let destination = std::ffi::OsStr::new("target");
            fs::write(parent.join(destination), b"prior target bytes").unwrap();
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(parent.join(temporary))
                .unwrap();
            file.write_all(b"retained bytes").unwrap();
            file.sync_all().unwrap();
            let inode = file.metadata().unwrap().ino();
            let position = file.stream_position().unwrap();
            verify_atomic_write_bytes(&file, b"retained bytes").unwrap();
            assert_eq!(file.stream_position().unwrap(), position);
            let held_parent = File::open(&parent).unwrap();
            if change == "links" {
                fs::hard_link(parent.join(temporary), parent.join("original-alias")).unwrap();
            } else {
                assert_eq!(file.write_at(b"X", 0).unwrap(), 1);
                file.sync_all().unwrap();
            }
            assert!(
                publish_atomic_temporary(
                    &held_parent,
                    &parent,
                    temporary,
                    destination,
                    &file,
                    b"retained bytes"
                )
                .is_err()
            );
            assert_eq!(file.metadata().unwrap().ino(), inode);
            assert_eq!(
                fs::read(parent.join(destination)).unwrap(),
                b"prior target bytes"
            );
            assert!(parent.join(temporary).is_file());
            let retained = fs::read(parent.join(temporary)).unwrap();
            if change == "links" {
                assert_eq!(retained, b"retained bytes");
                assert_eq!(
                    fs::read(parent.join("original-alias")).unwrap(),
                    b"retained bytes"
                );
            } else {
                assert_eq!(retained, b"Xetained bytes");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_publishes_a_held_write_only_file_without_changing_global_umask() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let temporary = std::ffi::OsStr::new("write-only.tmp");
        let destination = std::ffi::OsStr::new("target");
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(directory.path().join(temporary))
            .unwrap();
        file.write_all(b"held output bytes").unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o222))
            .unwrap();
        file.sync_all().unwrap();
        let inode = file.metadata().unwrap().ino();
        let parent = File::open(directory.path()).unwrap();
        publish_atomic_temporary(
            &parent,
            directory.path(),
            temporary,
            destination,
            &file,
            b"held output bytes",
        )
        .unwrap();
        assert_eq!(
            fs::symlink_metadata(directory.path().join(destination))
                .unwrap()
                .ino(),
            inode
        );
        assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o222);
        verify_atomic_write_bytes(&file, b"held output bytes").unwrap();
        assert!(!directory.path().join(temporary).exists());
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
