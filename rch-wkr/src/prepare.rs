//! Cross-process ownership of dependency preparation.
//!
//! Every public prepare call goes through this transaction; the installer is a
//! private implementation detail. The stable lock/journal inode lives outside
//! the project, where source synchronization and `npm ci` cannot remove it.
//! A dropped future, worker crash, timeout, or uncertain completion leaves a
//! write-ahead refusal fence. Another process must not turn that uncertainty
//! into a cache hit or start a competing installer in the same directory.

mod install;

pub use install::{PrepareAction, PrepareReport};

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use rch_common::types::RequiredRuntime;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const IDLE: &[u8] = b"RCH_PREPARE_V1:idle\n";
const RUNNING: &[u8] = b"RCH_PREPARE_V1:running\n";
const MAX_JOURNAL_BYTES: u64 = 128;
const MAX_FINGERPRINT_BYTES: u64 = 16 * 1024;
const LOCK_WAIT: Duration = Duration::from_secs(300);
const FINGERPRINT_FILE: &str = ".rch_dep_fingerprint.json";

/// A kernel lock and an in-place journal share one stable inode. Never unlink
/// or atomically replace this file: doing so would split concurrent owners.
/// Dropping this object releases the lock, but NEVER clears a running journal.
struct PrepareTransaction {
    file: File,
    path: PathBuf,
    project: PathBuf,
}

impl PrepareTransaction {
    async fn acquire(project: &Path) -> Result<Self> {
        let cache = dirs::cache_dir().context("cannot determine preparation cache directory")?;
        Self::acquire_in(project, &cache.join("rch/prepare-transactions"), LOCK_WAIT).await
    }

    async fn acquire_in(project: &Path, directory: &Path, budget: Duration) -> Result<Self> {
        let project = project.canonicalize().context("resolve preparation project")?;
        ensure!(project.is_dir(), "preparation project is not a directory");
        let mut key = blake3::Hasher::new();
        key.update(b"rch-prepare-project-v1\0");
        key.update(project.as_os_str().as_encoded_bytes());
        let path = directory.join(format!("{}.lock", key.finalize().to_hex()));
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(directory)
            .context("create preparation transaction directory")?;
        ensure!(
            std::fs::symlink_metadata(directory)?.file_type().is_dir(),
            "preparation transaction directory is not a real directory"
        );
        // This is a private worker cache, not a hostile-path sandbox. Refuse
        // static symlinks/special files before an open and revalidate the inode
        // after acquisition. No source path is created to repair a failed open.
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => ensure!(meta.file_type().is_file(), "invalid preparation journal type"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).context("open preparation journal")?;
        let mut transaction = Self {
            file,
            path,
            project,
        };
        transaction.verify_path()?;
        let started = Instant::now();
        loop {
            match transaction.file.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) => {
                    let remaining = budget.saturating_sub(started.elapsed());
                    ensure!(
                        !remaining.is_zero(),
                        "dependency preparation is busy; lock wait expired"
                    );
                    tokio::time::sleep(Duration::from_millis(25).min(remaining)).await;
                }
                Err(TryLockError::Error(error)) => {
                    return Err(error).context("lock dependency preparation");
                }
            }
        }
        transaction.verify_path()?;
        let mut state = Vec::new();
        (&mut transaction.file)
            .take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut state)?;
        ensure!(
            state.len() as u64 <= MAX_JOURNAL_BYTES,
            "oversized preparation journal"
        );
        if !state.is_empty() && state != IDLE {
            bail!(
                "dependency preparation has an interrupted or invalid transaction at {}; \
                 preserve it and retry in a fresh isolated project directory until the old \
                 installer and its descendants have been reconciled",
                transaction.path.display()
            );
        }
        Ok(transaction)
    }

    fn verify_path(&self) -> Result<()> {
        let named = std::fs::symlink_metadata(&self.path)?;
        let opened = self.file.metadata()?;
        ensure!(
            named.file_type().is_file() && opened.is_file(),
            "preparation journal is not a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                (named.dev(), named.ino()) == (opened.dev(), opened.ino()),
                "preparation journal inode changed"
            );
            ensure!(named.mode() & 0o077 == 0, "preparation journal is not private");
        }
        Ok(())
    }

    fn record(&mut self, state: &[u8]) -> Result<()> {
        self.verify_path()?;
        // Intentionally synchronous: dropping an async fs future must not
        // leave a detached journal write running after the kernel lock drops.
        self.file.rewind()?;
        self.file.write_all(state)?;
        self.file.set_len(state.len() as u64)?;
        self.file.sync_all()?;
        #[cfg(unix)]
        File::open(self.path.parent().context("journal has no parent")?)?.sync_all()?;
        self.verify_path()
    }
}

fn failure(runtime: RequiredRuntime, started: Instant, error: &anyhow::Error) -> PrepareReport {
    tracing::warn!(
        target: "rch::wkr::prepare", error = %format!("{error:#}"),
        "dependency preparation refused; user command must not run"
    );
    PrepareReport {
        runtime,
        action: PrepareAction::Failed,
        fingerprint: None,
        fingerprint_changed_from: None,
        install_log_path: None,
        took_ms: started.elapsed().as_millis() as u64,
        bytes_added_to_node_modules: 0,
        completed_at: Utc::now(),
    }
}

fn verified_fingerprint(project: &Path, report: &PrepareReport) -> Result<()> {
    match std::fs::symlink_metadata(project.join("node_modules")) {
        Ok(meta) => ensure!(meta.file_type().is_dir(), "node_modules is not a real directory"),
        // An empty dependency set (or a non-node_modules package-manager
        // layout) can install successfully without creating this directory.
        // The installer will not reuse that case as a node_modules cache hit.
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && report.action == PrepareAction::Installed => {}
        Err(error) => return Err(error).context("inspect prepared node_modules"),
    }
    let expected = report
        .fingerprint
        .as_ref()
        .context("preparation fingerprint missing")?;
    let file = File::open(project.join(FINGERPRINT_FILE))?;
    ensure!(file.metadata()?.is_file(), "cached fingerprint is not a regular file");
    let mut bytes = Vec::new();
    file.take(MAX_FINGERPRINT_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_FINGERPRINT_BYTES,
        "cached fingerprint exceeds byte limit"
    );
    let cached: install::DependencyFingerprint = serde_json::from_slice(&bytes)?;
    ensure!(
        cached == *expected,
        "completed preparation has no matching cached fingerprint"
    );
    Ok(())
}

/// Prepare dependencies once across cooperating worker processes. An inability
/// to coordinate or verify preparation is a Failed report, not an Err that
/// the executor's legacy best-effort branch could turn into command execution.
pub async fn prepare(
    project_root: &Path,
    runtime: RequiredRuntime,
    log_dir: &Path,
) -> Result<PrepareReport> {
    if !matches!(runtime, RequiredRuntime::Bun | RequiredRuntime::Node) {
        return install::prepare(project_root, runtime, log_dir).await;
    }
    let started = Instant::now();
    let result = async {
        let mut transaction = PrepareTransaction::acquire(project_root).await?;
        transaction.record(RUNNING)?;
        let mut report = install::prepare(&transaction.project, runtime, log_dir).await?;
        match report.action {
            PrepareAction::Installed | PrepareAction::Skipped => {
                if let Err(error) = verified_fingerprint(&transaction.project, &report) {
                    tracing::warn!(
                        target: "rch::wkr::prepare", error = %format!("{error:#}"),
                        journal = %transaction.path.display(),
                        "prepared dependencies are unconfirmed"
                    );
                    report.action = PrepareAction::Failed;
                    return Ok(report);
                }
                transaction.record(IDLE)?;
            }
            PrepareAction::Failed => {
                // The installer reported a terminal nonzero exit. Retire its
                // transaction only if its old success stamp really is absent;
                // the legacy installer invalidates that stamp best-effort.
                if matches!(
                    std::fs::symlink_metadata(transaction.project.join(FINGERPRINT_FILE)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound
                ) {
                    transaction.record(IDLE)?;
                }
            }
            PrepareAction::Timeout => {
                // Killing the immediate installer does not prove all lifecycle
                // script descendants stopped. Keep the write-ahead fence.
                tracing::warn!(
                    target: "rch::wkr::prepare", journal = %transaction.path.display(),
                    "timed-out preparation requires isolated retry or descendant reconciliation"
                );
            }
        }
        report.took_ms = started.elapsed().as_millis() as u64;
        Ok::<_, anyhow::Error>(report)
    }
    .await;
    Ok(match result {
        Ok(report) => report,
        Err(error) => failure(runtime, started, &error),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transaction_excludes_other_handles_without_replacing_its_inode() {
        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let directory = fixture.path().join("transactions");
        let mut first = PrepareTransaction::acquire_in(&project, &directory, Duration::ZERO)
            .await
            .unwrap();
        first.record(RUNNING).unwrap();
        assert!(
            PrepareTransaction::acquire_in(&project.join("."), &directory, Duration::ZERO)
                .await
                .is_err()
        );
        let path = first.path.clone();
        first.record(IDLE).unwrap();
        drop(first);
        let second = PrepareTransaction::acquire_in(&project, &directory, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(second.path, path);
        second.verify_path().unwrap();
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn unclean_drop_cannot_authorize_a_fresh_installer() {
        let fixture = tempfile::tempdir().unwrap();
        let directory = fixture.path().join("transactions");
        let mut first = PrepareTransaction::acquire_in(fixture.path(), &directory, Duration::ZERO)
            .await
            .unwrap();
        first.record(RUNNING).unwrap();
        let path = first.path.clone();
        drop(first);
        let result =
            PrepareTransaction::acquire_in(fixture.path(), &directory, Duration::ZERO).await;
        assert!(result.is_err());
        assert_eq!(std::fs::read(path).unwrap(), RUNNING);
    }

    #[tokio::test]
    async fn separate_projects_in_one_cache_do_not_share_a_gate() {
        let fixture = tempfile::tempdir().unwrap();
        let directory = fixture.path().join("transactions");
        let other = fixture.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let first = PrepareTransaction::acquire_in(fixture.path(), &directory, Duration::ZERO)
            .await
            .unwrap();
        let second = PrepareTransaction::acquire_in(&other, &directory, Duration::ZERO)
            .await
            .unwrap();
        assert_ne!(first.path, second.path);
    }

    #[tokio::test]
    async fn coordination_errors_are_failed_reports_not_executor_fail_open_errors() {
        let fixture = tempfile::tempdir().unwrap();
        let report = prepare(
            &fixture.path().join("missing"),
            RequiredRuntime::Node,
            fixture.path(),
        )
        .await
        .unwrap();
        assert_eq!(report.action, PrepareAction::Failed);
        assert!(report.fingerprint.is_none());
    }
}
