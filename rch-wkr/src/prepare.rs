//! Cross-process ownership of dependency preparation.
//!
//! Every public prepare call goes through this transaction; the installer is a
//! private implementation detail. The stable lock/journal inode lives outside
//! the project, where source synchronization and `npm ci` cannot remove it.
//! A dropped future, worker crash, timeout, or uncertain completion leaves a
//! write-ahead refusal fence. Another process must not turn that uncertainty
//! into a cache hit or start a competing installer in the same directory.

mod install;
mod workspace_inputs;

use install::{INPUT_NAMES, InstallPlan};
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
const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct InputIdentity {
    len: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    inode: (u64, u64, i64, i64),
}

impl InputIdentity {
    fn of(metadata: &std::fs::Metadata) -> Result<Self> {
        ensure!(
            metadata.file_type().is_file(),
            "dependency input is not a regular file"
        );
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified()?,
            #[cfg(unix)]
            inode: {
                use std::os::unix::fs::MetadataExt;
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            },
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct InputObservation {
    identity: InputIdentity,
    digest: blake3::Hash,
}

struct DependencyInputs {
    names: Vec<String>,
    members: Vec<Option<InputObservation>>,
    fingerprint: install::DependencyFingerprint,
    #[cfg(unix)]
    root: (u64, u64),
}

impl DependencyInputs {
    fn capture(project: &Path) -> Result<Self> {
        let root = std::fs::symlink_metadata(project)?;
        ensure!(
            root.file_type().is_dir(),
            "dependency project is not a real directory"
        );
        let inventory = workspace_inputs::discover(project, INPUT_NAMES)?;
        let names = inventory.names.clone();
        let mut budget = MAX_INPUT_BYTES;
        let mut hasher = install::fingerprint_hasher();
        let mut sources = Vec::new();
        let mut members = Vec::new();
        for name in &names {
            let path = project.join(name);
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    members.push(None);
                    continue;
                }
                Err(error) => return Err(error).with_context(|| format!("inspect {name}")),
            };
            let before = InputIdentity::of(&metadata).with_context(|| format!("inspect {name}"))?;
            budget = budget
                .checked_sub(before.len)
                .context("dependency inputs exceed byte limit")?;
            let mut file = File::open(&path).with_context(|| format!("open {name}"))?;
            ensure!(
                InputIdentity::of(&file.metadata()?)? == before,
                "{name} changed before read"
            );
            let mut bytes = Vec::new();
            (&mut file).take(before.len + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == before.len
                    && InputIdentity::of(&file.metadata()?)? == before
                    && InputIdentity::of(&std::fs::symlink_metadata(&path)?)? == before,
                "{name} changed during read"
            );
            hasher.update(&(name.len() as u32).to_le_bytes());
            hasher.update(name.as_bytes());
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
            sources.push(name.clone());
            members.push(Some(InputObservation {
                identity: before,
                digest: blake3::hash(&bytes),
            }));
        }
        let root_manifest = members[0]
            .as_ref()
            .context("package.json is required for dependency preparation")?;
        // Discovery and file reads must describe the same root manifest and
        // directory membership. A new glob-matched package is an input too.
        inventory.verify(root_manifest)?;
        // Revalidate earlier inputs after reading the last one: a coherent
        // observation must not combine generations changed during this walk.
        for (name, observed) in names.iter().zip(&members) {
            let now = match std::fs::symlink_metadata(project.join(name)) {
                Ok(metadata) => Some(InputIdentity::of(&metadata)?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
            ensure!(
                now.as_ref() == observed.as_ref().map(|input| &input.identity),
                "{name} changed during capture"
            );
        }
        #[cfg(unix)]
        let root = {
            use std::os::unix::fs::MetadataExt;
            let current = std::fs::symlink_metadata(project)?;
            ensure!(
                current.file_type().is_dir()
                    && (root.dev(), root.ino()) == (current.dev(), current.ino()),
                "dependency project changed during capture"
            );
            (root.dev(), root.ino())
        };
        let fingerprint = install::DependencyFingerprint {
            hash: hasher.finalize().to_hex().to_string(),
            sources,
        };
        ensure!(
            serde_json::to_vec(&fingerprint)?.len() as u64 <= MAX_FINGERPRINT_BYTES,
            "dependency input inventory exceeds fingerprint byte limit"
        );
        Ok(Self {
            names,
            members,
            fingerprint,
            #[cfg(unix)]
            root,
        })
    }

    fn verify_after(
        &self,
        after: &Self,
        runtime: RequiredRuntime,
        action: PrepareAction,
    ) -> Result<()> {
        #[cfg(unix)]
        ensure!(
            self.root == after.root,
            "dependency project was replaced during preparation"
        );
        ensure!(
            self.names == after.names,
            "workspace manifest inventory changed during preparation"
        );
        // Only the chosen installer's newly generated lockfile is permitted.
        // Existing files (including locks) must retain both bytes and identity.
        // Use the same selection as dispatch. A Bun test against an npm-locked
        // project still uses npm, and a frozen install may create no new lock.
        let generated =
            InstallPlan::for_sources(&self.fingerprint.sources, runtime)?.generated_lockfiles();
        for ((name, before), current) in self.names.iter().zip(&self.members).zip(&after.members) {
            match (before, current) {
                (Some(before), Some(current)) if before == current => {}
                (None, None) => {}
                (None, Some(_))
                    if action == PrepareAction::Installed && generated.contains(&name.as_str()) => {
                }
                _ => bail!("dependency input {name} changed during preparation"),
            }
        }
        Ok(())
    }
}

fn preflight_cache_files(project: &Path) -> Result<()> {
    for name in [FINGERPRINT_FILE, ".rch_dep_fingerprint.json.tmp"] {
        match std::fs::symlink_metadata(project.join(name)) {
            Ok(metadata) => ensure!(
                metadata.file_type().is_file() && metadata.len() <= MAX_FINGERPRINT_BYTES,
                "invalid dependency cache file: {name}"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("inspect {name}")),
        }
    }
    Ok(())
}

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
        let project = project
            .canonicalize()
            .context("resolve preparation project")?;
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
            Ok(meta) => ensure!(
                meta.file_type().is_file(),
                "invalid preparation journal type"
            ),
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
            ensure!(
                named.mode() & 0o077 == 0,
                "preparation journal is not private"
            );
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
        Ok(meta) => ensure!(
            meta.file_type().is_dir(),
            "node_modules is not a real directory"
        ),
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
    ensure!(
        file.metadata()?.is_file(),
        "cached fingerprint is not a regular file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_FINGERPRINT_BYTES + 1)
        .read_to_end(&mut bytes)?;
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
        preflight_cache_files(&transaction.project)?;
        let inputs = DependencyInputs::capture(&transaction.project)?;
        // A conflicting lock inventory has not started an installation. Refuse
        // before RUNNING so correcting that input does not require recovery.
        InstallPlan::for_sources(&inputs.fingerprint.sources, runtime)?;
        transaction.record(RUNNING)?;
        let mut report = install::prepare(&transaction.project, runtime, log_dir).await?;
        match report.action {
            PrepareAction::Installed | PrepareAction::Skipped => {
                let verified = (|| {
                    let after = DependencyInputs::capture(&transaction.project)?;
                    inputs.verify_after(&after, runtime, report.action)?;
                    ensure!(
                        report.fingerprint.as_ref() == Some(&after.fingerprint),
                        "published dependency fingerprint differs from observed inputs"
                    );
                    preflight_cache_files(&transaction.project)?;
                    verified_fingerprint(&transaction.project, &report)
                })();
                if let Err(error) = verified {
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

    #[test]
    fn npm_locked_bun_execution_cannot_publish_a_new_bun_lock() {
        for npm_lock in ["package-lock.json", "npm-shrinkwrap.json"] {
            let fixture = tempfile::tempdir().unwrap();
            std::fs::write(fixture.path().join("package.json"), b"{}").unwrap();
            std::fs::write(fixture.path().join(npm_lock), b"locked").unwrap();
            let before = DependencyInputs::capture(fixture.path()).unwrap();
            before
                .verify_after(
                    &DependencyInputs::capture(fixture.path()).unwrap(),
                    RequiredRuntime::Bun,
                    PrepareAction::Skipped,
                )
                .unwrap();
            std::fs::write(fixture.path().join("bun.lock"), b"unexpected migration").unwrap();
            assert!(
                before
                    .verify_after(
                        &DependencyInputs::capture(fixture.path()).unwrap(),
                        RequiredRuntime::Bun,
                        PrepareAction::Installed,
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn shrinkwrap_and_project_config_cannot_change_during_installation() {
        for name in ["npm-shrinkwrap.json", ".npmrc"] {
            let fixture = tempfile::tempdir().unwrap();
            std::fs::write(fixture.path().join("package.json"), b"{}").unwrap();
            std::fs::write(fixture.path().join(name), b"first").unwrap();
            let before = DependencyInputs::capture(fixture.path()).unwrap();
            std::fs::write(fixture.path().join(name), b"other").unwrap();
            let error = before
                .verify_after(
                    &DependencyInputs::capture(fixture.path()).unwrap(),
                    RequiredRuntime::Node,
                    PrepareAction::Installed,
                )
                .unwrap_err();
            assert!(error.to_string().contains(name));
        }
    }

    #[tokio::test]
    async fn input_observation_matches_the_installers_fingerprint() {
        let fixture = tempfile::tempdir().unwrap();
        for name in INPUT_NAMES {
            let contents = if *name == "package.json" {
                r#"{"name":"fixture"}"#.to_owned()
            } else {
                format!("contents of {name}")
            };
            std::fs::write(fixture.path().join(name), contents).unwrap();
        }
        let inputs = DependencyInputs::capture(fixture.path()).unwrap();
        assert_eq!(
            inputs.fingerprint,
            install::compute_fingerprint(fixture.path()).await.unwrap()
        );
        assert!(
            inputs
                .verify_after(
                    &DependencyInputs::capture(fixture.path()).unwrap(),
                    RequiredRuntime::Node,
                    PrepareAction::Skipped,
                )
                .is_err(),
            "mixed-manager inventory cannot be a completed preparation"
        );
    }

    #[test]
    fn preexisting_inputs_cannot_change_even_when_mtime_is_restored() {
        let fixture = tempfile::tempdir().unwrap();
        let manifest = fixture.path().join("package.json");
        std::fs::write(&manifest, br#"{"name":"first"}"#).unwrap();
        let before = DependencyInputs::capture(fixture.path()).unwrap();
        let modified = std::fs::metadata(&manifest).unwrap().modified().unwrap();
        std::fs::write(&manifest, br#"{"name":"other"}"#).unwrap();
        File::options()
            .write(true)
            .open(&manifest)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        let after = DependencyInputs::capture(fixture.path()).unwrap();
        let error = before
            .verify_after(&after, RequiredRuntime::Node, PrepareAction::Installed)
            .unwrap_err();
        assert!(error.to_string().contains("package.json changed"));
    }

    #[test]
    fn only_the_selected_installers_new_lockfile_may_appear() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(fixture.path().join("package.json"), b"{}").unwrap();
        let before = DependencyInputs::capture(fixture.path()).unwrap();
        std::fs::write(fixture.path().join("bun.lock"), b"new lock").unwrap();
        let after = DependencyInputs::capture(fixture.path()).unwrap();
        before
            .verify_after(&after, RequiredRuntime::Bun, PrepareAction::Installed)
            .unwrap();
        assert!(
            before
                .verify_after(&after, RequiredRuntime::Node, PrepareAction::Installed)
                .is_err()
        );
        assert!(
            before
                .verify_after(&after, RequiredRuntime::Bun, PrepareAction::Skipped)
                .is_err()
        );
        std::fs::write(fixture.path().join("bunfig.toml"), b"new configuration").unwrap();
        assert!(
            before
                .verify_after(
                    &DependencyInputs::capture(fixture.path()).unwrap(),
                    RequiredRuntime::Bun,
                    PrepareAction::Installed,
                )
                .is_err()
        );
    }

    #[test]
    fn input_capture_requires_a_manifest_and_bounds_regular_file_reads() {
        let fixture = tempfile::tempdir().unwrap();
        assert!(DependencyInputs::capture(fixture.path()).is_err());
        let manifest = fixture.path().join("package.json");
        std::fs::create_dir(&manifest).unwrap();
        assert!(DependencyInputs::capture(fixture.path()).is_err());
        std::fs::rename(&manifest, fixture.path().join("retained-directory")).unwrap();
        let file = File::create(&manifest).unwrap();
        file.set_len(MAX_INPUT_BYTES + 1).unwrap();
        assert!(DependencyInputs::capture(fixture.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cache_temp_symlink_cannot_redirect_fingerprint_publication() {
        let fixture = tempfile::tempdir().unwrap();
        let sentinel = fixture.path().join("sentinel");
        std::fs::write(&sentinel, b"retain these bytes").unwrap();
        std::os::unix::fs::symlink(
            &sentinel,
            fixture.path().join(".rch_dep_fingerprint.json.tmp"),
        )
        .unwrap();
        assert!(preflight_cache_files(fixture.path()).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"retain these bytes");
    }

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
