//! Cross-process ownership of dependency preparation.
//!
//! Every public prepare call goes through this transaction; the installer is a
//! private implementation detail. The stable lock/journal inode lives outside
//! the project, where source synchronization and `npm ci` cannot remove it.
//! A dropped future, worker crash, timeout, or uncertain completion leaves a
//! write-ahead refusal fence. Another process must not turn that uncertainty
//! into a cache hit or start a competing installer in the same directory.

mod environment;
mod install;
mod outputs;
mod workspace_inputs;
mod yarn;

pub use install::{DependencyLayout, PrepareAction, PrepareReport};
use install::{INPUT_NAMES, InstallPlan};
#[cfg(target_os = "linux")]
pub(crate) use install::{exec_installer, run_installer_supervisor};
pub use outputs::{proof_inspect, proof_install, proof_verify};

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
    environment: environment::CapturedEnvironment,
    fingerprint: install::DependencyFingerprint,
    dependency_layout: DependencyLayout,
    yarn: Option<yarn::Observation>,
    #[cfg(unix)]
    root: (u64, u64),
}

impl DependencyInputs {
    async fn capture_for_install(project: &Path) -> Result<Self> {
        // Standalone fingerprint callers have no outer transaction. Pure
        // captures never execute a manager or acquire its journal; Berry's
        // executable configuration requires the same durable owner as install.
        let project = project.to_owned();
        let captured_project = project.clone();
        let inputs = tokio::task::spawn_blocking(move || Self::capture(&captured_project))
            .await
            .context("capture dependency inputs")??;
        if !yarn::requires_query(&project, &inputs.fingerprint.sources)? {
            return Ok(inputs);
        }
        let mut transaction = PrepareTransaction::acquire(&project).await?;
        Self::capture_in_transaction(&mut transaction).await
    }

    async fn capture_in_transaction(transaction: &mut PrepareTransaction) -> Result<Self> {
        let project = transaction.project.clone();
        let captured_project = project.clone();
        let mut inputs = tokio::task::spawn_blocking(move || Self::capture(&captured_project))
            .await
            .context("capture dependency inputs")??;
        let yarn = yarn::capture(&project, &inputs.fingerprint.sources, transaction).await?;
        if let Some(observation) = &yarn {
            let mut digest = install::fingerprint_hasher();
            digest.update(inputs.fingerprint.hash.as_bytes());
            digest.update(observation.digest.as_bytes());
            inputs.fingerprint.hash = digest.finalize().to_hex().to_string();
            inputs.dependency_layout = observation.layout;
            let captured_project = project.clone();
            let after = tokio::task::spawn_blocking(move || Self::capture(&captured_project))
                .await
                .context("revalidate dependency inputs")??;
            ensure!(
                inputs.names == after.names
                    && inputs.members == after.members
                    && inputs.environment == after.environment,
                "dependency inputs changed during package-manager configuration query"
            );
        }
        inputs.yarn = yarn;
        Ok(inputs)
    }

    fn outputs_ready(&self, project: &Path) -> bool {
        self.yarn.as_ref().map_or_else(
            || project.join("node_modules").is_dir(),
            |yarn| yarn.outputs_ready(project),
        )
    }

    fn verify_invocation(&self, preparation: &Path, invocation: &Path) -> Result<()> {
        if let Some(yarn) = &self.yarn {
            yarn.verify_invocation(preparation, invocation)?;
        }
        Ok(())
    }

    fn capture(project: &Path) -> Result<Self> {
        let root = std::fs::symlink_metadata(project)?;
        ensure!(
            root.file_type().is_dir(),
            "dependency project is not a real directory"
        );
        let environment = environment::capture(project)?;
        let inventory = workspace_inputs::discover(project, INPUT_NAMES)?;
        let names = inventory.names.clone();
        let mut budget = MAX_INPUT_BYTES;
        let mut hasher = install::fingerprint_hasher();
        hasher.update(environment.digest.as_bytes());
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
        ensure!(
            environment::capture(project)? == environment,
            "package-manager environment changed during dependency capture"
        );
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
            environment,
            fingerprint,
            dependency_layout: DependencyLayout::NodeModules,
            yarn: None,
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
        ensure!(
            self.environment == after.environment,
            "package-manager environment changed during preparation"
        );
        let same_yarn = match (&self.yarn, &after.yarn) {
            (None, None) => true,
            (Some(before), Some(after)) => before.unchanged_after_install(after),
            _ => false,
        };
        ensure!(
            same_yarn && self.dependency_layout == after.dependency_layout,
            "Yarn configuration or auxiliary inputs changed during preparation"
        );
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
    #[cfg(target_os = "linux")]
    running: bool,
    #[cfg(target_os = "linux")]
    query_pending: bool,
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
            #[cfg(target_os = "linux")]
            running: false,
            #[cfg(target_os = "linux")]
            query_pending: false,
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
        #[cfg(target_os = "linux")]
        ensure!(
            state != IDLE || !self.query_pending,
            "Yarn configuration descendant completion remains unconfirmed"
        );
        self.verify_path()?;
        // Intentionally synchronous: dropping an async fs future must not
        // leave a detached journal write running after the kernel lock drops.
        self.file.rewind()?;
        self.file.write_all(state)?;
        self.file.set_len(state.len() as u64)?;
        self.file.sync_all()?;
        #[cfg(unix)]
        File::open(self.path.parent().context("journal has no parent")?)?.sync_all()?;
        self.verify_path()?;
        #[cfg(target_os = "linux")]
        {
            self.running = state == RUNNING;
        }
        Ok(())
    }

    /// A configuration probe may execute plugins and spawn detached writers.
    /// Persist its uncertainty before spawn, and do not clear an outer install
    /// fence when a post-install probe completes.
    #[cfg(target_os = "linux")]
    fn begin_query(&mut self) -> Result<bool> {
        ensure!(
            !self.query_pending,
            "Yarn configuration descendant completion remains unconfirmed"
        );
        let already_running = self.running;
        self.record(RUNNING)?;
        self.query_pending = true;
        Ok(already_running)
    }

    #[cfg(target_os = "linux")]
    fn finish_query(&mut self, already_running: bool) -> Result<()> {
        ensure!(
            self.query_pending,
            "Yarn configuration query was not started"
        );
        // The caller has validated the supervisor's complete descendant
        // receipt. All following operations are synchronous, so cancellation
        // cannot interleave a retirement with another writer.
        self.query_pending = false;
        self.record(if already_running { RUNNING } else { IDLE })
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
        dependency_layout: DependencyLayout::NodeModules,
        fingerprint: None,
        fingerprint_changed_from: None,
        install_log_path: None,
        took_ms: started.elapsed().as_millis() as u64,
        bytes_added_to_node_modules: 0,
        completed_at: Utc::now(),
    }
}

fn verified_fingerprint(
    project: &Path,
    report: &PrepareReport,
    inputs: &DependencyInputs,
) -> Result<()> {
    ensure!(
        report.dependency_layout == inputs.dependency_layout,
        "prepared dependency layout changed"
    );
    if inputs.dependency_layout == DependencyLayout::YarnPnp {
        ensure!(
            inputs.outputs_ready(project),
            "prepared Yarn PnP outputs are incomplete"
        );
    } else {
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
        let inputs = DependencyInputs::capture_in_transaction(&mut transaction).await?;
        // These deterministic refusals have not started an installation.
        // Reject before RUNNING so correcting the request needs no recovery.
        InstallPlan::for_sources(&inputs.fingerprint.sources, runtime)?;
        inputs.dependency_layout.verify_runtime(runtime)?;
        transaction.record(RUNNING)?;
        let mut report = install::prepare_observed_node(
            &mut transaction,
            runtime,
            log_dir,
            &inputs,
            true,
            false,
        )
        .await?;
        match report.action {
            PrepareAction::Installed | PrepareAction::Skipped => {
                let verified = async {
                    let after = DependencyInputs::capture_in_transaction(&mut transaction).await?;
                    inputs.verify_after(&after, runtime, report.action)?;
                    ensure!(
                        report.fingerprint.as_ref() == Some(&after.fingerprint),
                        "published dependency fingerprint differs from observed inputs"
                    );
                    preflight_cache_files(&transaction.project)?;
                    verified_fingerprint(&transaction.project, &report, &after)
                }
                .await;
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
                // Linux reports a terminal installer failure only after its
                // supervisor confirms the descendant tree is reaped. Missing
                // or invalid completion evidence returns Err above, retaining
                // RUNNING. Also require the old success stamp to be absent.
                // Other platforms retain their foreground-only wait behavior.
                if matches!(
                    std::fs::symlink_metadata(transaction.project.join(FINGERPRINT_FILE)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound
                ) {
                    transaction.record(IDLE)?;
                }
            }
            PrepareAction::Timeout => {
                // Stopping the installer/supervisor does not prove that all
                // lifecycle descendants stopped. Keep the write-ahead fence.
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
        for name in [
            "npm-shrinkwrap.json",
            ".npmrc",
            ".yarnrc",
            ".yarnrc.yml",
            ".pnpmfile.cjs",
            ".pnpmfile.mjs",
        ] {
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
    fn generated_lockfile_cannot_hide_an_install_environment_change() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(fixture.path().join("package.json"), b"{}").unwrap();
        let before = DependencyInputs::capture(fixture.path()).unwrap();
        std::fs::write(fixture.path().join("package-lock.json"), b"new lock").unwrap();
        let mut after = DependencyInputs::capture(fixture.path()).unwrap();
        before
            .verify_after(&after, RequiredRuntime::Node, PrepareAction::Installed)
            .unwrap();
        // Inject changed capture evidence without mutating the process-wide
        // environment used concurrently by other tests.
        after.environment.digest = blake3::hash(b"different installation environment");
        let error = before
            .verify_after(&after, RequiredRuntime::Node, PrepareAction::Installed)
            .unwrap_err();
        assert!(error.to_string().contains("environment changed"));
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn completed_queries_restore_only_their_own_journal_fence() {
        let fixture = tempfile::tempdir().unwrap();
        let directory = fixture.path().join("transactions");
        let mut transaction =
            PrepareTransaction::acquire_in(fixture.path(), &directory, Duration::ZERO)
                .await
                .unwrap();
        let was_running = transaction.begin_query().unwrap();
        assert!(!was_running);
        assert_eq!(std::fs::read(&transaction.path).unwrap(), RUNNING);
        transaction.finish_query(was_running).unwrap();
        assert_eq!(std::fs::read(&transaction.path).unwrap(), IDLE);
        transaction.record(RUNNING).unwrap();
        let was_running = transaction.begin_query().unwrap();
        assert!(was_running);
        transaction.finish_query(was_running).unwrap();
        assert_eq!(std::fs::read(&transaction.path).unwrap(), RUNNING);
        transaction.record(IDLE).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn unconfirmed_query_blocks_more_probes_and_idle_publication() {
        let fixture = tempfile::tempdir().unwrap();
        let directory = fixture.path().join("transactions");
        let mut transaction =
            PrepareTransaction::acquire_in(fixture.path(), &directory, Duration::ZERO)
                .await
                .unwrap();
        transaction.begin_query().unwrap();
        assert!(transaction.begin_query().is_err());
        assert!(transaction.record(IDLE).is_err());
        let path = transaction.path.clone();
        drop(transaction);
        assert_eq!(std::fs::read(path).unwrap(), RUNNING);
        assert!(
            PrepareTransaction::acquire_in(fixture.path(), &directory, Duration::ZERO)
                .await
                .is_err()
        );
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
