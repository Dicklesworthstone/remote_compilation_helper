//! Durable source ownership and identity-bound collection. Never replays a command.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RecoveryRecipe {
    version: u32,
    wrapper_id: String,
    build_id: u64,
    worker: WorkerConfig,
    identity: String,
    completion: String,
    source_roots: Vec<String>,
    pair: Option<(String, String)>,
    retire_root: Option<String>,
    transfer: TransferConfig,
    project_root: PathBuf,
    kind: Option<CompilationKind>,
    expected_triple: String,
    pinned_triple: Option<String>,
    allow_foreign: bool,
    package_archive: bool,
    phases: Vec<RecoveryPhase>,
    exit_code: Option<i32>,
    returned: Option<i32>,
    #[serde(default)]
    prepared: bool,
    #[serde(default)]
    execution_started: bool,
    #[serde(default)]
    preparation_cancelled: bool,
    #[serde(default)]
    sources_released: bool,
    #[serde(default)]
    tree_retired: bool,
    #[serde(default)]
    pair_released: bool,
    #[serde(default)]
    retired: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct RecoveryPhase {
    name: String,
    local: PathBuf,
    remote: String,
    patterns: Vec<String>,
    result_dir: Option<PathBuf>,
    custom_target: bool,
    output_gate: bool,
    baseline: BTreeMap<PathBuf, String>,
    published: BTreeMap<PathBuf, String>,
    #[serde(default)]
    pending: Option<(PathBuf, String)>,
    complete: bool,
}

pub(crate) struct RecoverySession {
    recipe: RecoveryRecipe,
    writer: DurableLeaseWriter,
    _output_locks: Vec<File>,
}

fn fingerprint(path: &Path) -> anyhow::Result<Option<String>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "output is not a regular file: {}",
        path.display()
    );
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut bytes = [0u8; 65536];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        hasher.update(&bytes[..count]);
    }
    Ok(Some(hasher.finalize().to_hex().to_string()))
}

fn regular_files(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    fn visit(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
        if !directory.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            anyhow::ensure!(
                !kind.is_symlink(),
                "symlink in recovery output: {}",
                entry.path().display()
            );
            if kind.is_dir() {
                visit(root, &entry.path(), files)?;
            } else if kind.is_file() {
                files.push(entry.path().strip_prefix(root)?.to_owned());
            } else {
                anyhow::bail!("non-regular recovery output: {}", entry.path().display());
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn local_locks(roots: impl Iterator<Item = PathBuf>) -> anyhow::Result<Vec<File>> {
    let mut roots: Vec<_> = roots.collect();
    roots.sort();
    roots.dedup();
    let directory = default_job_lease_directory().join("output-locks");
    std::fs::create_dir_all(&directory)?;
    roots.into_iter().map(|root| {
        let name = blake3::hash(root.as_os_str().as_encoded_bytes()).to_hex().to_string();
        let file = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(directory.join(name))?;
        file.try_lock().map_err(|error| anyhow::anyhow!("output ownership is held by another live wrapper for {}: {error}; the original wrapper must finish collection", root.display()))?;
        Ok(file)
    }).collect()
}

impl RecoverySession {
    /// Save the recovery identity before even a queued remote grant can exist.
    /// Until `starting_execution` is durable, recovery can drain transfers and
    /// cancel this exact preparation without replaying a compiler command.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin(
        writer: &DurableLeaseWriter,
        worker: &WorkerConfig,
        source_roots: Vec<String>,
        pair: Option<(String, String)>,
        retire_root: Option<String>,
        transfer: TransferConfig,
        project_root: PathBuf,
        identity: String,
    ) -> anyhow::Result<()> {
        let lease = writer.snapshot();
        let build_id = lease
            .identity
            .remote_build_id
            .context("source ownership requires admitted build identity")?;
        anyhow::ensure!(
            lease.worker_id.as_deref() == Some(worker.id.as_str()) && lease.recovery.is_none(),
            "source ownership requires a fresh admitted lease; recover the previous attempt first"
        );
        let completion = format!(
            "{}/recovery-{}-{}.done",
            transfer.remote_base.trim_end_matches('/'),
            build_id,
            identity
        );
        let recipe = RecoveryRecipe {
            version: 2,
            wrapper_id: lease.identity.local_wrapper_id,
            build_id,
            worker: worker.clone(),
            identity,
            completion,
            source_roots,
            pair,
            retire_root,
            transfer,
            project_root,
            kind: None,
            expected_triple: String::new(),
            pinned_triple: None,
            allow_foreign: false,
            package_archive: false,
            phases: Vec::new(),
            exit_code: None,
            returned: None,
            prepared: false,
            execution_started: false,
            preparation_cancelled: false,
            sources_released: false,
            tree_retired: false,
            pair_released: false,
            retired: false,
        };
        writer.set_recovery(serde_json::to_value(recipe)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        writer: &DurableLeaseWriter,
        worker: &WorkerConfig,
        pipeline: &TransferPipeline,
        source_roots: Vec<String>,
        pair: Option<(String, String)>,
        retire_root: Option<String>,
        transfer: TransferConfig,
        project_root: PathBuf,
        target: Option<&Path>,
        kind: Option<CompilationKind>,
        command: &str,
        result_dirs: &[PathBuf],
        identity: String,
    ) -> anyhow::Result<Self> {
        // Persist the output contract, not runtime-test policy: recovery is
        // collection-only and has no command to reparse after the wrapper dies.
        let kind = artifact_delivery_kind(kind, Some(command));
        let lease = writer.snapshot();
        let intent: RecoveryRecipe = serde_json::from_value(
            lease
                .recovery
                .clone()
                .context("output preparation requires the persisted source intent")?,
        )?;
        anyhow::ensure!(
            intent.version == 2
                && intent.identity == identity
                && intent.wrapper_id == lease.identity.local_wrapper_id
                && Some(intent.build_id) == lease.identity.remote_build_id
                && intent.worker.id == worker.id
                && intent.source_roots == source_roots
                && intent.pair == pair
                && intent.retire_root == retire_root
                && !intent.execution_started
                && !intent.preparation_cancelled
                && !intent.retired,
            "output preparation cannot replace another source ownership intent"
        );
        let build_id = lease
            .identity
            .remote_build_id
            .context("recovery requires admitted build identity")?;
        let completion = format!(
            "{}/recovery-{}-{}.done",
            transfer.remote_base.trim_end_matches('/'),
            build_id,
            identity
        );
        let output_locks = local_locks(
            std::iter::once(project_root.clone()).chain(target.map(Path::to_path_buf)),
        )?;
        let mut phases = Vec::new();
        let project_patterns = get_project_artifact_patterns(kind, Some(command), target.is_some());
        if !project_patterns.is_empty() {
            phases.push(RecoveryPhase {
                name: "project".into(),
                local: project_root.clone(),
                remote: pipeline.remote_path(),
                patterns: project_patterns,
                result_dir: None,
                custom_target: false,
                output_gate: target.is_none(),
                baseline: BTreeMap::new(),
                published: BTreeMap::new(),
                pending: None,
                complete: false,
            });
        }
        if let Some(target) = target {
            let patterns = get_custom_target_artifact_patterns(kind, Some(command));
            if !patterns.is_empty() {
                phases.push(RecoveryPhase {
                    name: "target".into(),
                    local: target.to_owned(),
                    remote: pipeline.remote_cargo_target_dir(),
                    patterns,
                    result_dir: None,
                    custom_target: true,
                    output_gate: true,
                    baseline: BTreeMap::new(),
                    published: BTreeMap::new(),
                    pending: None,
                    complete: false,
                });
            }
        }
        for dir in result_dirs {
            phases.push(RecoveryPhase {
                name: format!("result:{}", dir.display()),
                local: project_root.clone(),
                remote: pipeline.remote_path(),
                patterns: Vec::new(),
                result_dir: Some(dir.clone()),
                custom_target: false,
                output_gate: false,
                baseline: BTreeMap::new(),
                published: BTreeMap::new(),
                pending: None,
                complete: false,
            });
        }
        for phase in &mut phases {
            let patterns: Vec<_> = if let Some(dir) = &phase.result_dir {
                vec![format!("{}/**/*", dir.display())]
            } else {
                phase
                    .patterns
                    .iter()
                    .filter(|pattern| !pattern.starts_with("- "))
                    .map(|pattern| {
                        pattern
                            .trim_start_matches("+ ")
                            .trim_start_matches('/')
                            .to_owned()
                    })
                    .collect()
            };
            for pattern in patterns {
                let pattern = format!(
                    "{}/{}",
                    glob::Pattern::escape(&phase.local.to_string_lossy()),
                    pattern
                );
                for path in glob::glob(&pattern)? {
                    let path = path?;
                    if path.is_file() {
                        let relative = path.strip_prefix(&phase.local)?.to_owned();
                        if let Some(hash) = fingerprint(&path)? {
                            phase.baseline.insert(relative, hash);
                        }
                    }
                }
            }
        }
        let pinned_triple = explicit_target_triple_for_command(command);
        let recipe = RecoveryRecipe {
            version: 2,
            wrapper_id: lease.identity.local_wrapper_id,
            build_id,
            worker: worker.clone(),
            identity,
            completion,
            source_roots,
            pair,
            retire_root,
            transfer,
            project_root,
            kind,
            expected_triple: pinned_triple
                .clone()
                .unwrap_or_else(default_host_target_triple),
            pinned_triple,
            allow_foreign: foreign_artifact_gate_disabled(),
            package_archive: sync_back_verified_zero_package_archives(Some(0), command),
            phases,
            exit_code: None,
            returned: None,
            prepared: true,
            execution_started: false,
            preparation_cancelled: false,
            sources_released: false,
            tree_retired: false,
            pair_released: false,
            retired: false,
        };
        let session = Self {
            recipe,
            writer: writer.clone(),
            _output_locks: output_locks,
        };
        session.persist()?;
        Ok(session)
    }

    fn persist(&self) -> anyhow::Result<()> {
        self.writer
            .set_recovery(serde_json::to_value(&self.recipe)?)
    }
    pub(crate) fn completion_pipeline(&self, pipeline: TransferPipeline) -> TransferPipeline {
        pipeline
            .with_recovery_completion(self.recipe.completion.clone(), self.recipe.identity.clone())
    }
    pub(crate) fn completed(&mut self, exit: i32) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recipe.execution_started,
            "completion requires an admitted execution attempt"
        );
        self.recipe.exit_code = Some(exit);
        self.persist()
    }
    pub(crate) fn starting_execution(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recipe.prepared
                && !self.recipe.execution_started
                && !self.recipe.preparation_cancelled
                && !self.recipe.sources_released,
            "execution requires an unconsumed prepared source grant"
        );
        self.recipe.execution_started = true;
        self.persist()
    }
    fn stage(&self, index: usize) -> PathBuf {
        default_job_lease_directory()
            .join("retrieval")
            .join(&self.recipe.identity)
            .join(index.to_string())
    }
    pub(crate) fn staging_pipeline(
        &self,
        name: &str,
        pipeline: &TransferPipeline,
    ) -> anyhow::Result<TransferPipeline> {
        let index = self
            .recipe
            .phases
            .iter()
            .position(|phase| phase.name == name)
            .context("missing retrieval phase")?;
        let stage = self.stage(index);
        std::fs::create_dir_all(&stage)?;
        Ok(pipeline
            .clone()
            .with_retrieval_reference_root(self.recipe.phases[index].local.clone())
            .with_local_root(stage))
    }
    pub(crate) fn publish(&mut self, name: &str) -> anyhow::Result<()> {
        let index = self
            .recipe
            .phases
            .iter()
            .position(|phase| phase.name == name)
            .context("missing retrieval phase")?;
        if self.recipe.phases[index].complete {
            return Ok(());
        }
        let stage = self.stage(index);
        let files = regular_files(&stage)?;
        let phase = &self.recipe.phases[index];
        if phase.result_dir.is_none() {
            // A resumed transfer can retain files selected by an older
            // collector. Ownership fingerprints alone do not authorize a
            // source file as an artifact: validate the complete pending write
            // set before either journal recovery or ordinary publication.
            let mut writes: Vec<_> = files
                .iter()
                .filter(|path| !phase.published.contains_key(*path))
                .cloned()
                .collect();
            if let Some((relative, hash)) = &phase.pending {
                if !phase.baseline.contains_key(relative)
                    && fingerprint(&phase.local.join(relative))?.as_ref() == Some(hash)
                {
                    // The prior rename already created this new output. Only
                    // its journal remains to be completed; the live reference
                    // tree must not reclassify our own generic output as source.
                    writes.retain(|path| path != relative);
                } else if !writes.contains(relative) {
                    writes.push(relative.clone());
                }
            }
            TransferPipeline::new(
                phase.local.clone(),
                "recovery-publication".into(),
                self.recipe.identity.clone(),
                self.recipe.transfer.clone(),
            )
            .validate_staged_artifact_paths(&writes, &phase.patterns)?;
        }
        if let Some((relative, hash)) = self.recipe.phases[index].pending.clone() {
            let destination = self.recipe.phases[index].local.join(&relative);
            let parent = destination
                .parent()
                .context("pending output missing parent")?;
            let temporary = parent.join(format!(".rch-return-{}", self.recipe.identity));
            let current = fingerprint(&destination)?;
            if current.as_ref() != Some(&hash) {
                anyhow::ensure!(
                    temporary.is_file()
                        && fingerprint(&temporary)?.as_ref() == Some(&hash)
                        && current.as_ref() == self.recipe.phases[index].baseline.get(&relative),
                    "interrupted output publication cannot prove ownership at {}; refusing overwrite",
                    destination.display()
                );
                std::fs::rename(&temporary, &destination)?;
                File::open(parent)?.sync_all()?;
            }
            self.recipe.phases[index].published.insert(relative, hash);
            self.recipe.phases[index].pending = None;
            self.persist()?;
        }
        for relative in files {
            let phase = &self.recipe.phases[index];
            if phase.published.contains_key(&relative) {
                continue;
            }
            let source = stage.join(&relative);
            let destination = phase.local.join(&relative);
            let hash = fingerprint(&source)?.context("staged output disappeared")?;
            let current = fingerprint(&destination)?;
            anyhow::ensure!(
                current.as_ref() == phase.baseline.get(&relative),
                "output ownership changed at {}; refusing to overwrite",
                destination.display()
            );
            let parent = destination.parent().context("output missing parent")?;
            let mut ancestor = Some(parent);
            while let Some(path) = ancestor {
                if let Ok(metadata) = std::fs::symlink_metadata(path) {
                    anyhow::ensure!(
                        !metadata.file_type().is_symlink(),
                        "output ancestor is a symlink: {}",
                        path.display()
                    );
                }
                ancestor = path.parent();
            }
            std::fs::create_dir_all(parent)?;
            let temporary = parent.join(format!(".rch-return-{}", self.recipe.identity));
            std::fs::copy(&source, &temporary)?;
            File::open(&temporary)?.sync_all()?;
            File::open(parent)?.sync_all()?;
            self.recipe.phases[index].pending = Some((relative.clone(), hash.clone()));
            self.persist()?;
            anyhow::ensure!(
                fingerprint(&destination)?.as_ref()
                    == self.recipe.phases[index].baseline.get(&relative),
                "output changed while publishing {}",
                destination.display()
            );
            std::fs::rename(&temporary, &destination)?;
            File::open(parent)?.sync_all()?;
            self.recipe.phases[index].published.insert(relative, hash);
            self.recipe.phases[index].pending = None;
            self.persist()?;
        }
        self.recipe.phases[index].complete = true;
        self.persist()
    }
    pub(crate) fn returned(&mut self, exit: i32) -> anyhow::Result<()> {
        self.recipe.returned = Some(exit);
        self.persist()
    }
    pub(crate) fn tree_retired(&mut self) -> anyhow::Result<()> {
        self.recipe.tree_retired = true;
        self.persist()
    }
    pub(crate) fn pair_released(&mut self) -> anyhow::Result<()> {
        self.recipe.pair_released = true;
        self.persist()
    }
    pub(crate) fn sources_released(&mut self) -> anyhow::Result<()> {
        self.recipe.sources_released = true;
        self.persist()
    }
    pub(crate) fn retired(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recipe.returned.is_some(),
            "cannot retire before output publication completes"
        );
        anyhow::ensure!(
            self.recipe.retire_root.is_none() || self.recipe.tree_retired,
            "remote tree retirement is outstanding"
        );
        anyhow::ensure!(
            self.recipe.pair.is_none() || self.recipe.pair_released,
            "source-pair release is outstanding"
        );
        anyhow::ensure!(
            self.recipe.source_roots.is_empty() || self.recipe.sources_released,
            "remote source release is outstanding"
        );
        self.recipe.retired = true;
        self.persist()
    }
    pub(crate) async fn retire_returned(&mut self) -> anyhow::Result<()> {
        if self.recipe.retired {
            return Ok(());
        }
        anyhow::ensure!(
            self.recipe.returned.is_some(),
            "cannot retire outputs before durable return"
        );
        let worker = self.recipe.worker.clone();
        let mut pair = if !self.recipe.pair_released {
            if let Some((root, token)) = self.recipe.pair.clone() {
                if super::super::ssh::clean_overlay_source_pair_was_released(&worker, &root, &token)
                    .await?
                {
                    self.pair_released()?;
                    None
                } else {
                    Some(
                        super::super::ssh::recover_clean_overlay_source_pair(
                            &worker,
                            &root,
                            &token,
                            Duration::from_secs(15),
                        )
                        .await?,
                    )
                }
            } else {
                None
            }
        } else {
            None
        };
        let mut sources = if self.recipe.sources_released || self.recipe.source_roots.is_empty() {
            None
        } else if super::super::ssh::remote_source_authority_was_released(
            &worker,
            &self.recipe.source_roots,
            &self.recipe.identity,
        )
        .await?
        {
            // A release receipt is only a terminal reconciliation fact. It can
            // never reopen paths which a later invocation may now be writing.
            anyhow::ensure!(
                self.recipe.tree_retired,
                "source release preceded durable tree retirement; refusing path access"
            );
            self.sources_released()?;
            None
        } else {
            Some(
                super::super::ssh::recover_remote_source_authority_lock(
                    &worker,
                    &self.recipe.source_roots,
                    pair.as_mut(),
                    &self.recipe.identity,
                    Duration::from_secs(15),
                )
                .await?,
            )
        };
        if !self.recipe.tree_retired {
            let sources = sources
                .as_mut()
                .context("tree retirement requires the active source grant")?;
            sources.ensure_held()?;
            if let Some(pair) = pair.as_mut() {
                pair.ensure_held()?;
            }
            if let Some(root) = &self.recipe.retire_root {
                TransferPipeline::new(
                    self.recipe.project_root.clone(),
                    "recovery".into(),
                    self.recipe.identity.clone(),
                    self.recipe.transfer.clone(),
                )
                .with_source_authority(self.recipe.identity.clone())?
                .reap_remote_tree(&worker, root)
                .await?;
            }
            self.tree_retired()?;
        }
        if let Some(sources) = sources.take() {
            sources.release().await?;
            self.sources_released()?;
        }
        if let Some(pair) = pair.take() {
            pair.release().await?;
        }
        self.pair_released()?;
        self.retired()
    }
}

fn load_recipe(writer: &DurableLeaseWriter) -> anyhow::Result<RecoveryRecipe> {
    let lease = writer.snapshot();
    let recipe: RecoveryRecipe = serde_json::from_value(
        lease
            .recovery
            .context("job has no durable source/retrieval recipe")?,
    )?;
    anyhow::ensure!(
        recipe.version == 2
            && recipe.wrapper_id == lease.identity.local_wrapper_id
            && Some(recipe.build_id) == lease.identity.remote_build_id
            && lease.worker_id.as_deref() == Some(recipe.worker.id.as_str()),
        "recovery recipe identity mismatch or unsupported source ownership version"
    );
    Ok(recipe)
}

/// Cancel only preparation. The remote activity fence drains surviving sync
/// processes and denies late arrivals before any root becomes writable again.
/// Once execution might have started, only its exact completion can retire it.
pub(crate) async fn cancel_preparation(writer: &DurableLeaseWriter) -> anyhow::Result<bool> {
    let recipe = load_recipe(writer)?;
    if recipe.retired {
        return Ok(true);
    }
    if recipe.execution_started {
        return Ok(false);
    }
    let mut session = RecoverySession {
        recipe,
        writer: writer.clone(),
        _output_locks: Vec::new(),
    };
    session.recipe.preparation_cancelled = true;
    session.persist()?;
    let worker = session.recipe.worker.clone();
    let owned = super::super::ssh::cancel_remote_source_authority_intent(
        &worker,
        &session.recipe.source_roots,
        &session.recipe.identity,
    )
    .await?;
    let mut pair = if let Some((root, token)) = session.recipe.pair.clone() {
        super::super::ssh::cancel_clean_overlay_source_pair_intent(
            &worker,
            &root,
            &token,
            Duration::from_secs(15),
        )
        .await?
    } else {
        None
    };
    anyhow::ensure!(
        owned || pair.is_none(),
        "cancelled intent without a source grant cannot acquire a source pair"
    );
    if owned {
        if let Some(pair) = pair.as_mut() {
            pair.ensure_held()?;
        }
        if let Some(root) = session.recipe.retire_root.as_ref() {
            // The full durable grant still excludes every overlapping owner.
            // Cleanup activity survives its SSH client and is drained again
            // before final cancellation can make these paths writable.
            TransferPipeline::new(
                session.recipe.project_root.clone(),
                "recovery".into(),
                session.recipe.identity.clone(),
                session.recipe.transfer.clone(),
            )
            .with_source_authority_cleanup(session.recipe.identity.clone())?
            .reap_remote_tree(&worker, root)
            .await?;
        }
        session.tree_retired()?;
        if let Some(pair) = pair.take() {
            pair.release().await?;
        }
        super::super::ssh::finish_cancel_remote_source_authority_intent(
            &worker,
            &session.recipe.source_roots,
            &session.recipe.identity,
        )
        .await?;
    }
    // Without a full grant, cancellation only fences delayed acquisition and
    // abandons pair metadata. The paths may belong to another parent-root job.
    session.tree_retired()?;
    session.pair_released()?;
    session.sources_released()?;
    session.returned(EXIT_BUILD_ERROR)?;
    session.retired()?;
    Ok(true)
}

/// Recollect the admitted command's outputs; no execution path is reachable.
pub(crate) async fn recover_job(writer: &DurableLeaseWriter) -> anyhow::Result<i32> {
    let recipe = load_recipe(writer)?;
    if !recipe.execution_started {
        cancel_preparation(writer).await?;
        writer.record_exit(EXIT_BUILD_ERROR)?;
        writer.acknowledge_terminal()?;
        return Ok(EXIT_BUILD_ERROR);
    }
    if let Some(exit) = recipe.returned {
        let mut session = RecoverySession {
            recipe,
            writer: writer.clone(),
            _output_locks: Vec::new(),
        };
        session.retire_returned().await?;
        writer.record_exit(exit)?;
        writer.acknowledge_terminal()?;
        return Ok(exit);
    }
    let locks = local_locks(
        std::iter::once(recipe.project_root.clone()).chain(
            recipe
                .phases
                .iter()
                .filter(|phase| phase.custom_target)
                .map(|phase| phase.local.clone()),
        ),
    )?;
    let mut session = RecoverySession {
        recipe,
        writer: writer.clone(),
        _output_locks: locks,
    };
    let worker = session.recipe.worker.clone();
    let base = TransferPipeline::new(
        session.recipe.project_root.clone(),
        "recovery".into(),
        session.recipe.identity.clone(),
        session.recipe.transfer.clone(),
    );
    let base = session.completion_pipeline(base);
    let exit = base.read_recovery_completion(&worker).await?.context(
        "same-id remote execution has no durable completion yet; command was not replayed",
    )?;
    let mut pair = if let Some((root, token)) = &session.recipe.pair {
        Some(
            super::super::ssh::recover_clean_overlay_source_pair(
                &worker,
                root,
                token,
                Duration::from_secs(15),
            )
            .await?,
        )
    } else {
        None
    };
    let mut sources = super::super::ssh::recover_remote_source_authority_lock(
        &worker,
        &session.recipe.source_roots,
        pair.as_mut(),
        &session.recipe.identity,
        Duration::from_secs(15),
    )
    .await?;
    let base = base.with_source_authority(session.recipe.identity.clone())?;
    session.completed(exit)?;
    for index in 0..session.recipe.phases.len() {
        let phase = session.recipe.phases[index].clone();
        if phase.complete || (exit != 0 && phase.result_dir.is_none()) {
            continue;
        }
        sources.ensure_held()?;
        if let Some(pair) = pair.as_mut() {
            pair.ensure_held()?;
        }
        let pipeline = base
            .clone()
            .with_remote_path_override(phase.remote.clone())
            .with_retrieval_reference_root(phase.local.clone())
            .with_local_root(session.stage(index));
        std::fs::create_dir_all(session.stage(index))?;
        if let Some(dir) = &phase.result_dir {
            pipeline.retrieve_result_dir(&worker, dir).await?;
        } else {
            let retrieved = pipeline
                .retrieve_artifacts(&worker, &phase.patterns)
                .await?;
            if phase.output_gate {
                anyhow::ensure!(
                    !sync_back_verified_zero_build_outputs(
                        &retrieved.manifest_regular_files,
                        retrieved.matched_regular_files,
                        session.recipe.kind,
                        phase.custom_target
                    ) && !(session.recipe.package_archive
                        && retrieved.matched_regular_files == Some(0)),
                    "recovered transfer matched zero expected outputs"
                );
                if !session.recipe.allow_foreign
                    && kind_has_enumerable_output_contract(session.recipe.kind)
                {
                    let foreign = foreign_target_artifacts(
                        &session.stage(index),
                        &retrieved.manifest_regular_files,
                        phase.custom_target,
                        &session.recipe.expected_triple,
                        session.recipe.pinned_triple.as_deref(),
                    );
                    anyhow::ensure!(
                        foreign.is_empty(),
                        "recovered outputs target a foreign platform: {}",
                        describe_findings(&foreign)
                    );
                }
            }
        }
        session.publish(&phase.name)?;
    }
    // Publication is the durable terminal boundary. Retirement can be retried
    // independently and must never cause a second output write.
    session.returned(exit)?;
    if let Some(root) = &session.recipe.retire_root {
        base.reap_remote_tree(&worker, root).await?;
    }
    session.tree_retired()?;
    if let Some(pair) = pair.take() {
        pair.release().await?;
    }
    session.pair_released()?;
    sources.release().await?;
    session.sources_released()?;
    session.retired()?;
    writer.record_exit(exit)?;
    writer.acknowledge_terminal()?;
    Ok(exit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preparation_fixture() -> (tempfile::TempDir, DurableLeaseWriter, WorkerConfig) {
        let directory = tempfile::tempdir().unwrap();
        let worker = WorkerConfig {
            id: WorkerId::new("source-recovery"),
            host: "unreachable.invalid".into(),
            user: "worker".into(),
            identity_file: "/unused/test-key".into(),
            total_slots: 1,
            priority: 100,
            tags: Vec::new(),
            tools: Vec::new(),
        };
        let writer = DurableLeaseWriter {
            path: directory.path().join("lease.json"),
            lease: Arc::new(Mutex::new(DurableJobLease::new(
                JobIdentity::new_local(),
                std::process::id(),
                None,
                None,
                0,
                false,
                false,
                "test-command-fingerprint".into(),
            ))),
        };
        writer.admit(41, &worker.id).unwrap();
        RecoverySession::begin(
            &writer,
            &worker,
            vec!["/data/projects/source-recovery".into()],
            None,
            None,
            TransferConfig::default(),
            directory.path().to_owned(),
            "abc123".into(),
        )
        .unwrap();
        (directory, writer, worker)
    }

    fn publication_fixture() -> (tempfile::TempDir, tempfile::TempDir, RecoverySession) {
        let (directory, writer, _worker) = preparation_fixture();
        let stages = default_job_lease_directory().join("retrieval");
        std::fs::create_dir_all(&stages).unwrap();
        let stage_owner = tempfile::Builder::new()
            .prefix("publication-regression-")
            .tempdir_in(stages)
            .unwrap();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.identity = stage_owner
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        recipe.project_root = directory.path().join("checkout");
        std::fs::create_dir(&recipe.project_root).unwrap();
        recipe.phases.push(RecoveryPhase {
            name: "project".into(),
            local: recipe.project_root.clone(),
            remote: "/unused/remote".into(),
            patterns: default_c_cpp_artifact_patterns(),
            result_dir: None,
            custom_target: false,
            output_gate: false,
            baseline: BTreeMap::new(),
            published: BTreeMap::new(),
            pending: None,
            complete: false,
        });
        let session = RecoverySession {
            recipe,
            writer,
            _output_locks: Vec::new(),
        };
        std::fs::create_dir(session.stage(0)).unwrap();
        (directory, stage_owner, session)
    }

    #[test]
    fn recovery_publication_refuses_retained_or_pending_source_before_any_write() {
        for pending in [false, true] {
            let (_directory, _stage_owner, mut session) = publication_fixture();
            let local = session.recipe.project_root.clone();
            let stage = session.stage(0);
            let original = b"int main(void) { return 0; }\n";
            let remote = b"changed source from an earlier collector\n";
            std::fs::write(local.join("main.c"), original).unwrap();
            session.recipe.phases[0].baseline.insert(
                PathBuf::from("main.c"),
                fingerprint(&local.join("main.c")).unwrap().unwrap(),
            );
            std::fs::create_dir(stage.join("build")).unwrap();
            std::fs::write(stage.join("build/app"), b"valid artifact").unwrap();
            let retained = if pending {
                let temporary = local.join(format!(".rch-return-{}", session.recipe.identity));
                std::fs::write(&temporary, remote).unwrap();
                session.recipe.phases[0].pending = Some((
                    PathBuf::from("main.c"),
                    fingerprint(&temporary).unwrap().unwrap(),
                ));
                temporary
            } else {
                let retained = stage.join("main.c");
                std::fs::write(&retained, remote).unwrap();
                retained
            };
            session.persist().unwrap();
            let journal = std::fs::read(&session.writer.path).unwrap();

            assert!(session.publish("project").is_err(), "pending={pending}");
            assert_eq!(std::fs::read(local.join("main.c")).unwrap(), original);
            assert!(!local.join("build/app").exists());
            assert_eq!(std::fs::read(&retained).unwrap(), remote);
            assert_eq!(
                std::fs::read(stage.join("build/app")).unwrap(),
                b"valid artifact"
            );
            assert_eq!(std::fs::read(&session.writer.path).unwrap(), journal);
            assert!(session.recipe.phases[0].published.is_empty());
        }
    }

    #[test]
    fn recovery_publication_finishes_journaled_new_outputs_without_rewriting_them() {
        let (_directory, _stage_owner, mut session) = publication_fixture();
        let local = session.recipe.project_root.clone();
        let stage = session.stage(0);
        for (path, bytes) in [("a.out", b"first output"), ("b.out", b"other output")] {
            std::fs::write(local.join(path), bytes).unwrap();
            std::fs::write(stage.join(path), b"stale retained staging bytes").unwrap();
        }
        let first = fingerprint(&local.join("a.out")).unwrap().unwrap();
        session.recipe.phases[0].pending = Some((PathBuf::from("a.out"), first.clone()));
        session.recipe.phases[0].published.insert(
            PathBuf::from("b.out"),
            fingerprint(&local.join("b.out")).unwrap().unwrap(),
        );
        std::fs::create_dir(stage.join("build")).unwrap();
        std::fs::write(stage.join("build/next.o"), b"next output").unwrap();
        session.persist().unwrap();

        session.publish("project").unwrap();
        assert_eq!(std::fs::read(local.join("a.out")).unwrap(), b"first output");
        assert_eq!(std::fs::read(local.join("b.out")).unwrap(), b"other output");
        assert_eq!(
            std::fs::read(local.join("build/next.o")).unwrap(),
            b"next output"
        );
        assert_eq!(session.recipe.phases[0].published.len(), 3);
        assert_eq!(
            session.recipe.phases[0].published[Path::new("a.out")],
            first
        );
        assert!(session.recipe.phases[0].pending.is_none());
        assert!(session.recipe.phases[0].complete);
    }

    #[test]
    fn recovery_publication_retains_declared_result_directory_contract() {
        let (_directory, _stage_owner, mut session) = publication_fixture();
        let local = session.recipe.project_root.clone();
        let stage = session.stage(0);
        std::fs::create_dir(local.join("reports")).unwrap();
        std::fs::create_dir(stage.join("reports")).unwrap();
        std::fs::write(local.join("reports/result.json"), b"old report").unwrap();
        std::fs::write(stage.join("reports/result.json"), b"new report").unwrap();
        session.recipe.phases[0].patterns.clear();
        session.recipe.phases[0].result_dir = Some(PathBuf::from("reports"));
        session.recipe.phases[0].baseline.insert(
            PathBuf::from("reports/result.json"),
            fingerprint(&local.join("reports/result.json"))
                .unwrap()
                .unwrap(),
        );
        session.persist().unwrap();

        session.publish("project").unwrap();
        assert_eq!(
            std::fs::read(local.join("reports/result.json")).unwrap(),
            b"new report"
        );
        assert!(session.recipe.phases[0].complete);
    }

    #[test]
    fn source_intent_is_durable_before_remote_acquisition_and_blocks_re_admission() {
        let (_directory, writer, worker) = preparation_fixture();
        let disk: DurableJobLease =
            serde_json::from_slice(&std::fs::read(&writer.path).unwrap()).unwrap();
        let recipe: RecoveryRecipe = serde_json::from_value(disk.recovery.unwrap()).unwrap();
        assert_eq!(recipe.identity, "abc123");
        assert_eq!(recipe.source_roots, ["/data/projects/source-recovery"]);
        assert!(!recipe.prepared);
        assert!(!recipe.execution_started);
        assert!(recipe.phases.is_empty());
        assert!(writer.ensure_released_for_retry().is_err());
        assert!(writer.admit(42, &worker.id).is_err());
        assert_eq!(writer.snapshot().identity.remote_build_id, Some(41));
        assert!(writer.acknowledge_terminal().is_err());
    }

    #[test]
    fn source_execution_requires_preparation_and_persists_before_launch() {
        let (_directory, writer, _worker) = preparation_fixture();
        let mut session = RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer: writer.clone(),
            _output_locks: Vec::new(),
        };
        assert!(session.starting_execution().is_err());
        session.recipe.prepared = true;
        session.starting_execution().unwrap();
        let disk: DurableJobLease =
            serde_json::from_slice(&std::fs::read(&writer.path).unwrap()).unwrap();
        let recipe: RecoveryRecipe = serde_json::from_value(disk.recovery.unwrap()).unwrap();
        assert!(recipe.execution_started);
        assert!(
            session.starting_execution().is_err(),
            "a prepared execution is consumed once"
        );
    }

    #[test]
    fn delayed_heartbeat_publication_cannot_roll_back_execution_admission() {
        let (_directory, writer, _worker) = preparation_fixture();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.prepared = true;
        let mut session = RecoverySession {
            recipe,
            writer: writer.clone(),
            _output_locks: Vec::new(),
        };
        let (captured_tx, captured_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let heartbeat_writer = writer.clone();
        let older = std::thread::spawn(move || {
            heartbeat_writer.persist_snapshot(|path, bytes| {
                captured_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                atomic_write(path, bytes)
            })
        });
        captured_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (starting_tx, starting_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let newer = std::thread::spawn(move || {
            starting_tx.send(()).unwrap();
            let result = session.starting_execution();
            finished_tx.send(()).unwrap();
            result
        });
        starting_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let overtook = finished_rx.recv_timeout(Duration::from_millis(200)).is_ok();
        // Release both threads before asserting so a failed ordering assertion
        // never strands a blocked publisher in the test process.
        release_tx.send(()).unwrap();
        older.join().unwrap().unwrap();
        newer.join().unwrap().unwrap();
        assert!(
            !overtook,
            "new execution admission overtook an older pending disk publication"
        );
        let disk: DurableJobLease =
            serde_json::from_slice(&std::fs::read(&writer.path).unwrap()).unwrap();
        let persisted: RecoveryRecipe = serde_json::from_value(disk.recovery.unwrap()).unwrap();
        assert!(
            persisted.execution_started,
            "a delayed heartbeat replaced the durable execution boundary with Preparing"
        );
    }

    #[tokio::test]
    async fn started_source_intent_cannot_be_cancelled_as_preparation() {
        let (_directory, writer, _worker) = preparation_fixture();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.prepared = true;
        recipe.execution_started = true;
        writer
            .set_recovery(serde_json::to_value(&recipe).unwrap())
            .unwrap();
        let before = std::fs::read(&writer.path).unwrap();
        assert!(!cancel_preparation(&writer).await.unwrap());
        assert_eq!(
            std::fs::read(&writer.path).unwrap(),
            before,
            "a started attempt cannot contact the worker's cancellation path or rewrite its journal"
        );
    }

    #[test]
    fn returned_outputs_do_not_authorize_terminal_ack_until_sources_release() {
        let (_directory, writer, worker) = preparation_fixture();
        let mut session = RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer: writer.clone(),
            _output_locks: Vec::new(),
        };
        session.returned(0).unwrap();
        session.tree_retired().unwrap();
        session.pair_released().unwrap();
        assert!(session.retired().is_err());
        assert!(writer.acknowledge_terminal().is_err());
        session.sources_released().unwrap();
        session.retired().unwrap();
        writer.record_exit(0).unwrap();
        writer.acknowledge_terminal().unwrap();
        writer.ensure_released_for_retry().unwrap();
        writer.admit(42, &worker.id).unwrap();
        let next = writer.snapshot();
        assert!(next.recovery.is_none());
        assert!(!next.terminal_acknowledged);
        assert_eq!(next.exit_code, None);
        assert_eq!(next.identity.remote_build_id, Some(42));
    }

    #[test]
    fn unsupported_or_mismatched_source_intent_never_enters_recovery() {
        let (_directory, writer, _worker) = preparation_fixture();
        let original = load_recipe(&writer).unwrap();
        for changed in [
            {
                let mut recipe = original.clone();
                recipe.version = 1;
                recipe
            },
            {
                let mut recipe = original.clone();
                recipe.build_id += 1;
                recipe
            },
            {
                let mut recipe = original.clone();
                recipe.worker.id = WorkerId::new("other");
                recipe
            },
        ] {
            writer
                .set_recovery(serde_json::to_value(changed).unwrap())
                .unwrap();
            assert!(load_recipe(&writer).is_err());
        }
    }
}
