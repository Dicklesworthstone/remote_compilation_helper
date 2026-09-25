//! Identity-bound collection only. This module never stores or replays a command.
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

fn quote(value: &str) -> String {
    shell_escape::escape(value.into()).into_owned()
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

pub(crate) fn owner_marker(root: &str) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"rch.remote_source_authority_lock.v1\0");
    hash.update(root.as_bytes());
    format!(
        "/tmp/rch-source-authority-locks/{}.recovery-owner",
        hash.finalize().to_hex()
    )
}

pub(crate) async fn claim_sources(
    worker: &WorkerConfig,
    roots: &[String],
    identity: &str,
) -> anyhow::Result<()> {
    let mut script =
        String::from("set -eu; umask 077; mkdir -p /tmp/rch-source-authority-locks;\n");
    for root in roots {
        let marker = owner_marker(root);
        script.push_str(&format!(
            "[ ! -L {m} ]; printf '%s\\n' {i} > {m}.pending; mv -f -- {m}.pending {m};\n",
            m = quote(&marker),
            i = quote(identity)
        ));
    }
    let output = super::super::ssh::run_offload_ssh_command_with_stdin(
        worker,
        "sh -s",
        script.as_bytes(),
        Duration::from_secs(30),
    )
    .await?;
    anyhow::ensure!(
        output.status.success(),
        "cannot claim exact remote source ownership: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

impl RecoverySession {
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
            version: 1,
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
        self.recipe.exit_code = Some(exit);
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
        Ok(pipeline.clone().with_local_root(stage))
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
        let files = regular_files(&stage)?;
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
        self.recipe.retired = true;
        self.persist()
    }
    async fn retire_returned(&mut self) -> anyhow::Result<()> {
        if self.recipe.retired {
            return Ok(());
        }
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
        if !self.recipe.tree_retired {
            let mut sources = super::super::ssh::acquire_remote_source_authority_lock(
                &worker,
                &self.recipe.source_roots,
                pair.as_mut(),
                Duration::from_secs(15),
            )
            .await?;
            let mut script = String::from("set -eu;\n");
            for root in &self.recipe.source_roots {
                script.push_str(&format!(
                    "[ ! -L {m} ] && [ \"$(cat -- {m})\" = {i} ];\n",
                    m = quote(&owner_marker(root)),
                    i = quote(&self.recipe.identity),
                ));
            }
            let output = super::super::ssh::run_offload_ssh_command_with_stdin(
                &worker,
                "sh -s",
                script.as_bytes(),
                Duration::from_secs(30),
            )
            .await?;
            anyhow::ensure!(
                output.status.success(),
                "source ownership changed; refusing stale retirement"
            );
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
                .reap_remote_tree(&worker, root)
                .await?;
            }
            self.tree_retired()?;
            sources.release().await?;
        }
        if let Some(pair) = pair.take() {
            pair.release().await?;
        }
        self.pair_released()?;
        self.retired()
    }
}

/// Recollect the admitted command's outputs; no execution path is reachable.
pub(crate) async fn recover_job(writer: &DurableLeaseWriter) -> anyhow::Result<i32> {
    let lease = writer.snapshot();
    let recipe: RecoveryRecipe = serde_json::from_value(
        lease
            .recovery
            .context("job has no durable retrieval recipe")?,
    )?;
    anyhow::ensure!(
        recipe.version == 1
            && recipe.wrapper_id == lease.identity.local_wrapper_id
            && Some(recipe.build_id) == lease.identity.remote_build_id
            && lease.worker_id.as_deref() == Some(recipe.worker.id.as_str()),
        "recovery recipe identity mismatch"
    );
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
    let mut sources = super::super::ssh::acquire_remote_source_authority_lock(
        &worker,
        &session.recipe.source_roots,
        pair.as_mut(),
        Duration::from_secs(15),
    )
    .await?;
    let mut script = String::from("set -eu;\n");
    for root in &session.recipe.source_roots {
        script.push_str(&format!(
            "[ ! -L {m} ] && [ \"$(cat -- {m})\" = {i} ];\n",
            m = quote(&owner_marker(root)),
            i = quote(&session.recipe.identity)
        ));
    }
    let output = super::super::ssh::run_offload_ssh_command_with_stdin(
        &worker,
        "sh -s",
        script.as_bytes(),
        Duration::from_secs(30),
    )
    .await?;
    anyhow::ensure!(
        output.status.success(),
        "source/output ownership changed; refusing stale recovery"
    );
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
    session.retired()?;
    writer.record_exit(exit)?;
    writer.acknowledge_terminal()?;
    Ok(exit)
}
