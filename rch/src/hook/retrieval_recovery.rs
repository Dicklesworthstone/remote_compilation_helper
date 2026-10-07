//! Durable source ownership and identity-bound collection. Never replays a command.
use super::super::artifact_patterns::direct_compiler::{
    NativeOutputContract, native_output_contract,
};
use super::super::cargo_output_contract::{CargoOutputCapture, CargoOutputContract};
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read;

#[path = "recovery_completion.rs"]
mod recovery_completion;
#[path = "recovery_owner.rs"]
mod recovery_owner;
#[path = "result_recovery.rs"]
mod result_recovery;

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
    /// Persisted before execution: a successful captured build cannot publish
    /// until its complete, same-attempt Cargo receipt supplies the output set.
    #[serde(default)]
    cargo_output_capture: Option<CargoOutputCapture>,
    phases: Vec<RecoveryPhase>,
    exit_code: Option<i32>,
    returned: Option<i32>,
    /// Daemon accounting may have completed earlier through cancellation.
    /// Preserve its outcome independently of command and artifact delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    daemon_exit_code: Option<i32>,
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
    #[serde(default)]
    cargo_outputs: Option<CargoOutputContract>,
    /// Exact native-driver files, known before execution and independent of
    /// Cargo's target directory or target-root output gate.
    #[serde(default)]
    native_outputs: Option<NativeOutputContract>,
    baseline: BTreeMap<PathBuf, String>,
    published: BTreeMap<PathBuf, String>,
    #[serde(default)]
    pending: Option<(PathBuf, String)>,
    complete: bool,
    /// A failed delivery is terminal evidence, not a completed publication.
    #[serde(default)]
    missing_result: Option<result_recovery::MissingResult>,
}

pub(crate) struct RecoverySession {
    recipe: RecoveryRecipe,
    writer: DurableLeaseWriter,
}

/// An immutable, complete receipt cannot satisfy this invocation's contract.
/// Keep this separate from local journal I/O, which a collector may retry.
#[derive(Debug, thiserror::Error)]
#[error("invalid Cargo executable evidence: {0:#}")]
pub(super) struct CargoOutputContractRejected(anyhow::Error);

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

/// How long a publication waits for another wrapper's publication into the
/// same local output root. Publications only move already-staged files, so
/// contention lasts seconds; the bound turns a wedged holder into an error.
const OUTPUT_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(600);

/// Different spellings of one output directory must share publication
/// ownership. Resolve existing prefixes without creating a fresh target tree;
/// missing suffixes keep the same identity after another job creates them.
/// Resolve a symlink before applying a following `..`, as the filesystem does.
fn output_lock_root_identity(root: &Path) -> anyhow::Result<PathBuf> {
    use std::path::Component;

    let absolute = if root.is_absolute() {
        root.to_owned()
    } else {
        std::env::current_dir()?.join(root)
    };
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) => anyhow::bail!(
                "output publication requires a Unix directory path: {}",
                root.display()
            ),
            Component::RootDir => resolved.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) => {
                resolved.push(name);
                match std::fs::canonicalize(&resolved) {
                    Ok(canonical) => {
                        anyhow::ensure!(
                            std::fs::metadata(&canonical)?.is_dir(),
                            "output publication root has a non-directory component: {}",
                            resolved.display()
                        );
                        resolved = canonical;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        // A missing directory is allowed, but a dangling
                        // symlink is not an ordinary missing suffix: treating
                        // it as one would assign a different lock from its
                        // eventual target when that target appears.
                        match std::fs::symlink_metadata(&resolved) {
                            Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => {}
                            Ok(_) => {
                                return Err(error).with_context(|| {
                                    format!(
                                        "cannot resolve existing output root entry {}",
                                        resolved.display()
                                    )
                                });
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    Ok(resolved)
}

/// Exclusive ownership of one local output root for the duration of a single
/// phase publication. It is deliberately NOT held across the remote build:
/// dispatchers share one CARGO_TARGET_DIR (and run concurrent jobs in one
/// project), and a job-long lock failed every overlapping build outright.
async fn lock_output_root(root: &Path) -> anyhow::Result<File> {
    let identity = output_lock_root_identity(root)?;
    let directory = default_job_lease_directory().join("output-locks");
    std::fs::create_dir_all(&directory)?;
    let name = blake3::hash(identity.as_os_str().as_encoded_bytes())
        .to_hex()
        .to_string();
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join(name))?;
    let deadline = tokio::time::Instant::now() + OUTPUT_LOCK_WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => {
                anyhow::ensure!(
                    output_lock_root_identity(root)? == identity,
                    "output root changed while waiting for publication ownership: {}; journal retained",
                    root.display()
                );
                return Ok(file);
            }
            Err(std::fs::TryLockError::WouldBlock) if tokio::time::Instant::now() < deadline => {
                // The CLI uses a current-thread runtime. Blocking here stalls
                // heartbeats and prevents the caller's recovery deadline or
                // cancellation from being polled for the whole lock budget.
                // No output or journal has been touched while waiting, so a
                // dropped waiter can safely retry this exact publication.
                let next_poll = tokio::time::Instant::now() + std::time::Duration::from_millis(100);
                tokio::time::sleep_until(next_poll.min(deadline)).await;
            }
            Err(error) => anyhow::bail!(
                "output publication into {} is held by another wrapper: {error}",
                root.display()
            ),
        }
    }
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
            cargo_output_capture: None,
            phases: Vec::new(),
            exit_code: None,
            returned: None,
            daemon_exit_code: None,
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
        // The phase patterns below take the command's OWN kind, exactly as the
        // live retrieval does: from the delivery kind they lose the build-only
        // test/bench carve-out, and publication then skipped the very
        // executables the live retrieval fetched (bd-b7lot, seen live).
        let delivery_kind = artifact_delivery_kind(kind, Some(command));
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
        let mut phases = Vec::new();
        let native_outputs = (!WorkerPlatform::from_worker(worker).is_windows())
            .then(|| native_output_contract(kind, command, true))
            .flatten();
        let project_patterns = match &native_outputs {
            Some(contract) => contract.patterns()?,
            None => get_project_artifact_patterns(kind, Some(command), target.is_some()),
        };
        let native_project_outputs = native_outputs.is_some();
        if !project_patterns.is_empty() {
            phases.push(RecoveryPhase {
                name: "project".into(),
                local: project_root.clone(),
                remote: pipeline.remote_path(),
                patterns: project_patterns,
                result_dir: None,
                custom_target: false,
                output_gate: target.is_none(),
                cargo_outputs: None,
                native_outputs,
                baseline: BTreeMap::new(),
                published: BTreeMap::new(),
                pending: None,
                complete: false,
                missing_result: None,
            });
        }
        if let Some(target) = target.filter(|_| !native_project_outputs) {
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
                    cargo_outputs: None,
                    native_outputs: None,
                    baseline: BTreeMap::new(),
                    published: BTreeMap::new(),
                    pending: None,
                    complete: false,
                    missing_result: None,
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
                cargo_outputs: None,
                native_outputs: None,
                baseline: BTreeMap::new(),
                published: BTreeMap::new(),
                pending: None,
                complete: false,
                missing_result: None,
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
        let cargo_output_capture = CargoOutputCapture::for_command(kind, command);
        anyhow::ensure!(
            cargo_output_capture.is_none()
                || phases.iter().filter(|phase| phase.output_gate).count() == 1,
            "captured Cargo execution requires exactly one artifact output root"
        );
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
            kind: delivery_kind,
            expected_triple: pinned_triple
                .clone()
                .unwrap_or_else(default_host_target_triple),
            pinned_triple,
            allow_foreign: foreign_artifact_gate_disabled(),
            package_archive: sync_back_verified_zero_package_archives(Some(0), command),
            cargo_output_capture,
            phases,
            exit_code: None,
            returned: None,
            daemon_exit_code: None,
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
        };
        session.persist()?;
        Ok(session)
    }

    fn persist(&self) -> anyhow::Result<()> {
        self.writer
            .set_recovery(serde_json::to_value(&self.recipe)?)
    }
    pub(crate) fn needs_cargo_artifact_evidence(&self) -> bool {
        self.recipe.cargo_output_capture.is_some()
            && self
                .recipe
                .phases
                .iter()
                .any(|phase| phase.output_gate && phase.cargo_outputs.is_none())
    }
    pub(crate) fn cargo_artifact_remote_root(&self) -> Option<&str> {
        self.recipe.cargo_output_capture.as_ref()?;
        self.recipe
            .phases
            .iter()
            .find(|phase| phase.output_gate)
            .map(|phase| phase.remote.as_str())
    }
    /// Complete Cargo evidence authorizes the selected binary executables that
    /// this exact invocation emitted. Persist the contract and transfer policy
    /// together, before either live collection or detached recovery begins.
    pub(crate) fn install_cargo_artifact_evidence(
        &mut self,
        stdout: &[u8],
        canonical_remote_root: &Path,
    ) -> anyhow::Result<()> {
        let prepared = (|| -> anyhow::Result<_> {
            anyhow::ensure!(
                self.recipe.execution_started && self.recipe.exit_code == Some(0),
                "Cargo output evidence requires a successful admitted execution"
            );
            let capture = self
                .recipe
                .cargo_output_capture
                .as_ref()
                .context("this execution did not request Cargo output evidence")?;
            let configured_root = self
                .cargo_artifact_remote_root()
                .context("captured Cargo execution has no artifact output root")?;
            // The transport proved this exact configured path resolves to the
            // canonical root. Cargo can report either spelling (or both); no
            // unrelated suffix/prefix inference can authorize an output.
            let contract = capture.parse_receipt_with_roots(
                stdout,
                &[Path::new(configured_root), canonical_remote_root],
            )?;
            let index = self
                .recipe
                .phases
                .iter()
                .position(|phase| phase.output_gate)
                .context("captured Cargo execution has no artifact output root")?;
            let phase = &self.recipe.phases[index];
            if let Some(existing) = &phase.cargo_outputs {
                anyhow::ensure!(
                    existing.required_files == contract.required_files,
                    "Cargo output evidence contradicts the persisted required output set"
                );
                return Ok(None);
            }
            anyhow::ensure!(
                !phase.complete && phase.pending.is_none() && phase.published.is_empty(),
                "Cargo output evidence must precede every artifact publication"
            );
            let mut exact_patterns = Vec::new();
            for relative in &contract.required_files {
                // A project-root collection must never promote a source file
                // through the priority include below. With a custom Cargo
                // target, the phase root already is the designated output
                // tree; otherwise outputs must remain beneath target/.
                anyhow::ensure!(
                    phase.custom_target
                        || (relative.starts_with("target") && relative.components().count() > 1),
                    "Cargo output is outside the project's target tree: {}",
                    relative.display()
                );
                let name = relative.to_str().context("non-UTF-8 Cargo output path")?;
                let mut literal = String::with_capacity(name.len());
                for character in name.chars() {
                    if matches!(character, '\\' | '*' | '?' | '[' | ']') {
                        literal.push('\\');
                    }
                    literal.push(character);
                }
                exact_patterns.push(format!("+ {literal}"));
            }
            exact_patterns.extend(phase.patterns.iter().cloned());
            Ok(Some((index, contract, exact_patterns)))
        })()
        .map_err(CargoOutputContractRejected)?;
        let Some((index, contract, patterns)) = prepared else {
            return Ok(());
        };
        let mut next_recipe = self.recipe.clone();
        let phase = &mut next_recipe.phases[index];
        phase.patterns = patterns;
        phase.cargo_outputs = Some(contract);
        self.writer
            .set_recovery(serde_json::to_value(&next_recipe)?)?;
        self.recipe = next_recipe;
        Ok(())
    }
    pub(crate) fn cargo_artifact_patterns(&self, name: &str) -> anyhow::Result<Vec<String>> {
        self.recipe
            .phases
            .iter()
            .find(|phase| phase.name == name)
            .map(|phase| phase.patterns.clone())
            .context("missing retrieval phase")
    }
    pub(crate) fn has_native_output_contract(&self) -> bool {
        self.recipe
            .phases
            .iter()
            .any(|phase| phase.native_outputs.is_some())
    }
    fn verify_native_outputs(&self, index: usize) -> anyhow::Result<()> {
        if let Some(contract) = &self.recipe.phases[index].native_outputs {
            contract.verify_staged(&self.stage(index))?;
        }
        Ok(())
    }
    fn verify_cargo_outputs(&self, index: usize) -> anyhow::Result<()> {
        let phase = &self.recipe.phases[index];
        if self.recipe.cargo_output_capture.is_none() || !phase.output_gate {
            return Ok(());
        }
        phase
            .cargo_outputs
            .as_ref()
            .context("complete Cargo output evidence is required before publication")?
            .verify_staged(&self.stage(index))
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
        anyhow::ensure!(
            self.recipe
                .exit_code
                .is_none_or(|observed| observed == exit),
            "remote completion contradicts the recorded command outcome; ownership retained"
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
    pub(crate) async fn publish(&mut self, name: &str) -> anyhow::Result<()> {
        let index = self
            .recipe
            .phases
            .iter()
            .position(|phase| phase.name == name)
            .context("missing retrieval phase")?;
        anyhow::ensure!(
            self.recipe.phases[index].missing_result.is_none(),
            "a missing required result cannot be published as complete"
        );
        if self.recipe.phases[index].complete {
            return Ok(());
        }
        // Exclusive for this publication only; see `lock_output_root`.
        let _publication = lock_output_root(&self.recipe.phases[index].local).await?;
        // Validate the entire required set before the first journal/output
        // mutation. One executable or support library cannot satisfy another
        // selected Cargo target, and existing destination files are no proof.
        self.verify_cargo_outputs(index)?;
        self.verify_native_outputs(index)?;
        let stage = self.stage(index);
        let mut files = regular_files(&stage)?;
        let phase = &self.recipe.phases[index];
        if phase.result_dir.is_none() {
            // A resumed transfer can retain files selected by an older
            // collector. Ownership fingerprints alone do not authorize a
            // source file as an artifact, so only staged files the artifact
            // policy admits are ever published. The rest (retained Cargo
            // metadata such as `.rustc_info.json`) stay private to the stage:
            // refusing the whole publication instead left the job forever
            // unrecoverable and its worker-side source claim stranded.
            let policy = TransferPipeline::new(
                phase.local.clone(),
                "recovery-publication".into(),
                self.recipe.identity.clone(),
                self.recipe.transfer.clone(),
            );
            let (admitted, outside) =
                policy.partition_staged_artifact_paths(&files, &phase.patterns)?;
            for path in &outside {
                // Warn: a skip means collector and recipe disagree about the
                // policy (as in bd-3kskq); keep that skew visible.
                warn!(
                    "recovery skips staged file outside the artifact policy: {}",
                    path.display()
                );
            }
            files = admitted;
            if let Some((relative, hash)) = &phase.pending {
                // A journaled write already began renaming this path into
                // place. It must be in policy to be finished; never skip it.
                let completed = !phase.baseline.contains_key(relative)
                    && fingerprint(&phase.local.join(relative))?.as_ref() == Some(hash);
                if !completed {
                    policy.validate_staged_artifact_paths(
                        std::slice::from_ref(relative),
                        &phase.patterns,
                    )?;
                }
            }
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
        // Re-baseline, under the publication lock, every output this job has
        // not written yet. The preparation-time snapshot predates the remote
        // build, and in a shared target dir other jobs legitimately replace
        // these files meanwhile. Only this job's own interrupted write (the
        // journaled `pending` entry above) has to match the older baseline;
        // the refreshed one is persisted before any write so a crash mid-loop
        // recovers against exactly what this publication observed.
        {
            let phase = &mut self.recipe.phases[index];
            for relative in &files {
                if phase.published.contains_key(relative) {
                    continue;
                }
                match fingerprint(&phase.local.join(relative))? {
                    Some(hash) => {
                        phase.baseline.insert(relative.clone(), hash);
                    }
                    None => {
                        phase.baseline.remove(relative);
                    }
                }
            }
        }
        self.persist()?;
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
            // Only components BELOW the phase root can redirect a write out of
            // the output tree. The root itself is the caller's choice and may
            // legitimately sit behind system symlinks (macOS `/tmp` →
            // `/private/tmp`, `$TMPDIR` under `/var` → `/private/var`, a
            // symlinked `/data`); walking up to `/` rejected every such build
            // after its remote compile had already succeeded.
            let mut ancestor = Some(parent);
            while let Some(path) = ancestor {
                if path == phase.local.as_path() || !path.starts_with(&phase.local) {
                    break;
                }
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
        self.persist()?;
        // The stage is only needed to resume an unfinished publication. Once
        // `complete` is durable it is a full duplicate of the outputs; nothing
        // removed it, and 1339 of them held 43 GB on one dispatcher. Best
        // effort: a leftover stage wastes space but is never read again.
        let _ = std::fs::remove_dir_all(&stage);
        Ok(())
    }
    pub(crate) fn returned(&mut self, exit: i32) -> anyhow::Result<()> {
        anyhow::ensure!(
            exit != 0
                || self
                    .recipe
                    .phases
                    .iter()
                    .all(|phase| { phase.native_outputs.is_none() || phase.complete }),
            "native compilation cannot succeed before every required output is published"
        );
        anyhow::ensure!(
            !result_recovery::has_missing_results(&self.recipe)
                || exit == EXIT_ARTIFACT_TRANSFER_FAILED,
            "missing required outputs must remain a delivery failure"
        );
        anyhow::ensure!(
            exit != 0
                || self.recipe.cargo_output_capture.is_none()
                || self.recipe.phases.iter().all(|phase| {
                    !phase.output_gate || (phase.cargo_outputs.is_some() && phase.complete)
                }),
            "captured Cargo build cannot succeed before all required outputs are published"
        );
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
        self.persist()?;
        // Retain failed required-output evidence for inspection. Other retired
        // jobs never publish again and can release leftover staging bytes.
        if !self.retain_failed_delivery_evidence()
            && let Some(stages) = self.stage(0).parent()
        {
            let _ = std::fs::remove_dir_all(stages);
        }
        Ok(())
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
        self.retired()?;
        self.discard_completion_receipts().await;
        Ok(())
    }
    /// Worker receipts are garbage once retirement is durable. A failed delete
    /// strands a few small files and must never fail the finished build.
    fn retain_failed_delivery_evidence(&self) -> bool {
        result_recovery::has_missing_results(&self.recipe)
            || (self.recipe.exit_code == Some(0)
                && self
                    .recipe
                    .phases
                    .iter()
                    .any(|phase| phase.native_outputs.is_some() && !phase.complete))
            || (self.recipe.cargo_output_capture.is_some()
                && self.recipe.exit_code == Some(0)
                && self
                    .recipe
                    .phases
                    .iter()
                    .any(|phase| phase.output_gate && !phase.complete))
    }
    async fn discard_completion_receipts(&self) {
        // Keep the original outcome and any partial staging for inspection of
        // a terminal required-output failure. Never fabricate retrieved output.
        if self.retain_failed_delivery_evidence() {
            return;
        }
        let pipeline = self.completion_pipeline(TransferPipeline::new(
            self.recipe.project_root.clone(),
            "recovery".into(),
            self.recipe.identity.clone(),
            self.recipe.transfer.clone(),
        ));
        if let Err(error) = pipeline
            .discard_recovery_completion(&self.recipe.worker)
            .await
        {
            debug!(worker = %self.recipe.worker.id, %error, "completion receipt cleanup failed");
        }
    }
}

fn load_recipe(writer: &DurableLeaseWriter) -> anyhow::Result<RecoveryRecipe> {
    let lease = writer.snapshot();
    let mut recipe: RecoveryRecipe = serde_json::from_value(
        lease
            .recovery
            .context("job has no durable source/retrieval recipe")?,
    )?;
    // Leases written before bd-4d1hs may carry a trailing-slash root that the
    // source-authority lock plan refuses; recover them under the canonical
    // spelling instead of failing forever.
    for root in &mut recipe.source_roots {
        *root = super::super::ssh::canonical_source_authority_root(root);
    }
    anyhow::ensure!(
        recipe.version == 2
            && recipe.wrapper_id == lease.identity.local_wrapper_id
            && Some(recipe.build_id) == lease.identity.remote_build_id
            && lease.worker_id.as_deref() == Some(recipe.worker.id.as_str()),
        "recovery recipe identity mismatch or unsupported source ownership version"
    );
    anyhow::ensure!(
        recipe.cargo_output_capture.is_none()
            || (recipe.prepared
                && recipe
                    .phases
                    .iter()
                    .filter(|phase| phase.output_gate)
                    .count()
                    == 1),
        "captured Cargo recovery has an invalid output root contract"
    );
    anyhow::ensure!(
        recipe.phases.iter().all(|phase| {
            phase.cargo_outputs.is_none()
                || (recipe.cargo_output_capture.is_some() && phase.output_gate)
        }),
        "Cargo output evidence is attached to an unrelated recovery phase"
    );
    result_recovery::validate_missing_results(&recipe)?;
    for phase in &recipe.phases {
        if let Some(contract) = &phase.native_outputs {
            anyhow::ensure!(
                recipe.prepared
                    && phase.name == "project"
                    && phase.result_dir.is_none()
                    && !phase.custom_target
                    && phase.local == recipe.project_root
                    && !WorkerPlatform::from_worker(&recipe.worker).is_windows()
                    && contract.patterns()? == phase.patterns,
                "native output contract is attached to an unrelated recovery phase"
            );
        }
    }
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
    };
    session.recipe.preparation_cancelled = true;
    session.persist()?;
    cancel_source_grant(session).await
}

/// Cancel the job's source grant (and pair), reap its remote tree, and retire
/// the recipe with a build-error exit. Callers must have proven that nothing
/// of the job can still run remotely: execution never started, or the probe in
/// `remote_execution_lost` found it gone.
async fn cancel_source_grant(mut session: RecoverySession) -> anyhow::Result<bool> {
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
    // Resolve lazily so an already acknowledged journal stays a read-only
    // operation, but pin the chosen endpoint across the entire handoff.
    let mut socket = None;
    Box::pin(recover_job_with_daemon(writer, async |command: &str| {
        if socket.is_none() {
            let config = crate::config::load_config()?;
            socket = Some(shellexpand::tilde(&config.general.socket_path).into_owned());
        }
        recovery_completion::request(socket.as_deref().expect("resolved socket"), command).await
    }))
    .await
}

async fn recover_job_with_daemon(
    writer: &DurableLeaseWriter,
    mut daemon: impl AsyncFnMut(&str) -> anyhow::Result<String>,
) -> anyhow::Result<i32> {
    // Hold one journal owner across the ENTIRE detached recovery, including
    // worker probes, source release and final daemon reservation reconciliation.
    // claim reloads the latest disk state after acquisition and never mistakes
    // an unverified wrapper for a dead one.
    let _ownership = recovery_owner::claim(writer).await?;
    let recipe = load_recipe(writer)?;
    let lease = writer.snapshot();
    if lease.terminal_acknowledged {
        let exit = recipe
            .returned
            .context("terminal recovery lacks a delivery result")?;
        anyhow::ensure!(
            recipe.retired && lease.exit_code == Some(exit),
            "terminal recovery contradicts its retained delivery/retirement evidence"
        );
        return Ok(exit);
    }
    if !recipe.execution_started {
        cancel_preparation(writer).await?;
        writer.record_exit(EXIT_BUILD_ERROR)?;
        recovery_completion::finish(writer, &mut daemon).await?;
        return Ok(EXIT_BUILD_ERROR);
    }
    if let Some(exit) = recipe.returned {
        let mut session = RecoverySession {
            recipe,
            writer: writer.clone(),
        };
        session.retire_returned().await?;
        writer.record_exit(exit)?;
        recovery_completion::finish(writer, &mut daemon).await?;
        return Ok(exit);
    }
    let mut session = RecoverySession {
        recipe,
        writer: writer.clone(),
    };
    let worker = session.recipe.worker.clone();
    let base = TransferPipeline::new(
        session.recipe.project_root.clone(),
        "recovery".into(),
        session.recipe.identity.clone(),
        session.recipe.transfer.clone(),
    );
    let base = session.completion_pipeline(base);
    let Some(mut exit) = base.read_recovery_completion(&worker).await? else {
        // A supervisor that died without its receipt (worker reboot, OOM,
        // kill) never writes one, and waiting for it kept the lease's source
        // claim fencing the worker forever. When the probe proves the
        // execution is gone, retire it as a failed build: nothing is replayed.
        if !session.recipe.source_roots.is_empty()
            && super::super::ssh::remote_execution_lost(
                &worker,
                &session.recipe.identity,
                &session.recipe.completion,
            )
            .await?
        {
            tracing::warn!(
                identity = %session.recipe.identity,
                worker = %worker.id,
                "remote execution ended without a completion receipt; retiring it as failed"
            );
            cancel_source_grant(session).await?;
            writer.record_exit(EXIT_BUILD_ERROR)?;
            recovery_completion::finish(writer, &mut daemon).await?;
            return Ok(EXIT_BUILD_ERROR);
        }
        anyhow::bail!(
            "same-id remote execution has no durable completion yet; command was not replayed"
        );
    };
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
    let command_exit = exit;
    // A wrapper can disappear after Cargo finishes but before it records the
    // output set locally. Re-read the complete same-attempt receipt; never
    // rerun Cargo and never silently downgrade to the old glob-only policy.
    let mut rejected_cargo_evidence = false;
    if command_exit == 0 && session.needs_cargo_artifact_evidence() {
        let root = session
            .cargo_artifact_remote_root()
            .context("captured Cargo recovery has no output root")?
            .to_owned();
        // Transport failure remains retryable. A complete but invalid Cargo
        // receipt cannot improve by repeating collection, so retire that
        // attempt as a delivery failure while retaining its receipt/stage.
        match base.read_cargo_artifact_evidence(&worker, &root).await {
            Ok(evidence) => {
                if let Err(error) =
                    session.install_cargo_artifact_evidence(&evidence.stdout, &evidence.remote_root)
                {
                    if !error.is::<CargoOutputContractRejected>() {
                        return Err(error);
                    }
                    eprintln!(
                        "[RCH] recovered Cargo output evidence is invalid: {error:#}; \
                         no build artifacts published (exit {EXIT_ARTIFACT_TRANSFER_FAILED})"
                    );
                    rejected_cargo_evidence = true;
                }
            }
            Err(error) if error.is::<crate::transfer::CargoArtifactEvidenceRejected>() => {
                eprintln!(
                    "[RCH] recovered Cargo output evidence was rejected: {error:#}; \
                     no build artifacts published (exit {EXIT_ARTIFACT_TRANSFER_FAILED})"
                );
                rejected_cargo_evidence = true;
            }
            Err(error) if base.remote_path_absent(&worker, &root).await? => {
                eprintln!(
                    "[RCH] recovered Cargo output root is gone ({root}): {error:#}; \
                     no build artifacts published (exit {EXIT_ARTIFACT_TRANSFER_FAILED})"
                );
                rejected_cargo_evidence = true;
            }
            Err(error) => return Err(error),
        }
        if rejected_cargo_evidence {
            exit = EXIT_ARTIFACT_TRANSFER_FAILED;
        }
    }
    for index in 0..session.recipe.phases.len() {
        let phase = session.recipe.phases[index].clone();
        if phase.complete
            || ((command_exit != 0 || rejected_cargo_evidence) && phase.result_dir.is_none())
        {
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
        if phase.result_dir.is_some() {
            // The completion receipt and recovered source grant above fence
            // the producer. Absence is now a failed output contract, not an
            // endlessly retryable transfer. Still collect other result dirs.
            if !result_recovery::collect_result(&mut session, index, &pipeline, &worker).await? {
                exit = EXIT_ARTIFACT_TRANSFER_FAILED;
                continue;
            }
        } else {
            let retrieved = match pipeline.retrieve_artifacts(&worker, &phase.patterns).await {
                Ok(retrieved) => retrieved,
                // Outputs whose remote tree is gone (e.g. a GC'd target pool)
                // can never come back: failing here stranded the job and its
                // worker-side source claim on every retry. Like a rejected
                // output set, it is a terminal build failure.
                Err(error) if pipeline.remote_path_absent(&worker, &phase.remote).await? => {
                    eprintln!(
                        "[RCH] recovered outputs are gone from the worker ({}): {error:#}; \
                         treating the recovered build as failed (exit {EXIT_ARTIFACT_TRANSFER_FAILED})",
                        phase.remote
                    );
                    exit = EXIT_ARTIFACT_TRANSFER_FAILED;
                    break;
                }
                Err(error) => return Err(error),
            };
            if let Err(error) = session.verify_native_outputs(index) {
                eprintln!(
                    "[RCH] recovered native outputs are incomplete: {error:#}; \
                     no build artifacts published (exit {EXIT_ARTIFACT_TRANSFER_FAILED})"
                );
                exit = EXIT_ARTIFACT_TRANSFER_FAILED;
                break;
            }
            if phase.output_gate {
                // A rejected output set is a terminal build failure, exactly
                // as on the live path, not a recovery error: the remote outputs
                // never change, so an error would strand source ownership on
                // every retry. Publish nothing further, then retire normally.
                let rejection = if let Err(error) = session.verify_cargo_outputs(index) {
                    Some(format!("recovered Cargo outputs are incomplete: {error:#}"))
                } else if sync_back_verified_zero_build_outputs(
                    &retrieved.manifest_regular_files,
                    retrieved.matched_regular_files,
                    session.recipe.kind,
                    phase.custom_target,
                ) || (session.recipe.package_archive
                    && retrieved.matched_regular_files == Some(0))
                {
                    Some("recovered transfer matched zero expected outputs".to_owned())
                } else if !session.recipe.allow_foreign
                    && kind_has_enumerable_output_contract(session.recipe.kind)
                {
                    let foreign = foreign_target_artifacts(
                        &session.stage(index),
                        &retrieved.manifest_regular_files,
                        phase.custom_target,
                        &session.recipe.expected_triple,
                        session.recipe.pinned_triple.as_deref(),
                    );
                    (!foreign.is_empty()).then(|| {
                        format!(
                            "recovered outputs target a foreign platform: {}",
                            describe_findings(&foreign)
                        )
                    })
                } else {
                    None
                };
                if let Some(rejection) = rejection {
                    eprintln!(
                        "[RCH] {rejection}; treating the recovered build as failed \
                         (exit {EXIT_ARTIFACT_TRANSFER_FAILED})"
                    );
                    exit = EXIT_ARTIFACT_TRANSFER_FAILED;
                    break;
                }
            }
        }
        session.publish(&phase.name).await?;
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
    session.discard_completion_receipts().await;
    writer.record_exit(exit)?;
    recovery_completion::finish(writer, &mut daemon).await?;
    Ok(exit)
}

/// Exercise the same durable publication boundary with real Cargo records from
/// the selector's owned fixture, without running Cargo a second time here.
#[cfg(test)]
pub(crate) async fn assert_cargo_fixture_publication(
    kind: CompilationKind,
    command: &str,
    stdout: &[u8],
    remote_root: &Path,
    custom_target: bool,
) {
    tests::assert_cargo_fixture_publication(kind, command, stdout, remote_root, custom_target)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    fn preparation_fixture() -> (tempfile::TempDir, DurableLeaseWriter, WorkerConfig) {
        preparation_fixture_with_identity("abc123")
    }

    fn preparation_fixture_with_identity(
        identity: &str,
    ) -> (tempfile::TempDir, DurableLeaseWriter, WorkerConfig) {
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
            identity.into(),
        )
        .unwrap();
        (directory, writer, worker)
    }

    #[cfg(unix)]
    fn go_fixture_command(go: &str, args: &[&str], environment: &[&str]) -> String {
        shell_words::join(
            [
                "env",
                "GOENV=off",
                "GOTOOLCHAIN=local",
                "GOWORK=off",
                "GOFLAGS=",
                "GOOS=",
                "GOARCH=",
                "CGO_ENABLED=0",
                "GOMAXPROCS=1",
            ]
            .into_iter()
            .chain(environment.iter().copied())
            .chain(std::iter::once(go))
            .chain(args.iter().copied()),
        )
    }

    #[cfg(unix)]
    async fn run_go_fixture(command: &mut tokio::process::Command) -> std::process::Output {
        command.stdin(Stdio::null()).kill_on_drop(true);
        tokio::time::timeout(Duration::from_secs(120), command.output())
            .await
            .expect("Go output fixture exceeded its bound")
            .expect("Go and rsync are required for the Go delivery regression")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn go_build_explicit_output_survives_recovery_and_missing_delivery() {
        use super::super::artifact_patterns::direct_compiler::{
            go_build_execution_command, validate_go_build_output,
        };
        use tokio::process::Command;

        let _guard = test_guard!();
        for (relative, inline_output) in [
            ("app", false),
            ("products/app [dev]*?", false),
            ("target/app", true),
        ] {
            let identity = format!("go-output-{}", uuid::Uuid::new_v4());
            let (_owner, writer, worker) = preparation_fixture_with_identity(&identity);
            let base = writer.path.parent().unwrap();
            let local = base.join("checkout");
            let remote = base.join("worker");
            let missing = base.join("missing-worker");
            let unrelated_target = base.join("unrelated-cargo-target");
            for root in [&local, &remote, &missing, &unrelated_target] {
                std::fs::create_dir_all(root.join("products")).unwrap();
                std::fs::create_dir_all(root.join("target")).unwrap();
            }
            for root in [&local, &remote] {
                std::fs::write(
                    root.join("go.mod"),
                    b"module fixture.invalid/output\n\ngo 1.20\n",
                )
                .unwrap();
            }
            let (source, expected_stdout): (&[u8], &[u8]) = if relative == "app" {
                // The previous output can also be a build input. Moving it
                // away before compilation would break this real embed case.
                (
                    b"package main\nimport (\"fmt\"; _ \"embed\")\nvar label = \"unset\"\n//go:embed app\nvar previous string\nfunc main() { fmt.Println(label + \":\" + previous) }\n",
                    b"go-delivered-37:old remote output\n",
                )
            } else {
                (
                    b"package main\nimport \"fmt\"\nvar label = \"unset\"\nfunc main() { fmt.Println(label) }\n",
                    b"go-delivered-37\n",
                )
            };
            std::fs::write(remote.join("main.go"), source).unwrap();
            std::fs::write(local.join("main.go"), b"local source sentinel").unwrap();
            std::fs::write(local.join(relative), b"old local output").unwrap();
            std::fs::write(remote.join(relative), b"old remote output").unwrap();
            std::fs::write(local.join("foreign.o"), b"other job's object").unwrap();
            std::fs::write(unrelated_target.join("sentinel"), b"unrelated Cargo target").unwrap();
            let output_option = format!("-o={relative}");
            let mut argv = vec![
                "build",
                "-p=1",
                "-ldflags",
                "-s -w -X main.label=go-delivered-37",
            ];
            if inline_output {
                argv.push(&output_option);
            } else {
                argv.extend(["-o", relative]);
            }
            argv.push("main.go");
            let command = go_fixture_command("go", &argv, &[]);
            assert_eq!(
                rch_common::classify_command(&command).kind,
                Some(CompilationKind::GoBuild)
            );
            let environment = validate_go_build_output(&command, &local).await.unwrap();
            assert_eq!(
                std::fs::read(local.join(relative)).unwrap(),
                b"old local output"
            );
            let pipeline = TransferPipeline::new(
                local.clone(),
                "go-fixture".into(),
                identity.clone(),
                TransferConfig::default(),
            )
            .with_remote_path_override(remote.to_str().unwrap().to_owned());
            let mut session = RecoverySession::prepare(
                &writer,
                &worker,
                &pipeline,
                vec!["/data/projects/source-recovery".into()],
                None,
                None,
                TransferConfig::default(),
                local.clone(),
                Some(&unrelated_target),
                Some(CompilationKind::GoBuild),
                &command,
                &[],
                identity,
            )
            .unwrap();
            assert!(session.has_native_output_contract());
            assert_eq!(session.recipe.phases.len(), 1);
            assert_eq!(session.recipe.phases[0].name, "project");
            assert!(session.returned(0).is_err());
            session.starting_execution().unwrap();
            let guarded = go_build_execution_command(&command, &environment).unwrap();
            let mut compiler = Command::new("sh");
            compiler.args(["-c", &guarded]).current_dir(&remote);
            let output = run_go_fixture(&mut compiler).await;
            assert!(output.status.success(), "{output:?}");
            session.completed(0).unwrap();
            let mut session = reload_publication(&session);
            assert_eq!(
                session.recipe.phases[0]
                    .native_outputs
                    .as_ref()
                    .unwrap()
                    .required_files,
                std::collections::BTreeSet::from([PathBuf::from(relative)])
            );
            for root in [&remote, &missing] {
                std::fs::write(root.join("foreign.o"), b"unrelated remote object").unwrap();
                std::fs::write(root.join("source.go"), b"unselected remote source").unwrap();
                std::fs::write(root.join("products/app d-decoy"), b"wildcard decoy").unwrap();
            }
            for complete in [false, true] {
                let stage = session.stage(0);
                let staged = session.staging_pipeline("project", &pipeline).unwrap();
                let patterns = session.cargo_artifact_patterns("project").unwrap();
                let mut rsync = staged.local_artifact_retrieval_for_test(
                    &worker,
                    if complete { &remote } else { &missing },
                    &patterns,
                );
                let output = run_go_fixture(&mut rsync).await;
                assert!(output.status.success(), "{output:?}");
                assert!(!stage.join("foreign.o").exists());
                assert!(!stage.join("source.go").exists());
                assert!(!stage.join("products/app d-decoy").exists());
                let journal_before = std::fs::read(&writer.path).unwrap();
                if !complete {
                    assert!(session.publish("project").await.is_err());
                    assert!(session.returned(0).is_err());
                    assert!(session.retain_failed_delivery_evidence());
                    assert_eq!(std::fs::read(&writer.path).unwrap(), journal_before);
                    assert_eq!(
                        std::fs::read(local.join(relative)).unwrap(),
                        b"old local output"
                    );
                    session = reload_publication(&session);
                    assert!(session.recipe.phases[0].published.is_empty());
                    assert!(session.recipe.phases[0].pending.is_none());
                } else {
                    session.publish("project").await.unwrap();
                    session.returned(0).unwrap();
                    session = reload_publication(&session);
                    assert!(session.recipe.phases[0].complete);
                    session.publish("project").await.unwrap();
                    assert_eq!(
                        std::fs::read(local.join(relative)).unwrap(),
                        std::fs::read(remote.join(relative)).unwrap()
                    );
                    let mut executable = Command::new(local.join(relative));
                    let output = run_go_fixture(&mut executable).await;
                    assert!(output.status.success(), "{output:?}");
                    assert_eq!(output.stdout, expected_stdout);
                }
            }
            assert_eq!(
                std::fs::read(local.join("main.go")).unwrap(),
                b"local source sentinel"
            );
            assert_eq!(
                std::fs::read(local.join("foreign.o")).unwrap(),
                b"other job's object"
            );
            assert_eq!(
                std::fs::read(unrelated_target.join("sentinel")).unwrap(),
                b"unrelated Cargo target"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn go_output_guards_preserve_old_files_on_invalid_or_empty_builds() {
        use super::super::artifact_patterns::direct_compiler::{
            go_build_execution_command, validate_go_build_output,
        };
        use std::os::unix::fs::{PermissionsExt, symlink};
        use tokio::process::Command;

        let _guard = test_guard!();
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::write(
            root.join("go.mod"),
            b"module fixture.invalid/guard\n\ngo 1.20\n",
        )
        .unwrap();
        std::fs::write(root.join("main.go"), b"package main\nfunc main() {}\n").unwrap();
        std::fs::write(
            root.join("broken.go"),
            b"package main\nthis is invalid Go\n",
        )
        .unwrap();
        std::fs::write(root.join("app"), b"old output must survive").unwrap();
        std::fs::create_dir(root.join("directory-output")).unwrap();
        std::fs::create_dir(root.join("outside")).unwrap();
        std::fs::write(root.join("outside/app"), b"outside sentinel").unwrap();
        symlink(root.join("outside/app"), root.join("linked-output")).unwrap();
        symlink(root.join("outside"), root.join("linked-parent")).unwrap();
        std::fs::write(root.join("file-parent"), b"parent sentinel").unwrap();
        let foreign_os = if std::env::consts::OS == "linux" {
            "GOOS=darwin"
        } else {
            "GOOS=linux"
        };
        let foreign_arch = if std::env::consts::ARCH == "x86_64" {
            "GOARCH=arm64"
        } else {
            "GOARCH=amd64"
        };
        let baseline_command =
            go_fixture_command("go", &["build", "-p=1", "-o", "app", "main.go"], &[]);
        let baseline = validate_go_build_output(&baseline_command, root)
            .await
            .unwrap();
        for (output_path, environment, reason) in [
            ("app", vec!["GOFLAGS=-n"], "empty GOFLAGS"),
            ("app", vec![foreign_os], "native GOOS/GOARCH"),
            ("app", vec![foreign_arch], "native GOOS/GOARCH"),
            ("directory-output", vec![], "regular file"),
            ("linked-output", vec![], "regular file"),
            ("linked-parent/app", vec![], "real directories"),
            ("file-parent/app", vec![], "real directories"),
        ] {
            let command = go_fixture_command(
                "go",
                &["build", "-p=1", "-o", output_path, "main.go"],
                &environment,
            );
            let error = validate_go_build_output(&command, root).await.unwrap_err();
            assert!(format!("{error:#}").contains(reason), "{error:#}");
            let guarded = go_build_execution_command(&command, &baseline).unwrap();
            let mut process = Command::new("sh");
            process.args(["-c", &guarded]).current_dir(root);
            let output = run_go_fixture(&mut process).await;
            assert_eq!(output.status.code(), Some(113), "{output:?}");
            let remote_reason = if environment.is_empty() {
                reason
            } else {
                "settings differ"
            };
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(remote_reason),
                "{output:?}"
            );
            assert_eq!(
                std::fs::read(root.join("app")).unwrap(),
                b"old output must survive"
            );
            assert_eq!(
                std::fs::read(root.join("outside/app")).unwrap(),
                b"outside sentinel"
            );
        }
        // An ambient build setting that is absent on the worker is a mismatch,
        // even when both endpoints still report the same GOOS/GOARCH.
        for changed in ["CGO_ENABLED=1", "GOEXPERIMENT=none", "GOAMD64=v2"] {
            let command =
                go_fixture_command("go", &["build", "-p=1", "-o", "app", "main.go"], &[changed]);
            validate_go_build_output(&command, root).await.unwrap();
            let guarded = go_build_execution_command(&command, &baseline).unwrap();
            let mut process = Command::new("sh");
            process.args(["-c", &guarded]).current_dir(root);
            let output = run_go_fixture(&mut process).await;
            assert_eq!(output.status.code(), Some(113), "{changed}: {output:?}");
            assert!(String::from_utf8_lossy(&output.stderr).contains("settings differ"));
            assert_eq!(
                std::fs::read(root.join("app")).unwrap(),
                b"old output must survive"
            );
        }
        // Matching CGO_ENABLED=1 remains supported; the guard does not force
        // otherwise ordinary Go builds into a pure-Go-only policy.
        let cgo_command = go_fixture_command(
            "go",
            &["build", "-p=1", "-o", "cgo-enabled-app", "main.go"],
            &["CGO_ENABLED=1"],
        );
        let cgo_environment = validate_go_build_output(&cgo_command, root).await.unwrap();
        let guarded = go_build_execution_command(&cgo_command, &cgo_environment).unwrap();
        let mut process = Command::new("sh");
        process.args(["-c", &guarded]).current_dir(root);
        let output = run_go_fixture(&mut process).await;
        assert!(output.status.success(), "{output:?}");
        assert!(root.join("cgo-enabled-app").is_file());

        // Both are real Go failures, including the explicit -o/no-packages
        // case. Neither may replace a previous successful build's output.
        for package in ["broken.go", "./missing/..."] {
            let command = go_fixture_command("go", &["build", "-p=1", "-o", "app", package], &[]);
            let environment = validate_go_build_output(&command, root).await.unwrap();
            let guarded = go_build_execution_command(&command, &environment).unwrap();
            let mut process = Command::new("sh");
            process.args(["-c", &guarded]).current_dir(root);
            let output = run_go_fixture(&mut process).await;
            assert_eq!(output.status.code(), Some(1), "{output:?}");
            assert_eq!(
                std::fs::read(root.join("app")).unwrap(),
                b"old output must survive"
            );
        }

        // Package loading must see exactly the caller's embed inputs. An
        // adjacent empty staging directory or a newly created output parent
        // changes `go:embed *` and makes an otherwise valid package fail.
        for (fixture, output_path) in [
            ("wildcard-root-output", "app"),
            ("wildcard-new-parent", "new-products/app"),
        ] {
            let project = root.join(fixture);
            std::fs::create_dir(&project).unwrap();
            std::fs::write(
                project.join("go.mod"),
                b"module fixture.invalid/embed\n\ngo 1.20\n",
            )
            .unwrap();
            std::fs::write(project.join("app"), b"embedded prior output").unwrap();
            std::fs::write(
                project.join("main.go"),
                b"package main\nimport (\"embed\"; \"fmt\")\n//go:embed *\nvar inputs embed.FS\nfunc main() { previous, err := inputs.ReadFile(\"app\"); if err != nil { panic(err) }; fmt.Println(string(previous)) }\n",
            )
            .unwrap();
            assert!(!project.join("new-products").exists());
            let command = go_fixture_command("go", &["build", "-p=1", "-o", output_path, "."], &[]);
            let environment = validate_go_build_output(&command, &project).await.unwrap();
            let guarded = go_build_execution_command(&command, &environment).unwrap();
            let mut compiler = Command::new("sh");
            compiler.args(["-c", &guarded]).current_dir(&project);
            let output = run_go_fixture(&mut compiler).await;
            assert!(output.status.success(), "{fixture}: {output:?}");
            let mut executable = Command::new(project.join(output_path));
            let output = run_go_fixture(&mut executable).await;
            assert!(output.status.success(), "{fixture}: {output:?}");
            assert_eq!(output.stdout, b"embedded prior output\n");
            if output_path != "app" {
                assert_eq!(
                    std::fs::read(project.join("app")).unwrap(),
                    b"embedded prior output"
                );
            }
        }

        // Failure injection: a Go shim reports success but creates no file.
        // Its env probe forwards to the actual compiler; an
        // old destination must still not satisfy the fresh-output contract.
        let mut real_env = Command::new("sh");
        real_env
            .args(["-c", &go_fixture_command("go", &["env", "GOROOT"], &[])])
            .current_dir(root);
        let goroot = run_go_fixture(&mut real_env).await;
        assert!(goroot.status.success(), "{goroot:?}");
        let go = PathBuf::from(String::from_utf8(goroot.stdout).unwrap().trim()).join("bin/go");
        let go = shell_escape::escape(go.to_string_lossy());
        let shim = root.join("shim/go");
        std::fs::create_dir(shim.parent().unwrap()).unwrap();
        std::fs::write(
            &shim,
            format!("#!/bin/sh\nif [ \"$1\" = env ]; then exec {go} \"$@\"; fi\nexit 0\n"),
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let command = go_fixture_command(
            shim.to_str().unwrap(),
            &["build", "-o", "app", "main.go"],
            &[],
        );
        let environment = validate_go_build_output(&command, root).await.unwrap();
        let guarded = go_build_execution_command(&command, &environment).unwrap();
        let mut process = Command::new("sh");
        process.args(["-c", &guarded]).current_dir(root);
        let output = run_go_fixture(&mut process).await;
        assert_eq!(output.status.code(), Some(113), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("without its required output file")
        );
        assert_eq!(
            std::fs::read(root.join("app")).unwrap(),
            b"old output must survive"
        );
        assert!(!std::fs::read_dir(root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".rch-go-output.")
        }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_native_outputs_are_complete_before_publication_and_survive_recovery() {
        use tokio::process::Command;
        async fn run(command: &mut Command) -> std::process::Output {
            command.stdin(Stdio::null()).kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(20), command.output())
                .await
                .expect("native output fixture exceeded its bound")
                .expect("GCC and rsync are required for the native delivery regression");
            assert!(output.status.success(), "{output:?}");
            output
        }

        let _guard = test_guard!();
        for (argv, expected, missing_index) in [
            (vec!["main.c", "lib/helper.c"], vec!["a.out"], 0),
            (
                vec!["-c", "main.c", "lib/helper.c"],
                vec!["helper.o", "main.o"],
                1,
            ),
            (
                vec!["-S", "main.c", "lib/helper.c"],
                vec!["helper.s", "main.s"],
                1,
            ),
            (
                vec![
                    "main.c",
                    "lib/helper.c",
                    "-o",
                    "products/app[dev]*?",
                    "-MMD",
                    "-MF",
                    "products/app.d",
                ],
                vec!["products/app.d", "products/app[dev]*?"],
                1,
            ),
            (
                vec![
                    "main.c",
                    "lib/helper.c",
                    "-o",
                    "target/app[dev]*?",
                    "-MMD",
                    "-MF",
                    "target/app.d",
                ],
                vec!["target/app.d", "target/app[dev]*?"],
                0,
            ),
        ] {
            let identity = format!("native-output-{}", uuid::Uuid::new_v4());
            let (_owner, writer, worker) = preparation_fixture_with_identity(&identity);
            let base = writer.path.parent().unwrap();
            let local = base.join("checkout");
            let remote = base.join("worker");
            let partial = base.join("partial-worker");
            let unrelated_target = base.join("unrelated-cargo-target");
            for path in [&local, &remote, &partial, &unrelated_target] {
                std::fs::create_dir_all(path.join("products")).unwrap();
                std::fs::create_dir_all(path.join("target")).unwrap();
            }
            std::fs::create_dir(remote.join("lib")).unwrap();
            std::fs::write(remote.join("main.c"),
                b"#include <stdio.h>\nint helper(void); int main(void) { printf(\"native-%d\\n\", helper()); return 0; }\n").unwrap();
            std::fs::write(
                remote.join("lib/helper.c"),
                b"int helper(void) { return 37; }\n",
            )
            .unwrap();
            std::fs::write(local.join("main.c"), b"local source sentinel").unwrap();
            std::fs::write(local.join("foreign.o"), b"other job's object").unwrap();
            std::fs::write(unrelated_target.join("sentinel"), b"unrelated Cargo target").unwrap();
            for relative in &expected {
                std::fs::write(local.join(relative), b"old local output").unwrap();
            }
            let command = shell_words::join(std::iter::once("gcc").chain(argv.iter().copied()));
            let pipeline = TransferPipeline::new(
                local.clone(),
                "native-fixture".into(),
                identity.clone(),
                TransferConfig::default(),
            )
            .with_remote_path_override(remote.to_str().unwrap().to_owned());
            let mut session = RecoverySession::prepare(
                &writer,
                &worker,
                &pipeline,
                vec!["/data/projects/source-recovery".into()],
                None,
                None,
                TransferConfig::default(),
                local.clone(),
                Some(&unrelated_target),
                Some(CompilationKind::Gcc),
                &command,
                &[],
                identity,
            )
            .unwrap();
            assert!(session.has_native_output_contract());
            assert_eq!(
                session.recipe.phases.len(),
                1,
                "ambient Cargo target must not displace native outputs"
            );
            assert_eq!(session.recipe.phases[0].name, "project");
            assert!(
                !session.recipe.phases[0].output_gate,
                "native completeness is independent of Cargo gating"
            );
            assert!(
                session.returned(0).is_err(),
                "pre-execution contract already forbids empty success"
            );
            session.starting_execution().unwrap();
            let mut compiler = Command::new("gcc");
            compiler
                .args(&argv)
                .current_dir(&remote)
                .env_remove("DEPENDENCIES_OUTPUT")
                .env_remove("SUNPRO_DEPENDENCIES");
            run(&mut compiler).await;
            session.completed(0).unwrap();
            let mut session = reload_publication(&session);
            assert_eq!(
                session.recipe.phases[0]
                    .native_outputs
                    .as_ref()
                    .unwrap()
                    .required_files,
                expected
                    .iter()
                    .map(PathBuf::from)
                    .collect::<std::collections::BTreeSet<_>>()
            );

            // A successful local rsync from this incomplete worker view must
            // not turn one object/depfile into proof of the entire contract.
            let missing = &expected[missing_index];
            for relative in expected.iter().filter(|relative| *relative != missing) {
                std::fs::copy(remote.join(relative), partial.join(relative)).unwrap();
            }
            for root in [&remote, &partial] {
                std::fs::write(root.join("foreign.o"), b"unrelated remote object").unwrap();
                std::fs::write(root.join("source.c"), b"unselected remote source").unwrap();
            }
            for complete in [false, true] {
                let stage = session.stage(0);
                let staged = session.staging_pipeline("project", &pipeline).unwrap();
                let patterns = session.cargo_artifact_patterns("project").unwrap();
                let mut rsync = staged.local_artifact_retrieval_for_test(
                    &worker,
                    if complete { &remote } else { &partial },
                    &patterns,
                );
                run(&mut rsync).await;
                assert!(!stage.join("foreign.o").exists());
                assert!(!stage.join("source.c").exists());
                let journal_before = std::fs::read(&writer.path).unwrap();
                if !complete {
                    assert!(session.publish("project").await.is_err());
                    assert_eq!(
                        std::fs::read(&writer.path).unwrap(),
                        journal_before,
                        "no durable publication frontier crossed"
                    );
                    assert!(session.returned(0).is_err());
                    assert!(session.retain_failed_delivery_evidence());
                    for relative in &expected {
                        assert_eq!(
                            std::fs::read(local.join(relative)).unwrap(),
                            b"old local output"
                        );
                    }
                    session = reload_publication(&session);
                    assert!(session.recipe.phases[0].published.is_empty());
                    assert!(session.recipe.phases[0].pending.is_none());
                } else {
                    session.publish("project").await.unwrap();
                    session.returned(0).unwrap();
                    session = reload_publication(&session);
                    assert!(session.recipe.phases[0].complete);
                    assert_eq!(session.recipe.phases[0].published.len(), expected.len());
                    session.publish("project").await.unwrap();
                    for relative in &expected {
                        assert_eq!(
                            std::fs::read(local.join(relative)).unwrap(),
                            std::fs::read(remote.join(relative)).unwrap()
                        );
                    }
                    if argv[0] != "-c" && argv[0] != "-S" {
                        let mut executable = Command::new(local.join(expected.last().unwrap()));
                        assert_eq!(run(&mut executable).await.stdout, b"native-37\n");
                    }
                }
            }
            assert_eq!(
                std::fs::read(local.join("main.c")).unwrap(),
                b"local source sentinel"
            );
            assert_eq!(
                std::fs::read(local.join("foreign.o")).unwrap(),
                b"other job's object"
            );
            assert_eq!(
                std::fs::read(unrelated_target.join("sentinel")).unwrap(),
                b"unrelated Cargo target"
            );
        }
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
            cargo_outputs: None,
            native_outputs: None,
            baseline: BTreeMap::new(),
            published: BTreeMap::new(),
            pending: None,
            complete: false,
            missing_result: None,
        });
        let session = RecoverySession { recipe, writer };
        std::fs::create_dir(session.stage(0)).unwrap();
        (directory, stage_owner, session)
    }

    fn reload_publication(session: &RecoverySession) -> RecoverySession {
        let writer = DurableLeaseWriter {
            path: session.writer.path.clone(),
            lease: Arc::new(Mutex::new(
                serde_json::from_slice(&std::fs::read(&session.writer.path).unwrap()).unwrap(),
            )),
        };
        RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer,
        }
    }

    fn captured_publication_fixture(
        kind: CompilationKind,
        command: &str,
        remote_root: &Path,
        custom_target: bool,
    ) -> (tempfile::TempDir, tempfile::TempDir, RecoverySession) {
        let (directory, stage_owner, mut session) = publication_fixture();
        let kind = Some(kind);
        session.recipe.kind = artifact_delivery_kind(kind, Some(command));
        session.recipe.prepared = true;
        session.recipe.execution_started = true;
        session.recipe.exit_code = Some(0);
        session.recipe.cargo_output_capture = CargoOutputCapture::for_command(kind, command);
        assert!(session.recipe.cargo_output_capture.is_some());
        let phase = &mut session.recipe.phases[0];
        phase.name = if custom_target { "target" } else { "project" }.into();
        phase.remote = remote_root.to_str().unwrap().to_owned();
        phase.custom_target = custom_target;
        phase.output_gate = true;
        phase.patterns = if custom_target {
            get_custom_target_artifact_patterns(kind, Some(command))
        } else {
            get_project_artifact_patterns(kind, Some(command), false)
        };
        session.persist().unwrap();
        (directory, stage_owner, session)
    }

    pub(super) async fn assert_cargo_fixture_publication(
        kind: CompilationKind,
        command: &str,
        stdout: &[u8],
        remote_root: &Path,
        custom_target: bool,
    ) {
        let (_directory, _stage_owner, session) =
            captured_publication_fixture(kind, command, remote_root, custom_target);
        // A detached collector must remember that evidence is still owed,
        // even if the wrapper stopped immediately after remote completion.
        let mut session = reload_publication(&session);
        assert!(session.needs_cargo_artifact_evidence());
        session
            .install_cargo_artifact_evidence(stdout, remote_root)
            .unwrap();
        let mut session = reload_publication(&session);
        assert!(!session.needs_cargo_artifact_evidence());
        let required = session.recipe.phases[0]
            .cargo_outputs
            .as_ref()
            .unwrap()
            .required_files
            .clone();
        assert_eq!(
            required.len(),
            2,
            "fixture must select two named executables"
        );
        let missing = required
            .iter()
            .nth(1)
            .expect("fixture must contain a second executable");
        let local = session.recipe.phases[0].local.clone();
        let phase_name = session.recipe.phases[0].name.clone();
        let stage = session.stage(0);
        for relative in &required {
            let destination = local.join(relative);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::write(&destination, b"previous local executable").unwrap();
            if relative != missing {
                let staged = stage.join(relative);
                std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
                std::fs::copy(remote_root.join(relative), staged).unwrap();
            }
        }
        // A genuine non-empty support-file transfer used to hide a missing
        // requested executable from the old zero-output gate.
        let support = missing.parent().unwrap().join("deps/unrelated-runtime.so");
        std::fs::create_dir_all(stage.join(&support).parent().unwrap()).unwrap();
        std::fs::write(
            stage.join(&support),
            b"runtime support is not a requested binary",
        )
        .unwrap();
        let journal = std::fs::read(&session.writer.path).unwrap();
        assert!(session.publish(&phase_name).await.is_err());
        for relative in &required {
            assert_eq!(
                std::fs::read(local.join(relative)).unwrap(),
                b"previous local executable",
                "a missing executable must not partially replace {}",
                relative.display()
            );
        }
        assert!(!local.join(&support).exists());
        assert!(stage.join(&support).is_file());
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), journal);
        assert!(session.recipe.phases[0].published.is_empty());
        assert!(!session.recipe.phases[0].complete);
        assert!(session.returned(0).is_err());

        // Supply the missing output on the same attempt, then recover solely
        // from the disk journal and staged bytes. No command is replayed.
        let mut resumed = reload_publication(&session);
        std::fs::create_dir_all(stage.join(missing).parent().unwrap()).unwrap();
        std::fs::copy(remote_root.join(missing), stage.join(missing)).unwrap();
        resumed.publish(&phase_name).await.unwrap();
        for relative in &required {
            assert_eq!(
                std::fs::read(local.join(relative)).unwrap(),
                std::fs::read(remote_root.join(relative)).unwrap()
            );
        }
        resumed.returned(0).unwrap();
        let finished = reload_publication(&resumed);
        assert!(finished.recipe.phases[0].complete);
        assert_eq!(finished.recipe.returned, Some(0));
        assert_eq!(
            finished.recipe.phases[0]
                .cargo_outputs
                .as_ref()
                .unwrap()
                .required_files,
            required
        );
        assert!(!stage.exists());
    }

    fn cargo_bin_receipt(root: &Path, custom_target: bool) -> Vec<u8> {
        let mut receipt = Vec::new();
        for name in ["app", "helper"] {
            let path = root
                .join(if custom_target { "lean" } else { "target/lean" })
                .join(name);
            let record = serde_json::json!({
                "reason": "compiler-artifact",
                "target": {"name": name, "kind": ["bin"]},
                "filenames": [path], "executable": path, "fresh": true
            });
            receipt.extend(serde_json::to_vec(&record).unwrap());
            receipt.push(b'\n');
        }
        receipt.extend_from_slice(b"{\"reason\":\"build-finished\",\"success\":true}\n");
        receipt
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cargo_no_run_delivers_every_real_named_test_and_bench_after_recovery() {
        use std::process::Stdio;
        use tokio::process::Command;

        for (kind, subcommand, selector, target_kind, custom_target) in [
            (CompilationKind::CargoTest, "test", "test", "test", false),
            (CompilationKind::CargoTest, "test", "test", "test", true),
            (
                CompilationKind::CargoBench,
                "bench",
                "bench",
                "bench",
                false,
            ),
            (CompilationKind::CargoBench, "bench", "bench", "bench", true),
        ] {
            let fixture = tempfile::tempdir().unwrap();
            let source = fixture.path().join("source project");
            for directory in ["src", "tests", "benches"] {
                std::fs::create_dir_all(source.join(directory)).unwrap();
            }
            std::fs::write(source.join("Cargo.toml"), concat!(
                "[package]\nname = \"rch_named_no_run_fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
                "[workspace]\n",
                "[[test]]\nname = \"alpha\"\npath = \"tests/alpha.rs\"\n",
                "[[test]]\nname = \"beta\"\npath = \"tests/beta.rs\"\n",
                "[[bench]]\nname = \"alpha\"\npath = \"benches/alpha.rs\"\nharness = false\n",
                "[[bench]]\nname = \"beta\"\npath = \"benches/beta.rs\"\nharness = false\n",
                "[profile.contract-fixture]\ninherits = \"dev\"\ndebug = 0\n",
            )).unwrap();
            std::fs::write(source.join("src/lib.rs"), "pub fn answer() -> u8 { 42 }\n").unwrap();
            for name in ["alpha", "beta"] {
                std::fs::write(
                    source.join("tests").join(format!("{name}.rs")),
                    format!("#[test] fn {name}_must_not_run() {{ panic!(\"no-run executed a test\"); }}\n"),
                ).unwrap();
                std::fs::write(
                    source.join("benches").join(format!("{name}.rs")),
                    "fn main() { panic!(\"no-run executed a benchmark\"); }\n",
                )
                .unwrap();
            }
            let remote_target = if custom_target {
                fixture.path().join("worker target")
            } else {
                source.join("target")
            };
            let remote_root = if custom_target {
                &remote_target
            } else {
                &source
            };
            let command = format!(
                "cargo {subcommand} --no-run --{selector} alpha --{selector} beta --profile contract-fixture --offline --jobs=1"
            );
            let capture = CargoOutputCapture::for_command(Some(kind), &command).unwrap();
            let instrumented = capture.execution_command(&command);
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let mut compile = Command::new(cargo);
            compile
                .current_dir(&source)
                .args(instrumented.split_ascii_whitespace().skip(1))
                // The live command pins build.build-dir into the worker output
                // tree. Exercise the real new layout, including executable
                // files beneath normally excluded build-cache directories.
                .arg("--config")
                .arg(format!(
                    "build.build-dir={}",
                    serde_json::to_string(remote_target.to_str().unwrap()).unwrap()
                ))
                .env("CARGO_HOME", fixture.path().join("cargo-home"))
                .env("CARGO_TARGET_DIR", &remote_target)
                .env_remove("RUSTC_WRAPPER")
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env_remove("RUSTFLAGS")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env_remove("CARGO_BUILD_TARGET")
                .env_remove("CARGO_BUILD_TARGET_DIR")
                .env_remove("CARGO_BUILD_BUILD_DIR")
                .env_remove("CARGO_MAKEFLAGS")
                .env_remove("MAKEFLAGS")
                .stdin(Stdio::null())
                .kill_on_drop(true);
            let mut completed_stdout = Vec::new();
            for warm in [false, true] {
                let output = tokio::time::timeout(Duration::from_secs(90), compile.output())
                    .await
                    .expect("owned no-run Cargo fixture timed out")
                    .expect("Cargo is required for the named no-run delivery regression");
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
                    .unwrap()
                    .lines()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .filter(|record: &serde_json::Value| {
                        record["reason"] == "compiler-artifact"
                            && record["target"]["kind"] == serde_json::json!([target_kind])
                    })
                    .collect();
                assert_eq!(records.len(), 2, "both requested targets must be emitted");
                assert!(records.iter().all(|record| record["fresh"] == warm));
                let contract = capture.parse_receipt(&output.stdout, remote_root).unwrap();
                assert_eq!(contract.required_files.len(), 2);
                assert!(
                    contract
                        .required_files
                        .iter()
                        .all(|path| { path.components().any(|part| part.as_os_str() == "build") }),
                    "fixture must exercise the managed build directory: {contract:?}"
                );
                completed_stdout = output.stdout;
            }

            let (_local_owner, _stage_owner, mut session) =
                captured_publication_fixture(kind, &command, remote_root, custom_target);
            session
                .install_cargo_artifact_evidence(&completed_stdout, remote_root)
                .unwrap();
            let mut session = reload_publication(&session);
            let phase = &session.recipe.phases[0];
            let required = phase.cargo_outputs.as_ref().unwrap().required_files.clone();
            let patterns = phase.patterns.clone();
            let name = phase.name.clone();
            let local = phase.local.clone();
            let stage = session.stage(0);
            let missing = required.iter().next_back().unwrap();
            for relative in &required {
                std::fs::create_dir_all(local.join(relative).parent().unwrap()).unwrap();
                std::fs::write(local.join(relative), b"previous local executable").unwrap();
            }
            let source_sentinel = local.join("source.rs");
            std::fs::write(&source_sentinel, b"local source remains owned locally").unwrap();
            for complete_transfer in [false, true] {
                let mut transfer = Command::new("rsync");
                transfer.args(["-a", "--checksum", "--safe-links", "--prune-empty-dirs"]);
                if !complete_transfer {
                    // Simulate a successful but incomplete artifact transfer.
                    // The other executable makes the old nonempty gate pass.
                    transfer.arg(format!("--exclude=/{}", missing.display()));
                }
                for rule in crate::transfer::priority_rsync_includes(&patterns) {
                    transfer.arg(format!("--include={rule}"));
                }
                for pattern in &patterns {
                    if let Some(excluded) = pattern.strip_prefix("- ") {
                        transfer.arg(format!("--exclude={excluded}"));
                    }
                }
                transfer.arg("--include=*/");
                for pattern in &patterns {
                    if !pattern.starts_with("- ") {
                        transfer.arg(format!(
                            "--include=/{}",
                            pattern.strip_prefix("+ ").unwrap_or(pattern)
                        ));
                    }
                }
                transfer
                    .arg("--exclude=*")
                    .arg(format!("{}/", remote_root.display()))
                    .arg(format!("{}/", stage.display()))
                    .stdin(Stdio::null())
                    .kill_on_drop(true);
                let copied = tokio::time::timeout(Duration::from_secs(15), transfer.output())
                    .await
                    .expect("owned no-run rsync fixture timed out")
                    .expect("rsync is required for the named no-run delivery regression");
                assert!(copied.status.success(), "{copied:?}");
                if !complete_transfer {
                    assert!(
                        required
                            .iter()
                            .any(|relative| stage.join(relative).is_file())
                    );
                    assert!(!stage.join(missing).exists());
                    let journal = std::fs::read(&session.writer.path).unwrap();
                    assert!(session.publish(&name).await.is_err());
                    assert_eq!(std::fs::read(&session.writer.path).unwrap(), journal);
                    assert!(session.returned(0).is_err());
                    for relative in &required {
                        assert_eq!(
                            std::fs::read(local.join(relative)).unwrap(),
                            b"previous local executable"
                        );
                    }
                    session = reload_publication(&session);
                } else {
                    session.publish(&name).await.unwrap();
                    session.returned(0).unwrap();
                    for relative in &required {
                        assert_eq!(
                            std::fs::read(local.join(relative)).unwrap(),
                            std::fs::read(remote_root.join(relative)).unwrap()
                        );
                    }
                    let restored = reload_publication(&session);
                    assert_eq!(restored.recipe.returned, Some(0));
                    assert!(restored.recipe.phases[0].complete);
                }
                assert_eq!(
                    std::fs::read(&source_sentinel).unwrap(),
                    b"local source remains owned locally"
                );
            }
        }
    }

    #[tokio::test]
    async fn cargo_missing_named_bin_preserves_all_outputs_until_disk_reloaded_retry() {
        for custom_target in [false, true] {
            let remote = tempfile::tempdir().unwrap();
            let outputs = remote
                .path()
                .join(if custom_target { "lean" } else { "target/lean" });
            std::fs::create_dir_all(&outputs).unwrap();
            std::fs::write(outputs.join("app"), b"new app executable").unwrap();
            std::fs::write(outputs.join("helper"), b"new helper executable").unwrap();
            assert_cargo_fixture_publication(
                CompilationKind::CargoBuild,
                "cargo build --bin app --bin helper --profile lean",
                &cargo_bin_receipt(remote.path(), custom_target),
                remote.path(),
                custom_target,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn cargo_awaiting_receipt_cannot_publish_or_report_success_and_retains_failure_stage() {
        let remote = tempfile::tempdir().unwrap();
        let (_directory, _stage_owner, session) = captured_publication_fixture(
            CompilationKind::CargoBuild,
            "cargo build --bin app --bin helper --profile lean",
            remote.path(),
            false,
        );
        let mut session = reload_publication(&session);
        let stage = session.stage(0);
        std::fs::create_dir_all(stage.join("target/lean")).unwrap();
        std::fs::write(stage.join("target/lean/app"), b"new app").unwrap();
        let before = std::fs::read(&session.writer.path).unwrap();
        assert!(session.publish("project").await.is_err());
        assert!(session.returned(0).is_err());
        assert!(
            !session.recipe.phases[0]
                .local
                .join("target/lean/app")
                .exists()
        );
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
        session.returned(EXIT_ARTIFACT_TRANSFER_FAILED).unwrap();
        session.sources_released().unwrap();
        session.retired().unwrap();
        assert!(session.retain_failed_delivery_evidence());
        assert_eq!(
            std::fs::read(stage.join("target/lean/app")).unwrap(),
            b"new app"
        );
        let retired = reload_publication(&session);
        assert!(retired.recipe.retired);
        assert!(!retired.recipe.phases[0].complete);
        assert_eq!(retired.recipe.returned, Some(EXIT_ARTIFACT_TRANSFER_FAILED));
    }

    #[test]
    fn cargo_invalid_evidence_cannot_expand_policy_or_replace_sources() {
        let remote = tempfile::tempdir().unwrap();
        let (_directory, _stage_owner, mut session) = captured_publication_fixture(
            CompilationKind::CargoBuild,
            "cargo build --bin app --bin helper --profile lean",
            remote.path(),
            false,
        );
        let before = std::fs::read(&session.writer.path).unwrap();
        let patterns = session.recipe.phases[0].patterns.clone();
        let receipt = cargo_bin_receipt(remote.path(), false);
        let finished_start = receipt[..receipt.len() - 1]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .unwrap()
            + 1;
        let missing_finished = &receipt[..finished_start];
        let error = session
            .install_cargo_artifact_evidence(missing_finished, remote.path())
            .unwrap_err();
        assert!(error.is::<CargoOutputContractRejected>());
        let forged = String::from_utf8(cargo_bin_receipt(remote.path(), false))
            .unwrap()
            .replace("target/lean/app", "Cargo.toml");
        assert!(
            session
                .install_cargo_artifact_evidence(forged.as_bytes(), remote.path())
                .is_err()
        );
        assert_eq!(session.recipe.phases[0].patterns, patterns);
        assert!(session.recipe.phases[0].cargo_outputs.is_none());
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
    }

    #[test]
    fn cargo_evidence_journal_failure_remains_retryable_and_cannot_authorize_publication() {
        let remote = tempfile::tempdir().unwrap();
        let (directory, _stage_owner, mut session) = captured_publication_fixture(
            CompilationKind::CargoBuild,
            "cargo build --bin app --bin helper --profile lean",
            remote.path(),
            false,
        );
        let journal = session.writer.path.clone();
        let before = std::fs::read(&journal).unwrap();
        // Atomic publication cannot replace a directory with the lease file.
        // This is a real filesystem failure, not an invalid Cargo receipt.
        session.writer.path = directory.path().to_owned();
        let error = session
            .install_cargo_artifact_evidence(
                &cargo_bin_receipt(remote.path(), false),
                remote.path(),
            )
            .unwrap_err();
        assert!(!error.is::<CargoOutputContractRejected>());
        assert!(session.needs_cargo_artifact_evidence());
        assert_eq!(std::fs::read(journal).unwrap(), before);
    }

    #[tokio::test]
    async fn recovery_publication_refuses_retained_or_pending_source_before_any_write() {
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

            let published = session.publish("project").await;
            // Source is never overwritten.
            assert_eq!(std::fs::read(local.join("main.c")).unwrap(), original);
            if pending {
                // The refused publication keeps its journaled copy for a retry.
                assert_eq!(std::fs::read(&retained).unwrap(), remote);
                // An interrupted write of an out-of-policy path cannot be
                // finished or skipped: refuse before any write.
                assert!(published.is_err());
                assert!(!local.join("build/app").exists());
                assert_eq!(std::fs::read(&session.writer.path).unwrap(), journal);
                assert!(session.recipe.phases[0].published.is_empty());
            } else {
                // A retained out-of-policy file is skipped, not fatal: the
                // job's real outputs still publish, so recovery can retire
                // and release the worker-side source claim.
                published.unwrap();
                assert_eq!(
                    std::fs::read(local.join("build/app")).unwrap(),
                    b"valid artifact"
                );
                assert!(
                    !session.recipe.phases[0]
                        .published
                        .contains_key(&PathBuf::from("main.c"))
                );
                // Completion drops the stage, retained copy included; it was
                // never published and nothing reads it again.
                assert!(!stage.exists());
            }
        }
    }

    #[tokio::test]
    async fn publication_overwrites_outputs_another_job_replaced_after_preparation() {
        // Dispatchers share one CARGO_TARGET_DIR: between this job's
        // preparation snapshot and its publication, another job may replace
        // the same output. That is not an ownership conflict; publishing must
        // re-baseline under the publication lock and write, not refuse.
        let (_directory, _stage_owner, mut session) = publication_fixture();
        let local = session.recipe.project_root.clone();
        let stage = session.stage(0);
        std::fs::create_dir(local.join("build")).unwrap();
        std::fs::write(local.join("build/app"), b"snapshot at preparation").unwrap();
        session.recipe.phases[0].baseline.insert(
            PathBuf::from("build/app"),
            fingerprint(&local.join("build/app")).unwrap().unwrap(),
        );
        std::fs::write(local.join("build/app"), b"written by a concurrent job").unwrap();
        std::fs::create_dir(stage.join("build")).unwrap();
        std::fs::write(stage.join("build/app"), b"this job's output").unwrap();
        session.persist().unwrap();

        session.publish("project").await.unwrap();
        assert_eq!(
            std::fs::read(local.join("build/app")).unwrap(),
            b"this job's output"
        );
        assert!(session.recipe.phases[0].complete);
        assert!(
            !stage.exists(),
            "a completed publication must not keep its duplicate stage"
        );
    }

    /// The output root may sit behind system symlinks (macOS `/tmp`, `/var`,
    /// a symlinked `/data`): publication must accept that root, while a
    /// symlink BELOW it, which could redirect a write, is still refused.
    #[cfg(unix)]
    #[tokio::test]
    async fn publication_accepts_symlinked_root_but_refuses_symlinks_inside_it() {
        let (directory, _stage_owner, mut session) = publication_fixture();
        let real = directory.path().join("real-target");
        std::fs::create_dir(&real).unwrap();
        let link = directory.path().join("linked-target");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        session.recipe.phases[0].local = link;
        let stage = session.stage(0);
        std::fs::create_dir(stage.join("build")).unwrap();
        std::fs::write(stage.join("build/app"), b"output").unwrap();
        session.persist().unwrap();
        session.publish("project").await.unwrap();
        assert_eq!(std::fs::read(real.join("build/app")).unwrap(), b"output");

        let (directory, _stage_owner, mut session) = publication_fixture();
        let local = session.recipe.project_root.clone();
        let elsewhere = directory.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, local.join("build")).unwrap();
        let stage = session.stage(0);
        std::fs::create_dir(stage.join("build")).unwrap();
        std::fs::write(stage.join("build/app"), b"output").unwrap();
        session.persist().unwrap();
        assert!(session.publish("project").await.is_err());
        assert!(!elsewhere.join("app").exists());
    }

    #[tokio::test]
    async fn publication_lock_is_released_between_publications() {
        let (_directory, _stage_owner, session) = publication_fixture();
        let root = session.recipe.project_root.clone();
        let first = lock_output_root(&root).await.unwrap();
        drop(first);
        // A second wrapper can publish into the same root once the first is done.
        let _second = lock_output_root(&root).await.unwrap();
    }

    /// Keep a real kernel lock held independently of the Tokio reactor. The
    /// watchdog makes a regression to a blocking wait fail in seconds instead
    /// of hanging the test for the production ten-minute publication budget.
    fn hold_publication_lock(
        lock: File,
    ) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let (release, released) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _ = released.recv_timeout(Duration::from_secs(2));
            drop(lock);
        });
        (release, holder)
    }

    #[cfg(unix)]
    #[test]
    fn publication_identity_resolves_symlinks_before_parent_components_without_creating_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        std::fs::create_dir_all(real.join("nested")).unwrap();
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(real.join("nested"), &alias).unwrap();
        let expected = std::fs::canonicalize(&real).unwrap().join("target");
        for path in [
            real.join("target"),
            alias.join("../target"),
            alias.join("missing/../../target"),
        ] {
            assert_eq!(output_lock_root_identity(&path).unwrap(), expected);
        }
        assert!(!real.join("target").exists());
        assert!(!real.join("nested/missing").exists());

        let dangling = directory.path().join("dangling");
        std::os::unix::fs::symlink(directory.path().join("absent"), &dangling).unwrap();
        assert!(output_lock_root_identity(&dangling.join("target")).is_err());
        std::fs::write(real.join("file"), b"not a directory").unwrap();
        assert!(output_lock_root_identity(&real.join("file/../target")).is_err());
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn symlinked_and_canonical_output_roots_share_publication_ownership() {
        let (directory, _stage_owner, session) = publication_fixture();
        let root = session.recipe.project_root.clone();
        let alias = directory.path().join("output-alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let lock = lock_output_root(&root).await.unwrap();
        let (release, holder) = hold_publication_lock(lock);
        let alias_lock =
            tokio::time::timeout(Duration::from_millis(25), lock_output_root(&alias)).await;
        let _ = release.send(());
        holder.join().unwrap();
        assert!(
            alias_lock.is_err(),
            "path alias bypassed the existing publication owner"
        );
        let _after_release = lock_output_root(&alias).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn missing_output_root_keeps_its_lock_when_another_job_creates_the_directory() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let root = real.join("new-target/profile");
        let aliased_root = alias.join("new-target/profile");
        let lock = lock_output_root(&aliased_root).await.unwrap();
        assert!(
            !root.exists(),
            "lock discovery created the caller's output tree"
        );
        let (release, holder) = hold_publication_lock(lock);
        std::fs::create_dir_all(&root).unwrap();
        let created_lock =
            tokio::time::timeout(Duration::from_millis(25), lock_output_root(&root)).await;
        let _ = release.send(());
        holder.join().unwrap();
        assert!(
            created_lock.is_err(),
            "creating the output tree changed its ownership identity"
        );
        let _after_release = lock_output_root(&root).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn retargeted_output_alias_refuses_publication_and_retains_the_journal() {
        let (directory, _stage_owner, mut session) = publication_fixture();
        let original = session.recipe.project_root.clone();
        let replacement = directory.path().join("other-output");
        std::fs::create_dir(&replacement).unwrap();
        let alias = directory.path().join("output-alias");
        std::os::unix::fs::symlink(&original, &alias).unwrap();
        session.recipe.phases[0].local = alias.clone();
        let stage = session.stage(0);
        std::fs::create_dir(stage.join("build")).unwrap();
        std::fs::write(stage.join("build/app"), b"completed remote output").unwrap();
        session.persist().unwrap();
        let before = std::fs::read(&session.writer.path).unwrap();
        let lock = lock_output_root(&original).await.unwrap();
        let (release, holder) = hold_publication_lock(lock);
        let mut publication = Box::pin(session.publish("project"));
        // Borrow the future so the first deadline leaves its original lock
        // identity pending, then retarget the alias before ownership arrives.
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut publication)
                .await
                .is_err()
        );
        std::fs::rename(&alias, directory.path().join("previous-output-alias")).unwrap();
        std::os::unix::fs::symlink(&replacement, &alias).unwrap();
        let _ = release.send(());
        holder.join().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), publication)
            .await
            .expect("publication did not resume after its original owner released the lock")
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("output root changed while waiting")
        );
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
        assert!(!original.join("build/app").exists());
        assert!(!replacement.join("build/app").exists());
        assert_eq!(
            std::fs::read(stage.join("build/app")).unwrap(),
            b"completed remote output"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn publication_deadline_keeps_staged_outputs_and_journal_for_same_job_retry() {
        let (_directory, _stage_owner, mut session) = publication_fixture();
        let local = session.recipe.project_root.clone();
        let stage = session.stage(0);
        std::fs::create_dir(local.join("build")).unwrap();
        std::fs::write(local.join("build/app"), b"previous output").unwrap();
        std::fs::create_dir(stage.join("build")).unwrap();
        std::fs::write(stage.join("build/app"), b"completed remote output").unwrap();
        session.persist().unwrap();
        let before = std::fs::read(&session.writer.path).unwrap();
        let lock = lock_output_root(&local).await.unwrap();
        let (release, holder) = hold_publication_lock(lock);

        // This is the same cancellation boundary as jobs recover's deadline:
        // dropping the wait must not begin publication or retire ownership.
        let publication =
            tokio::time::timeout(Duration::from_millis(25), session.publish("project")).await;
        let _ = release.send(());
        holder.join().unwrap();
        assert!(
            publication.is_err(),
            "contended publication blocked its caller's deadline"
        );
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
        assert_eq!(
            std::fs::read(local.join("build/app")).unwrap(),
            b"previous output"
        );
        assert_eq!(
            std::fs::read(stage.join("build/app")).unwrap(),
            b"completed remote output"
        );
        assert!(!session.recipe.phases[0].complete);
        assert!(session.recipe.phases[0].pending.is_none());
        assert!(session.recipe.phases[0].published.is_empty());
        assert!(!session.recipe.sources_released);

        // Resume from the retained disk journal, not the cancelled future's
        // in-memory session. Only the already-staged bytes are published.
        let writer = DurableLeaseWriter {
            path: session.writer.path.clone(),
            lease: Arc::new(Mutex::new(serde_json::from_slice(&before).unwrap())),
        };
        let mut resumed = RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer,
        };
        resumed.publish("project").await.unwrap();
        assert_eq!(
            std::fs::read(local.join("build/app")).unwrap(),
            b"completed remote output"
        );
        assert!(resumed.recipe.phases[0].complete);
        assert!(!stage.exists());
        assert_eq!(resumed.recipe.wrapper_id, session.recipe.wrapper_id);
        assert_eq!(resumed.recipe.build_id, session.recipe.build_id);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn same_root_publishers_wait_without_stalling_runtime_progress() {
        let (_first_dir, _first_stage_owner, mut first) = publication_fixture();
        let (_second_dir, _second_stage_owner, mut second) = publication_fixture();
        let local = first.recipe.project_root.clone();
        second.recipe.phases[0].local = local.clone();
        std::fs::create_dir(local.join("build")).unwrap();
        std::fs::write(local.join("build/app"), b"before both jobs").unwrap();
        for (session, name, bytes) in [
            (&mut first, "first.o", b"first job".as_slice()),
            (&mut second, "second.o", b"second job".as_slice()),
        ] {
            let stage = session.stage(0);
            std::fs::create_dir(stage.join("build")).unwrap();
            std::fs::write(stage.join("build/app"), bytes).unwrap();
            std::fs::write(stage.join("build").join(name), bytes).unwrap();
            session.persist().unwrap();
        }
        let lock = lock_output_root(&local).await.unwrap();
        let (release, holder) = hold_publication_lock(lock);
        let publications = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(first.publish("project"), second.publish("project"), async {
                // A heartbeat/recovery timer must still run while both jobs
                // wait. Neither may touch the shared output before ownership.
                tokio::time::sleep(Duration::from_millis(25)).await;
                assert_eq!(
                    std::fs::read(local.join("build/app")).unwrap(),
                    b"before both jobs"
                );
                release.send(()).unwrap();
            })
        })
        .await;
        drop(release);
        holder.join().unwrap();
        let (first_result, second_result, ()) = publications
            .expect("contended publication prevented the timer from releasing its owner");
        first_result.unwrap();
        second_result.unwrap();
        assert!(first.recipe.phases[0].complete);
        assert!(second.recipe.phases[0].complete);
        assert_eq!(
            std::fs::read(local.join("build/first.o")).unwrap(),
            b"first job"
        );
        assert_eq!(
            std::fs::read(local.join("build/second.o")).unwrap(),
            b"second job"
        );
        let final_output = std::fs::read(local.join("build/app")).unwrap();
        assert!(matches!(
            final_output.as_slice(),
            b"first job" | b"second job"
        ));
        assert!(!first.stage(0).exists());
        assert!(!second.stage(0).exists());
    }

    #[tokio::test]
    async fn recovery_publication_finishes_journaled_new_outputs_without_rewriting_them() {
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

        session.publish("project").await.unwrap();
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

    #[tokio::test]
    async fn recovery_publication_retains_declared_result_directory_contract() {
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

        session.publish("project").await.unwrap();
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
