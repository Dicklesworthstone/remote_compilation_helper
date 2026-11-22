//! Compact lease storage and replay of per-phase publication evidence.
//!
//! Heartbeats retain only a fixed journal reference. The complete logical
//! recipe stays available for output checks, caller JSON, and stale-owner
//! comparisons; only the explicit storage adapter omits publication maps.

use super::*;
use publication_journal::{Intent, JournalRef, Replay};
use serde_json::Value;

impl RecoveryRecipe {
    pub(super) fn storage_value(&self) -> anyhow::Result<Value> {
        let mut value = serde_json::to_value(self)?;
        for phase in value["phases"]
            .as_array_mut()
            .context("recovery recipe has no phase array")?
        {
            if phase
                .get("publication_journal")
                .is_some_and(|value| !value.is_null())
            {
                let phase = phase.as_object_mut().context("invalid publication phase")?;
                // These are required fields in the legacy wire format. Their
                // absence makes an older binary refuse this newer recipe,
                // rather than mistake an omitted map for completed evidence.
                phase.remove("baseline");
                phase.remove("published");
                phase.remove("pending");
            }
        }
        Ok(value)
    }

    fn publication_binding(&self, index: usize, include_patterns: bool) -> anyhow::Result<String> {
        let phase = self
            .phases
            .get(index)
            .context("missing publication phase")?;
        let mut authority = serde_json::json!({
            "version": 1,
            "wrapper_id": self.wrapper_id,
            "build_id": self.build_id,
            "worker": self.worker,
            "identity": self.identity,
            "phase_index": index,
            "name": phase.name,
            "local": phase.local,
            "remote": phase.remote,
            "result_dir": phase.result_dir,
            "custom_target": phase.custom_target,
            "output_gate": phase.output_gate,
            "patterns": include_patterns.then_some(&phase.patterns),
            "cargo_outputs": phase.cargo_outputs,
            "native_outputs": phase.native_outputs,
            "kind": self.kind,
            "expected_triple": self.expected_triple,
            "pinned_triple": self.pinned_triple,
            "allow_foreign": self.allow_foreign,
            "package_archive": self.package_archive,
            "result_destination": self.result_destination,
            "caller_json_policy": self.caller_json_policy,
        });
        // Ordinary jobs retain their existing journal binding across upgrades.
        // New freshness authority is part of the seal only when it exists.
        if let Some(preparation) = &self.fresh_job_results {
            authority["fresh_job_results"] = serde_json::to_value(preparation)?;
        }
        Ok(blake3::hash(&serde_json::to_vec(&authority)?)
            .to_hex()
            .to_string())
    }

    /// An override retains the previous lease bytes. Fork its logs too so
    /// subsequent publication cannot change that snapshot's historical state.
    pub(super) fn fork_publication_journals(
        &mut self,
        writer: &DurableLeaseWriter,
    ) -> anyhow::Result<()> {
        if !self
            .phases
            .iter()
            .any(|phase| phase.publication_journal.is_some())
        {
            return Ok(());
        }
        let owner = writer
            .recovery_ownership
            .as_deref()
            .context("publication journal fork requires exclusive recovery ownership")?;
        let directory = owner.publication_directory()?;
        let lease = writer.snapshot();
        let previous = decode_recipe_value(
            lease
                .recovery
                .clone()
                .context("publication fork lost its original recipe")?,
            Some(owner),
        )?;
        anyhow::ensure!(
            self.phases.len() == previous.phases.len(),
            "publication override changed its admitted phase set"
        );
        for index in 0..self.phases.len() {
            let Some(mut journal) = self.phases[index].publication_journal.clone() else {
                continue;
            };
            let original_binding = previous.publication_binding(index, true)?;
            anyhow::ensure!(
                journal.binding() == original_binding,
                "publication override does not retain its original journal binding"
            );
            let replay = journal.replay(directory, &original_binding)?;
            let binding = self.publication_binding(index, true)?;
            let replacement = if binding == original_binding {
                journal.fork(directory, &binding)?
            } else {
                anyhow::ensure!(
                    self.publication_binding(index, false)?
                        == previous.publication_binding(index, false)?,
                    "publication override changed an admitted output identity or required contract"
                );
                recovery_owner::validate_publication_rebind(&lease, &previous, self, index)?;
                // This explicit policy operation can narrow disjoint Make
                // outputs after a partial publication. Preserve every prior
                // commit and the pending rename's ORIGINAL predecessor.
                JournalRef::create(
                    directory,
                    &binding,
                    &replay.published,
                    replay.pending.clone(),
                )?
            };
            self.phases[index].publication_journal = Some(replacement);
            apply_replay(&mut self.phases[index], replay)?;
        }
        owner.verify()
    }

    /// Baseline observations for untouched paths expire with the output lock.
    /// Keeping them in a returned session would disagree with a fresh replay
    /// even though all durable publication evidence is exactly the same.
    pub(super) fn finish_publication_epoch(&mut self) {
        for phase in &mut self.phases {
            if phase.publication_journal.is_some() {
                let pending = phase.pending.as_ref().map(|(relative, _)| relative);
                phase
                    .baseline
                    .retain(|relative, _| pending == Some(relative));
            }
        }
    }
}

fn validate_sealed_phase(phase: &RecoveryPhase) -> anyhow::Result<()> {
    anyhow::ensure!(
        phase.pending.is_none() && phase.missing_result.is_none(),
        "completed publication has pending or failed delivery evidence"
    );
    for relative in phase
        .cargo_outputs
        .iter()
        .flat_map(|contract| &contract.required_files)
        .chain(
            phase
                .native_outputs
                .iter()
                .flat_map(|contract| &contract.required_files),
        )
    {
        anyhow::ensure!(
            phase.published.contains_key(relative),
            "sealed publication lacks a required output: {}",
            relative.display()
        );
    }
    for directory in phase
        .cargo_outputs
        .iter()
        .flat_map(|contract| &contract.required_directories)
    {
        anyhow::ensure!(
            phase
                .published
                .keys()
                .any(|path| path != directory && path.starts_with(directory)),
            "sealed publication lacks required Cargo bundle contents: {}",
            directory.display()
        );
    }
    Ok(())
}

fn apply_replay(phase: &mut RecoveryPhase, replay: Replay) -> anyhow::Result<()> {
    anyhow::ensure!(
        !phase.complete || replay.sealed,
        "completed publication lost its durable terminal seal"
    );
    if let Some(directory) = &phase.result_dir {
        for relative in replay
            .published
            .keys()
            .chain(replay.pending.iter().map(|intent| &intent.relative))
        {
            validate_result_member(directory, relative)?;
        }
    }
    phase.published = replay.published;
    phase.baseline.clear();
    phase.pending = replay.pending.map(|intent| {
        if let Some(prior) = intent.prior {
            phase.baseline.insert(intent.relative.clone(), prior);
        }
        (intent.relative, intent.hash)
    });
    if replay.sealed {
        validate_sealed_phase(phase)?;
        // The seal can be durable even if the final small lease write failed.
        // It is the same verified publication, not permission to rerun it.
        phase.complete = true;
    }
    Ok(())
}

pub(super) fn decode_recipe_value(
    value: Value,
    ownership: Option<&recovery_owner::RecoveryOwnership>,
) -> anyhow::Result<RecoveryRecipe> {
    decode(value, ownership, false)
}

/// Only FreshStage's explicitly validated override uses the old binding while
/// loading a proposed narrowed selector. Its next step must fork/rebind it.
pub(super) fn decode_recipe_value_for_override(
    value: Value,
    ownership: Option<&recovery_owner::RecoveryOwnership>,
) -> anyhow::Result<RecoveryRecipe> {
    decode(value, ownership, true)
}

fn decode(
    mut value: Value,
    ownership: Option<&recovery_owner::RecoveryOwnership>,
    proposed_override: bool,
) -> anyhow::Result<RecoveryRecipe> {
    if let Some(phases) = value.get_mut("phases").and_then(Value::as_array_mut) {
        for phase in phases {
            if phase
                .get("publication_journal")
                .is_some_and(|value| !value.is_null())
            {
                let phase = phase
                    .as_object_mut()
                    .context("invalid compact publication phase")?;
                anyhow::ensure!(
                    !phase.contains_key("baseline")
                        && !phase.contains_key("published")
                        && !phase.contains_key("pending"),
                    "publication journal contradicts duplicate inline progress evidence"
                );
                phase.insert("baseline".into(), serde_json::json!({}));
                phase.insert("published".into(), serde_json::json!({}));
                phase.insert("pending".into(), Value::Null);
            }
        }
    }
    let mut recipe: RecoveryRecipe = serde_json::from_value(value)?;
    recipe.validate_fresh_job_results_contract()?;
    for index in 0..recipe.phases.len() {
        let Some(mut journal) = recipe.phases[index].publication_journal.clone() else {
            continue;
        };
        let owner =
            ownership.context("publication journal replay requires held recovery ownership")?;
        let binding = if proposed_override {
            journal.binding().to_owned()
        } else {
            recipe.publication_binding(index, true)?
        };
        let replay = journal.replay(owner.publication_directory()?, &binding)?;
        owner.verify()?;
        recipe.phases[index].publication_journal = Some(journal);
        apply_replay(&mut recipe.phases[index], replay)?;
    }
    recipe.validate_result_destination_contract()?;
    Ok(recipe)
}

impl RecoverySession {
    /// Called once under the output lock after stage/policy validation, never
    /// once per file. Legacy unowned fixtures keep their inline storage path;
    /// live wrappers and detached recovery both hold the real journal gate.
    pub(super) fn ensure_publication_journal(&mut self, index: usize) -> anyhow::Result<()> {
        let Some(owner) = self.writer.recovery_ownership.clone() else {
            anyhow::ensure!(
                self.recipe.phases[index].publication_journal.is_none(),
                "publication journal requires exclusive recovery ownership"
            );
            return Ok(());
        };
        let directory = owner.publication_directory()?;
        let binding = self.recipe.publication_binding(index, true)?;
        let mut next = self.recipe.clone();
        if let Some(mut journal) = next.phases[index].publication_journal.clone() {
            let replay = journal.replay(directory, &binding)?;
            let repair = replay.torn_tail;
            if repair {
                journal = journal.fork(directory, &binding)?;
            }
            next.phases[index].publication_journal = Some(journal);
            apply_replay(&mut next.phases[index], replay)?;
            owner.verify()?;
            if repair || next.phases[index].complete {
                // Bind a repaired inode before a single new append. Also
                // adopt a durable seal whose last lease update was interrupted.
                self.persist_next_recipe(next)?;
            } else {
                self.recipe = next;
            }
        } else {
            let phase = &next.phases[index];
            let pending = phase.pending.as_ref().map(|(relative, hash)| Intent {
                relative: relative.clone(),
                hash: hash.clone(),
                prior: phase.baseline.get(relative).cloned(),
            });
            let journal = JournalRef::create(directory, &binding, &phase.published, pending)?;
            next.phases[index].publication_journal = Some(journal);
            owner.verify()?;
            self.persist_next_recipe(next)?;
        }
        owner.verify()
    }

    pub(super) fn append_publication_intent(
        &mut self,
        index: usize,
        pending: Option<(PathBuf, String)>,
    ) -> anyhow::Result<()> {
        let (relative, hash) =
            pending.context("a publication journal intent cannot clear progress")?;
        let phase = &mut self.recipe.phases[index];
        anyhow::ensure!(
            phase.pending.is_none() && !phase.published.contains_key(&relative),
            "publication intent would replace existing output evidence"
        );
        let owner = self
            .writer
            .recovery_ownership
            .as_deref()
            .context("publication append requires exclusive recovery ownership")?;
        phase
            .publication_journal
            .as_mut()
            .context("missing publication journal")?
            .append_pending(
                owner.publication_directory()?,
                &relative,
                &hash,
                phase.baseline.get(&relative).map(String::as_str),
            )?;
        owner.verify()?;
        phase.pending = Some((relative, hash));
        Ok(())
    }

    pub(super) fn append_publication_commit(
        &mut self,
        index: usize,
        relative: PathBuf,
        hash: String,
    ) -> anyhow::Result<()> {
        let phase = &mut self.recipe.phases[index];
        anyhow::ensure!(
            phase
                .pending
                .as_ref()
                .is_some_and(|(path, expected)| path == &relative && expected == &hash),
            "publication commit has no exact pending output"
        );
        let owner = self
            .writer
            .recovery_ownership
            .as_deref()
            .context("publication commit requires exclusive recovery ownership")?;
        phase
            .publication_journal
            .as_mut()
            .context("missing publication journal")?
            .append_published(owner.publication_directory()?, &relative, &hash)?;
        owner.verify()?;
        phase.published.insert(relative.clone(), hash);
        phase.pending = None;
        phase.baseline.remove(&relative);
        Ok(())
    }

    pub(super) fn seal_publication(&mut self, index: usize) -> anyhow::Result<()> {
        validate_sealed_phase(&self.recipe.phases[index])?;
        if let Some(journal) = self.recipe.phases[index].publication_journal.as_mut() {
            let owner = self
                .writer
                .recovery_ownership
                .as_deref()
                .context("publication seal requires exclusive recovery ownership")?;
            if !journal.is_sealed() {
                journal.seal(owner.publication_directory()?)?;
            }
            owner.verify()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod fresh_job_results_tests {
    use super::*;
    use rch_common::job_results::{
        JobResultsPreparationRequest, JobResultsPreparationResponse, JobResultsPreparationResult,
        PreviousResultDirectory, SCHEMA_VERSION, retention_root_for,
    };

    // Frozen authority emitted before fresh-result preparation existed. Keep
    // this wire payload independent of publication_binding's current fields:
    // adding a null optional field would invalidate already-written journals.
    const LEGACY_AUTHORITY: &str = r#"{
        "version": 1,
        "wrapper_id": "fixture-wrapper",
        "build_id": 41,
        "worker": {
            "id": "fixture-worker", "host": "worker.invalid", "user": "builder",
            "identity_file": "/unused/key", "total_slots": 1, "priority": 100, "tags": []
        },
        "identity": "abc123", "phase_index": 0, "name": "result:reports",
        "local": "/caller/project", "remote": "/worker/project", "result_dir": "reports",
        "custom_target": false, "output_gate": false, "patterns": [],
        "cargo_outputs": null, "native_outputs": null, "kind": "job",
        "expected_triple": "x86_64-unknown-linux-gnu", "pinned_triple": null,
        "allow_foreign": false, "package_archive": false,
        "result_destination": null, "caller_json_policy": null
    }"#;

    fn legacy_recipe() -> RecoveryRecipe {
        serde_json::from_str(
            r#"{
                "version": 1, "wrapper_id": "fixture-wrapper", "build_id": 41,
                "worker": {
                    "id": "fixture-worker", "host": "worker.invalid", "user": "builder",
                    "identity_file": "/unused/key", "total_slots": 1, "priority": 100, "tags": []
                },
                "identity": "abc123", "completion": "/worker/completion",
                "source_roots": ["/worker/project"], "pair": null, "retire_root": null,
                "transfer": {}, "project_root": "/caller/project", "kind": "job",
                "expected_triple": "x86_64-unknown-linux-gnu", "pinned_triple": null,
                "allow_foreign": false, "package_archive": false,
                "phases": [{
                    "name": "result:reports", "local": "/caller/project",
                    "remote": "/worker/project", "patterns": [], "result_dir": "reports",
                    "custom_target": false, "output_gate": false,
                    "baseline": {}, "published": {}, "pending": null, "complete": false
                }],
                "exit_code": null, "returned": null
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn ordinary_publication_preserves_the_pre_fresh_results_journal_binding() {
        let recipe = legacy_recipe();
        assert!(recipe.fresh_job_results.is_none());
        let legacy_authority: Value = serde_json::from_str(LEGACY_AUTHORITY).unwrap();
        let legacy_binding = blake3::hash(&serde_json::to_vec(&legacy_authority).unwrap())
            .to_hex()
            .to_string();
        assert_eq!(recipe.publication_binding(0, true).unwrap(), legacy_binding);
    }

    #[test]
    fn fresh_publication_binds_preparation_identity_and_exact_receipt() {
        let mut recipe = legacy_recipe();
        let ordinary = recipe.publication_binding(0, true).unwrap();
        let mut request = JobResultsPreparationRequest {
            schema_version: SCHEMA_VERSION,
            plan_id: "0123456789abcdef0123456789abcdef".into(),
            source_root: "/worker/project".into(),
            retention_root: String::new(),
            result_dirs: vec!["reports".into()],
        };
        request.retention_root =
            retention_root_for(&request.source_root, &request.plan_id).unwrap();
        request.validate().unwrap();
        recipe.fresh_job_results = Some(crate::hook::fresh_job_results::Preparation {
            request: request.clone(),
            receipt: None,
        });
        let pending = recipe.publication_binding(0, true).unwrap();
        assert_ne!(pending, ordinary);

        let receipt = JobResultsPreparationResponse {
            schema_version: SCHEMA_VERSION,
            request: request.clone(),
            results: vec![JobResultsPreparationResult {
                result_dir: "reports".into(),
                previous: PreviousResultDirectory::Absent,
                retained_path: None,
            }],
        };
        receipt.validate_for(&request).unwrap();
        recipe.fresh_job_results.as_mut().unwrap().receipt = Some(receipt);
        let confirmed = recipe.publication_binding(0, true).unwrap();
        assert_ne!(confirmed, pending);
        assert_ne!(confirmed, ordinary);

        request.plan_id = "ffffffffffffffffffffffffffffffff".into();
        request.retention_root =
            retention_root_for(&request.source_root, &request.plan_id).unwrap();
        request.validate().unwrap();
        recipe.fresh_job_results = Some(crate::hook::fresh_job_results::Preparation {
            request,
            receipt: None,
        });
        assert_ne!(recipe.publication_binding(0, true).unwrap(), pending);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_cargo_bundle_replay_requires_published_descendants() {
        let bundle = PathBuf::from("debug/app.dSYM");
        let phase = RecoveryPhase {
            name: "target".into(),
            local: PathBuf::from("/caller/target"),
            remote: "/worker/target".into(),
            patterns: Vec::new(),
            result_dir: None,
            custom_target: true,
            output_gate: true,
            cargo_outputs: Some(CargoOutputContract {
                required_files: [PathBuf::from("debug/app")].into(),
                required_directories: [bundle.clone()].into(),
            }),
            native_outputs: None,
            baseline: BTreeMap::new(),
            published: BTreeMap::new(),
            pending: None,
            publication_journal: None,
            complete: false,
            missing_result: None,
        };
        for extra in [
            None,
            Some(bundle.clone()),
            Some(bundle.join("Contents/symbols")),
        ] {
            let mut replayed = phase.clone();
            let mut published =
                BTreeMap::from([(PathBuf::from("debug/app"), "executable-fingerprint".into())]);
            let complete_bundle = extra.as_ref().is_some_and(|path| path != &bundle);
            if let Some(path) = extra {
                published.insert(path, "bundle-content-fingerprint".into());
            }
            let result = apply_replay(
                &mut replayed,
                Replay {
                    published,
                    pending: None,
                    torn_tail: false,
                    sealed: true,
                },
            );
            assert_eq!(result.is_ok(), complete_bundle);
            assert_eq!(replayed.complete, complete_bundle);
        }
    }
}
