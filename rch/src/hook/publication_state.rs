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
        let phase = self.phases.get(index).context("missing publication phase")?;
        let authority = serde_json::json!({
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
        Ok(blake3::hash(&serde_json::to_vec(&authority)?)
            .to_hex()
            .to_string())
    }

    /// An override retains the previous lease bytes. Fork its logs too so
    /// subsequent publication cannot change that snapshot's historical state.
    pub(super) fn fork_publication_journals(&mut self, writer: &DurableLeaseWriter) -> anyhow::Result<()> {
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
                phase.baseline.retain(|relative, _| pending == Some(relative));
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
        let (relative, hash) = pending.context("a publication journal intent cannot clear progress")?;
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
