//! Explicit relocation of an unfinished collection, not a publication reset.
//!
//! Low space can interrupt a job after it has delivered another phase or
//! journaled a pending rename. Ordinary configuration changes rightly cannot
//! adopt an arbitrary staging tree at that point. This same-wrapper request
//! instead creates a fresh stage and retains the old journal and staging.
//! No output pattern, checkpoint, source grant or completion fact may change.

use super::*;
use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;

#[cfg(test)]
#[path = "recovery_staging_tests.rs"]
mod integration_tests;

pub(super) const REQUEST_ENV: &str = "RCH_RECOVERY_RELOCATE_STAGING";

/// Keep the exact fresh namespace open until the journal has selected it.
/// Dropping this guard only closes descriptors; failed preparations are never
/// removed. This guards the preparation-to-publication handoff, not arbitrary
/// later mutation by processes outside RCH's ownership protocol.
pub(super) struct FreshStage {
    base: File,
    directory: File,
    root: PathBuf,
    identity: std::ffi::CString,
    protected: Vec<PathBuf>,
}

impl FreshStage {
    pub(super) fn hold(
        base: File,
        root: &Path,
        identity: std::ffi::CString,
        protected: Vec<PathBuf>,
    ) -> anyhow::Result<Self> {
        use rustix::fs::{Mode, OFlags};
        let directory = File::from(rustix::fs::openat(
            base.as_fd(),
            identity.as_c_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        let stage = Self {
            base,
            directory,
            root: root.to_owned(),
            identity,
            protected,
        };
        stage.verify()?;
        stage.directory.sync_all()?;
        stage.base.sync_all()?;
        stage.verify()?;
        Ok(stage)
    }

    fn verify_names(&self) -> anyhow::Result<()> {
        use rustix::fs::{Mode, OFlags};
        let base = self.base.metadata()?;
        let named_base = std::fs::symlink_metadata(&self.root)?;
        let directory = self.directory.metadata()?;
        let named_directory = File::from(rustix::fs::openat(
            self.base.as_fd(),
            self.identity.as_c_str(),
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            Mode::empty(),
        )?)
        .metadata()?;
        let uid = rustix::process::geteuid().as_raw();
        anyhow::ensure!(
            base.is_dir()
                && named_base.is_dir()
                && base.dev() == named_base.dev()
                && base.ino() == named_base.ino()
                && base.uid() == uid
                && named_base.uid() == uid
                && base.mode() & 0o022 == 0
                && named_base.mode() & 0o022 == 0
                && directory.is_dir()
                && named_directory.is_dir()
                && directory.dev() == named_directory.dev()
                && directory.ino() == named_directory.ino()
                && directory.uid() == uid
                && named_directory.uid() == uid
                && directory.mode() & 0o077 == 0
                && named_directory.mode() & 0o077 == 0
                && output_lock_root_identity(&self.root)? == self.root,
            "prepared retrieval staging identity or permissions changed; all evidence retained"
        );
        let path = self.root.join(self.identity.to_str()?);
        for protected in &self.protected {
            let protected = output_lock_root_identity(protected)?;
            anyhow::ensure!(
                !path.starts_with(&protected) && !protected.starts_with(&path),
                "prepared retrieval staging overlaps retained evidence or output ownership"
            );
        }
        Ok(())
    }

    fn verify(&self) -> anyhow::Result<()> {
        self.verify_names()?;
        // A fresh tree populated by another actor is not ours to merge, even
        // when it contains only empty directories or ordinary compiler files.
        // Inspect through the held descriptor, not a reopened pathname.
        let mut entries = rustix::fs::Dir::read_from(&self.directory)?;
        entries.rewind();
        while let Some(entry) = entries.read() {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            anyhow::ensure!(
                name == b"." || name == b"..",
                "prepared retrieval staging is no longer empty; retained entries were not changed"
            );
        }
        self.verify_names()
    }

    fn check_space(&self, reserve: u64) -> anyhow::Result<()> {
        self.verify()?;
        // Never reopen a possibly substituted path just to measure another
        // filesystem. Both refinement and storage-only relocation use this.
        let stats = rustix::fs::fstatvfs(self.directory.as_fd())?;
        anyhow::ensure!(
            stats.f_frsize > 0,
            "staging filesystem has no allocation size"
        );
        let available = stats.f_bavail.saturating_mul(stats.f_frsize);
        anyhow::ensure!(
            available >= reserve,
            "insufficient fresh retrieval staging space: available {available}, reserve {reserve}; \
             journal and old staging retained; choose another fresh durable base"
        );
        self.verify()
    }

    pub(super) fn publish(
        &self,
        writer: &DurableLeaseWriter,
        lease: &DurableJobLease,
        next: serde_json::Value,
        reserve: u64,
    ) -> anyhow::Result<PathBuf> {
        let ownership = writer
            .recovery_ownership
            .as_ref()
            .context("fresh staging publication requires exclusive recovery ownership")?;
        anyhow::ensure!(
            next["transfer"]["retrieval_staging_dir"] == serde_json::to_value(&self.root)?,
            "proposed retrieval recipe does not select the prepared staging base"
        );
        self.check_space(reserve)?;
        let previous = retain_previous_journal(ownership, writer, lease)?;
        // Retaining/syncing the audit copy is an I/O boundary, not proof that
        // the prepared stage still exists at its original name afterward.
        self.check_space(reserve)?;
        anyhow::ensure!(
            ownership.read(&writer.wrapper_id())? == *lease,
            "journal changed before fresh staging publication; all evidence retained"
        );
        writer.set_recovery(next).with_context(|| {
            format!(
                "fresh staging publication unverified; prior journal {}",
                previous.display()
            )
        })?;
        // A post-publication error must not be reported as a rollback: leave
        // the journal and both trees for reconciliation, never erase evidence.
        self.verify().context(
            "staging changed during journal publication; recorded location requires reconciliation",
        )?;
        Ok(previous)
    }
}

pub(super) fn requested_wrapper(
    value: Option<&OsStr>,
    has_exclusions: bool,
) -> anyhow::Result<Option<&str>> {
    let Some(value) = value else {
        return Ok(None);
    };
    anyhow::ensure!(
        !has_exclusions,
        "request staging relocation or artifact exclusions separately, not both"
    );
    let wrapper = value
        .to_str()
        .context("staging relocation wrapper is not UTF-8")?;
    anyhow::ensure!(
        !wrapper.is_empty()
            && wrapper.len() <= 128
            && wrapper
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "staging relocation requires the exact original wrapper ID, not a boolean"
    );
    Ok(Some(wrapper))
}

/// This runs only after exclusive claim and original-owner absence. The normal
/// collector subsequently reacquires the original source grant, rechecks the
/// completion, skips completed phases and verifies every unfinished output.
pub(super) fn relocate(
    writer: &DurableLeaseWriter,
    wrapper: &str,
    current: &TransferConfig,
) -> anyhow::Result<()> {
    let ownership = writer
        .recovery_ownership
        .as_ref()
        .context("staging relocation requires exclusive recovery ownership")?;
    ownership.verify()?;
    let lease = writer.snapshot();
    anyhow::ensure!(
        ownership.read(&writer.wrapper_id())? == lease,
        "journal changed before staging relocation; reload its retained evidence"
    );
    let recipe = load_recipe(writer)?;
    anyhow::ensure!(
        wrapper == lease.identity.local_wrapper_id && wrapper == recipe.wrapper_id,
        "staging relocation names a different wrapper; no location changed"
    );
    let root = current.retrieval_staging_dir.as_deref().context(
        "staging relocation requires transfer.retrieval_staging_dir pointing to a fresh durable base"
    )?;
    if recipe.transfer.retrieval_staging_dir.as_deref() == Some(root) {
        // Restart or an identical repeated request, including after completion.
        // Do not create a new stage, reset progress or rewrite the journal.
        return Ok(());
    }
    anyhow::ensure!(
        !lease.terminal_acknowledged
            && recipe.prepared
            && recipe.execution_started
            && recipe.exit_code == Some(0)
            && recipe.returned.is_none()
            && !recipe.preparation_cancelled
            && !recipe.sources_released
            && !recipe.pair_released
            && !recipe.tree_retired
            && !recipe.retired
            && !recipe.source_roots.is_empty(),
        "staging relocation requires successful execution and outstanding delivery/source ownership"
    );
    anyhow::ensure!(
        recipe.phases.iter().any(|phase| !phase.complete)
            && recipe.phases.iter().all(|phase| {
                phase.missing_result.is_none() && (!phase.complete || phase.pending.is_none())
            }),
        "staging relocation cannot reopen completed delivery or reset a failed/contradictory phase"
    );
    let old_base = recipe
        .transfer
        .retrieval_staging_dir
        .clone()
        .unwrap_or_else(|| default_job_lease_directory().join("retrieval"));
    let old_stage = output_lock_root_identity(&old_base.join(&recipe.identity))?;
    let new_stage = output_lock_root_identity(&root.join(&recipe.identity))?;
    anyhow::ensure!(
        !new_stage.starts_with(&old_stage) && !old_stage.starts_with(&new_stage),
        "new retrieval stage overlaps retained staging; no retained tree may be adopted or changed"
    );
    // Validate pending/published path spelling without consulting current
    // destination bytes. A later job may legitimately own a published output;
    // only the existing publisher may resolve a pending ownership checkpoint.
    for phase in &recipe.phases {
        for relative in phase
            .published
            .keys()
            .chain(phase.pending.iter().map(|(relative, _)| relative))
        {
            anyhow::ensure!(
                !relative.as_os_str().is_empty()
                    && relative
                        .components()
                        .all(|part| { matches!(part, std::path::Component::Normal(_)) }),
                "staging relocation has an invalid publication checkpoint"
            );
        }
    }
    // Change ONE field in the original value, preserving even unknown fields
    // and old source-root spellings. load_recipe's normalization is for reads,
    // not permission to rewrite the admitted contract during relocation.
    let mut next = lease
        .recovery
        .clone()
        .context("missing relocation recipe")?;
    next.get_mut("transfer")
        .and_then(serde_json::Value::as_object_mut)
        .context("invalid persisted transfer configuration")?
        .insert("retrieval_staging_dir".into(), serde_json::to_value(root)?);
    let stage = prepare_fresh_stage(writer, &recipe, root)?;
    // Payload sizing still happens through the real, filtered collector after
    // source reacquisition. Check the configured reserve here too so a clearly
    // unusable destination cannot replace the recorded staging location.
    let reserve = current
        .retrieval_min_free_bytes
        .max(recipe.transfer.retrieval_min_free_bytes);
    let previous = stage.publish(writer, &lease, next, reserve)?;
    eprintln!(
        "[RCH] relocated collection for {wrapper} to {}; prior journal {}; \
         old staging {}; publication checkpoints preserved; compilation was not replayed",
        new_stage.display(),
        previous.display(),
        old_stage.display(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::fixture_with_results;
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn next_stage(lease: &DurableJobLease, root: &Path) -> serde_json::Value {
        let mut next = lease.recovery.clone().unwrap();
        next["transfer"]["retrieval_staging_dir"] = serde_json::to_value(root).unwrap();
        next
    }

    #[test]
    fn replaced_prepared_names_never_switch_the_journal_or_touch_either_tree() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        for replacement in [
            "base",
            "directory",
            "symlink",
            "file",
            "base-mode",
            "stage-mode",
        ] {
            let (root, session, _, _) = fixture_with_results(true, &[]);
            let writer = &session.writer;
            let lease = writer.snapshot();
            let base = root.join("fresh-stage");
            let stage_path = base.join(&session.recipe.identity);
            let guard = prepare_fresh_stage(writer, &session.recipe, &base).unwrap();
            let original_inode = guard.directory.metadata().unwrap().ino();
            let retained = root.join("retained-preparation");
            match replacement {
                "base" => {
                    std::fs::rename(&base, &retained).unwrap();
                    std::fs::create_dir_all(&stage_path).unwrap();
                    std::fs::set_permissions(&stage_path, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
                "directory" | "symlink" | "file" => {
                    std::fs::rename(&stage_path, &retained).unwrap();
                    match replacement {
                        "directory" => {
                            std::fs::create_dir(&stage_path).unwrap();
                            std::fs::set_permissions(
                                &stage_path,
                                std::fs::Permissions::from_mode(0o700),
                            )
                            .unwrap();
                        }
                        "symlink" => symlink(&retained, &stage_path).unwrap(),
                        "file" => std::fs::write(&stage_path, b"other owner's evidence").unwrap(),
                        _ => unreachable!(),
                    }
                }
                "base-mode" | "stage-mode" => {
                    let path = if replacement == "base-mode" {
                        &base
                    } else {
                        &stage_path
                    };
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
                }
                _ => unreachable!(),
            }
            let before = std::fs::read(&writer.path).unwrap();
            let journal_entries = std::fs::read_dir(writer.path.parent().unwrap())
                .unwrap()
                .count();
            assert!(
                guard
                    .publish(writer, &lease, next_stage(&lease, &base), 0)
                    .is_err(),
                "{replacement}"
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), before);
            assert_eq!(writer.snapshot(), lease);
            assert_eq!(
                std::fs::read_dir(writer.path.parent().unwrap())
                    .unwrap()
                    .count(),
                journal_entries,
                "refused destination created a journal temporary or backup"
            );
            assert_eq!(guard.directory.metadata().unwrap().ino(), original_inode);
            assert!(std::fs::symlink_metadata(&stage_path).is_ok());
            if replacement == "file" {
                assert_eq!(
                    std::fs::read(&stage_path).unwrap(),
                    b"other owner's evidence"
                );
            }
            if replacement == "symlink" {
                assert_eq!(std::fs::read_link(&stage_path).unwrap(), retained);
            }
            assert!(!writer.snapshot().terminal_acknowledged);
            assert!(acquire_gate(&writer.path).is_err());
        }
    }

    #[test]
    fn populated_preparation_is_retained_not_merged_as_fresh_staging() {
        for entry in ["file", "directory", "symlink"] {
            let (root, session, _, _) = fixture_with_results(true, &[]);
            let writer = &session.writer;
            let lease = writer.snapshot();
            let base = root.join("fresh-stage");
            let guard = prepare_fresh_stage(writer, &session.recipe, &base).unwrap();
            let name = base.join(&session.recipe.identity).join("unowned");
            match entry {
                "file" => std::fs::write(&name, b"retain unrelated bytes").unwrap(),
                "directory" => std::fs::create_dir(&name).unwrap(),
                "symlink" => std::os::unix::fs::symlink(&writer.path, &name).unwrap(),
                _ => unreachable!(),
            }
            let before = std::fs::read(&writer.path).unwrap();
            let inode = std::fs::symlink_metadata(&name).unwrap().ino();
            assert!(
                guard
                    .publish(writer, &lease, next_stage(&lease, &base), 0)
                    .is_err()
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), before);
            assert_eq!(writer.snapshot(), lease);
            assert_eq!(std::fs::symlink_metadata(&name).unwrap().ino(), inode);
            if entry == "file" {
                assert_eq!(std::fs::read(&name).unwrap(), b"retain unrelated bytes");
            }
        }
    }

    #[test]
    fn prepared_stage_rechecks_output_aliases_before_journal_publication() {
        let (root, mut session, _, _) = fixture_with_results(true, &[]);
        let alias = root.join("output-alias");
        std::os::unix::fs::symlink(&session.recipe.project_root, &alias).unwrap();
        session.recipe.phases[0].local = alias.clone();
        session.persist().unwrap();
        let writer = &session.writer;
        let lease = writer.snapshot();
        let base = root.join("fresh-stage");
        let guard = prepare_fresh_stage(writer, &session.recipe, &base).unwrap();
        // Keep the original alias as evidence; a new output alias would now
        // point publication into the staging tree. The handoff must refuse.
        let original_alias = root.join("original-output-alias");
        std::fs::rename(&alias, &original_alias).unwrap();
        std::os::unix::fs::symlink(base.join(&session.recipe.identity), &alias).unwrap();
        let before = std::fs::read(&writer.path).unwrap();
        assert!(
            guard
                .publish(writer, &lease, next_stage(&lease, &base), 0)
                .is_err()
        );
        assert_eq!(std::fs::read(&writer.path).unwrap(), before);
        assert_eq!(writer.snapshot(), lease);
        assert_eq!(
            std::fs::read_link(original_alias).unwrap(),
            session.recipe.project_root
        );
        assert!(
            std::fs::symlink_metadata(alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn fresh_stage_budget_and_recipe_binding_precede_any_journal_write() {
        let (root, session, _, _) = fixture_with_results(true, &[]);
        let writer = &session.writer;
        let lease = writer.snapshot();
        let base = root.join("fresh-stage");
        let guard = prepare_fresh_stage(writer, &session.recipe, &base).unwrap();
        let before = std::fs::read(&writer.path).unwrap();
        let count = std::fs::read_dir(writer.path.parent().unwrap())
            .unwrap()
            .count();
        assert!(
            guard
                .publish(writer, &lease, next_stage(&lease, &base), u64::MAX)
                .is_err()
        );
        assert!(
            guard
                .publish(
                    writer,
                    &lease,
                    next_stage(&lease, &root.join("not-prepared")),
                    0
                )
                .is_err()
        );
        assert_eq!(std::fs::read(&writer.path).unwrap(), before);
        assert_eq!(writer.snapshot(), lease);
        assert_eq!(
            std::fs::read_dir(writer.path.parent().unwrap())
                .unwrap()
                .count(),
            count
        );
        // The exact same, still-empty preparation remains usable after a
        // transient refusal. No need to delete or regenerate any output.
        let backup = guard
            .publish(writer, &lease, next_stage(&lease, &base), 0)
            .unwrap();
        assert_eq!(std::fs::read(backup).unwrap(), before);
        assert_eq!(
            writer.snapshot().recovery.unwrap(),
            next_stage(&lease, &base)
        );
        assert!(guard.verify().is_ok());
        assert!(!writer.snapshot().terminal_acknowledged);
    }

    #[test]
    fn relocation_request_is_explicit_literal_and_not_combined_with_exclusions() {
        assert!(requested_wrapper(None, true).unwrap().is_none());
        assert_eq!(
            requested_wrapper(Some(OsStr::new("rchw-example_1")), false).unwrap(),
            Some("rchw-example_1")
        );
        for invalid in ["", "../job", "job/name", "job\n", "job name", "job:1"] {
            assert!(requested_wrapper(Some(OsStr::new(invalid)), false).is_err());
        }
        assert!(requested_wrapper(Some(OsStr::new(&"x".repeat(129))), false).is_err());
        let invalid = std::ffi::OsString::from_vec(vec![0xff]);
        assert!(requested_wrapper(Some(&invalid), false).is_err());
        assert!(requested_wrapper(Some(OsStr::new("rchw-example")), true).is_err());
    }

    #[test]
    fn relocation_changes_only_the_stage_and_preserves_partial_and_completed_phases() {
        let (root, mut session, _, _) = fixture_with_results(true, &["reports".into()]);
        session.recipe.phases[0].pending = Some(("build/pending.o".into(), "pending-hash".into()));
        session.recipe.phases[0]
            .published
            .insert("build/done.o".into(), "done-hash".into());
        session.recipe.phases[1].complete = true;
        session.persist().unwrap();
        session
            .writer
            .record_exit(EXIT_ARTIFACT_TRANSFER_FAILED)
            .unwrap();
        let old = session.stage(0).join("retained-output");
        std::fs::write(&old, b"retained bytes").unwrap();
        let old_inode = std::fs::metadata(&old).unwrap().ino();
        let before = std::fs::read(&session.writer.path).unwrap();
        let current = TransferConfig {
            retrieval_staging_dir: Some(root.join("fresh-stage")),
            ..Default::default()
        };
        let wrapper = session.writer.wrapper_id();
        let mut expected = session.writer.snapshot();
        expected.recovery.as_mut().unwrap()["transfer"]["retrieval_staging_dir"] =
            serde_json::to_value(&current.retrieval_staging_dir).unwrap();
        relocate(&session.writer, &wrapper, &current).unwrap();
        // set_recovery may update journal heartbeat fields; the complete
        // recovery value and all immutable admitted identity remain exact.
        let actual = session.writer.snapshot();
        assert_eq!(actual.recovery, expected.recovery);
        assert_eq!(actual.identity, expected.identity);
        assert_eq!(actual.exit_code, expected.exit_code);
        assert!(!actual.terminal_acknowledged);
        assert_eq!(std::fs::read(&old).unwrap(), b"retained bytes");
        assert_eq!(std::fs::metadata(&old).unwrap().ino(), old_inode);
        let backups: Vec<_> = std::fs::read_dir(session.writer.path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "before")
            })
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(std::fs::read(&backups[0]).unwrap(), before);
        assert!(acquire_gate(&session.writer.path).is_err());
        let committed = std::fs::read(&session.writer.path).unwrap();
        relocate(&session.writer, &wrapper, &current).unwrap();
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), committed);
        let mut recovered = RecoverySession {
            recipe: load_recipe(&session.writer).unwrap(),
            writer: session.writer.clone(),
        };
        recovered.apply_retrieval_config(&current).unwrap();
        assert!(recovered.recipe.phases[0].pending.is_some());
        assert_eq!(recovered.recipe.phases[0].published.len(), 1);
        assert!(recovered.recipe.phases[1].complete);
        assert!(recovered.writer.acknowledge_terminal().is_err());
    }

    #[test]
    fn relocation_refuses_foreign_unsettled_or_released_execution_without_mutation() {
        for boundary in [
            "foreign",
            "unprepared",
            "unstarted",
            "unknown",
            "failed",
            "cancelled",
            "returned",
            "source",
            "pair",
            "tree",
            "retired",
            "no-grant",
            "complete",
            "contradictory",
            "unsafe-checkpoint",
        ] {
            let (root, mut session, _, _) = fixture_with_results(true, &["reports".into()]);
            let mut wrapper = session.writer.wrapper_id();
            match boundary {
                "foreign" => wrapper = "rchw-other".into(),
                "unprepared" => session.recipe.prepared = false,
                "unstarted" => session.recipe.execution_started = false,
                "unknown" => session.recipe.exit_code = None,
                "failed" => session.recipe.exit_code = Some(7),
                "cancelled" => session.recipe.preparation_cancelled = true,
                "returned" => session.recipe.returned = Some(102),
                "source" => session.recipe.sources_released = true,
                "pair" => session.recipe.pair_released = true,
                "tree" => session.recipe.tree_retired = true,
                "retired" => session.recipe.retired = true,
                "no-grant" => session.recipe.source_roots.clear(),
                "complete" => session
                    .recipe
                    .phases
                    .iter_mut()
                    .for_each(|phase| phase.complete = true),
                "contradictory" => {
                    session.recipe.phases[1].complete = true;
                    session.recipe.phases[1].pending =
                        Some(("reports/result".into(), "hash".into()));
                }
                "unsafe-checkpoint" => {
                    session.recipe.phases[0].pending = Some(("../foreign".into(), "hash".into()));
                }
                _ => unreachable!(),
            }
            session.persist().unwrap();
            let before = std::fs::read(&session.writer.path).unwrap();
            let current = TransferConfig {
                retrieval_staging_dir: Some(root.join("fresh-stage")),
                ..Default::default()
            };
            assert!(
                relocate(&session.writer, &wrapper, &current).is_err(),
                "{boundary}"
            );
            assert_eq!(
                std::fs::read(&session.writer.path).unwrap(),
                before,
                "{boundary}"
            );
            assert!(!root.join("fresh-stage").exists(), "{boundary}");
            assert!(!session.writer.snapshot().terminal_acknowledged);
        }
    }

    #[test]
    fn unsafe_or_full_staging_never_replaces_the_recorded_location() {
        for destination in [
            "occupied", "alias", "caller", "journal", "nested", "relative", "full",
        ] {
            let (root, session, _, _) = fixture_with_results(true, &[]);
            let old = session.stage(0).join("evidence");
            std::fs::write(&old, b"retain this output").unwrap();
            let fresh = root.join("fresh-stage");
            let selected = match destination {
                "occupied" => {
                    std::fs::create_dir_all(fresh.join(&session.recipe.identity)).unwrap();
                    fresh.clone()
                }
                "alias" => {
                    std::os::unix::fs::symlink(root.join("old-stage"), &fresh).unwrap();
                    fresh.clone()
                }
                "caller" => session.recipe.project_root.clone(),
                "journal" => session.writer.path.parent().unwrap().to_owned(),
                "nested" => session.stage(0).join("new-base"),
                "relative" => "relative-base".into(),
                "full" => fresh.clone(),
                _ => unreachable!(),
            };
            let current = TransferConfig {
                retrieval_staging_dir: Some(selected),
                retrieval_min_free_bytes: if destination == "full" { u64::MAX } else { 0 },
                ..Default::default()
            };
            let before = std::fs::read(&session.writer.path).unwrap();
            let snapshot = session.writer.snapshot();
            assert!(
                relocate(&session.writer, &session.writer.wrapper_id(), &current).is_err(),
                "{destination}"
            );
            assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
            assert_eq!(session.writer.snapshot(), snapshot);
            assert_eq!(std::fs::read(&old).unwrap(), b"retain this output");
            assert!(!session.writer.snapshot().terminal_acknowledged);
        }
    }
}
