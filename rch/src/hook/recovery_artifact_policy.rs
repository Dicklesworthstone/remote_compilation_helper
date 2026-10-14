//! Explicit, same-wrapper refinement of implicit Make artifact selection.
//!
//! A successful gate can leave synthetic tool trees beneath `build/`. They
//! are not necessarily deliverable outputs, but their names are project policy,
//! not an RCH-wide exclusion heuristic. The operator must name the directories
//! and original wrapper. This never turns symlinks into publishable files.

use super::*;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::os::fd::AsFd;

#[path = "recovery_staging.rs"]
mod staging;

const REQUEST_ENV: &str = "RCH_RECOVERY_ARTIFACT_EXCLUSIONS";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_DIRECTORIES: usize = 64;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    wrapper_id: String,
    directories: Vec<String>,
}

impl Request {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            raw.len() <= MAX_REQUEST_BYTES,
            "artifact exclusion request is too large"
        );
        let request: Self = serde_json::from_str(raw)
            .context("artifact exclusions require a wrapper_id and directories JSON object")?;
        anyhow::ensure!(
            !request.wrapper_id.is_empty()
                && request.wrapper_id.len() <= 128
                && request
                    .wrapper_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "invalid artifact exclusion wrapper identity"
        );
        anyhow::ensure!(
            !request.directories.is_empty() && request.directories.len() <= MAX_DIRECTORIES,
            "artifact exclusions require between 1 and {MAX_DIRECTORIES} directories"
        );
        let mut seen = BTreeSet::new();
        for directory in &request.directories {
            // Reject wildcard/escape syntax rather than letting rsync and glob
            // disagree about a literal directory. Spaces and Unicode are fine.
            anyhow::ensure!(
                directory.len() <= 4096
                    && !directory.contains(['\\', '*', '?', '[', ']', ':'])
                    && !directory.chars().any(char::is_control)
                    && directory
                        .split('/')
                        .all(|part| !matches!(part, "" | "." | "..")),
                "artifact exclusion must be a literal root-relative directory: {directory:?}"
            );
            anyhow::ensure!(
                seen.insert(directory),
                "duplicate artifact exclusion directory"
            );
        }
        Ok(request)
    }
}

/// Called only AFTER claim has verified owner absence and reloaded the journal.
/// With neither explicit request, every existing recovery path is unchanged.
pub(super) fn apply_from_environment(writer: &DurableLeaseWriter) -> anyhow::Result<()> {
    let relocation = std::env::var_os(staging::REQUEST_ENV);
    if let Some(wrapper) = staging::requested_wrapper(
        relocation.as_deref(),
        std::env::var_os(REQUEST_ENV).is_some(),
    )? {
        let config = crate::config::load_config()?;
        return staging::relocate(writer, wrapper, &config.transfer);
    }
    let raw = match std::env::var(REQUEST_ENV) {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return Ok(()),
        Err(error) => return Err(error).context("artifact exclusion request is not UTF-8"),
    };
    let request = Request::parse(&raw).with_context(|| format!("invalid {REQUEST_ENV}"))?;
    let config = crate::config::load_config()?;
    apply(writer, &request, &config.transfer)
}

fn plan(
    lease: &DurableJobLease,
    recipe: &RecoveryRecipe,
    request: &Request,
) -> anyhow::Result<Option<RecoveryRecipe>> {
    anyhow::ensure!(
        request.wrapper_id == lease.identity.local_wrapper_id
            && request.wrapper_id == recipe.wrapper_id,
        "artifact exclusion request names a different wrapper; no policy changed"
    );
    let projects: Vec<_> = recipe
        .phases
        .iter()
        .enumerate()
        .filter(|(_, phase)| {
            phase.name == "project"
                && phase.local == recipe.project_root
                && phase.result_dir.is_none()
                && !phase.custom_target
        })
        .map(|(index, _)| index)
        .collect();
    anyhow::ensure!(
        projects.len() == 1,
        "artifact exclusions require one implicit Make project phase"
    );
    if request.directories.iter().all(|directory| {
        recipe.phases[projects[0]]
            .patterns
            .contains(&format!("- /{directory}/"))
    }) {
        // Repeating an already persisted request must also resume partially
        // published or terminal jobs. This is not permission to change them.
        return Ok(None);
    }
    anyhow::ensure!(
        !lease.terminal_acknowledged
            && recipe.execution_started
            && recipe.exit_code == Some(0)
            && recipe.returned.is_none()
            && !recipe.preparation_cancelled
            && !recipe.sources_released
            && !recipe.pair_released
            && !recipe.tree_retired
            && !recipe.retired,
        "artifact exclusions require successful execution with delivery and source ownership still outstanding"
    );
    anyhow::ensure!(
        recipe.kind == Some(CompilationKind::Make)
            && !recipe.package_archive
            && recipe.cargo_output_capture.is_none()
            && recipe.caller_json_policy.is_none()
            && recipe.phases.iter().all(|phase| {
                phase.native_outputs.is_none()
                    && phase.cargo_outputs.is_none()
                    && !phase
                        .patterns
                        .iter()
                        .any(|pattern| pattern.starts_with("+ "))
            }),
        "artifact exclusions cannot refine an explicit, priority, Cargo or non-Make output contract"
    );
    let project = &recipe.phases[projects[0]];
    anyhow::ensure!(
        !project.complete,
        "a completed project artifact policy cannot be changed; all evidence retained"
    );
    anyhow::ensure!(
        recipe.phases.iter().all(|phase| {
            phase.missing_result.is_none() && (!phase.complete || phase.pending.is_none())
        }),
        "artifact policy cannot change a failed result or contradictory publication checkpoint"
    );
    for directory in &request.directories {
        let directory = Path::new(directory);
        // Live collection can deliver a declared report even when its project
        // pull fails. A detached publisher can also stop after committing some
        // files. Those checkpoints are evidence to KEEP, not a reason to erase
        // progress or replay Make. Only a disjoint, unfinished selection may
        // be refined. Never exclude a path already written or being renamed.
        for relative in project
            .published
            .keys()
            .chain(project.pending.iter().map(|(relative, _)| relative))
        {
            validate_output_ancestors(&project.local, relative)?;
            anyhow::ensure!(
                !directory.starts_with(relative) && !relative.starts_with(directory),
                "artifact exclusion overlaps a pending or published output: {}",
                relative.display()
            );
        }
        for result in recipe
            .phases
            .iter()
            .filter_map(|phase| phase.result_dir.as_deref())
        {
            anyhow::ensure!(
                !directory.starts_with(result) && !result.starts_with(directory),
                "artifact exclusion overlaps a declared result directory: {}",
                result.display()
            );
        }
    }
    // Clone every phase unchanged. In particular, never clear a pending hash,
    // reset a completed report or replace a published file's fingerprint when
    // selecting a fresh stage. Recovery resumes its existing publication state.
    let mut next = recipe.clone();
    let patterns = &mut next.phases[projects[0]].patterns;
    let mut changed = false;
    for directory in &request.directories {
        // Anchoring avoids excluding a same-named directory in another tree.
        // A directory-only rule also excludes its descendants in both rsync
        // and ArtifactFilters, without excluding a regular file of this name.
        let rule = format!("- /{directory}/");
        if !patterns.contains(&rule) {
            patterns.insert(0, rule);
            changed = true;
        }
    }
    Ok(changed.then_some(next))
}

/// Retain the exact previous journal through the already-held directory. This
/// is evidence, not a second writer or a replacement recovery journal.
fn retain_previous_journal(
    ownership: &RecoveryOwnership,
    writer: &DurableLeaseWriter,
    expected: &DurableJobLease,
) -> anyhow::Result<PathBuf> {
    use rustix::fs::{Mode, OFlags};
    ownership.verify()?;
    let bytes = crate::state::primitives::read_regular_file_at(
        ownership.directory.as_fd(),
        &ownership.journal_name,
    )?;
    anyhow::ensure!(
        DurableLeaseWriter::decode_journal(&bytes, &writer.wrapper_id())? == *expected,
        "journal changed before artifact policy refinement; retry its latest evidence"
    );
    let name = std::ffi::CString::new(format!(
        "artifact-policy-{}.before",
        uuid::Uuid::new_v4().simple()
    ))?;
    let mut file = File::from(rustix::fs::openat(
        ownership.directory.as_fd(),
        name.as_c_str(),
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )?);
    file.write_all(&bytes)?;
    file.sync_all()?;
    ownership.require_named_file(&file, &name)?;
    crate::state::primitives::verify_atomic_write_bytes(&file, &bytes)?;
    ownership.directory.sync_all()?;
    ownership.verify()?;
    ownership.require_named_file(&file, &name)?;
    crate::state::primitives::verify_atomic_write_bytes(&file, &bytes)?;
    Ok(ownership.parent.join(name.to_str()?))
}

fn prepare_fresh_stage(
    writer: &DurableLeaseWriter,
    recipe: &RecoveryRecipe,
    root: &Path,
) -> anyhow::Result<staging::FreshStage> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::DirBuilderExt;
    anyhow::ensure!(
        root.is_absolute(),
        "fresh retrieval staging base must be absolute"
    );
    anyhow::ensure!(
        !root.as_os_str().as_encoded_bytes().contains(&0)
            && !root.to_string_lossy().chars().any(char::is_control)
            && output_lock_root_identity(root)? == root,
        "fresh retrieval staging base must use its canonical absolute spelling"
    );
    anyhow::ensure!(
        !recipe.identity.is_empty()
            && recipe.identity.len() <= 128
            && recipe
                .identity
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "invalid retained staging identity"
    );
    let stage = root.join(&recipe.identity);
    // A stage must not become part of the caller's output set, or contain the
    // journal that owns it or enter an old retained stage. Keep original names
    // so the held preparation can recheck aliases before journal publication.
    let old_stage = recipe
        .transfer
        .retrieval_staging_dir
        .clone()
        .unwrap_or_else(|| default_job_lease_directory().join("retrieval"))
        .join(&recipe.identity);
    let protected: Vec<_> = recipe
        .phases
        .iter()
        .map(|phase| phase.local.as_path())
        .chain(writer.path.parent())
        .chain(std::iter::once(old_stage.as_path()))
        .map(Path::to_owned)
        .collect();
    for protected in &protected {
        let protected = output_lock_root_identity(protected)?;
        anyhow::ensure!(
            !stage.starts_with(&protected) && !protected.starts_with(&stage),
            "fresh retrieval stage overlaps a publication, journal or retained staging directory"
        );
    }
    // Do not reuse even an empty pre-existing identity tree: it can contain
    // an earlier collector's excluded symlinks or an unverified partial copy.
    match std::fs::symlink_metadata(&stage) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
        Ok(_) => anyhow::bail!(
            "retrieval stage already exists: {}; choose a fresh staging base; retained data was not changed",
            stage.display()
        ),
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)?;
    let directory = File::from(rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?);
    let held = directory.metadata()?;
    anyhow::ensure!(
        held.uid() == rustix::process::geteuid().as_raw() && held.mode() & 0o022 == 0,
        "fresh staging base must be owned by this user and not writable by group or others"
    );
    let identity = std::ffi::CString::new(recipe.identity.as_str())?;
    rustix::fs::mkdirat(
        directory.as_fd(),
        identity.as_c_str(),
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    )
    .context("create exclusive fresh recovery stage; prior trees are never adopted")?;
    staging::FreshStage::hold(directory, root, identity, protected)
}

fn apply(
    writer: &DurableLeaseWriter,
    request: &Request,
    current: &TransferConfig,
) -> anyhow::Result<()> {
    let ownership = writer
        .recovery_ownership
        .as_ref()
        .context("artifact policy refinement requires exclusive recovery ownership")?;
    ownership.verify()?;
    let lease = writer.snapshot();
    let recipe = load_recipe(writer)?;
    let Some(mut next) = plan(&lease, &recipe, request)? else {
        // Exact same request on a later collection retry is read-only.
        return Ok(());
    };
    let root = current.retrieval_staging_dir.as_deref().context(
        "artifact policy refinement requires transfer.retrieval_staging_dir pointing to a fresh base; existing staging is retained"
    )?;
    let stage = prepare_fresh_stage(writer, &recipe, root)?;
    // Store the SAME configured root used by the ordinary recovery config
    // merge, so that merge cannot redirect collection back into the old tree.
    next.transfer.retrieval_staging_dir = Some(root.to_owned());
    let reserve = current
        .retrieval_min_free_bytes
        .max(recipe.transfer.retrieval_min_free_bytes);
    let previous = stage.publish(writer, &lease, serde_json::to_value(next)?, reserve)?;
    eprintln!(
        "[RCH] refined implicit Make artifact selection for {}: excluded directories {:?}; prior journal {}; prior staging retained; compilation was not replayed",
        request.wrapper_id,
        request.directories,
        previous.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(completed: bool) -> (PathBuf, RecoverySession, TransferPipeline, WorkerConfig) {
        fixture_with_results(completed, &[])
    }

    pub(super) fn fixture_with_results(
        completed: bool,
        result_dirs: &[PathBuf],
    ) -> (PathBuf, RecoverySession, TransferPipeline, WorkerConfig) {
        let root = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap()
            .keep();
        let root = root.canonicalize().unwrap();
        let project = root.join("caller");
        let remote = root.join("worker");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&remote).unwrap();
        let writer =
            DurableLeaseWriter::create_in(&root.join("journals"), "make test-gates", true, false)
                .unwrap();
        let worker = WorkerConfig {
            id: WorkerId::new("make-policy-fixture"),
            host: "unreachable.invalid".into(),
            user: "worker".into(),
            identity_file: "/unused/test-key".into(),
            total_slots: 1,
            priority: 100,
            tags: Vec::new(),
            tools: Vec::new(),
        };
        writer.admit(41, &worker.id).unwrap();
        let identity = uuid::Uuid::new_v4().simple().to_string();
        let transfer = TransferConfig {
            retrieval_staging_dir: Some(root.join("old-stage")),
            ..Default::default()
        };
        let pipeline = TransferPipeline::new(
            project.clone(),
            "make-policy".into(),
            identity.clone(),
            transfer.clone(),
        )
        .with_remote_path_override(remote.to_str().unwrap());
        let source_roots = vec![remote.to_str().unwrap().to_owned()];
        RecoverySession::begin(
            &writer,
            &worker,
            source_roots.clone(),
            None,
            None,
            None,
            transfer.clone(),
            project.clone(),
            identity.clone(),
        )
        .unwrap();
        let mut session = RecoverySession::prepare(
            &writer,
            &worker,
            &pipeline,
            source_roots,
            None,
            None,
            None,
            transfer,
            project,
            None,
            Some(CompilationKind::Make),
            "make test-gates",
            result_dirs,
            identity,
        )
        .unwrap();
        session.starting_execution().unwrap();
        if completed {
            // Unit input, not an assertion that a remote worker ran. The
            // integration fixture instead records its actual Make outcome.
            session.completed(0).unwrap();
        }
        session.staging_pipeline("project", &pipeline).unwrap();
        (root, session, pipeline, worker)
    }

    fn request(session: &RecoverySession, directories: &[&str]) -> Request {
        Request::parse(
            &serde_json::json!({
                "wrapper_id": session.recipe.wrapper_id,
                "directories": directories,
            })
            .to_string(),
        )
        .unwrap()
    }

    #[test]
    fn exclusion_request_is_literal_bounded_and_identity_scoped() {
        for directory in ["build/tool fixtures", "build/工具", "build/-tools"] {
            let raw = serde_json::json!({
                "wrapper_id": "rchw-fixture", "directories": [directory],
            })
            .to_string();
            assert_eq!(Request::parse(&raw).unwrap().directories, [directory]);
        }
        for directory in [
            "",
            "/build/tools",
            ".",
            "..",
            "build/../tools",
            "build//tools",
            "build/tools/",
            "build/*",
            "build/?",
            "build/[x]",
            "build/\\x",
            "build/a:b",
            "build/\ntools",
        ] {
            let raw = serde_json::json!({
                "wrapper_id": "rchw-fixture", "directories": [directory],
            })
            .to_string();
            assert!(Request::parse(&raw).is_err(), "{directory:?}");
        }
        for raw in [
            r#"{"wrapper_id":"rchw-fixture","directories":[]}"#,
            r#"{"wrapper_id":"rchw-fixture","directories":["build/a","build/a"]}"#,
            r#"{"wrapper_id":"rchw-fixture","directories":["build/a"],"force":true}"#,
            r#"{"wrapper_id":"rchw-fixture","wrapper_id":"rchw-other","directories":["build/a"]}"#,
        ] {
            assert!(Request::parse(raw).is_err(), "{raw}");
        }
        assert!(Request::parse(&" ".repeat(MAX_REQUEST_BYTES + 1)).is_err());
    }

    #[test]
    fn refinement_preserves_identity_outputs_prior_journal_and_old_stage_across_retry() {
        let (root, session, _pipeline, _worker) = fixture(true);
        let writer = &session.writer;
        let old_stage = session.stage(0);
        std::fs::write(old_stage.join("retained-output"), b"original bytes").unwrap();
        let before = std::fs::read(&writer.path).unwrap();
        let input = request(&session, &["build/test-gates/path-without-cosign"]);
        let current = TransferConfig {
            retrieval_staging_dir: Some(root.join("fresh-stage")),
            ..Default::default()
        };
        apply(writer, &input, &current).unwrap();
        let next = load_recipe(writer).unwrap();
        let mut expected = serde_json::to_value(&session.recipe).unwrap();
        expected["transfer"]["retrieval_staging_dir"] =
            serde_json::to_value(&current.retrieval_staging_dir).unwrap();
        expected["phases"][0]["patterns"]
            .as_array_mut()
            .unwrap()
            .insert(0, "- /build/test-gates/path-without-cosign/".into());
        assert_eq!(serde_json::to_value(next).unwrap(), expected);
        assert_eq!(
            std::fs::read(old_stage.join("retained-output")).unwrap(),
            b"original bytes"
        );
        let backups: Vec<_> = std::fs::read_dir(writer.path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "before")
            })
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(std::fs::read(&backups[0]).unwrap(), before);
        assert!(!writer.snapshot().terminal_acknowledged);
        assert!(
            acquire_gate(&writer.path).is_err(),
            "refinement released the journal owner"
        );
        let committed = std::fs::read(&writer.path).unwrap();
        apply(writer, &input, &TransferConfig::default()).unwrap();
        assert_eq!(
            std::fs::read(&writer.path).unwrap(),
            committed,
            "repeat request must not rewrite evidence"
        );
        let disk = DurableLeaseWriter::read_journal(&writer.path, &writer.wrapper_id()).unwrap();
        assert_eq!(disk.recovery.unwrap(), expected);
        assert!(!disk.terminal_acknowledged);
        let mut next = load_recipe(writer).unwrap();
        next.phases[0].pending = Some((PathBuf::from("build/app"), "hash".into()));
        assert!(plan(&writer.snapshot(), &next, &input).unwrap().is_none());
        next.phases[0].complete = true;
        next.returned = Some(0);
        next.retired = true;
        let mut terminal = writer.snapshot();
        terminal.terminal_acknowledged = true;
        assert!(plan(&terminal, &next, &input).unwrap().is_none());
    }

    #[test]
    fn refinement_refuses_existing_or_overlapping_stages_without_touching_evidence() {
        for location in [
            "old", "occupied", "caller", "journal", "relative", "alias", "writable",
        ] {
            let (root, session, _pipeline, _worker) = fixture(true);
            let proposed = match location {
                "old" => root.join("old-stage"),
                "occupied" => {
                    let base = root.join("occupied");
                    std::fs::create_dir_all(base.join(&session.recipe.identity)).unwrap();
                    base
                }
                "caller" => session.recipe.project_root.clone(),
                "journal" => session.writer.path.parent().unwrap().to_owned(),
                "relative" => PathBuf::from("relative"),
                "alias" => {
                    let alias = root.join("alias");
                    std::os::unix::fs::symlink(root.join("old-stage"), &alias).unwrap();
                    alias
                }
                "writable" => {
                    use std::os::unix::fs::PermissionsExt;
                    let base = root.join("world-writable");
                    std::fs::create_dir(&base).unwrap();
                    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777))
                        .unwrap();
                    base
                }
                _ => unreachable!(),
            };
            let before = std::fs::read(&session.writer.path).unwrap();
            let old = session.stage(0).join("retained");
            std::fs::write(&old, b"retained").unwrap();
            let current = TransferConfig {
                retrieval_staging_dir: Some(proposed),
                ..Default::default()
            };
            assert!(
                apply(
                    &session.writer,
                    &request(&session, &["build/tools"]),
                    &current
                )
                .is_err(),
                "{location}"
            );
            assert_eq!(
                std::fs::read(&session.writer.path).unwrap(),
                before,
                "{location}"
            );
            assert_eq!(std::fs::read(old).unwrap(), b"retained");
            assert!(!session.writer.snapshot().terminal_acknowledged);
        }
    }

    #[test]
    fn refinement_honors_current_and_persisted_reserves_before_changing_policy() {
        for persisted in [false, true] {
            let (root, mut session, _, _) = fixture(true);
            if persisted {
                session.recipe.transfer.retrieval_min_free_bytes = u64::MAX;
                session.persist().unwrap();
            }
            let old = session.stage(0).join("retained-result");
            std::fs::write(&old, b"completed worker result").unwrap();
            let before = std::fs::read(&session.writer.path).unwrap();
            let lease = session.writer.snapshot();
            let current = TransferConfig {
                retrieval_staging_dir: Some(root.join("fresh-stage")),
                retrieval_min_free_bytes: if persisted { 0 } else { u64::MAX },
                ..Default::default()
            };
            let error = apply(
                &session.writer,
                &request(&session, &["build/tools"]),
                &current,
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("insufficient fresh retrieval staging space"));
            assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
            assert_eq!(session.writer.snapshot(), lease);
            assert_eq!(std::fs::read(old).unwrap(), b"completed worker result");
            assert!(!session.writer.snapshot().terminal_acknowledged);
        }
    }

    #[test]
    fn refinement_cannot_create_its_fresh_stage_inside_retained_staging() {
        let (root, session, _, _) = fixture(true);
        let old = session.stage(0).join(".rch-clean-overlay-base.tar");
        std::fs::write(&old, b"retained source input").unwrap();
        let current = TransferConfig {
            retrieval_staging_dir: Some(session.stage(0).join("nested-stage")),
            ..Default::default()
        };
        let before = std::fs::read(&session.writer.path).unwrap();
        assert!(
            apply(
                &session.writer,
                &request(&session, &["build/tools"]),
                &current
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
        assert_eq!(std::fs::read(old).unwrap(), b"retained source input");
        assert!(!session.stage(0).join("nested-stage").exists());
        assert!(!root.join("fresh-stage").exists());
    }

    #[test]
    fn refinement_cannot_erase_publication_or_declared_output_contracts() {
        for boundary in [
            "pending",
            "published",
            "complete",
            "returned",
            "released",
            "retired",
            "failed",
            "not-started",
            "other-wrapper",
            "cargo",
            "priority",
            "declared-result",
            "terminal",
        ] {
            let (_root, session, _pipeline, _worker) = fixture(true);
            let mut lease = session.writer.snapshot();
            let mut recipe = session.recipe.clone();
            let mut input = request(&session, &["build/tools"]);
            match boundary {
                "pending" => {
                    recipe.phases[0].pending =
                        Some((PathBuf::from("build/tools/app"), "hash".into()));
                }
                "published" => {
                    recipe.phases[0]
                        .published
                        .insert(PathBuf::from("build/tools/app"), "hash".into());
                }
                "complete" => recipe.phases[0].complete = true,
                "returned" => recipe.returned = Some(102),
                "released" => recipe.sources_released = true,
                "retired" => recipe.retired = true,
                "failed" => recipe.exit_code = Some(7),
                "not-started" => recipe.execution_started = false,
                "other-wrapper" => input.wrapper_id = "rchw-other".into(),
                "cargo" => recipe.kind = Some(CompilationKind::CargoBuild),
                "priority" => recipe.phases[0].patterns.push("+ build/tools/app".into()),
                "declared-result" => {
                    let mut phase = recipe.phases[0].clone();
                    phase.name = "result:build".into();
                    phase.result_dir = Some(PathBuf::from("build"));
                    recipe.phases.push(phase);
                }
                "terminal" => lease.terminal_acknowledged = true,
                _ => unreachable!(),
            }
            let before = std::fs::read(&session.writer.path).unwrap();
            assert!(plan(&lease, &recipe, &input).is_err(), "{boundary}");
            assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
        }
    }

    #[test]
    fn refinement_checks_checkpoint_components_not_text_prefixes() {
        for pending in [false, true] {
            for (recorded, excluded, overlaps) in [
                ("build/tools/app", "build/tools", true),
                ("build/tools", "build/tools", true),
                ("build", "build/tools", true),
                ("build/tools", "build/tools/nested", true),
                ("build/tools-sibling/app", "build/tools", false),
                ("other/build/tools/app", "build/tools", false),
                ("build/工具/app", "build/工具", true),
                ("build/工具-sibling/app", "build/工具", false),
                ("../outside/app", "build/tools", true),
                ("/outside/app", "build/tools", true),
            ] {
                let (_root, session, _pipeline, _worker) = fixture(true);
                let mut recipe = session.recipe.clone();
                let phase = &mut recipe.phases[0];
                if pending {
                    phase.pending = Some((PathBuf::from(recorded), "original-hash".into()));
                } else {
                    phase
                        .published
                        .insert(recorded.into(), "original-hash".into());
                }
                let before = std::fs::read(&session.writer.path).unwrap();
                let input = request(&session, &[excluded]);
                let result = plan(&session.writer.snapshot(), &recipe, &input);
                if overlaps {
                    assert!(
                        result.is_err(),
                        "{recorded} / {excluded}; pending={pending}"
                    );
                } else {
                    let next = result.unwrap().unwrap();
                    let mut expected = serde_json::to_value(&recipe).unwrap();
                    expected["phases"][0]["patterns"]
                        .as_array_mut()
                        .unwrap()
                        .insert(0, format!("- /{excluded}/").into());
                    assert_eq!(serde_json::to_value(&next).unwrap(), expected);
                }
                assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
                assert!(!session.writer.snapshot().terminal_acknowledged);
            }
        }
    }

    #[test]
    fn refinement_cannot_reopen_a_complete_phase_with_pending_publication() {
        let (_root, session, _pipeline, _worker) =
            fixture_with_results(true, &[PathBuf::from("reports")]);
        let mut recipe = session.recipe.clone();
        recipe.phases[1].complete = true;
        recipe.phases[1].pending = Some((PathBuf::from("reports/result"), "hash".into()));
        assert!(
            plan(
                &session.writer.snapshot(),
                &recipe,
                &request(&session, &["build/tools"]),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn refinement_resumes_pending_rename_without_rewriting_published_output() {
        // Exercise the real pending/rename/published boundaries. These bytes
        // model an interrupted collector; the separate Make fixture exercises
        // an actual compiler and an independently completed result phase.
        let (root, mut session, pipeline, worker) = fixture(true);
        let local = session.recipe.project_root.clone();
        let remote = root.join("worker");
        let old_stage = session.stage(0);
        let done = PathBuf::from("build/delivered.o");
        let pending = PathBuf::from("out/pending.o");
        for base in [&local, &remote, &old_stage] {
            std::fs::create_dir_all(base.join("build")).unwrap();
            std::fs::create_dir_all(base.join("out")).unwrap();
        }
        for base in [&remote, &old_stage] {
            std::fs::write(base.join(&done), b"original delivered bytes").unwrap();
            std::fs::write(base.join(&pending), b"original pending bytes").unwrap();
        }
        std::fs::write(local.join(&pending), b"previous caller output").unwrap();
        let done_hash = fingerprint(&old_stage.join(&done)).unwrap().unwrap();
        let pending_hash = fingerprint(&old_stage.join(&pending)).unwrap().unwrap();
        let temporary_name = format!(".rch-return-{}", session.recipe.identity);
        let pending_temporary = local.join("out").join(&temporary_name);
        {
            let _publication = lock_output_root(&local).await.unwrap();
            session
                .persist_output_baseline(0, &[done.clone(), pending.clone()])
                .unwrap();
            let prepared = prepare_output_temporary(
                &old_stage.join(&done),
                &local.join("build").join(&temporary_name),
                &done_hash,
            )
            .unwrap();
            prepared.directory.sync_all().unwrap();
            session
                .persist_pending_output(0, Some((done.clone(), done_hash.clone())))
                .unwrap();
            prepared.publish(&local.join(&done)).unwrap();
            session
                .persist_published_output(0, done.clone(), done_hash.clone())
                .unwrap();
            let prepared = prepare_output_temporary(
                &old_stage.join(&pending),
                &pending_temporary,
                &pending_hash,
            )
            .unwrap();
            prepared.directory.sync_all().unwrap();
            session
                .persist_pending_output(0, Some((pending.clone(), pending_hash.clone())))
                .unwrap();
            // Stop after durable pending, before rename. Its exact temporary
            // remains evidence; refinement must not move, replace or reset it.
        }
        let delivered_inode = std::fs::metadata(local.join(&done)).unwrap().ino();
        let pending_inode = std::fs::metadata(&pending_temporary).unwrap().ino();
        session
            .writer
            .record_exit(EXIT_ARTIFACT_TRANSFER_FAILED)
            .unwrap();
        let before = std::fs::read(&session.writer.path).unwrap();
        let old_phase = serde_json::to_value(&session.recipe.phases[0]).unwrap();
        let input = request(&session, &["build/tools"]);
        let current = TransferConfig {
            retrieval_staging_dir: Some(root.join("fresh-stage")),
            max_transfer_time_ms: Some(900_000),
            ..Default::default()
        };
        apply(&session.writer, &input, &current).unwrap();
        let mut recovered = RecoverySession {
            recipe: load_recipe(&session.writer).unwrap(),
            writer: session.writer.clone(),
        };
        let mut expected_phase = old_phase;
        expected_phase["patterns"]
            .as_array_mut()
            .unwrap()
            .insert(0, "- /build/tools/".into());
        assert_eq!(
            serde_json::to_value(&recovered.recipe.phases[0]).unwrap(),
            expected_phase
        );
        assert_eq!(
            recovered.writer.snapshot().exit_code,
            Some(EXIT_ARTIFACT_TRANSFER_FAILED)
        );
        // The normal recovery configuration merge must accept the newly
        // pinned root even though publication checkpoints are nonempty.
        recovered.apply_retrieval_config(&current).unwrap();
        let disk = DurableLeaseWriter::read_journal(
            &recovered.writer.path,
            &recovered.writer.wrapper_id(),
        )
        .unwrap();
        assert_eq!(
            disk.recovery.unwrap(),
            serde_json::to_value(&recovered.recipe).unwrap()
        );
        let backups: Vec<_> = std::fs::read_dir(recovered.writer.path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "before")
            })
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(std::fs::read(&backups[0]).unwrap(), before);
        assert_eq!(
            std::fs::metadata(&pending_temporary).unwrap().ino(),
            pending_inode
        );
        let staged = recovered.staging_pipeline("project", &pipeline).unwrap();
        let mut copy = staged.local_artifact_retrieval_for_test(
            &worker,
            &remote,
            &recovered.recipe.phases[0].patterns,
        );
        copy.stdin(Stdio::null()).kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(15), copy.output())
            .await
            .expect("owned rsync fixture timed out")
            .expect("rsync is required for the pending-refinement regression");
        assert!(output.status.success(), "{output:?}");
        recovered.publish("project").await.unwrap();
        assert_eq!(
            std::fs::metadata(local.join(&done)).unwrap().ino(),
            delivered_inode
        );
        assert_eq!(
            std::fs::metadata(local.join(&pending)).unwrap().ino(),
            pending_inode
        );
        assert_eq!(fingerprint(&local.join(&done)).unwrap(), Some(done_hash));
        assert_eq!(
            fingerprint(&local.join(&pending)).unwrap(),
            Some(pending_hash)
        );
        assert!(recovered.recipe.phases[0].pending.is_none());
        assert_eq!(recovered.recipe.phases[0].published.len(), 2);
        assert!(recovered.recipe.phases[0].complete);
        recovered.returned(0).unwrap();
        assert!(recovered.writer.acknowledge_terminal().is_err());
        assert!(!recovered.recipe.sources_released);
        let committed = std::fs::read(&recovered.writer.path).unwrap();
        apply(&recovered.writer, &input, &current).unwrap();
        assert_eq!(std::fs::read(&recovered.writer.path).unwrap(), committed);
        for (path, bytes) in [
            (done, b"original delivered bytes".as_slice()),
            (pending, b"original pending bytes".as_slice()),
        ] {
            assert_eq!(std::fs::read(old_stage.join(&path)).unwrap(), bytes);
            assert_eq!(std::fs::read(remote.join(path)).unwrap(), bytes);
        }
    }

    #[tokio::test]
    async fn real_make_fixture_recovery_keeps_symlink_validation_and_never_replays() {
        use tokio::process::Command;
        async fn run(command: &mut Command) -> Vec<u8> {
            command.stdin(Stdio::null()).kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(30), command.output())
                .await
                .expect("owned Make/rsync fixture exceeded its bound")
                .expect("make, a C compiler and rsync are required for artifact-policy tests");
            assert!(output.status.success(), "{output:?}");
            output.stdout
        }
        let (root, mut session, pipeline, worker) =
            fixture_with_results(false, &[PathBuf::from("reports")]);
        let remote = root.join("worker");
        let directory = "build/test-gates/path-without-cosign";
        std::fs::write(
            remote.join("program.c"),
            b"#include <stdio.h>\nint main(void) { puts(\"recovered-only\"); return 0; }\n",
        )
        .unwrap();
        std::fs::write(
            remote.join("Makefile"),
            concat!(
                ".PHONY: test-gates\ntest-gates:\n",
                "\tmkdir -p build/results build/test-gates/path-without-cosign reports\n",
                "\t$(CC) program.c -o build/results/app\n",
                "\tprintf 'build\\n' >> build/invocations\n",
                "\tprintf 'PASS\\n' > build/results/report.txt\n",
                "\tprintf 'PASS\\n' > reports/summary.txt\n",
                "\tln -s ../../results/app build/test-gates/path-without-cosign/printf\n",
            ),
        )
        .unwrap();
        run(Command::new("make").arg("test-gates").current_dir(&remote)).await;
        session.completed(0).unwrap();
        std::fs::write(
            remote.join(".rch-clean-overlay-base.tar"),
            b"immutable source archive",
        )
        .unwrap();
        let old_stage = session.stage(0);
        let old_pipeline = session.staging_pipeline("project", &pipeline).unwrap();
        let mut old_copy = old_pipeline.local_artifact_retrieval_for_test(
            &worker,
            &remote,
            &session.recipe.phases[0].patterns,
        );
        run(&mut old_copy).await;
        let old_link = old_stage.join(directory).join("printf");
        assert!(
            std::fs::symlink_metadata(&old_link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            regular_files(&old_stage).is_err(),
            "old selector must reach the safety refusal"
        );
        assert!(session.publish("project").await.is_err());
        // The live path still collects declared results when the project
        // artifact phase fails. Deliver a real report before refining the
        // failed phase; it must remain complete and must never be rewritten.
        let result_pipeline = session
            .staging_pipeline("result:reports", &pipeline)
            .unwrap();
        let mut result_copy = result_pipeline.local_artifact_retrieval_for_test(
            &worker,
            &remote,
            &["reports/**".into()],
        );
        run(&mut result_copy).await;
        session.publish("result:reports").await.unwrap();
        let report = root.join("caller/reports/summary.txt");
        let report_inode = std::fs::metadata(&report).unwrap().ino();
        let result_phase = serde_json::to_value(&session.recipe.phases[1]).unwrap();
        assert!(session.recipe.phases[1].complete);
        assert!(!session.recipe.phases[0].complete);
        assert!(!session.writer.snapshot().terminal_acknowledged);
        session
            .writer
            .record_exit(EXIT_ARTIFACT_TRANSFER_FAILED)
            .unwrap();
        let current = TransferConfig {
            retrieval_staging_dir: Some(root.join("fresh-stage")),
            ..Default::default()
        };
        apply(&session.writer, &request(&session, &[directory]), &current).unwrap();
        let mut recovered = RecoverySession {
            recipe: load_recipe(&session.writer).unwrap(),
            writer: session.writer.clone(),
        };
        assert_eq!(
            serde_json::to_value(&recovered.recipe.phases[1]).unwrap(),
            result_phase
        );
        assert_eq!(std::fs::metadata(&report).unwrap().ino(), report_inode);
        assert_eq!(
            recovered.writer.snapshot().exit_code,
            Some(EXIT_ARTIFACT_TRANSFER_FAILED)
        );
        let staged = recovered.staging_pipeline("project", &pipeline).unwrap();
        let mut copy = staged.local_artifact_retrieval_for_test(
            &worker,
            &remote,
            &recovered.recipe.phases[0].patterns,
        );
        run(&mut copy).await;
        let stage = recovered.stage(0);
        assert!(!stage.join(directory).exists());
        assert!(!stage.join(".rch-clean-overlay-base.tar").exists());
        // A symlink in an ADMITTED output location still refuses publication.
        std::os::unix::fs::symlink("app", stage.join("build/results/unexpected-link")).unwrap();
        let before = std::fs::read(&session.writer.path).unwrap();
        assert!(recovered.publish("project").await.is_err());
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
        assert!(!recovered.writer.snapshot().terminal_acknowledged);
        assert!(!recovered.recipe.sources_released);
        // Retain the injected link outside the stage; never delete it or
        // change the real worker fixture to make publication succeed.
        std::fs::rename(
            stage.join("build/results/unexpected-link"),
            root.join("retained-injected-link"),
        )
        .unwrap();
        recovered.publish("project").await.unwrap();
        recovered.returned(0).unwrap();
        assert!(
            recovered.writer.acknowledge_terminal().is_err(),
            "delivery alone is not source release"
        );
        assert_eq!(
            run(&mut Command::new(root.join("caller/build/results/app"))).await,
            b"recovered-only\n"
        );
        assert_eq!(
            std::fs::read(remote.join("build/invocations")).unwrap(),
            b"build\n"
        );
        assert_eq!(
            std::fs::read(remote.join(".rch-clean-overlay-base.tar")).unwrap(),
            b"immutable source archive"
        );
        assert!(
            std::fs::symlink_metadata(old_link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read(root.join("caller/build/results/report.txt")).unwrap(),
            b"PASS\n"
        );
        assert_eq!(
            serde_json::to_value(&recovered.recipe.phases[1]).unwrap(),
            result_phase
        );
        assert_eq!(std::fs::metadata(&report).unwrap().ino(), report_inode);
        assert_eq!(std::fs::read(report).unwrap(), b"PASS\n");
    }
}
