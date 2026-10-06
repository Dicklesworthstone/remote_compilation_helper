//! Terminal missing-result handling after execution completion and source fencing.
//!
//! A failed command may never create a declared result directory. Retrying
//! rsync forever cannot repair it, but an rsync error alone does not prove it
//! absent. Probe through directory descriptors: EACCES, I/O errors and dangling
//! links must not become absence evidence. Preserve the failed phase and the
//! command's original exit while the caller retires ownership with exit 102.

use super::*;
use std::future::Future;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MissingResult {
    remote_root: String,
    directory: PathBuf,
    command_exit: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Presence {
    Present,
    Absent,
}

pub(super) fn has_missing_results(recipe: &RecoveryRecipe) -> bool {
    recipe
        .phases
        .iter()
        .any(|phase| phase.missing_result.is_some())
}

pub(super) fn validate_missing_results(recipe: &RecoveryRecipe) -> anyhow::Result<()> {
    for phase in &recipe.phases {
        if let Some(failure) = &phase.missing_result {
            anyhow::ensure!(
                recipe.prepared
                    && recipe.execution_started
                    && !recipe.preparation_cancelled
                    && recipe.exit_code == Some(failure.command_exit)
                    && !phase.complete
                    && phase.remote == failure.remote_root
                    && phase.result_dir.as_ref() == Some(&failure.directory)
                    && recipe
                        .returned
                        .is_none_or(|code| code == EXIT_ARTIFACT_TRANSFER_FAILED),
                "missing-result evidence contradicts the execution or output contract"
            );
            validate_directory(&failure.directory)?;
        }
    }
    Ok(())
}

fn validate_directory(directory: &Path) -> anyhow::Result<&str> {
    let normalized =
        crate::hook::normalize_repository_relative_path("result directory", directory)?;
    anyhow::ensure!(
        normalized.as_os_str() == directory.as_os_str(),
        "result directory must retain its admitted normalized spelling"
    );
    directory.to_str().context("result directory is not UTF-8")
}

// The root may be an operator-selected system alias (e.g. macOS /tmp), but
// never follow a link below it. Only a failed lstat of one name relative to a
// successfully opened parent directory proves absence. Failure to open the
// root, permission errors, non-directories and a replacement during traversal
// do NOT prove absence. The source grant held by the caller excludes writers.
const RESULT_DIRECTORY_PROBE: &str = r#"import os, stat, sys
root, relative, token = sys.argv[1:]
parts = relative.split('/')
if not root.startswith('/') or not parts or any(p in ('', '.', '..') for p in parts):
    raise ValueError('invalid admitted result path')
fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    for index, part in enumerate(parts):
        try:
            metadata = os.stat(part, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            print(token + ':absent')
            break
        if not stat.S_ISDIR(metadata.st_mode) or index == len(parts) - 1:
            print(token + ':present')
            break
        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        os.close(fd)
        fd = child
finally:
    os.close(fd)
"#;

fn probe_command(root: &str, directory: &Path, token: &str) -> anyhow::Result<String> {
    let relative = validate_directory(directory)?;
    anyhow::ensure!(
        Path::new(root).is_absolute() && !root.chars().any(char::is_control),
        "result probe requires an absolute Unix source root"
    );
    Ok(format!(
        "python3 -I -S -c {} {} {} {}",
        shell_escape::escape(RESULT_DIRECTORY_PROBE.into()),
        shell_escape::escape(root.into()),
        shell_escape::escape(relative.into()),
        shell_escape::escape(token.into()),
    ))
}

fn parse_probe(output: &Output, token: &str) -> anyhow::Result<Presence> {
    anyhow::ensure!(
        output.status.success(),
        "result directory probe failed; ownership retained"
    );
    if output.stdout == format!("{token}:absent\n").as_bytes() {
        Ok(Presence::Absent)
    } else if output.stdout == format!("{token}:present\n").as_bytes() {
        Ok(Presence::Present)
    } else {
        anyhow::bail!("unrecognized result directory probe receipt; ownership retained")
    }
}

async fn probe_directory(
    worker: &WorkerConfig,
    source_identity: &str,
    root: &str,
    directory: &Path,
) -> anyhow::Result<Presence> {
    if WorkerPlatform::from_worker(worker).is_windows() {
        // No descriptor-relative POSIX proof on the Windows lane. Continue
        // its normal transfer; never reinterpret a failed transfer as absence.
        return Ok(Presence::Present);
    }
    let token = format!("RCH_RESULT_DIRECTORY_V1:{}", uuid::Uuid::new_v4().simple());
    let command = probe_command(root, directory, &token)?;
    let command = crate::hook::ssh::wrap_remote_source_activity(&command, source_identity)?;
    let output =
        crate::hook::ssh::run_offload_ssh_command(worker, &command, Duration::from_secs(20))
            .await?;
    parse_probe(&output, &token)
}

/// Called ONLY after the identity-bound completion and source/pair recovery in
/// recover_job. Read the small existence receipt BEFORE starting rsync so an
/// impossible transfer cannot consume every operator recovery timeout.
pub(super) async fn collect_result(
    session: &mut RecoverySession,
    index: usize,
    pipeline: &TransferPipeline,
    worker: &WorkerConfig,
) -> anyhow::Result<bool> {
    let phase = session
        .recipe
        .phases
        .get(index)
        .context("missing result phase")?
        .clone();
    let directory = phase
        .result_dir
        .as_deref()
        .context("not a result-directory phase")?;
    let identity = session.recipe.identity.clone();
    settle_result_phase(
        session,
        index,
        probe_directory(worker, &identity, &phase.remote, directory),
        async {
            pipeline
                .retrieve_result_dir(worker, directory)
                .await
                .map(|_| ())
        },
    )
    .await
}

/// The production settlement boundary with its two I/O futures supplied, so
/// tests can prove that absent results never dispatch a transfer and that
/// transport/probe errors never authorize release or fabricate publication.
async fn settle_result_phase(
    session: &mut RecoverySession,
    index: usize,
    probe: impl Future<Output = anyhow::Result<Presence>>,
    transfer: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<bool> {
    validate_missing_results(&session.recipe)?;
    anyhow::ensure!(
        session.recipe.prepared
            && session.recipe.execution_started
            && !session.recipe.preparation_cancelled
            && !session.recipe.sources_released
            && !session.recipe.retired
            && session.recipe.returned.is_none(),
        "result recovery requires completed execution and an unretired source grant"
    );
    let command_exit = session
        .recipe
        .exit_code
        .context("no observed remote completion")?;
    let phase = session
        .recipe
        .phases
        .get(index)
        .context("missing result phase")?;
    let directory = phase
        .result_dir
        .as_ref()
        .context("not a result-directory phase")?;
    validate_directory(directory)?;
    if phase.missing_result.is_some() {
        // A later phase's transport failure may have interrupted recovery.
        // Never retry or publish this previously settled missing directory.
        return Ok(false);
    }
    anyhow::ensure!(!phase.complete, "result phase is already published");
    let failure = MissingResult {
        remote_root: phase.remote.clone(),
        directory: directory.clone(),
        command_exit,
    };
    match probe.await? {
        Presence::Present => {
            transfer.await?;
            Ok(true)
        }
        Presence::Absent => {
            session.recipe.phases[index].missing_result = Some(failure);
            session.persist()?;
            eprintln!(
                "[RCH] required result directory '{}' is absent after remote completion \
                 (command exit {command_exit}); delivery remains failed (exit {EXIT_ARTIFACT_TRANSFER_FAILED})",
                session.recipe.phases[index]
                    .result_dir
                    .as_ref()
                    .unwrap()
                    .display()
            );
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::process::ExitStatusExt;

    fn fixture(code: i32) -> (tempfile::TempDir, RecoverySession) {
        let directory = tempfile::tempdir().unwrap();
        let worker = WorkerConfig {
            id: WorkerId::new("result-recovery"),
            host: "unreachable.invalid".into(),
            user: "worker".into(),
            identity_file: "/unused/key".into(),
            total_slots: 1,
            priority: 100,
            tags: Vec::new(),
            tools: Vec::new(),
        };
        let writer = DurableLeaseWriter {
            path: directory.path().join("lease.json"),
            lease: Arc::new(Mutex::new(DurableJobLease::new(
                JobIdentity::new_local(),
                0,
                None,
                None,
                0,
                true,
                false,
                "test".into(),
            ))),
        };
        writer.admit(41, &worker.id).unwrap();
        RecoverySession::begin(
            &writer,
            &worker,
            vec!["/test/source".into()],
            None,
            None,
            TransferConfig::default(),
            directory.path().to_owned(),
            uuid::Uuid::new_v4().simple().to_string(),
        )
        .unwrap();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.prepared = true;
        recipe.execution_started = true;
        recipe.exit_code = Some(code);
        recipe.phases.push(RecoveryPhase {
            name: "result:reports/export".into(),
            local: directory.path().to_owned(),
            remote: directory.path().to_string_lossy().into_owned(),
            patterns: Vec::new(),
            result_dir: Some(PathBuf::from("reports/export")),
            custom_target: false,
            output_gate: false,
            baseline: BTreeMap::new(),
            published: BTreeMap::new(),
            pending: None,
            complete: false,
            missing_result: None,
        });
        let session = RecoverySession { recipe, writer };
        session.persist().unwrap();
        (directory, session)
    }

    fn local_probe(root: &Path, relative: &str) -> anyhow::Result<Presence> {
        let token = "test-receipt";
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(probe_command(
                root.to_str().unwrap(),
                Path::new(relative),
                token,
            )?)
            .output()?;
        parse_probe(&output, token)
    }

    #[test]
    fn descriptor_probe_distinguishes_absence_from_links_and_wrong_types() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("source : with ' quotes");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("reports")).unwrap();
        std::fs::write(root.join("reports/file"), b"retained").unwrap();
        std::os::unix::fs::symlink(root.join("nowhere"), root.join("dangling")).unwrap();
        std::os::unix::fs::symlink(root.join("reports"), root.join("alias")).unwrap();
        for path in ["missing", "reports/missing", "missing/deep/result"] {
            assert_eq!(
                local_probe(&root, path).unwrap(),
                Presence::Absent,
                "{path}"
            );
        }
        for path in [
            "reports",
            "reports/file",
            "reports/file/child",
            "dangling",
            "alias/missing",
        ] {
            assert_eq!(
                local_probe(&root, path).unwrap(),
                Presence::Present,
                "{path}"
            );
        }
        assert!(local_probe(&directory.path().join("missing-root"), "reports").is_err());
        assert!(local_probe(&root.join("dangling"), "reports").is_err());
        let root_alias = directory.path().join("source-alias");
        std::os::unix::fs::symlink(&root, &root_alias).unwrap();
        assert_eq!(
            local_probe(&root_alias, "reports/missing").unwrap(),
            Presence::Absent
        );
    }

    #[test]
    fn result_probe_refuses_unadmitted_paths_and_unbound_receipts() {
        for directory in [
            "",
            "/reports",
            "../reports",
            "reports/../out",
            "reports//out",
            "./reports",
            "reports/",
            "reports\n",
            "reports\\out",
        ] {
            assert!(
                probe_command("/source", Path::new(directory), "token").is_err(),
                "{directory:?}"
            );
        }
        for (code, bytes) in [
            (1, b"token:absent\n".to_vec()),
            (0, b"other:absent\n".to_vec()),
            (0, b"token:absent".to_vec()),
            (0, b"token:absent\ntoken:present\n".to_vec()),
            (0, vec![255]),
        ] {
            let output = Output {
                status: std::process::ExitStatus::from_raw(code << 8),
                stdout: bytes,
                stderr: Vec::new(),
            };
            assert!(parse_probe(&output, "token").is_err());
        }
    }

    #[tokio::test]
    async fn absent_result_is_a_durable_failure_not_a_publication_or_release() {
        for code in [0, 1, 101, 137] {
            let (_directory, mut session) = fixture(code);
            let transferred = Cell::new(false);
            assert!(
                !settle_result_phase(&mut session, 0, async { Ok(Presence::Absent) }, async {
                    transferred.set(true);
                    Ok(())
                })
                .await
                .unwrap()
            );
            assert!(!transferred.get());
            let persisted = load_recipe(&session.writer).unwrap();
            assert_eq!(persisted.exit_code, Some(code));
            assert!(!persisted.phases[0].complete);
            assert!(persisted.phases[0].missing_result.is_some());
            assert!(persisted.phases[0].published.is_empty());
            assert!(!persisted.sources_released);
            assert!(!persisted.retired);
            assert!(session.returned(0).is_err());
            assert!(session.publish("result:reports/export").await.is_err());
            assert!(session.writer.acknowledge_terminal().is_err());
            assert!(session.writer.ensure_released_for_retry().is_err());
            let before = std::fs::read(&session.writer.path).unwrap();
            assert!(session.completed(code + 1).is_err());
            assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
        }
    }

    #[tokio::test]
    async fn probe_and_transport_failures_retain_unsettled_ownership() {
        let (_directory, mut session) = fixture(1);
        let before = std::fs::read(&session.writer.path).unwrap();
        let transferred = Cell::new(false);
        assert!(
            settle_result_phase(
                &mut session,
                0,
                async { anyhow::bail!("permission denied") },
                async {
                    transferred.set(true);
                    Ok(())
                }
            )
            .await
            .is_err()
        );
        assert!(!transferred.get());
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
        let result = settle_result_phase(&mut session, 0, async { Ok(Presence::Present) }, async {
            anyhow::bail!("transport interrupted")
        })
        .await;
        assert_eq!(result.unwrap_err().to_string(), "transport interrupted");
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
        assert!(!has_missing_results(&session.recipe));
        assert!(session.writer.acknowledge_terminal().is_err());
    }

    #[tokio::test]
    async fn missing_result_is_sticky_across_reloads_and_other_phase_errors() {
        let (_directory, mut session) = fixture(1);
        settle_result_phase(&mut session, 0, async { Ok(Presence::Absent) }, async {
            panic!("no transfer for absent output")
        })
        .await
        .unwrap();
        session.recipe = load_recipe(&session.writer).unwrap();
        assert!(
            !settle_result_phase(
                &mut session,
                0,
                async { panic!("settled absence must not probe again") },
                async { panic!("settled absence must not transfer again") }
            )
            .await
            .unwrap()
        );
        let original = session.recipe.clone();
        for changed in [
            {
                let mut r = original.clone();
                r.phases[0].remote = "/another/root".into();
                r
            },
            {
                let mut r = original.clone();
                r.phases[0].complete = true;
                r
            },
            {
                let mut r = original.clone();
                r.exit_code = Some(0);
                r
            },
            {
                let mut r = original.clone();
                r.returned = Some(0);
                r
            },
            {
                let mut r = original.clone();
                r.phases[0].result_dir = None;
                r
            },
        ] {
            assert!(validate_missing_results(&changed).is_err());
        }
    }

    #[tokio::test]
    async fn present_results_still_require_transfer_and_publication() {
        let (_directory, mut session) = fixture(1);
        let transferred = Cell::new(false);
        assert!(
            settle_result_phase(&mut session, 0, async { Ok(Presence::Present) }, async {
                transferred.set(true);
                Ok(())
            })
            .await
            .unwrap()
        );
        assert!(transferred.get());
        assert!(!session.recipe.phases[0].complete);
        assert!(!has_missing_results(&session.recipe));
        assert!(session.writer.acknowledge_terminal().is_err());
    }

    #[tokio::test]
    async fn other_results_publish_and_terminal_failure_resumes_without_recollection() {
        let (directory, mut session) = fixture(1);
        let first_stage = session.stage(0);
        std::fs::create_dir_all(&first_stage).unwrap();
        std::fs::write(first_stage.join("partial-evidence"), b"keep me").unwrap();
        let mut logs = session.recipe.phases[0].clone();
        logs.name = "result:logs".into();
        logs.result_dir = Some(PathBuf::from("logs"));
        session.recipe.phases.push(logs);
        session.persist().unwrap();
        assert!(
            !settle_result_phase(&mut session, 0, async { Ok(Presence::Absent) }, async {
                panic!("an absent directory must never be transferred")
            },)
            .await
            .unwrap()
        );

        let log_stage = session.stage(1);
        assert!(
            settle_result_phase(&mut session, 1, async { Ok(Presence::Present) }, async {
                std::fs::create_dir_all(log_stage.join("logs"))?;
                std::fs::write(log_stage.join("logs/failure.txt"), b"original failure")?;
                Ok(())
            },)
            .await
            .unwrap()
        );
        session.publish("result:logs").await.unwrap();
        assert!(!session.recipe.phases[0].complete);
        assert!(session.recipe.phases[1].complete);
        session.returned(EXIT_ARTIFACT_TRANSFER_FAILED).unwrap();
        assert!(session.retired().is_err());
        assert!(session.writer.acknowledge_terminal().is_err());

        // Model successful remote release acknowledgements. This tests the
        // durable terminal boundary, not SSH or fleet ownership enforcement.
        session.tree_retired().unwrap();
        session.pair_released().unwrap();
        session.sources_released().unwrap();
        session.retired().unwrap();
        session
            .writer
            .record_exit(EXIT_ARTIFACT_TRANSFER_FAILED)
            .unwrap();
        session.writer.acknowledge_terminal().unwrap();
        assert_eq!(
            recover_job(&session.writer).await.unwrap(),
            EXIT_ARTIFACT_TRANSFER_FAILED
        );
        assert_eq!(
            session.writer.snapshot().exit_code,
            Some(EXIT_ARTIFACT_TRANSFER_FAILED)
        );
        assert_eq!(load_recipe(&session.writer).unwrap().exit_code, Some(1));
        assert_eq!(
            std::fs::read(first_stage.join("partial-evidence")).unwrap(),
            b"keep me"
        );
        assert_eq!(
            std::fs::read(directory.path().join("logs/failure.txt")).unwrap(),
            b"original failure"
        );
        assert!(!directory.path().join("reports/export").exists());
        session.writer.ensure_released_for_retry().unwrap();
    }
}
