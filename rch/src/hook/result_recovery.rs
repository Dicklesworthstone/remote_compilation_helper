//! Terminal unavailable-result handling after completion and source fencing.
//!
//! A failed command may never create a declared result directory. Retrying
//! rsync forever cannot repair it, but an rsync error alone does not prove it
//! absent. A file, special entry or symlink in the declared directory path is
//! also a terminal output-contract failure, not permission to follow that link
//! or retry forever. Descriptor-relative observations distinguish these facts
//! from EACCES, I/O errors and races, which retain unsettled ownership. Preserve
//! the failed phase and original command exit while retirement returns exit 102.

use super::*;
use std::future::Future;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MissingResult {
    remote_root: String,
    directory: PathBuf,
    command_exit: i32,
    // Existing durable journals record absence without this field. Keep their
    // meaning while distinguishing newly observed invalid directory entries.
    #[serde(default)]
    reason: UnavailableReason,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UnavailableReason {
    #[default]
    Absent,
    NotDirectory,
    Symlink,
}

impl UnavailableReason {
    fn description(self) -> &'static str {
        match self {
            Self::Absent => "is absent",
            Self::NotDirectory => "contains a non-directory entry",
            Self::Symlink => "contains a symlink (not followed)",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Presence {
    Present,
    Absent,
    NotDirectory,
    Symlink,
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
                "unavailable-result evidence contradicts the execution or output contract"
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

fn probe_command(root: &str, directory: &Path, token: &str) -> anyhow::Result<String> {
    let relative = validate_directory(directory)?;
    anyhow::ensure!(
        Path::new(root).is_absolute() && !root.chars().any(char::is_control),
        "result probe requires an absolute Unix source root"
    );
    anyhow::ensure!(
        !token.is_empty() && token.len() <= 256 && !token.chars().any(char::is_control),
        "invalid result receipt token"
    );
    // The worker owns the descriptor-relative traversal and revalidation.
    // A missing/older binary retains ownership with a diagnostic; it never
    // turns an unavailable observation into sticky absence evidence.
    Ok(format!(
        "( {locate}\n\
         if ! rch_wkr_locate; then \
         printf 'RCH_RESULT_DIRECTORY_UNAVAILABLE: rch-wkr is not installed on this worker\\n' >&2; exit 73; fi; \
         if ! rch_result_version=$(\"$RCH_WKR\" result-directory probe) || \
         [ \"$rch_result_version\" != 'rch-wkr result-directory v1' ]; then \
         printf 'RCH_RESULT_DIRECTORY_UNAVAILABLE: deploy the matching rch-wkr with result-directory support\\n' >&2; exit 73; fi; \
         exec \"$RCH_WKR\" result-directory {} {} {} )",
        shell_escape::escape(root.into()),
        shell_escape::escape(relative.into()),
        shell_escape::escape(token.into()),
        locate = rch_common::wkr_locate::WKR_LOCATE_SHELL,
    ))
}

fn parse_probe(output: &Output, token: &str) -> anyhow::Result<Presence> {
    anyhow::ensure!(
        output.status.success() && output.stderr.is_empty(),
        "result directory probe failed or produced diagnostics; ownership retained"
    );
    if output.stdout == format!("{token}:absent\n").as_bytes() {
        Ok(Presence::Absent)
    } else if output.stdout == format!("{token}:present\n").as_bytes() {
        Ok(Presence::Present)
    } else if output.stdout == format!("{token}:not-directory\n").as_bytes() {
        Ok(Presence::NotDirectory)
    } else if output.stdout == format!("{token}:symlink\n").as_bytes() {
        Ok(Presence::Symlink)
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
    let token = format!("RCH_RESULT_DIRECTORY_V2:{}", uuid::Uuid::new_v4().simple());
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
/// tests can prove that unavailable results never dispatch a transfer and that
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
        // Never retry or publish this previously settled unavailable directory.
        return Ok(false);
    }
    anyhow::ensure!(!phase.complete, "result phase is already published");
    let remote_root = phase.remote.clone();
    let directory = directory.clone();
    let reason = match probe.await? {
        Presence::Present => {
            transfer.await?;
            return Ok(true);
        }
        Presence::Absent => UnavailableReason::Absent,
        Presence::NotDirectory => UnavailableReason::NotDirectory,
        Presence::Symlink => UnavailableReason::Symlink,
    };
    session.recipe.phases[index].missing_result = Some(MissingResult {
        remote_root,
        directory,
        command_exit,
        reason,
    });
    if let Err(error) = session.persist() {
        // A failed journal write is not a settled phase. An in-process retry
        // must obtain proof again instead of skipping an undurable failure.
        session.recipe.phases[index].missing_result = None;
        return Err(error);
    }
    eprintln!(
        "[RCH] required result directory '{}' {} after remote completion \
         (command exit {command_exit}); delivery remains failed (exit {EXIT_ARTIFACT_TRANSFER_FAILED})",
        session.recipe.phases[index]
            .result_dir
            .as_ref()
            .unwrap()
            .display(),
        reason.description()
    );
    Ok(false)
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
            recovery_ownership: None,
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
            cargo_outputs: None,
            native_outputs: None,
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

    // Filesystem/type/replacement tests live with the descriptor probe in
    // rch-wkr::result_probe. These exercise the transport and journal boundary.
    fn worker_fixture(path: &Path, script: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, script).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn run_probe_command(root: &Path, binary: &Path) -> Output {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(
                probe_command(
                    root.to_str().unwrap(),
                    Path::new("reports/export"),
                    "test-receipt",
                )
                .unwrap(),
            )
            .env("RCH_WKR_BIN", binary)
            .output()
            .expect("run result-probe transport")
    }

    #[test]
    fn result_probe_native_worker_returns_bound_observations() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("source with ' quotes");
        std::fs::create_dir_all(root.join("reports")).unwrap();
        std::fs::create_dir(root.join("reports/export")).unwrap();
        std::fs::write(root.join("reports/file"), b"not a directory").unwrap();
        std::os::unix::fs::symlink("export", root.join("reports/link")).unwrap();
        for (relative, expected) in [
            ("reports/export", Presence::Present),
            ("reports/missing", Presence::Absent),
            ("reports/file", Presence::NotDirectory),
            ("reports/link", Presence::Symlink),
        ] {
            let output = std::process::Command::new("/bin/sh")
                .args([
                    "-c",
                    &probe_command(root.to_str().unwrap(), Path::new(relative), "native-token")
                        .unwrap(),
                ])
                .env(
                    "RCH_WKR_BIN",
                    crate::transfer::native_control_worker_for_test(),
                )
                .env("PATH", directory.path().join("no-tools"))
                .output()
                .unwrap();
            assert_eq!(
                parse_probe(&output, "native-token").unwrap(),
                expected,
                "{relative}: {output:?}"
            );
            assert!(parse_probe(&output, "other-token").is_err());
        }
    }

    #[test]
    fn result_probe_transport_preserves_quoted_paths_and_bound_token() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("source : with ' quotes");
        let binary = directory.path().join("worker with ' quotes");
        worker_fixture(
            &binary,
            r#"#!/bin/sh
set -eu
[ "$1" = result-directory ] || exit 2
if [ "$#" = 2 ] && [ "$2" = probe ]; then
    printf 'rch-wkr result-directory v1\n'
    exit 0
fi
[ "$#" = 4 ] && [ "$2" = "$TEST_ROOT" ] && [ "$3" = 'reports/export' ] && [ "$4" = test-receipt ] || exit 2
printf '%s:absent\n' "$4"
"#,
        );
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(
                probe_command(
                    root.to_str().unwrap(),
                    Path::new("reports/export"),
                    "test-receipt",
                )
                .unwrap(),
            )
            .env("RCH_WKR_BIN", binary)
            .env("TEST_ROOT", &root)
            .output()
            .unwrap();
        assert_eq!(
            parse_probe(&output, "test-receipt").unwrap(),
            Presence::Absent
        );
        assert!(
            !root.exists(),
            "transport fixture must not invent a result tree"
        );
    }

    #[tokio::test]
    async fn unavailable_worker_probe_cannot_settle_delivery_or_release_ownership() {
        for script in [
            None,
            Some("#!/bin/sh\necho 'error: unknown subcommand' >&2\nexit 2\n"),
            Some("#!/bin/sh\necho 'rch-wkr result-directory v0'\nexit 0\n"),
            Some("#!/bin/sh\necho 'rch-wkr result-directory v1'\nexit 1\n"),
        ] {
            let (directory, mut session) = fixture(1);
            let binary = directory.path().join("worker");
            if let Some(script) = script {
                worker_fixture(&binary, script);
            }
            let before = std::fs::read(&session.writer.path).unwrap();
            let output = run_probe_command(directory.path(), &binary);
            assert_eq!(output.status.code(), Some(73), "{output:?}");
            assert!(output.stdout.is_empty(), "no absence receipt: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("RCH_RESULT_DIRECTORY_UNAVAILABLE")
            );
            assert!(
                settle_result_phase(
                    &mut session,
                    0,
                    async { parse_probe(&output, "test-receipt") },
                    async { panic!("an unavailable probe must not dispatch result transfer") },
                )
                .await
                .is_err()
            );
            assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
            assert!(!has_missing_results(&session.recipe));
            assert!(session.writer.acknowledge_terminal().is_err());
            assert!(session.writer.ensure_released_for_retry().is_err());
        }
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

    #[test]
    fn result_probe_requires_exact_clean_typed_receipts() {
        for (text, expected) in [
            ("absent", Presence::Absent),
            ("present", Presence::Present),
            ("not-directory", Presence::NotDirectory),
            ("symlink", Presence::Symlink),
        ] {
            let mut output = Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: format!("token:{text}\n").into_bytes(),
                stderr: Vec::new(),
            };
            assert_eq!(parse_probe(&output, "token").unwrap(), expected);
            output.stderr = b"filesystem inspection failed\n".to_vec();
            assert!(parse_probe(&output, "token").is_err());
            output.stderr.clear();
            output.status = std::process::ExitStatus::from_raw(1 << 8);
            assert!(parse_probe(&output, "token").is_err());
            output.status = std::process::ExitStatus::from_raw(0);
            output.stdout.extend_from_slice(b"token:present\n");
            assert!(parse_probe(&output, "token").is_err());
        }
    }

    #[test]
    fn result_failure_preserves_legacy_absence_and_rejects_unknown_reasons() {
        let legacy = serde_json::json!({
            "remote_root": "/source", "directory": "reports/export", "command_exit": 1
        });
        let record: MissingResult = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(record.reason, UnavailableReason::Absent);
        for reason in [UnavailableReason::NotDirectory, UnavailableReason::Symlink] {
            let record = MissingResult {
                reason,
                ..record.clone()
            };
            let bytes = serde_json::to_vec(&record).unwrap();
            assert_eq!(
                serde_json::from_slice::<MissingResult>(&bytes).unwrap(),
                record
            );
        }
        for reason in ["present", "permission_denied", "unknown"] {
            let mut invalid = legacy.clone();
            invalid["reason"] = serde_json::json!(reason);
            assert!(serde_json::from_value::<MissingResult>(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn wrong_type_is_durable_failure_without_transfer_and_stays_settled() {
        for code in [0, 1, 101, 137] {
            for (presence, reason) in [
                (Presence::NotDirectory, UnavailableReason::NotDirectory),
                (Presence::Symlink, UnavailableReason::Symlink),
            ] {
                let (_directory, mut session) = fixture(code);
                assert!(
                    !settle_result_phase(&mut session, 0, async { Ok(presence) }, async {
                        panic!("invalid directory must not dispatch rsync or follow a link")
                    })
                    .await
                    .unwrap()
                );
                session.recipe = load_recipe(&session.writer).unwrap();
                let failure = session.recipe.phases[0].missing_result.as_ref().unwrap();
                assert_eq!(failure.reason, reason);
                assert_eq!(failure.command_exit, code);
                assert!(!session.recipe.phases[0].complete);
                assert!(session.recipe.phases[0].published.is_empty());
                assert!(!session.recipe.sources_released);
                assert!(!session.recipe.retired);
                assert!(session.returned(0).is_err());
                assert!(session.publish("result:reports/export").await.is_err());
                assert!(session.writer.acknowledge_terminal().is_err());
                assert!(session.writer.ensure_released_for_retry().is_err());
                assert!(
                    !settle_result_phase(
                        &mut session,
                        0,
                        async { panic!("settled failure must not re-probe") },
                        async { panic!("settled failure must not transfer") },
                    )
                    .await
                    .unwrap()
                );
            }
        }
    }

    #[tokio::test]
    async fn unavailable_result_is_not_settled_after_failed_journal_write() {
        let (_directory, mut session) = fixture(1);
        let path = session.writer.path.clone();
        let saved = path.with_extension("saved");
        std::fs::rename(&path, &saved).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(
            settle_result_phase(
                &mut session,
                0,
                async { Ok(Presence::NotDirectory) },
                async { panic!("invalid output must not transfer, even on a persistence failure") }
            )
            .await
            .is_err()
        );
        assert!(!has_missing_results(&session.recipe));
        assert!(!session.recipe.retired);
        assert!(path.is_dir());
        // Only restore the test-owned journal path; no production lock or
        // source root is involved in this injected persistence failure.
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&saved, &path).unwrap();
        assert!(
            !settle_result_phase(
                &mut session,
                0,
                async { Ok(Presence::NotDirectory) },
                async { panic!("retry still must not transfer an invalid directory") }
            )
            .await
            .unwrap()
        );
        assert!(has_missing_results(&load_recipe(&session.writer).unwrap()));
        assert!(session.writer.acknowledge_terminal().is_err());
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
        for presence in [Presence::Absent, Presence::NotDirectory, Presence::Symlink] {
            terminal_result_recovery(presence).await;
        }
    }

    async fn terminal_result_recovery(presence: Presence) {
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
            !settle_result_phase(&mut session, 0, async { Ok(presence) }, async {
                panic!("an unavailable directory must never be transferred")
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
        // Explicit recovery otherwise asks the worker whether an older failed
        // delivery hides a cancellation. Record that this one has none to find.
        session.recipe.source_cancellation_settled = Some(true);
        session.persist().unwrap();
        session.retired().unwrap();
        session
            .writer
            .record_exit(EXIT_ARTIFACT_TRANSFER_FAILED)
            .unwrap();
        session.writer.acknowledge_terminal().unwrap();
        assert_eq!(
            recover_job(&session.writer).await.unwrap().0,
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
