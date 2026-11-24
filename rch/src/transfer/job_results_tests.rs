//! Retained job outputs stay outside future source and artifact transfers.
use super::*;
use rch_common::job_results::{RETENTION_EXCLUDE_PATTERN, is_retention_basename};

const PLAN_ID: &str = "0123456789abcdef0123456789abcdef";

fn worker() -> WorkerConfig {
    WorkerConfig {
        id: WorkerId::new("retention-test"),
        host: "unused.invalid".to_owned(),
        user: "unused".to_owned(),
        identity_file: "unused".to_owned(),
        total_slots: 1,
        priority: 1,
        tags: Vec::new(),
        tools: Vec::new(),
        remote_base: None,
    }
}

fn pipeline(root: &Path) -> TransferPipeline {
    TransferPipeline::new(
        root.to_owned(),
        "retention-test".to_owned(),
        "identity".to_owned(),
        TransferConfig {
            exclude_patterns: Vec::new(),
            ..TransferConfig::default()
        },
    )
}

fn assert_excluded_before_includes(command: &Command) {
    let args: Vec<_> = command
        .as_std()
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let excluded = args
        .windows(2)
        .position(|args| args[0] == "--exclude" && args[1] == RETENTION_EXCLUDE_PATTERN)
        .expect("retained outputs must have an unconditional exclusion");
    if let Some(included) = args.iter().position(|arg| arg == "--include") {
        assert!(
            excluded < included,
            "retention must precede priority includes"
        );
    }
}

#[test]
fn retained_results_match_only_the_reserved_suffix_at_every_depth() {
    let directory = tempfile::tempdir().unwrap();
    let pipeline = pipeline(directory.path());
    let filters = pipeline
        .artifact_retrieval_filters(&["+ **".to_owned()])
        .unwrap();
    let exclusion = WindowsArtifactFilter::new(RETENTION_EXCLUDE_PATTERN, false).unwrap();
    let retained = format!("project.rch-job-results-{PLAN_ID}");
    for path in [
        retained.clone(),
        format!("nested/{retained}/old/reports/report.json"),
        format!("build/{retained}/outcome.json"),
    ] {
        assert!(is_internal_transfer_data(Path::new(&path)), "{path}");
        assert!(exclusion.excludes(&path), "{path}");
        assert!(!filters.selects(&path), "priority include admitted {path}");
    }
    for name in [
        format!(".rch-job-results-{PLAN_ID}"),
        format!("project.rch-job-results-{PLAN_ID}.json"),
        format!("project.rch-job-results-{PLAN_ID}0"),
        format!("project.rch-job-results-{}", &PLAN_ID[..31]),
        format!("project.rch-job-results-{}", PLAN_ID.to_uppercase()),
        "project.rch-job-results-latest".to_owned(),
        "job-results".to_owned(),
    ] {
        assert!(!is_retention_basename(&name), "{name}");
        let path = format!("build/{name}/report.json");
        assert!(!is_internal_transfer_data(Path::new(&path)), "{path}");
        assert!(!exclusion.excludes(&path), "{path}");
        assert!(filters.selects(&path), "ordinary output was hidden: {path}");
    }
}

#[test]
fn retained_results_remain_excluded_when_config_and_priority_rules_change() {
    let _guard = rch_common::test_guard!();
    let directory = tempfile::tempdir().unwrap();
    let mut pipeline = pipeline(directory.path());
    let excludes = pipeline.get_effective_excludes();
    assert!(
        excludes
            .iter()
            .any(|pattern| pattern == RETENTION_EXCLUDE_PATTERN)
    );
    assert!(
        TransferPipeline::clean_overlay_namespace_excludes()
            .iter()
            .any(|pattern| pattern == RETENTION_EXCLUDE_PATTERN)
    );
    for explicit_includes in [false, true] {
        pipeline.sync_include_patterns =
            explicit_includes.then(|| vec!["*/".to_owned(), "*".to_owned()]);
        let mut command = Command::new("rsync");
        pipeline.append_sync_filter_args(&mut command, &excludes);
        assert_excluded_before_includes(&command);
    }
    let patterns = vec!["+ **".to_owned()];
    for command in [
        pipeline.build_retrieve_command(&worker(), "/worker/source", &patterns),
        pipeline.build_retrieve_streaming_command(&worker(), "/worker/source", &patterns),
        pipeline.build_result_dir_retrieve_command(
            &worker(),
            "/worker/source",
            Path::new("reports"),
        ),
    ] {
        assert_excluded_before_includes(&command);
    }
}

#[test]
fn fresh_result_upload_protection_is_literal_and_precedes_include_only_selection() {
    let directory = tempfile::tempdir().unwrap();
    for explicit_includes in [false, true] {
        let mut pipeline = pipeline(directory.path());
        if explicit_includes {
            pipeline = pipeline.with_sync_include_patterns(vec!["*/".into(), "*".into()]);
        }
        let pipeline = pipeline
            .with_protected_job_result_dirs(&[
                PathBuf::from("reports"),
                PathBuf::from("nested/out[1]"),
            ])
            .unwrap();
        let effective = pipeline.get_effective_excludes();
        for pattern in [
            "/reports",
            "/reports/***",
            "/nested/out\\[1]",
            "/nested/out\\[1]/***",
        ] {
            assert!(effective.iter().any(|actual| actual == pattern));
            assert!(
                pipeline
                    .source_content_priority_excludes()
                    .iter()
                    .any(|actual| actual == pattern)
            );
        }
        let mut command = Command::new("rsync");
        pipeline.append_sync_filter_args(&mut command, &effective);
        let args: Vec<_> = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        for pattern in ["/reports", "/nested/out\\[1]"] {
            let excluded = args
                .windows(2)
                .position(|args| args[0] == "--exclude" && args[1] == pattern)
                .unwrap();
            if let Some(included) = args.iter().position(|arg| arg == "--include") {
                assert!(excluded < included);
            }
        }
    }
    for dirs in [
        vec![PathBuf::from("../reports")],
        vec![PathBuf::from("reports"), PathBuf::from("reports/shards")],
    ] {
        assert!(
            pipeline(directory.path())
                .with_protected_job_result_dirs(&dirs)
                .is_err()
        );
    }
    assert!(
        pipeline(directory.path())
            .with_protected_job_result_dirs(&[])
            .is_ok()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn fresh_result_directories_survive_source_sync_before_preparation() {
    let _guard = rch_common::test_guard!();
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    let remote = directory.path().join("worker");
    for (base, relative, contents) in [
        (&source, "reports/same.json", b"caller result".as_slice()),
        (
            &source,
            "reports/new.json",
            b"caller-only result".as_slice(),
        ),
        (
            &remote,
            "reports/same.json",
            b"previous worker result".as_slice(),
        ),
        (
            &remote,
            "reports/old.json",
            b"previous worker-only result".as_slice(),
        ),
        (
            &source,
            "nested/out[1]/same.json",
            b"caller nested result".as_slice(),
        ),
        (
            &remote,
            "nested/out[1]/same.json",
            b"previous nested result".as_slice(),
        ),
        (&remote, "absent/old.json", b"no local directory".as_slice()),
        (
            &source,
            "nested/out1/ordinary.json",
            b"literal sibling".as_slice(),
        ),
        (&source, "src/main.rs", b"current source".as_slice()),
    ] {
        let path = base.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    for explicit_includes in [false, true] {
        let mut pipeline = pipeline(&source);
        if explicit_includes {
            pipeline = pipeline.with_sync_include_patterns(vec!["*/".into(), "*".into()]);
        }
        let pipeline = pipeline
            .with_protected_job_result_dirs(&[
                PathBuf::from("reports"),
                PathBuf::from("nested/out[1]"),
                PathBuf::from("absent"),
            ])
            .unwrap();
        std::fs::write(remote.join("obsolete-source"), b"old source").unwrap();
        let mut command = Command::new("rsync");
        command.args(["-a", "--checksum", "--delete"]);
        pipeline.append_sync_filter_args(&mut command, &pipeline.get_effective_excludes());
        let output = command
            .arg(format!("{}/", source.display()))
            .arg(format!("{}/", remote.display()))
            .output()
            .await
            .expect("run pre-preparation output protection regression (requires rsync)");
        assert!(output.status.success(), "{output:?}");
        for (relative, expected) in [
            ("reports/same.json", b"previous worker result".as_slice()),
            (
                "reports/old.json",
                b"previous worker-only result".as_slice(),
            ),
            (
                "nested/out[1]/same.json",
                b"previous nested result".as_slice(),
            ),
            ("absent/old.json", b"no local directory".as_slice()),
            ("nested/out1/ordinary.json", b"literal sibling".as_slice()),
            ("src/main.rs", b"current source".as_slice()),
        ] {
            assert_eq!(
                std::fs::read(remote.join(relative)).unwrap(),
                expected,
                "{relative}"
            );
        }
        assert!(!remote.join("reports/new.json").exists());
        assert!(!remote.join("obsolete-source").exists());
    }
}

#[tokio::test]
async fn retained_result_roots_are_refused_before_any_transfer_or_destination_creation() {
    let directory = tempfile::tempdir().unwrap();
    let local = directory.path().join("not-created");
    let reserved = format!("project.rch-job-results-{PLAN_ID}");
    for pipeline in [
        pipeline(&local).with_remote_path_override(format!("/worker/{reserved}/old")),
        pipeline(&local.join(&reserved)).with_remote_path_override("/worker/source"),
    ] {
        let worker = worker();
        let patterns = vec!["+ **".to_owned()];
        for error in [
            pipeline.sync_to_remote(&worker).await.unwrap_err(),
            pipeline
                .sync_to_remote_streaming(&worker, |_| {})
                .await
                .unwrap_err(),
            pipeline
                .retrieve_artifacts(&worker, &patterns)
                .await
                .unwrap_err(),
            pipeline
                .retrieve_artifacts_streaming(&worker, &patterns, |_| {})
                .await
                .unwrap_err(),
            pipeline
                .retrieve_result_dir(&worker, Path::new("reports"))
                .await
                .unwrap_err(),
        ] {
            assert!(
                error.to_string().contains("retained job results"),
                "{error:#}"
            );
        }
        assert!(
            pipeline
                .validate_staged_artifact_paths(&[], &patterns)
                .is_err()
        );
    }
    let pipeline = pipeline(&local);
    for relative in [&reserved, &format!("reports/{reserved}/old")] {
        assert!(
            pipeline
                .retrieve_result_dir(&worker(), Path::new(relative))
                .await
                .unwrap_err()
                .to_string()
                .contains("retained job results")
        );
    }
    assert!(!local.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn retained_nested_results_survive_parent_rsync_delete_and_artifact_collection() {
    let _guard = rch_common::test_guard!();
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    let remote = directory.path().join("worker");
    let stage = directory.path().join("stage");
    let retained = format!("nested/project.rch-job-results-{PLAN_ID}/old/report.json");
    let remote_only = format!("nested/other.rch-job-results-{PLAN_ID}/old/report.json");
    let source_only = format!("nested/local.rch-job-results-{PLAN_ID}/old/report.json");
    let lookalike = format!("nested/project.rch-job-results-{PLAN_ID}.json/report.json");
    for (base, relative, contents) in [
        (
            &source,
            retained.as_str(),
            b"caller private bytes".as_slice(),
        ),
        (
            &remote,
            retained.as_str(),
            b"retained worker bytes".as_slice(),
        ),
        (
            &remote,
            remote_only.as_str(),
            b"worker only bytes".as_slice(),
        ),
        (
            &source,
            source_only.as_str(),
            b"local only bytes".as_slice(),
        ),
        (&source, lookalike.as_str(), b"ordinary report".as_slice()),
        (
            &source,
            "nested/project/main.rs",
            b"current source".as_slice(),
        ),
    ] {
        let path = base.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    let mut pipeline = pipeline(&source);
    for explicit_includes in [false, true] {
        pipeline.sync_include_patterns =
            explicit_includes.then(|| vec!["*/".to_owned(), "*".to_owned()]);
        std::fs::write(remote.join("obsolete-source"), b"obsolete").unwrap();
        let mut command = Command::new("rsync");
        command.args(["-a", "--checksum", "--delete"]);
        pipeline.append_sync_filter_args(&mut command, &pipeline.get_effective_excludes());
        let output = command
            .arg(format!("{}/", source.display()))
            .arg(format!("{}/", remote.display()))
            .output()
            .await
            .expect("run retained-results transfer regression (requires rsync)");
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            std::fs::read(remote.join(&retained)).unwrap(),
            b"retained worker bytes"
        );
        assert_eq!(
            std::fs::read(remote.join(&remote_only)).unwrap(),
            b"worker only bytes"
        );
        assert!(!remote.join(&source_only).exists());
        assert!(!remote.join("obsolete-source").exists());
        assert_eq!(
            std::fs::read(remote.join(&lookalike)).unwrap(),
            b"ordinary report"
        );
        assert_eq!(
            std::fs::read(remote.join("nested/project/main.rs")).unwrap(),
            b"current source"
        );
    }
    std::fs::create_dir(&stage).unwrap();
    let output = pipeline
        .with_local_root(stage.clone())
        .local_artifact_retrieval_for_test(&worker(), &remote, &["+ **".to_owned()])
        .output()
        .await
        .expect("run retained-results artifact regression (requires rsync)");
    assert!(output.status.success(), "{output:?}");
    assert!(!stage.join(&retained).exists());
    assert!(!stage.join(&remote_only).exists());
    assert!(!stage.join(&source_only).exists());
    assert_eq!(
        std::fs::read(stage.join(&lookalike)).unwrap(),
        b"ordinary report"
    );
}
