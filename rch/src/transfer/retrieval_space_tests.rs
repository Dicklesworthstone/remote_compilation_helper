//! Real local-rsync regressions through the production retrieval builders and
//! budget planner. The only substituted boundary is the worker source operand;
//! no SSH, compilation, daemon release or terminal acknowledgment is claimed.

use super::*;
use rch_common::{WorkerId, test_guard};
use std::fs::{File, FileTimes};
use std::os::unix::fs::MetadataExt;

#[tokio::test]
async fn platform_probe_reads_only_headers_of_a_large_suite_without_materializing_outputs() {
    let _guard = test_guard!();
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let worker = root.path().join("worker λ with ' quote");
    let stage = root.path().join("stage");
    std::fs::create_dir_all(&worker).unwrap();
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("sentinel"), b"caller owned").unwrap();
    let paths: Vec<String> = (0..1040).map(|n| format!("test-{n}")).collect();
    for path in &paths {
        let mut file = File::create(worker.join(path)).unwrap();
        std::io::Write::write_all(&mut file, b"\x7fELF").unwrap();
        // Sparse payload: the regression must never read/copy these 54 GB.
        file.set_len(52_000_000).unwrap();
    }
    let (_, pipeline, config) = fixture();
    let pipeline = pipeline.with_local_root(stage.clone());
    for _ in 0..2 {
        // The second pass models a recovery attempt: probing never consumes
        // remote outputs or modifies already-owned local artifacts.
        let mut selection = artifact_header_selection_command(
            pipeline.local_artifact_retrieval_for_test(&config, &worker, &["test-*".into()]),
        );
        assert!(!selection.as_std().get_args().any(|arg| arg == "--checksum"));
        let selected = tokio::time::timeout(Duration::from_secs(10), selection.output())
            .await
            .unwrap()
            .unwrap();
        assert!(selected.status.success(), "{selected:?}");
        assert_eq!(
            parse_rsync_selected_size(&String::from_utf8_lossy(&selected.stdout)),
            Some(1040 * 52_000_000)
        );
        let selected_paths =
            parse_rsync_itemized_regular_files(&String::from_utf8_lossy(&selected.stdout));
        assert_eq!(selected_paths.len(), 1040);
        let script =
            artifact_header_probe_script(worker.to_str().unwrap(), None, &selected_paths).unwrap();
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let headers: Vec<(String, Vec<u8>)> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(headers.len(), 1040);
        assert_eq!(
            headers.iter().map(|(_, h)| h.len()).sum::<usize>(),
            1040 * 64
        );
        assert!(headers.iter().all(|(_, h)| h.starts_with(b"\x7fELF")));
        assert_eq!(std::fs::read_dir(&stage).unwrap().count(), 1);
        assert_eq!(
            std::fs::read(stage.join("sentinel")).unwrap(),
            b"caller owned"
        );
    }
    std::os::unix::fs::symlink(stage.join("sentinel"), worker.join("escape")).unwrap();
    // A lexically unsafe path is refused before any probe is built.
    assert!(
        artifact_header_probe_script(
            worker.to_str().unwrap(),
            None,
            &["../stage/sentinel".into()]
        )
        .is_err()
    );
    // One that escapes only through a symlink is refused by the probe itself.
    let script =
        artifact_header_probe_script(worker.to_str().unwrap(), None, &["escape".into()]).unwrap();
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    assert!(!output.status.success());

    // Ordinary intermediate symlinks are never followed, even when their
    // referent remains under the selected root. Cargo's managed target alias
    // is the sole exception and must bind the separately authorized root.
    std::fs::create_dir_all(worker.join("real/deps")).unwrap();
    std::fs::write(worker.join("real/deps/native"), b"\x7fELF").unwrap();
    std::os::unix::fs::symlink(worker.join("real"), worker.join("link")).unwrap();
    let script =
        artifact_header_probe_script(worker.to_str().unwrap(), None, &["link/deps/native".into()])
            .unwrap();
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    assert!(!output.status.success());

    let managed = root.path().join("managed-target");
    std::fs::create_dir_all(managed.join("debug/deps")).unwrap();
    std::fs::write(managed.join("debug/deps/native"), b"\x7fELF").unwrap();
    std::os::unix::fs::symlink(&managed, worker.join("target")).unwrap();
    let script = artifact_header_probe_script(
        worker.to_str().unwrap(),
        Some(managed.to_str().unwrap()),
        &["target/debug/deps/native".into()],
    )
    .unwrap();
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let headers: Vec<(String, Vec<u8>)> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(headers[0].0, "target/debug/deps/native");
    assert!(headers[0].1.starts_with(b"\x7fELF"));

    let wrong = root.path().join("wrong-target");
    std::fs::create_dir_all(&wrong).unwrap();
    let script = artifact_header_probe_script(
        worker.to_str().unwrap(),
        Some(wrong.to_str().unwrap()),
        &["target/debug/deps/native".into()],
    )
    .unwrap();
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    assert!(!output.status.success());
}

fn fixture() -> (PathBuf, TransferPipeline, WorkerConfig) {
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap()
        .keep();
    let caller = root.join("caller");
    let worker = root.join("worker");
    let stage = root.join("stage");
    for directory in [&caller, &worker, &stage] {
        std::fs::create_dir_all(directory.join("build")).unwrap();
    }
    let worker_config = WorkerConfig {
        id: WorkerId::new("retrieval-space-fixture"),
        host: "unreachable.invalid".into(),
        user: "worker".into(),
        identity_file: "/unused/test-key".into(),
        total_slots: 1,
        priority: 100,
        tags: Vec::new(),
        tools: Vec::new(),
    };
    let config = TransferConfig {
        max_transfer_time_ms: Some(900_000),
        ..Default::default()
    };
    let mut pipeline = TransferPipeline::new(
        stage,
        "storage-fixture".into(),
        "storage-fixture".into(),
        config,
    )
    .with_retrieval_reference_root(caller);
    pipeline.ssh_options.control_master = false;
    (root, pipeline, worker_config)
}

fn command(pipeline: &TransferPipeline, worker: &WorkerConfig, root: &Path) -> Command {
    let mut command = pipeline.local_artifact_retrieval_for_test(
        worker,
        &root.join("worker"),
        &default_c_cpp_artifact_patterns(),
    );
    command.env("LC_ALL", "C");
    command
}

/// Preserve every production result-directory argument and replace only the
/// remote source operand with this test's owned local worker directory.
fn result_command(
    pipeline: &TransferPipeline,
    worker: &WorkerConfig,
    root: &Path,
    relative: &Path,
) -> Command {
    let planned = pipeline.build_result_dir_retrieve_command(
        worker,
        root.join("worker").to_str().unwrap(),
        relative,
    );
    let planned = planned.as_std();
    let args: Vec<_> = planned.get_args().collect();
    let mut command = Command::new(planned.get_program());
    command
        .args(&args[..args.len() - 2])
        .arg(format!("{}/", root.join("worker").join(relative).display()))
        .arg(args.last().unwrap())
        .env("LC_ALL", "C");
    command
}

async fn run(command: &mut Command) -> std::process::Output {
    command.stdin(Stdio::null()).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .expect("local rsync storage regression timed out")
        .expect("rsync is required for this regression");
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    output
}

#[test]
fn artifact_and_declared_result_collectors_use_the_same_integrity_policy() {
    let _guard = test_guard!();
    let (root, pipeline, worker) = fixture();
    let argument = TransferPipeline::artifact_integrity_arg(pipeline.resolved_rsync().flavor);
    for built in [
        pipeline.build_retrieve_command(
            &worker,
            root.to_str().unwrap(),
            &default_c_cpp_artifact_patterns(),
        ),
        pipeline.build_retrieve_streaming_command(
            &worker,
            root.to_str().unwrap(),
            &default_c_cpp_artifact_patterns(),
        ),
        pipeline.build_result_dir_retrieve_command(
            &worker,
            root.to_str().unwrap(),
            Path::new("reports/gates"),
        ),
    ] {
        assert!(built.as_std().get_args().any(|actual| actual == argument));
        assert!(!built.as_std().get_args().any(|argument| {
            matches!(
                argument.to_str(),
                Some("--inplace" | "--append" | "--size-only")
            )
        }));
    }
}

#[tokio::test]
async fn declared_result_recovery_repairs_equal_metadata_without_touching_caller_outputs() {
    let _guard = test_guard!();
    let (root, pipeline, worker) = fixture();
    let relative = Path::new("reports/gates");
    let remote = root.join("worker").join(relative);
    let stage = root.join("stage").join(relative);
    let caller = root.join("caller").join(relative);
    for directory in [&remote, &stage, &caller] {
        std::fs::create_dir_all(directory).unwrap();
    }
    std::fs::write(remote.join("conformance.txt"), b"PASS\n").unwrap();
    std::fs::write(stage.join("conformance.txt"), b"FAIL\n").unwrap();
    std::fs::write(caller.join("conformance.txt"), b"previous caller report\n").unwrap();
    std::fs::write(remote.join("fixture.bin"), [0, 255, 13, 10, 0]).unwrap();
    std::fs::write(remote.join("empty-result"), b"").unwrap();
    for directory in [&remote, &remote.join("nested")] {
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            directory.join(".rch-clean-overlay-base.tar"),
            b"immutable source input",
        )
        .unwrap();
    }
    let timestamp = std::fs::metadata(remote.join("conformance.txt"))
        .unwrap()
        .modified()
        .unwrap();
    File::options()
        .write(true)
        .open(stage.join("conformance.txt"))
        .unwrap()
        .set_times(FileTimes::new().set_modified(timestamp))
        .unwrap();
    let caller_inode = std::fs::metadata(caller.join("conformance.txt"))
        .unwrap()
        .ino();

    // The dry run is read-only. Current staging must not be treated as proof
    // of the successful conformance report merely because metadata matches.
    let mut estimate = result_command(&pipeline, &worker, &root, relative);
    estimate.arg("--dry-run");
    run(&mut estimate).await;
    assert_eq!(
        std::fs::read(stage.join("conformance.txt")).unwrap(),
        b"FAIL\n"
    );
    assert!(!stage.join("fixture.bin").exists());
    run(&mut result_command(&pipeline, &worker, &root, relative)).await;
    for name in ["conformance.txt", "fixture.bin", "empty-result"] {
        assert_eq!(
            std::fs::read(stage.join(name)).unwrap(),
            std::fs::read(remote.join(name)).unwrap()
        );
    }
    for directory in [Path::new(""), Path::new("nested")] {
        assert!(
            !stage
                .join(directory)
                .join(".rch-clean-overlay-base.tar")
                .exists()
        );
        assert_eq!(
            std::fs::read(remote.join(directory).join(".rch-clean-overlay-base.tar")).unwrap(),
            b"immutable source input"
        );
    }
    assert_eq!(
        std::fs::read(caller.join("conformance.txt")).unwrap(),
        b"previous caller report\n"
    );
    assert_eq!(
        std::fs::metadata(caller.join("conformance.txt"))
            .unwrap()
            .ino(),
        caller_inode
    );
}

#[tokio::test]
async fn declared_result_integrity_preserves_missing_and_empty_directory_semantics() {
    let _guard = test_guard!();
    let (root, pipeline, worker) = fixture();
    let parent = root.join("stage/reports");
    std::fs::create_dir_all(&parent).unwrap();
    let missing = Path::new("reports/missing");
    let mut command = result_command(&pipeline, &worker, &root, missing);
    command.stdin(Stdio::null()).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .expect("missing result-directory probe timed out")
        .expect("rsync is required for this regression");
    assert!(
        !output.status.success(),
        "absent required source became success"
    );
    assert!(!root.join("worker").join(missing).exists());
    // An existing empty source is different: no required-file contract was
    // admitted, and zero files must not turn this into a failed collection.
    let empty = Path::new("reports/empty");
    std::fs::create_dir_all(root.join("worker").join(empty)).unwrap();
    run(&mut result_command(&pipeline, &worker, &root, empty)).await;
    assert!(root.join("stage").join(empty).is_dir());
    assert_eq!(
        std::fs::read_dir(root.join("stage").join(empty))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn openrsync_and_unknown_flavours_force_full_refresh_instead_of_metadata_reuse() {
    for flavor in [
        RsyncFlavor::Rsync {
            major: 2,
            minor: 6,
            patch: 9,
        },
        RsyncFlavor::Rsync {
            major: 3,
            minor: 4,
            patch: 1,
        },
    ] {
        assert_eq!(
            TransferPipeline::artifact_integrity_arg(flavor),
            "--checksum"
        );
    }
    for flavor in [
        RsyncFlavor::OpenRsync { protocol: Some(29) },
        RsyncFlavor::Unknown,
    ] {
        assert_eq!(
            TransferPipeline::artifact_integrity_arg(flavor),
            "--ignore-times"
        );
    }
}

#[tokio::test]
async fn integrity_plan_repairs_equal_metadata_and_credits_only_verified_staged_files() {
    let _guard = test_guard!();
    let (root, pipeline, worker) = fixture();
    let worker_root = root.join("worker");
    let stage = root.join("stage");
    let checksummed =
        TransferPipeline::artifact_integrity_arg(pipeline.resolved_rsync().flavor) == "--checksum";
    let retained = vec![7_u8; 2 * 1024 * 1024];
    let replaced = vec![9_u8; 128 * 1024];
    for (name, bytes) in [
        ("retained.o", retained.as_slice()),
        ("changed.o", replaced.as_slice()),
    ] {
        std::fs::write(worker_root.join("build").join(name), bytes).unwrap();
    }
    std::fs::copy(
        worker_root.join("build/retained.o"),
        stage.join("build/retained.o"),
    )
    .unwrap();
    // Wrong bytes with EXACTLY the right size and timestamp: a quick-check
    // no-op must not count as content-verified staging or successful delivery.
    std::fs::write(stage.join("build/changed.o"), vec![3_u8; replaced.len()]).unwrap();
    for name in ["retained.o", "changed.o"] {
        let modified = std::fs::metadata(worker_root.join("build").join(name))
            .unwrap()
            .modified()
            .unwrap();
        File::options()
            .write(true)
            .open(stage.join("build").join(name))
            .unwrap()
            .set_times(FileTimes::new().set_modified(modified))
            .unwrap();
    }
    std::fs::write(worker_root.join("build/report.txt"), b"PASS\n").unwrap();
    std::fs::write(
        worker_root.join("build/.rch-clean-overlay-base.tar"),
        b"immutable input",
    )
    .unwrap();
    let inode = std::fs::metadata(stage.join("build/retained.o"))
        .unwrap()
        .ino();
    let mut dry_run = command(&pipeline, &worker, &root);
    dry_run.arg("--dry-run");
    let output = run(&mut dry_run).await;
    let selected_bytes = (retained.len() + replaced.len() + 5) as u64;
    if checksummed {
        let plan = retrieval_space::RsyncStoragePlan::parse(&output.stdout).unwrap();
        assert_eq!(plan.selected_bytes, selected_bytes);
        assert_eq!(plan.replacement_bytes, replaced.len() as u64 + 5);
        assert!(plan.additional_bytes(4096).unwrap() < plan.selected_bytes);
    }
    assert_eq!(
        std::fs::read(stage.join("build/changed.o")).unwrap(),
        vec![3; replaced.len()]
    );
    assert!(!stage.join("build/report.txt").exists());

    // Exercise the actual planning method, not just a duplicate stats parser.
    let budget = pipeline
        .retrieval_retry_config_inner(|| command(&pipeline, &worker, &root), checksummed)
        .await
        .unwrap();
    assert_eq!(
        budget.total_timeout_ms, 900_000,
        "allocation credit must not shorten the transfer deadline"
    );
    run(&mut command(&pipeline, &worker, &root)).await;
    assert_eq!(
        std::fs::read(stage.join("build/changed.o")).unwrap(),
        replaced
    );
    assert_eq!(
        std::fs::read(stage.join("build/retained.o")).unwrap(),
        retained
    );
    if checksummed {
        assert_eq!(
            std::fs::metadata(stage.join("build/retained.o"))
                .unwrap()
                .ino(),
            inode
        );
    }
    assert_eq!(
        std::fs::read(stage.join("build/report.txt")).unwrap(),
        b"PASS\n"
    );
    assert!(!stage.join("build/.rch-clean-overlay-base.tar").exists());

    let mut complete = command(&pipeline, &worker, &root);
    complete.arg("--dry-run");
    let output = run(&mut complete).await;
    if checksummed {
        let finished = retrieval_space::RsyncStoragePlan::parse(&output.stdout).unwrap();
        assert_eq!(finished.selected_bytes, selected_bytes);
        assert_eq!(finished.additional_bytes(4096), Some(0));
    }
}

#[tokio::test]
async fn insufficient_reserve_refuses_before_collection_without_mutating_staging() {
    let _guard = test_guard!();
    let (root, mut pipeline, worker) = fixture();
    let stage = root.join("stage/build/retained.o");
    std::fs::write(&stage, b"retained evidence").unwrap();
    std::fs::write(root.join("worker/build/new.o"), b"new output").unwrap();
    pipeline.transfer_config.retrieval_min_free_bytes = u64::MAX;
    let before = std::fs::metadata(&stage).unwrap();
    let checksummed =
        TransferPipeline::artifact_integrity_arg(pipeline.resolved_rsync().flavor) == "--checksum";
    let result = pipeline
        .retrieval_retry_config_inner(|| command(&pipeline, &worker, &root), checksummed)
        .await;
    assert!(result.is_err());
    assert!(!root.join("stage/build/new.o").exists());
    assert_eq!(std::fs::read(&stage).unwrap(), b"retained evidence");
    assert_eq!(std::fs::metadata(&stage).unwrap().ino(), before.ino());
    assert_eq!(
        std::fs::read(root.join("worker/build/new.o")).unwrap(),
        b"new output"
    );
}
