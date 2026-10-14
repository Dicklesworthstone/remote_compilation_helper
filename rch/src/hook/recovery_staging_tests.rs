//! Real Make, rsync, journal and publisher integration. Source-grant identity
//! is fixture input: these tests do not contact a worker or fabricate release
//! receipts. Neither successful collection nor relocation may acknowledge it.
use super::*;
use std::os::unix::fs::MetadataExt;
use tokio::process::Command;

async fn run(command: &mut Command) -> std::process::Output {
    command.stdin(Stdio::null()).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .expect("owned Make/rsync staging fixture timed out")
        .expect("git, make, cc, ar and rsync are required for this regression");
    assert!(output.status.success(), "{output:?}");
    output
}

async fn recover_partial_publication(ram_caller: bool) {
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap()
        .keep()
        .canonicalize()
        .unwrap();
    let caller = if ram_caller {
        tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir_in("/dev/shm")
            .unwrap()
            .keep()
            .canonicalize()
            .unwrap()
    } else {
        let caller = root.join("caller");
        std::fs::create_dir(&caller).unwrap();
        caller
    };
    let remote = root.join("worker");
    std::fs::create_dir(&remote).unwrap();
    std::fs::write(caller.join("caller-source"), b"source sentinel").unwrap();
    std::fs::write(remote.join("program.c"), b"int main(void) { return 0; }\n").unwrap();
    std::fs::write(
        remote.join("Makefile"),
        concat!(
            ".PHONY: all\nall:\n",
            "\tmkdir -p build/nested out reports\n",
            "\t$(CC) program.c -o build/app\n",
            "\t$(CC) -c program.c -o build/delivered.o\n",
            "\tcp build/delivered.o out/pending.o\n",
            "\t$(AR) rcs build/libfixture.a build/delivered.o\n",
            "\tprintf 'build\\n' >> build/invocations\n",
            "\tprintf 'PASS\\n' > reports/summary.txt\n",
        ),
    )
    .unwrap();
    std::fs::copy(remote.join("program.c"), caller.join("program.c")).unwrap();
    std::fs::copy(remote.join("Makefile"), caller.join("Makefile")).unwrap();
    run(Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(&remote))
    .await;
    run(Command::new("git")
        .args(["add", "program.c", "Makefile"])
        .current_dir(&remote))
    .await;
    run(Command::new("git")
        .args([
            "-c",
            "user.name=RCH fixture",
            "-c",
            "user.email=rch-fixture@localhost",
            "commit",
            "-m",
            "owned staging fixture",
        ])
        .current_dir(&remote))
    .await;
    run(Command::new("git")
        .args([
            "archive",
            "--format=tar",
            "--output=.rch-clean-overlay-base.tar",
            "HEAD",
        ])
        .current_dir(&remote))
    .await;
    let archive = std::fs::read(remote.join(".rch-clean-overlay-base.tar")).unwrap();
    let worker = WorkerConfig {
        id: WorkerId::new("staging-relocation-fixture"),
        host: "unreachable.invalid".into(),
        user: "worker".into(),
        identity_file: "/unused/key".into(),
        total_slots: 1,
        priority: 100,
        tags: Vec::new(),
        tools: Vec::new(),
    };
    let writer =
        DurableLeaseWriter::create_in(&root.join("journals"), "make all", true, false).unwrap();
    writer.admit(41, &worker.id).unwrap();
    let identity = uuid::Uuid::new_v4().simple().to_string();
    let remote_name = remote.to_str().unwrap().to_owned();
    let retained = format!("{remote_name}.retained-{identity}");
    let source_roots = vec![remote_name.clone(), retained.clone()];
    let pair = Some((remote_name.clone(), identity.clone()));
    let config = TransferConfig {
        retrieval_staging_dir: Some(root.join("old-stage")),
        ..Default::default()
    };
    let pipeline = TransferPipeline::new(
        caller.clone(),
        "staging-fixture".into(),
        identity.clone(),
        config.clone(),
    )
    .with_remote_path_override(remote_name.clone());
    RecoverySession::begin(
        &writer,
        &worker,
        source_roots.clone(),
        pair.clone(),
        Some(remote_name.clone()),
        Some(retained.clone()),
        config.clone(),
        caller.clone(),
        identity.clone(),
    )
    .unwrap();
    let mut session = RecoverySession::prepare(
        &writer,
        &worker,
        &pipeline,
        source_roots,
        pair,
        Some(remote_name),
        Some(retained),
        config,
        caller.clone(),
        None,
        Some(CompilationKind::Make),
        "make all",
        &["reports".into()],
        identity.clone(),
    )
    .unwrap();
    session.starting_execution().unwrap();
    let outcome = run(Command::new("make").arg("all").current_dir(&remote)).await;
    session.completed(outcome.status.code().unwrap()).unwrap();
    std::fs::write(
        remote.join("build/nested/.rch-clean-overlay-base.tar"),
        &archive,
    )
    .unwrap();
    let old_stage = session.stage(0);
    let old_pipeline = session.staging_pipeline("project", &pipeline).unwrap();
    run(&mut old_pipeline.local_artifact_retrieval_for_test(
        &worker,
        &remote,
        &session.recipe.phases[0].patterns,
    ))
    .await;
    let reports = session
        .staging_pipeline("result:reports", &pipeline)
        .unwrap();
    run(&mut reports.local_artifact_retrieval_for_test(&worker, &remote, &["reports/**".into()]))
        .await;
    session.publish("result:reports").await.unwrap();
    let report = caller.join("reports/summary.txt");
    let report_inode = std::fs::metadata(&report).unwrap().ino();
    let done = PathBuf::from("build/delivered.o");
    let pending = PathBuf::from("out/pending.o");
    let temporary_name = format!(".rch-return-{identity}");
    let pending_temporary = caller.join("out").join(&temporary_name);
    let pending_hash = fingerprint(&old_stage.join(&pending)).unwrap().unwrap();
    {
        let _publication = lock_output_root(&caller).await.unwrap();
        session
            .persist_output_baseline(0, &[done.clone(), pending.clone()])
            .unwrap();
        for (relative, publish) in [(&done, true), (&pending, false)] {
            let destination = caller.join(relative);
            let temporary = destination.parent().unwrap().join(&temporary_name);
            let hash = fingerprint(&old_stage.join(relative)).unwrap().unwrap();
            let prepared =
                prepare_output_temporary(&old_stage.join(relative), &temporary, &hash).unwrap();
            prepared.directory.sync_all().unwrap();
            session
                .persist_pending_output(0, Some((relative.clone(), hash.clone())))
                .unwrap();
            if publish {
                prepared.publish(&destination).unwrap();
                session
                    .persist_published_output(0, relative.clone(), hash)
                    .unwrap();
            }
        }
    }
    let done_inode = std::fs::metadata(caller.join(&done)).unwrap().ino();
    let pending_inode = std::fs::metadata(&pending_temporary).unwrap().ino();
    // Model residue from an older, interrupted collector. Relocation must not
    // traverse or delete it, nor transplant it into the new output selection.
    let old_archive = old_stage.join(".rch-clean-overlay-base.tar");
    std::fs::write(&old_archive, &archive[..127]).unwrap();
    let old_link = old_stage.join("old-fixture-link");
    std::os::unix::fs::symlink(caller.join("caller-source"), &old_link).unwrap();
    let old_app = std::fs::read(old_stage.join("build/app")).unwrap();
    writer.record_exit(EXIT_ARTIFACT_TRANSFER_FAILED).unwrap();
    let before = std::fs::read(&writer.path).unwrap();
    let phases = serde_json::to_value(&session.recipe.phases).unwrap();
    let mut current = TransferConfig {
        retrieval_staging_dir: Some(root.join("full-stage")),
        retrieval_min_free_bytes: u64::MAX,
        max_transfer_time_ms: Some(900_000),
        ..Default::default()
    };
    assert!(relocate(&writer, &writer.wrapper_id(), &current).is_err());
    assert_eq!(std::fs::read(&writer.path).unwrap(), before);
    assert_eq!(
        std::fs::metadata(&pending_temporary).unwrap().ino(),
        pending_inode
    );
    assert!(!writer.snapshot().terminal_acknowledged);
    current.retrieval_staging_dir = Some(root.join("fresh-stage"));
    current.retrieval_min_free_bytes = 0;
    relocate(&writer, &writer.wrapper_id(), &current).unwrap();
    let mut recovered = RecoverySession {
        recipe: load_recipe(&writer).unwrap(),
        writer: writer.clone(),
    };
    assert_eq!(
        serde_json::to_value(&recovered.recipe.phases).unwrap(),
        phases
    );
    recovered.apply_retrieval_config(&current).unwrap();
    let fresh = recovered.stage(0);
    assert!(!fresh.starts_with(&caller));
    let staged = recovered.staging_pipeline("project", &pipeline).unwrap();
    // A fresh-stage retry still has to repair partial bytes, not accept their
    // presence as delivery. This is injected residue, not a live SSH timeout.
    std::fs::create_dir_all(fresh.join("build")).unwrap();
    std::fs::write(fresh.join("build/app"), &old_app[..127]).unwrap();
    assert!(!recovered.recipe.phases[0].complete);
    assert!(!writer.snapshot().terminal_acknowledged);
    run(&mut staged.local_artifact_retrieval_for_test(
        &worker,
        &remote,
        &recovered.recipe.phases[0].patterns,
    ))
    .await;
    assert!(!fresh.join(".rch-clean-overlay-base.tar").exists());
    assert!(
        !fresh
            .join("build/nested/.rch-clean-overlay-base.tar")
            .exists()
    );
    assert!(!fresh.join("old-fixture-link").exists());
    recovered.publish("project").await.unwrap();
    recovered.publish("result:reports").await.unwrap();
    recovered.returned(0).unwrap();
    assert_eq!(
        std::fs::metadata(caller.join(&done)).unwrap().ino(),
        done_inode
    );
    assert_eq!(
        std::fs::metadata(caller.join(&pending)).unwrap().ino(),
        pending_inode
    );
    assert_eq!(
        fingerprint(&caller.join(&pending)).unwrap(),
        Some(pending_hash)
    );
    assert_eq!(std::fs::metadata(&report).unwrap().ino(), report_inode);
    assert_eq!(std::fs::read(&report).unwrap(), b"PASS\n");
    assert!(
        !recovered.stage(1).exists(),
        "completed report was recollected"
    );
    for relative in ["build/app", "build/libfixture.a", "build/invocations"] {
        assert_eq!(
            std::fs::read(caller.join(relative)).unwrap(),
            std::fs::read(remote.join(relative)).unwrap()
        );
    }
    assert_eq!(std::fs::read(old_stage.join("build/app")).unwrap(), old_app);
    assert_eq!(std::fs::read(&old_archive).unwrap(), archive[..127]);
    assert_eq!(
        std::fs::read_link(&old_link).unwrap(),
        caller.join("caller-source")
    );
    assert_eq!(
        std::fs::read(remote.join(".rch-clean-overlay-base.tar")).unwrap(),
        archive
    );
    assert_eq!(
        std::fs::read(remote.join("build/invocations")).unwrap(),
        b"build\n"
    );
    assert_eq!(
        std::fs::read(caller.join("caller-source")).unwrap(),
        b"source sentinel"
    );
    assert!(!recovered.recipe.sources_released);
    assert!(writer.acknowledge_terminal().is_err());
    assert_eq!(
        writer.snapshot().exit_code,
        Some(EXIT_ARTIFACT_TRANSFER_FAILED)
    );
    let committed = std::fs::read(&writer.path).unwrap();
    relocate(&writer, &writer.wrapper_id(), &current).unwrap();
    assert_eq!(std::fs::read(&writer.path).unwrap(), committed);
}

#[tokio::test]
async fn make_collection_relocates_after_partial_publication_without_replay() {
    recover_partial_publication(false).await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ram_caller_recovers_to_explicit_staging_without_losing_checkpoints() {
    // Do not execute the delivered binary: /dev/shm is often mounted noexec.
    // Exact bytes, publication checkpoints and ownership are checked instead.
    recover_partial_publication(true).await;
}
