//! The production publisher's predecessor lifetime, rollback and old-journal
//! compatibility. Remote completion is fixture input; files, locks, journal
//! writes, cancellation and same-id publication are real local operations.
use super::*;
use std::os::unix::fs::{MetadataExt, symlink};

fn predecessor(index: usize) -> String {
    format!("previous output {index}\n")
}

fn old_outputs(session: &mut RecoverySession, count: usize, obsolete: usize) {
    let local = session.recipe.phases[0].local.clone();
    std::fs::create_dir_all(local.join("doc")).unwrap();
    for index in 0..count {
        std::fs::write(local.join(relative(index)), predecessor(index)).unwrap();
        session.recipe.phases[0].baseline.insert(
            relative(index),
            fingerprint(&local.join(relative(index))).unwrap().unwrap(),
        );
    }
    // Legacy journals can have a preparation-wide inventory, including files
    // unrelated to this invocation. These hashes are explicit old-state input.
    for index in 0..obsolete {
        session.recipe.phases[0].baseline.insert(
            PathBuf::from(format!("other-profile/obsolete-{index:05}.rlib")),
            blake3::hash(format!("old unrelated {index}").as_bytes())
                .to_hex()
                .to_string(),
        );
    }
    session.persist().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn preparation_does_not_fingerprint_a_reused_local_output_inventory() {
    let _guard = test_guard!();
    let directory = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let local = directory.path().join("caller");
    std::fs::create_dir_all(local.join("doc")).unwrap();
    for index in 0..2048 {
        std::fs::write(local.join(relative(index)), predecessor(index)).unwrap();
    }
    let outside = directory.path().join("unrelated-output");
    std::fs::write(&outside, b"outside this invocation").unwrap();
    let alias = local.join("doc/unselected.html");
    symlink(&outside, &alias).unwrap();
    // The removed glob/hash pass rejected this existing symlink. Preparation
    // must not inspect unselected destination bytes or use them as authority.
    // Publication still rejects a symlink when that destination IS selected.
    let worker = WorkerConfig {
        id: WorkerId::new("baseline-preparation"),
        host: "unreachable.invalid".into(),
        user: "worker".into(),
        identity_file: "/unused/key".into(),
        total_slots: 1,
        priority: 100,
        tags: Vec::new(),
        tools: Vec::new(),
    };
    let writer = DurableLeaseWriter::create_in(
        &directory.path().join("journals"),
        "fixture-results",
        true,
        false,
    )
    .unwrap();
    writer.admit(41, &worker.id).unwrap();
    let identity = uuid::Uuid::new_v4().simple().to_string();
    let remote = "/data/projects/baseline-preparation".to_owned();
    let transfer = TransferConfig {
        retrieval_staging_dir: Some(directory.path().join("staging")),
        ..Default::default()
    };
    let pipeline = TransferPipeline::new(
        local.clone(),
        "baseline-preparation".into(),
        identity.clone(),
        transfer.clone(),
    )
    .with_remote_path_override(remote.clone());
    RecoverySession::begin(
        &writer,
        &worker,
        vec![remote.clone()],
        None,
        None,
        None,
        transfer.clone(),
        local.clone(),
        identity.clone(),
    )
    .unwrap();
    let mut session = RecoverySession::prepare(
        &writer,
        &worker,
        &pipeline,
        vec![remote],
        None,
        None,
        None,
        transfer,
        local.clone(),
        None,
        None,
        "fixture-results",
        &[PathBuf::from("doc")],
        identity,
    )
    .unwrap();
    assert!(
        session
            .recipe
            .phases
            .iter()
            .all(|phase| phase.baseline.is_empty())
    );
    assert_acknowledged(&session);
    let phase_index = session
        .recipe
        .phases
        .iter()
        .position(|phase| phase.name == "result:doc")
        .unwrap();
    session.staging_pipeline("result:doc", &pipeline).unwrap();
    let stage = session.stage(phase_index);
    std::fs::create_dir_all(stage.join("doc")).unwrap();
    std::fs::write(stage.join(relative(0)), bytes(0)).unwrap();
    // A concurrent build may replace an output during remote execution. Only
    // the lock-held publication observation is the relevant predecessor.
    let later = b"another build completed after preparation";
    std::fs::write(local.join(relative(0)), later).unwrap();
    session.starting_execution().unwrap();
    session.completed(0).unwrap();
    let error = session
        .publish_with_observer("result:doc", |point, _| {
            anyhow::ensure!(
                point != PublicationPoint::PendingDurable,
                "pending boundary fixture"
            );
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("pending boundary fixture"));
    let phase = &session.recipe.phases[phase_index];
    assert_eq!(phase.baseline.len(), 1);
    assert_eq!(
        phase.baseline[&relative(0)],
        blake3::hash(later).to_hex().to_string()
    );
    assert!(phase.pending.is_some());
    assert_eq!(std::fs::read(local.join(relative(0))).unwrap(), later);
    assert_acknowledged(&session);
    session.publish("result:doc").await.unwrap();
    assert!(session.recipe.phases[phase_index].baseline.is_empty());
    assert!(session.recipe.phases[phase_index].complete);
    assert_eq!(
        std::fs::read_to_string(local.join(relative(0))).unwrap(),
        bytes(0)
    );
    for index in 1..2048 {
        assert_eq!(
            std::fs::read_to_string(local.join(relative(index))).unwrap(),
            predecessor(index)
        );
    }
    assert_eq!(std::fs::read_link(alias).unwrap(), outside);
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside this invocation");
    assert_acknowledged(&session);
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_baselines_shrink_at_real_durable_publication_boundaries() {
    let _guard = test_guard!();
    let (directory, mut session) = docs(64);
    old_outputs(&mut session, 64, 4096);
    let local = session.recipe.phases[0].local.clone();
    let untouched = local.join("other-profile/obsolete-00000.rlib");
    std::fs::create_dir_all(untouched.parent().unwrap()).unwrap();
    std::fs::write(&untouched, b"unrelated old target artifact").unwrap();
    let journal = session.writer.path.clone();
    let mut published = 0;
    let result = session
        .publish_with_observer("docs", move |point, _| {
            if point == PublicationPoint::PendingDurable
                || point == PublicationPoint::PublishedDurable
            {
                if point == PublicationPoint::PublishedDurable {
                    published += 1;
                }
                let lease: DurableJobLease = serde_json::from_slice(&std::fs::read(&journal)?)?;
                let recipe: RecoveryRecipe = serde_json::from_value(lease.recovery.unwrap())?;
                let phase = &recipe.phases[0];
                assert_eq!(phase.published.len(), published);
                assert_eq!(phase.baseline.len(), 64 - published);
                assert!(phase.baseline.keys().all(|path| path.starts_with("doc")));
                assert!(
                    phase
                        .baseline
                        .keys()
                        .all(|path| !phase.published.contains_key(path))
                );
                assert_eq!(
                    phase.pending.is_some(),
                    point == PublicationPoint::PendingDurable
                );
                if let Some((path, _)) = &phase.pending {
                    assert!(phase.baseline.contains_key(path));
                }
                anyhow::ensure!(published != 23, "interruption after 23 durable outputs");
            }
            Ok(())
        })
        .await;
    assert!(result.unwrap_err().to_string().contains("23 durable"));
    assert_eq!(session.recipe.phases[0].published.len(), 23);
    assert_eq!(session.recipe.phases[0].baseline.len(), 41);
    assert_acknowledged(&session);
    let first_inode = std::fs::metadata(local.join(relative(0))).unwrap().ino();
    // Reload the actual disk recipe while retaining the exact original owner.
    let mut recovered = RecoverySession {
        recipe: disk_recipe(&session),
        writer: session.writer.clone(),
    };
    recovered.publish("docs").await.unwrap();
    assert_docs(&recovered, 64);
    assert!(recovered.recipe.phases[0].baseline.is_empty());
    assert_eq!(
        std::fs::metadata(local.join(relative(0))).unwrap().ino(),
        first_inode
    );
    assert_eq!(
        std::fs::read(untouched).unwrap(),
        b"unrelated old target artifact"
    );
    assert!(directory.path().join("journals").exists());
}

#[tokio::test(flavor = "current_thread")]
async fn baseline_compaction_failure_restores_selected_and_discarded_entries() {
    let _guard = test_guard!();
    for journal_failure in [false, true] {
        let (directory, mut session) = docs(2);
        old_outputs(&mut session, 2, 128);
        let local = session.recipe.phases[0].local.clone();
        let selected = vec![relative(0), relative(1)];
        if journal_failure {
            // Invalidate the real single-link journal gate without replacing,
            // truncating, deleting, or mocking any retained journal bytes.
            let gate = session.writer.path.with_extension("recovery.lock");
            std::fs::hard_link(&gate, directory.path().join("additional-gate-link")).unwrap();
            std::fs::write(local.join(relative(0)), b"new observed predecessor").unwrap();
        } else {
            let second = local.join(relative(1));
            std::fs::rename(&second, directory.path().join("retained-second-output")).unwrap();
            std::fs::create_dir(&second).unwrap();
        }
        let before_recipe = serde_json::to_value(&session.recipe).unwrap();
        let before_lease = session.writer.snapshot();
        let before_disk = std::fs::read(&session.writer.path).unwrap();
        let _publication = lock_output_root(&local).await.unwrap();
        assert!(session.persist_publication_baseline(0, &selected).is_err());
        assert_eq!(
            serde_json::to_value(&session.recipe).unwrap(),
            before_recipe
        );
        assert_eq!(session.writer.snapshot(), before_lease);
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before_disk);
        assert_eq!(session.recipe.phases[0].baseline.len(), 130);
        assert!(session.recipe.phases[0].published.is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn published_checkpoint_failure_keeps_its_pending_predecessor_for_retry() {
    let _guard = test_guard!();
    for previously_published in [false, true] {
        let (directory, mut session) = docs(1);
        old_outputs(&mut session, 1, 4);
        let hash = blake3::hash(bytes(0).as_bytes()).to_hex().to_string();
        session.recipe.phases[0].pending = Some((relative(0), hash.clone()));
        if previously_published {
            session.recipe.phases[0]
                .published
                .insert(relative(0), "earlier receipt".into());
        }
        session.persist().unwrap();
        let before_recipe = serde_json::to_value(&session.recipe).unwrap();
        let before_lease = session.writer.snapshot();
        let before_disk = std::fs::read(&session.writer.path).unwrap();
        let gate = session.writer.path.with_extension("recovery.lock");
        std::fs::hard_link(&gate, directory.path().join("additional-gate-link")).unwrap();
        let _publication = lock_output_root(&session.recipe.phases[0].local)
            .await
            .unwrap();
        assert!(
            session
                .persist_published_output(0, relative(0), hash)
                .is_err()
        );
        assert_eq!(
            serde_json::to_value(&session.recipe).unwrap(),
            before_recipe
        );
        assert_eq!(session.writer.snapshot(), before_lease);
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before_disk);
        assert_eq!(
            std::fs::read_to_string(session.recipe.phases[0].local.join(relative(0))).unwrap(),
            predecessor(0)
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn pending_conflict_cannot_be_rebaselined_or_compacted_into_permission() {
    let _guard = test_guard!();
    let (directory, mut session) = docs(2);
    old_outputs(&mut session, 2, 128);
    let result = session
        .publish_with_observer("docs", |point, _| {
            anyhow::ensure!(
                point != PublicationPoint::PendingDurable,
                "stop before rename"
            );
            Ok(())
        })
        .await;
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("stop before rename")
    );
    let local = session.recipe.phases[0].local.clone();
    let first = local.join(relative(0));
    let prior = directory.path().join("original-predecessor");
    std::fs::rename(&first, &prior).unwrap();
    std::fs::write(&first, b"another writer's output").unwrap();
    let before = std::fs::read(&session.writer.path).unwrap();
    {
        let _publication = lock_output_root(&local).await.unwrap();
        assert!(session.persist_publication_baseline(0, &[]).is_err());
    }
    assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
    let error = session.publish("docs").await.unwrap_err();
    assert!(error.to_string().contains("cannot prove ownership"));
    assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
    assert_eq!(std::fs::read(&first).unwrap(), b"another writer's output");
    assert_eq!(
        session.recipe.phases[0].baseline[&relative(0)],
        blake3::hash(predecessor(0).as_bytes()).to_hex().to_string()
    );
    assert_acknowledged(&session);
    // Restore only the original owned fixture, keeping the competing output
    // too. The same pending copy can now finish without replaying a compiler.
    std::fs::rename(&first, directory.path().join("competing-output")).unwrap();
    std::fs::rename(&prior, &first).unwrap();
    session.publish("docs").await.unwrap();
    assert_docs(&session, 2);
    assert!(session.recipe.phases[0].baseline.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_keeps_compacted_predecessors_until_publication_is_durable() {
    let _guard = test_guard!();
    for point in [
        PublicationPoint::PendingDurable,
        PublicationPoint::Renamed,
        PublicationPoint::PublishedDurable,
    ] {
        let (_directory, mut session) = docs(3);
        old_outputs(&mut session, 3, 128);
        let (ready, started) = tokio::sync::oneshot::channel();
        let mut publication =
            Box::pin(session.publish_with_observer("docs", cancellation_gate(point, ready)));
        tokio::select! {
            result = &mut publication => panic!("publication escaped cancellation boundary: {result:?}"),
            started = started => started.unwrap(),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(25), publication)
                .await
                .is_err()
        );
        let published = usize::from(point == PublicationPoint::PublishedDurable);
        let phase = &session.recipe.phases[0];
        assert_eq!(phase.baseline.len(), 3 - published);
        assert_eq!(phase.published.len(), published);
        assert_eq!(phase.pending.is_some(), published == 0);
        assert!(phase.baseline.keys().all(|path| path.starts_with("doc")));
        if published == 0 {
            assert_eq!(
                phase.baseline[&relative(0)],
                blake3::hash(predecessor(0).as_bytes()).to_hex().to_string()
            );
        }
        assert_acknowledged(&session);
        let mut recovered = RecoverySession {
            recipe: disk_recipe(&session),
            writer: session.writer.clone(),
        };
        recovered.publish("docs").await.unwrap();
        assert_docs(&recovered, 3);
        assert!(recovered.recipe.phases[0].baseline.is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn selected_destination_symlink_still_refuses_without_pruning_the_journal() {
    let _guard = test_guard!();
    let (directory, mut session) = docs(1);
    old_outputs(&mut session, 1, 128);
    let destination = session.recipe.phases[0].local.join(relative(0));
    let retained = directory.path().join("retained-predecessor");
    std::fs::rename(&destination, &retained).unwrap();
    symlink(&retained, &destination).unwrap();
    let before_recipe = serde_json::to_value(&session.recipe).unwrap();
    let before_disk = std::fs::read(&session.writer.path).unwrap();
    let error = session.publish("docs").await.unwrap_err();
    assert!(error.to_string().contains("not a regular file"));
    assert_eq!(
        serde_json::to_value(&session.recipe).unwrap(),
        before_recipe
    );
    assert_eq!(std::fs::read(&session.writer.path).unwrap(), before_disk);
    assert_eq!(std::fs::read_link(&destination).unwrap(), retained);
    assert_eq!(std::fs::read_to_string(&retained).unwrap(), predecessor(0));
    assert_eq!(
        std::fs::read_to_string(session.stage(0).join(relative(0))).unwrap(),
        bytes(0)
    );
    assert_acknowledged(&session);
}
