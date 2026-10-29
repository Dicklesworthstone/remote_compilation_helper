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

fn prepared_suitability_session(
    local: &Path,
) -> (tempfile::TempDir, RecoverySession, TransferPipeline) {
    let directory = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let worker = WorkerConfig {
        id: WorkerId::new("publication-suitability"),
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
        "fixture-suitability",
        true,
        false,
    )
    .unwrap();
    writer.admit(41, &worker.id).unwrap();
    let identity = uuid::Uuid::new_v4().simple().to_string();
    let remote = "/data/projects/publication-suitability".to_owned();
    let transfer = TransferConfig {
        retrieval_staging_dir: Some(directory.path().join("staging")),
        ..Default::default()
    };
    let pipeline = TransferPipeline::new(
        local.to_owned(),
        "publication-suitability".into(),
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
        local.to_owned(),
        identity.clone(),
    )
    .unwrap();
    let session = RecoverySession::prepare(
        &writer,
        &worker,
        &pipeline,
        vec![remote],
        None,
        None,
        None,
        transfer,
        local.to_owned(),
        None,
        None,
        "fixture-suitability",
        &[PathBuf::from("doc")],
        identity,
    )
    .unwrap();
    (directory, session, pipeline)
}

fn find_probe_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".rch-pub-probe-"))
        })
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn publication_suitability_allows_current_owner_and_preserves_full_publication_and_reopen() {
    let _guard = test_guard!();
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let local = root.path().join("caller");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(local.join("source-sentinel"), b"not an artifact").unwrap();
    let (_directory, mut session, pipeline) = prepared_suitability_session(&local);
    session.verify_publication_suitability().await.unwrap();
    assert!(find_probe_files(&local).is_empty());
    assert!(!session.recipe.execution_started);
    assert_acknowledged(&session);

    // The fixture's Cargo-default project phase precedes the result phase.
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
    session.starting_execution().unwrap();
    session.completed(0).unwrap();
    let mut reopened = reload(&session);
    reopened.publish("result:doc").await.unwrap();
    reopened.returned(0).unwrap();
    assert_phase_docs(&reopened, phase_index, 1);
    assert_eq!(reopened.recipe.returned, Some(0));
}

#[tokio::test(flavor = "current_thread")]
async fn publication_suitability_probes_nearest_existing_prefix_without_creating_missing_suffix() {
    let _guard = test_guard!();
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let existing = root.path().join("existing");
    std::fs::create_dir_all(&existing).unwrap();
    let local = existing.join("missing/nested/target");
    let (_directory, mut session, pipeline) = prepared_suitability_session(&local);
    let observed_parent = Arc::new(std::sync::Mutex::new(None));
    let observed_parent_for_obs = Arc::clone(&observed_parent);
    let uid = rustix::process::geteuid().as_raw();
    session
        .verify_publication_suitability_with(uid, move |probe| {
            *observed_parent_for_obs.lock().unwrap() = probe.parent().map(Path::to_path_buf);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        *observed_parent.lock().unwrap(),
        Some(existing.canonicalize().unwrap())
    );
    assert!(!existing.join("missing").exists());
    assert!(find_probe_files(&existing).is_empty());

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
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(local.join("source-sentinel"), b"not an artifact").unwrap();
    session.starting_execution().unwrap();
    session.completed(0).unwrap();
    session.publish("result:doc").await.unwrap();
    assert_phase_docs(&session, phase_index, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn publication_suitability_refuses_dangling_symlink_prefix_before_execution() {
    let _guard = test_guard!();
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let dangling = root.path().join("dangling-usb");
    symlink(root.path().join("absent-volume"), &dangling).unwrap();
    let local = dangling.join("project/target");
    let (_directory, mut session, _pipeline) = prepared_suitability_session(&local);
    let before_recipe = serde_json::to_value(&session.recipe).unwrap();
    let before_disk = std::fs::read(&session.writer.path).unwrap();
    let error = session.verify_publication_suitability().await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot resolve existing output root entry"),
        "{error:#}"
    );
    assert!(!session.recipe.execution_started);
    assert_eq!(
        serde_json::to_value(&session.recipe).unwrap(),
        before_recipe
    );
    assert_eq!(std::fs::read(&session.writer.path).unwrap(), before_disk);
    // The refused session is still cancellable preparation: the cancel path
    // journals the cancellation before its remote half, which this fixture's
    // unresolvable worker host must fail.
    let error = cancel_preparation(&session.writer).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot cancel durable source intent"),
        "{error:#}"
    );
    assert!(load_recipe(&session.writer).unwrap().preparation_cancelled);
}

#[tokio::test(flavor = "current_thread")]
async fn publication_suitability_refuses_retargeted_root_during_probe() {
    let _guard = test_guard!();
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let first = root.path().join("first-target");
    let second = root.path().join("second-target");
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    let linked = root.path().join("linked-target");
    symlink(&first, &linked).unwrap();
    let local = linked.join("missing-suffix");
    let (_directory, mut session, _pipeline) = prepared_suitability_session(&local);
    let before_recipe = serde_json::to_value(&session.recipe).unwrap();
    let before_disk = std::fs::read(&session.writer.path).unwrap();
    let rebind = root.path().join("rebind-target");
    symlink(&second, &rebind).unwrap();
    let linked_for_obs = linked.clone();
    let uid = rustix::process::geteuid().as_raw();
    let error = session
        .verify_publication_suitability_with(uid, move |_| {
            std::fs::rename(&rebind, &linked_for_obs)?;
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("output publication root changed during suitability probe"),
        "{error:#}"
    );
    assert!(!session.recipe.execution_started);
    assert!(find_probe_files(&first).is_empty());
    assert!(find_probe_files(&second).is_empty());
    assert_eq!(
        serde_json::to_value(&session.recipe).unwrap(),
        before_recipe
    );
    assert_eq!(std::fs::read(&session.writer.path).unwrap(), before_disk);
}

#[tokio::test(flavor = "current_thread")]
async fn publication_suitability_refuses_injected_wrong_uid_and_preserves_probe_evidence() {
    // Injected expected-UID test (models a writable NFS mount that maps newly
    // created 0600 files to a non-caller UID; distinct from live Mac/NFS runs).
    let _guard = test_guard!();
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let local = root.path().join("nfs-mapped");
    std::fs::create_dir_all(&local).unwrap();
    let (_directory, mut session, _pipeline) = prepared_suitability_session(&local);
    let before_recipe = serde_json::to_value(&session.recipe).unwrap();
    let before_disk = std::fs::read(&session.writer.path).unwrap();
    let wrong_uid = rustix::process::geteuid().as_raw() ^ 1;
    let error = session
        .verify_publication_suitability_with(wrong_uid, |_| Ok(()))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("publication copy identity, length, permissions or links changed"),
        "{error:#}"
    );
    assert!(!session.recipe.execution_started);
    let probes = find_probe_files(&local);
    assert_eq!(
        probes.len(),
        1,
        "wrong-UID probe evidence must be preserved"
    );
    assert!(probes[0].is_file());
    assert_eq!(
        serde_json::to_value(&session.recipe).unwrap(),
        before_recipe
    );
    assert_eq!(std::fs::read(&session.writer.path).unwrap(), before_disk);
}

#[tokio::test(flavor = "current_thread")]
async fn publication_suitability_refuses_changed_mode_and_preserves_probe_evidence() {
    use std::os::unix::fs::PermissionsExt;
    let _guard = test_guard!();
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let local = root.path().join("mode-changed");
    std::fs::create_dir_all(&local).unwrap();
    let (_directory, mut session, _pipeline) = prepared_suitability_session(&local);
    let uid = rustix::process::geteuid().as_raw();
    let error = session
        .verify_publication_suitability_with(uid, |probe| {
            std::fs::set_permissions(probe, std::fs::Permissions::from_mode(0o644))?;
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("publication copy identity, length, permissions or links changed"),
        "{error:#}"
    );
    assert!(!session.recipe.execution_started);
    let probes = find_probe_files(&local);
    assert_eq!(probes.len(), 1);
    assert_eq!(
        std::fs::metadata(&probes[0]).unwrap().mode() & 0o7777,
        0o644
    );
}

#[tokio::test(flavor = "current_thread")]
async fn publication_suitability_refuses_additional_hard_link_and_preserves_probe_evidence() {
    let _guard = test_guard!();
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let local = root.path().join("linked-probe");
    std::fs::create_dir_all(&local).unwrap();
    let extra = local.join("extra-link");
    let extra_for_obs = extra.clone();
    let (_directory, mut session, _pipeline) = prepared_suitability_session(&local);
    let uid = rustix::process::geteuid().as_raw();
    let error = session
        .verify_publication_suitability_with(uid, move |probe| {
            std::fs::hard_link(probe, &extra_for_obs)?;
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("publication copy identity, length, permissions or links changed"),
        "{error:#}"
    );
    assert!(!session.recipe.execution_started);
    let probes = find_probe_files(&local);
    assert_eq!(probes.len(), 1);
    assert!(probes[0].is_file());
    assert!(extra.is_file());
}

#[tokio::test(flavor = "current_thread")]
async fn publication_suitability_refuses_replaced_probe_name_and_preserves_replacement() {
    let _guard = test_guard!();
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let local = root.path().join("replaced-probe");
    std::fs::create_dir_all(&local).unwrap();
    let moved = local.join("moved-original-probe");
    let moved_for_obs = moved.clone();
    let (_directory, mut session, _pipeline) = prepared_suitability_session(&local);
    let uid = rustix::process::geteuid().as_raw();
    let error = session
        .verify_publication_suitability_with(uid, move |probe| {
            std::fs::rename(probe, &moved_for_obs)?;
            std::fs::write(probe, b"unowned replacement")?;
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("publication copy identity, length, permissions or links changed"),
        "{error:#}"
    );
    assert!(!session.recipe.execution_started);
    let probes = find_probe_files(&local);
    assert_eq!(probes.len(), 1);
    assert_eq!(std::fs::read(&probes[0]).unwrap(), b"unowned replacement");
    assert!(moved.is_file());
}

#[tokio::test(flavor = "current_thread")]
async fn publication_suitability_refuses_substituted_parent_and_preserves_entries() {
    let _guard = test_guard!();
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let local = root.path().join("substituted-parent");
    std::fs::create_dir_all(&local).unwrap();
    let displaced = root.path().join("displaced-parent");
    let displaced_for_obs = displaced.clone();
    let local_for_obs = local.clone();
    let (_directory, mut session, _pipeline) = prepared_suitability_session(&local);
    let uid = rustix::process::geteuid().as_raw();
    let error = session
        .verify_publication_suitability_with(uid, move |_| {
            std::fs::rename(&local_for_obs, &displaced_for_obs)?;
            std::fs::create_dir_all(&local_for_obs)?;
            std::fs::write(local_for_obs.join("unowned-entry"), b"keep")?;
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("publication copy directory changed"),
        "{error:#}"
    );
    assert!(!session.recipe.execution_started);
    assert_eq!(std::fs::read(local.join("unowned-entry")).unwrap(), b"keep");
    assert_eq!(find_probe_files(&displaced).len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn publication_suitability_cancellation_and_consumed_session_guards_preserve_invariants() {
    let _guard = test_guard!();
    let root = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let local = root.path().join("cancellation-suitability");
    std::fs::create_dir_all(&local).unwrap();
    let (_directory, mut session, _pipeline) = prepared_suitability_session(&local);
    let uid = rustix::process::geteuid().as_raw();

    // Cooperative cancellation cleans up our owned probe and leaves the journal untouched.
    let error = session
        .verify_publication_suitability_with(uid, |_| {
            Err(publication_runtime::PublicationCancelled.into())
        })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("cancelled"), "{error:#}");
    assert!(find_probe_files(&local).is_empty());
    assert!(!session.recipe.execution_started);
    assert_acknowledged(&session);

    // Dropped-future cancellation drains the worker, cleans up the owned probe,
    // and releases the output-root lock.
    let (ready, started) = tokio::sync::oneshot::channel();
    let mut ready = Some(ready);
    {
        let mut suitability =
            Box::pin(session.verify_publication_suitability_with(uid, move |_| {
                if let Some(ready) = ready.take() {
                    let _ = ready.send(());
                    let deadline = std::time::Instant::now() + Duration::from_secs(3);
                    loop {
                        publication_runtime::checkpoint()?;
                        anyhow::ensure!(
                            std::time::Instant::now() < deadline,
                            "suitability cancellation was not polled"
                        );
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Ok(())
            }));
        tokio::select! {
            result = &mut suitability => panic!("suitability escaped cancellation gate: {result:?}"),
            started = started => started.unwrap(),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(25), suitability)
                .await
                .is_err()
        );
    }
    assert!(find_probe_files(&local).is_empty());
    assert!(!session.recipe.execution_started);
    assert_acknowledged(&session);
    let lock = tokio::time::timeout(Duration::from_secs(1), lock_output_root(&local))
        .await
        .unwrap()
        .unwrap();
    drop(lock);

    // Upfront consumed/cancelled/released session guards refuse before probing
    // and without mutating the recipe or persisted journal.
    for mutate in [
        |r: &mut RecoveryRecipe| r.prepared = false,
        |r: &mut RecoveryRecipe| r.execution_started = true,
        |r: &mut RecoveryRecipe| r.preparation_cancelled = true,
        |r: &mut RecoveryRecipe| r.sources_released = true,
        |r: &mut RecoveryRecipe| r.pair_released = true,
        |r: &mut RecoveryRecipe| r.tree_retired = true,
        |r: &mut RecoveryRecipe| r.retired = true,
        |r: &mut RecoveryRecipe| r.exit_code = Some(0),
        |r: &mut RecoveryRecipe| r.returned = Some(0),
        |r: &mut RecoveryRecipe| r.phases[0].complete = true,
    ] {
        let original = session.recipe.clone();
        let before_disk = std::fs::read(&session.writer.path).unwrap();
        mutate(&mut session.recipe);
        let mutated_snapshot = serde_json::to_value(&session.recipe).unwrap();
        let probed = Arc::new(AtomicUsize::new(0));
        let probed_for_obs = Arc::clone(&probed);
        let error = session
            .verify_publication_suitability_with(uid, move |_| {
                probed_for_obs.fetch_add(1, Ordering::Release);
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains(
                "pre-execution publication suitability requires an unconsumed prepared session"
            ),
            "{error:#}"
        );
        assert_eq!(probed.load(Ordering::Acquire), 0);
        assert!(find_probe_files(&local).is_empty());
        assert_eq!(
            serde_json::to_value(&session.recipe).unwrap(),
            mutated_snapshot
        );
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before_disk);
        session.recipe = original;
    }
}
