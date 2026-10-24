//! Real filesystem/journal publication with an already-successful exit fixture.
//! No SSH, ambient daemon, compiler replay, or process-global fault injection.

use super::*;
use crate::hook::progress_reporting::BuildHeartbeatLoop;
use rch_common::test_guard;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn docs(count: usize) -> (tempfile::TempDir, RecoverySession) {
    let identity = uuid::Uuid::new_v4().simple().to_string();
    let directory = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let worker = WorkerConfig {
        id: WorkerId::new("publication-runtime"),
        host: "unreachable.invalid".into(),
        user: "worker".into(),
        identity_file: "/unused/test-key".into(),
        total_slots: 1,
        priority: 100,
        tags: Vec::new(),
        tools: Vec::new(),
    };
    // Use the real descriptor-bound journal owner in every case. Only the
    // already-completed remote execution is fixture input, not journal I/O.
    let writer =
        DurableLeaseWriter::create_in(&directory.path().join("journals"), "cargo doc", true, false)
            .unwrap();
    writer.admit(41, &worker.id).unwrap();
    RecoverySession::begin(
        &writer,
        &worker,
        vec!["/data/projects/publication-runtime".into()],
        None,
        None,
        None,
        TransferConfig::default(),
        directory.path().to_owned(),
        identity,
    )
    .unwrap();
    let mut recipe: RecoveryRecipe =
        serde_json::from_value(writer.snapshot().recovery.unwrap()).unwrap();
    recipe.transfer.retrieval_staging_dir = Some(directory.path().join("staging"));
    recipe.prepared = true;
    recipe.execution_started = true;
    recipe.exit_code = Some(0); // The remote completion is explicitly fixture input.
    let local = directory.path().join("target");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(local.join("source-sentinel"), b"not an artifact").unwrap();
    recipe.phases.push(RecoveryPhase {
        name: "docs".into(),
        local,
        remote: "/unused/already-retrieved".into(),
        patterns: Vec::new(),
        result_dir: Some(PathBuf::from("doc")),
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
    let stage = session.stage(0);
    std::fs::create_dir_all(stage.join("doc")).unwrap();
    for index in 0..count {
        std::fs::write(stage.join(relative(index)), bytes(index)).unwrap();
    }
    (directory, session)
}

fn relative(index: usize) -> PathBuf {
    PathBuf::from(format!("doc/fn.{index:05}.html"))
}

fn bytes(index: usize) -> String {
    format!("<html>documentation for function {index}</html>\n")
}

fn disk_recipe(session: &RecoverySession) -> RecoveryRecipe {
    let lease: DurableJobLease =
        serde_json::from_slice(&std::fs::read(&session.writer.path).unwrap()).unwrap();
    assert!(!lease.terminal_acknowledged);
    serde_json::from_value(lease.recovery.unwrap()).unwrap()
}

fn assert_acknowledged(session: &RecoverySession) {
    let recipe = serde_json::to_value(&session.recipe).unwrap();
    assert_eq!(recipe, session.writer.snapshot().recovery.unwrap());
    assert_eq!(recipe, serde_json::to_value(disk_recipe(session)).unwrap());
}

fn assert_docs(session: &RecoverySession, count: usize) {
    let phase = &session.recipe.phases[0];
    assert!(phase.complete);
    assert!(phase.pending.is_none());
    assert_eq!(phase.published.len(), count);
    for index in 0..count {
        assert_eq!(
            std::fs::read_to_string(phase.local.join(relative(index))).unwrap(),
            bytes(index)
        );
    }
    assert_eq!(
        std::fs::read(phase.local.join("source-sentinel")).unwrap(),
        b"not an artifact"
    );
    assert_eq!(session.recipe.exit_code, Some(0));
    assert!(!session.recipe.sources_released);
    assert!(!session.recipe.retired);
    assert_acknowledged(session);
    assert!(session.writer.acknowledge_terminal().is_err());
}

fn reload(session: &RecoverySession) -> RecoverySession {
    RecoverySession {
        recipe: load_recipe(&session.writer).unwrap(),
        writer: session.writer.clone(),
    }
}

// Block only this invocation at a real publication boundary. A wall-clock
// watchdog makes a missing offload/checkpoint fail rather than hang the suite.
fn cancellation_gate(
    point: PublicationPoint,
    ready: tokio::sync::oneshot::Sender<()>,
) -> impl FnMut(PublicationPoint, &Path) -> anyhow::Result<()> + Send + 'static {
    let mut ready = Some(ready);
    move |observed, _| {
        if observed == point
            && let Some(ready) = ready.take()
        {
            let _ = ready.send(());
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            loop {
                publication_runtime::checkpoint()?;
                anyhow::ensure!(
                    std::time::Instant::now() < deadline,
                    "cancellation was not polled"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn slow_publication_keeps_caller_reactor_and_real_heartbeats_running() {
    let _guard = test_guard!();
    let (directory, mut session) = docs(24);
    let socket = directory.path().join("heartbeat.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let beats = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&beats);
    let build_id = session.recipe.build_id;
    let worker_id = session.recipe.worker.id.clone();
    let server_worker = worker_id.clone();
    // The peer is deliberately on the caller runtime, not the independent
    // heartbeat executor. Merely moving heartbeats cannot pass this test.
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).await.unwrap();
            let (route, body) = request.split_once('\n').unwrap();
            assert_eq!(route, "POST /build-heartbeat");
            let heartbeat: BuildHeartbeatRequest = serde_json::from_str(body).unwrap();
            assert_eq!(heartbeat.build_id, build_id);
            assert_eq!(heartbeat.worker_id, server_worker);
            let response = serde_json::json!({
                "status": "ok", "build_id": heartbeat.build_id,
                "worker_id": heartbeat.worker_id, "phase": heartbeat.phase,
            });
            stream
                .write_all(
                    format!(
                        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{response}\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            counted.fetch_add(1, Ordering::Release);
        }
    });
    // No durable_lease in the service loop: it must never query an ambient
    // job endpoint. Exercise real durable heartbeats explicitly below instead.
    let heartbeat = BuildHeartbeatLoop::start(
        socket.to_str().unwrap(),
        build_id,
        &worker_id,
        Some(&session.recipe.wrapper_id),
        None,
    );
    heartbeat.update_phase(BuildHeartbeatPhase::SyncDown, Some("publication".into()));
    let writer = session.writer.clone();
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let ticks = Arc::new(AtomicUsize::new(0));
    let counted_ticks = Arc::clone(&ticks);
    let heartbeat_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(10));
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                _ = ticker.tick() => {}
            }
            let writer = writer.clone();
            tokio::task::spawn_blocking(move || writer.heartbeat("sync_down"))
                .await
                .unwrap()
                .unwrap();
            heartbeat.flush().await;
            counted_ticks.fetch_add(1, Ordering::Release);
        }
    });
    let result = session
        .publish_with_observer("docs", |point, _| {
            if point == PublicationPoint::BeforeFile {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(())
        })
        .await;
    let during = ticks.load(Ordering::Acquire);
    let wire = beats.load(Ordering::Acquire);
    let _ = stop.send(());
    heartbeat_task.await.unwrap();
    server.abort();
    let _ = server.await;
    result.unwrap();
    assert!(
        during >= 4 && wire >= 4,
        "caller reactor starved: ticks={during}, wire={wire}"
    );
    assert_docs(&session, 24);
    session.returned(0).unwrap();
    assert_acknowledged(&session);
}

#[tokio::test(flavor = "current_thread")]
async fn deadline_drains_pending_renamed_and_published_boundaries_before_retry() {
    let _guard = test_guard!();
    for point in [
        PublicationPoint::PendingDurable,
        PublicationPoint::Renamed,
        PublicationPoint::PublishedDurable,
    ] {
        let (_directory, mut session) = docs(4);
        let (ready, started) = tokio::sync::oneshot::channel();
        let mut publication =
            Box::pin(session.publish_with_observer("docs", cancellation_gate(point, ready)));
        tokio::select! {
            result = &mut publication => panic!("publication escaped the cancellation gate: {result:?}"),
            started = started => started.unwrap(),
        }
        let elapsed = std::time::Instant::now();
        assert!(
            tokio::time::timeout(Duration::from_millis(25), publication)
                .await
                .is_err()
        );
        assert!(
            elapsed.elapsed() < Duration::from_secs(2),
            "deadline waited for the whole phase"
        );
        let phase = &session.recipe.phases[0];
        assert!(!phase.complete);
        assert_eq!(
            phase.published.len(),
            usize::from(point == PublicationPoint::PublishedDurable)
        );
        assert_eq!(
            phase.pending.is_some(),
            point != PublicationPoint::PublishedDurable
        );
        assert_eq!(
            phase.local.join(relative(0)).exists(),
            point != PublicationPoint::PendingDurable
        );
        assert!(session.recipe.returned.is_none());
        assert!(session.stage(0).exists());
        assert_acknowledged(&session);
        let journal = std::fs::read(&session.writer.path).unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            std::fs::read(&session.writer.path).unwrap(),
            journal,
            "detached publication after timeout"
        );
        let lock = tokio::time::timeout(Duration::from_secs(1), lock_output_root(&phase.local))
            .await
            .unwrap()
            .unwrap();
        drop(lock);
        session.publish("docs").await.unwrap();
        assert_docs(&session, 4);
        let mut recovered = reload(&session);
        recovered.publish("docs").await.unwrap();
        assert_docs(&recovered, 4);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn aborting_publication_task_drains_the_worker_before_recovery() {
    let _guard = test_guard!();
    let (_directory, mut session) = docs(3);
    let path = session.writer.path.clone();
    let wrapper = session.recipe.wrapper_id.clone();
    let root = session.recipe.phases[0].local.clone();
    let (ready, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        session
            .publish_with_observer(
                "docs",
                cancellation_gate(PublicationPoint::PendingDurable, ready),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), started)
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(25), lock_output_root(&root))
            .await
            .is_err()
    );
    assert!(
        recovery_owner::acquire_gate(&path).is_err(),
        "journal gate released during publication"
    );
    task.abort();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap_err()
            .is_cancelled()
    );
    // No original writer is retained here: the cancelled task's scope must
    // drain its worker and release the actual kernel journal gate before join.
    let ownership = recovery_owner::acquire_gate(&path).unwrap();
    let disk = ownership.read(&wrapper).unwrap();
    let writer = DurableLeaseWriter {
        path,
        lease: Arc::new(Mutex::new(disk)),
        recovery_ownership: Some(Arc::new(ownership)),
    };
    let mut recovered = RecoverySession {
        recipe: load_recipe(&writer).unwrap(),
        writer,
    };
    assert!(recovered.recipe.phases[0].pending.is_some());
    assert!(!recovered.recipe.phases[0].complete);
    assert_acknowledged(&recovered);
    recovered.publish("docs").await.unwrap();
    assert_docs(&recovered, 3);
}

#[tokio::test(flavor = "current_thread")]
async fn worker_error_preserves_acknowledged_checkpoints_for_same_session_retry() {
    let _guard = test_guard!();
    let (_directory, mut session) = docs(3);
    let result = session
        .publish_with_observer("docs", |point, _| {
            anyhow::ensure!(
                point != PublicationPoint::PublishedDurable,
                "injected after durable checkpoint"
            );
            Ok(())
        })
        .await;
    assert!(result.is_err());
    assert_eq!(session.recipe.phases[0].published.len(), 1);
    assert!(!session.recipe.phases[0].complete);
    assert_acknowledged(&session);
    session.publish("docs").await.unwrap();
    assert_docs(&session, 3);
}

#[tokio::test(flavor = "current_thread")]
async fn worker_panic_wakes_caller_and_reloads_committed_recipe() {
    let _guard = test_guard!();
    let (_directory, mut session) = docs(3);
    let result = session
        .publish_with_observer("docs", |point, _| {
            assert_ne!(
                point,
                PublicationPoint::PublishedDurable,
                "injected worker panic"
            );
            Ok(())
        })
        .await;
    assert!(result.unwrap_err().to_string().contains("panicked"));
    assert_eq!(session.recipe.phases[0].published.len(), 1);
    assert_acknowledged(&session);
    session.publish("docs").await.unwrap();
    assert_docs(&session, 3);
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_is_scoped_to_one_publication() {
    let _guard = test_guard!();
    let (_first_directory, mut first) = docs(2);
    let (_second_directory, mut second) = docs(2);
    let (ready, started) = tokio::sync::oneshot::channel();
    let mut publication = Box::pin(first.publish_with_observer(
        "docs",
        cancellation_gate(PublicationPoint::PendingDurable, ready),
    ));
    tokio::select! {
        result = &mut publication => panic!("first publication escaped its gate: {result:?}"),
        started = started => started.unwrap(),
    }
    second.publish("docs").await.unwrap();
    assert_docs(&second, 2);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), publication)
            .await
            .is_err()
    );
    assert_acknowledged(&first);
    publication_runtime::checkpoint().unwrap(); // No cancellation on the caller thread.
    first.publish("docs").await.unwrap();
    assert_docs(&first, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_destination_changes_are_not_overwritten_before_or_after_pending() {
    let _guard = test_guard!();
    for boundary in [
        PublicationPoint::BeforeFile,
        PublicationPoint::PendingDurable,
    ] {
        let (_directory, mut session) = docs(1);
        let destination = session.recipe.phases[0].local.join(relative(0));
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(&destination, b"original baseline").unwrap();
        let result = session
            .publish_with_observer("docs", move |point, path| {
                if point == boundary {
                    std::fs::write(path, b"concurrent owner's output")?;
                }
                Ok(())
            })
            .await;
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"concurrent owner's output"
        );
        assert!(session.recipe.phases[0].published.is_empty());
        assert!(!session.recipe.phases[0].complete);
        assert_acknowledged(&session);
        if boundary == PublicationPoint::PendingDurable {
            // Once a write is pending, recovery must use its old baseline.
            assert!(session.publish("docs").await.is_err());
            assert_eq!(
                std::fs::read(&destination).unwrap(),
                b"concurrent owner's output"
            );
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn lock_wait_cancellation_does_not_start_publication_or_change_evidence() {
    let _guard = test_guard!();
    let (_directory, mut session) = docs(2);
    let journal = std::fs::read(&session.writer.path).unwrap();
    let lock = lock_output_root(&session.recipe.phases[0].local)
        .await
        .unwrap();
    let observed = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&observed);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            session.publish_with_observer("docs", move |_, _| {
                counted.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
        )
        .await
        .is_err()
    );
    assert_eq!(observed.load(Ordering::Relaxed), 0);
    assert_eq!(std::fs::read(&session.writer.path).unwrap(), journal);
    assert_acknowledged(&session);
    drop(lock);
    session.publish("docs").await.unwrap();
    assert_docs(&session, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_chunk_copy_retains_prefix_and_resumes_without_rewriting_it() {
    use std::os::unix::fs::{FileExt, MetadataExt};
    let _guard = test_guard!();
    let (_directory, mut session) = docs(1);
    let source = session.stage(0).join(relative(0));
    let bytes: Vec<u8> = (0..131_089).map(|index| (index % 251) as u8).collect();
    std::fs::write(&source, &bytes).unwrap();
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let destination = session.recipe.phases[0].local.join(relative(0));
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    let temporary = destination
        .parent()
        .unwrap()
        .join(format!(".rch-return-{}", session.recipe.identity));
    let owned_source = source.clone();
    let owned_temporary = temporary.clone();
    let owned_hash = hash.clone();
    let lock = lock_output_root(&session.recipe.phases[0].local)
        .await
        .unwrap();
    let before = std::fs::read(&session.writer.path).unwrap();
    let (ready, started) = tokio::sync::oneshot::channel();
    let mut publication = Box::pin(publication_runtime::run(&mut session, lock, move |_| {
        let mut ready = Some(ready);
        publication_copy::prepare_with_write(
            &owned_source,
            &owned_temporary,
            &owned_hash,
            |file, bytes, offset| {
                let count = file.write_at(&bytes[..bytes.len().min(17)], offset)?;
                if let Some(ready) = ready.take() {
                    let _ = ready.send(());
                    let deadline = std::time::Instant::now() + Duration::from_secs(3);
                    while publication_runtime::checkpoint().is_ok()
                        && std::time::Instant::now() < deadline
                    {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Ok(count)
            },
        )?;
        Ok(())
    }));
    tokio::select! {
        result = &mut publication => panic!("copy escaped its cancellation gate: {result:?}"),
        started = started => started.unwrap(),
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(25), publication)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
    assert_eq!(std::fs::read(&temporary).unwrap(), bytes[..17]);
    assert!(!destination.exists());
    let inode = std::fs::metadata(&temporary).unwrap().ino();
    // The actual publisher resumes the retained copy, not the injected writer.
    session.publish("docs").await.unwrap();
    assert_eq!(std::fs::metadata(&destination).unwrap().ino(), inode);
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    assert!(session.recipe.phases[0].complete);
    assert_acknowledged(&session);
}

#[tokio::test(flavor = "current_thread")]
async fn missing_stage_is_not_empty_success_and_same_session_can_retry() {
    let _guard = test_guard!();
    let (_directory, mut session) = docs(6);
    let stage = session.stage(0);
    let retained = stage.with_extension("retained");
    std::fs::rename(&stage, &retained).unwrap();
    let before = std::fs::read(&session.writer.path).unwrap();
    assert!(session.publish("docs").await.is_err());
    assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
    assert_acknowledged(&session);
    std::fs::rename(&retained, &stage).unwrap();
    session.publish("docs").await.unwrap();
    assert_docs(&session, 6);
}

#[tokio::test(flavor = "current_thread")]
async fn large_set_resumes_after_partial_durable_publication() {
    let _guard = test_guard!();
    let (_directory, mut session) = docs(256);
    let result = session
        .publish_with_observer("docs", {
            let mut count = 0;
            move |point, _| {
                if point == PublicationPoint::PublishedDurable {
                    count += 1;
                    anyhow::ensure!(count != 73, "injected interruption after 73 outputs");
                }
                Ok(())
            }
        })
        .await;
    assert!(result.is_err());
    assert_eq!(session.recipe.phases[0].published.len(), 73);
    assert_acknowledged(&session);
    let mut recovered = reload(&session);
    recovered.publish("docs").await.unwrap();
    assert_docs(&recovered, 256);
    recovered.returned(0).unwrap();
    assert_acknowledged(&recovered);
}

#[path = "publication_baseline_tests.rs"]
mod baseline_tests;
