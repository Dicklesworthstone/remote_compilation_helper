//! Keep liveness independent of the caller's current-thread runtime (#112).
//!
//! Artifact publication and other synchronous filesystem work can occupy the
//! caller for minutes. Moving journal writes to spawn_blocking is not enough:
//! a wire-heartbeat task spawned on that caller still cannot be polled. Use one
//! process-wide service executor, not one runtime/thread per tick or per job.
//! Its tasks retain the existing per-build stop/abort handles and the existing
//! serialized, identity-checked lease writer. No progress is fabricated here.
//!
//! This is a liveness boundary, not a publication timeout implementation. It
//! does not detach a publisher, release its locks, alter a recovery checkpoint,
//! change daemon cancellation thresholds, or make filesystem calls abortable.

use std::sync::OnceLock;
use tokio::runtime::{Builder, Runtime};

pub(super) fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("rch-heartbeat")
            .enable_all()
            .build()
            .expect("cannot start independent build-heartbeat executor")
    })
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::hook::transfer_orchestration::recovery::RecoverySession;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    /// A real socket peer on an OS thread, deliberately independent of BOTH
    /// Tokio runtimes. A caller-runtime timer would conceal the same starvation
    /// as the bug. Its wall-clock watchdog also bounds failure on the old code.
    struct Daemon {
        root: PathBuf,
        socket: PathBuf,
        received: mpsc::Receiver<BuildHeartbeatRequest>,
        publication_beats: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<anyhow::Result<()>>>,
    }

    impl Daemon {
        fn start() -> Self {
            let root = tempfile::Builder::new()
                .disable_cleanup(true)
                .tempdir()
                .unwrap()
                .keep();
            let socket = root.join("heartbeat.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let stopped = Arc::clone(&stop);
            let (sender, received) = mpsc::channel();
            let publication_beats = Arc::new(AtomicUsize::new(0));
            let observed_publication = Arc::clone(&publication_beats);
            let worker = thread::spawn(move || -> anyhow::Result<()> {
                let deadline = Instant::now() + Duration::from_secs(30);
                while !stopped.load(Ordering::Acquire) {
                    anyhow::ensure!(Instant::now() < deadline, "heartbeat peer watchdog expired");
                    let (mut stream, _) = match listener.accept() {
                        Ok(stream) => stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    };
                    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
                    let mut request = String::new();
                    if stream.read_to_string(&mut request).is_err() {
                        continue;
                    }
                    let Some((route, body)) = request.split_once('\n') else {
                        continue; // An aborted sender can leave an incomplete request.
                    };
                    let Ok(heartbeat) = serde_json::from_str::<BuildHeartbeatRequest>(body) else {
                        continue;
                    };
                    anyhow::ensure!(route == "POST /build-heartbeat", "unexpected route");
                    let response = serde_json::json!({
                        "status": "ok",
                        "build_id": heartbeat.build_id,
                        "worker_id": heartbeat.worker_id,
                        "phase": heartbeat_phase_token(&heartbeat.phase),
                    });
                    let reply = format!(
                        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{response}\n"
                    );
                    if stream.write_all(reply.as_bytes()).is_ok() {
                        if heartbeat.phase == BuildHeartbeatPhase::SyncDown {
                            observed_publication.fetch_add(1, Ordering::AcqRel);
                        }
                        if sender.send(heartbeat).is_err() {
                            break;
                        }
                    }
                }
                Ok(())
            });
            Self {
                root,
                socket,
                received,
                publication_beats,
                stop,
                worker: Some(worker),
            }
        }

        fn heartbeat(&self, build: u64, wrapper: &str) -> BuildHeartbeatLoop {
            BuildHeartbeatLoop::start_with_interval(
                self.socket.to_str().unwrap(),
                build,
                &WorkerId::new("independent-worker"),
                Some(wrapper),
                None, // Never consult an ambient daemon or cancellation marker.
                Duration::from_millis(20),
            )
        }

        fn receive(&self, deadline: Instant) -> anyhow::Result<BuildHeartbeatRequest> {
            Ok(self
                .received
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))?)
        }

        fn finish(mut self) {
            self.stop.store(true, Ordering::Release);
            self.worker.take().unwrap().join().unwrap().unwrap();
        }
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_caller_does_not_starve_wire_heartbeats_or_invent_progress() {
        let daemon = Daemon::start();
        let heartbeat = daemon.heartbeat(812, "publication-wrapper");
        heartbeat.update_phase(BuildHeartbeatPhase::SyncDown, Some("publishing".into()));
        let state = heartbeat.shared_state();
        mark_heartbeat_progress(&state);
        mark_heartbeat_progress(&state);
        // Real synchronous writes/fsyncs, followed by a synchronous rendezvous.
        // There is intentionally NO await until all four heartbeats arrive.
        // This fails on the caller-spawn implementation even on a fast tmpfs.
        let outcome = (|| -> anyhow::Result<()> {
            for index in 0u8..64 {
                let path = daemon.root.join(format!("artifact-{index:04}"));
                let mut file = std::fs::File::create(&path)?;
                file.write_all(&[index; 8192])?;
                file.sync_all()?;
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut publishing = 0;
            while publishing < 4 {
                let observed = daemon.receive(deadline)?;
                anyhow::ensure!(observed.build_id == 812, "wrong build");
                anyhow::ensure!(
                    observed.worker_id.as_str() == "independent-worker",
                    "wrong worker"
                );
                anyhow::ensure!(
                    observed.local_wrapper_id.as_deref() == Some("publication-wrapper"),
                    "wrong wrapper"
                );
                if observed.phase != BuildHeartbeatPhase::SyncDown
                    || observed.progress_counter != Some(3)
                {
                    continue; // A snapshot may precede the caller's phase/progress updates.
                }
                anyhow::ensure!(
                    observed.detail.as_deref() == Some("publishing"),
                    "wrong detail"
                );
                publishing += 1;
            }
            anyhow::ensure!(
                state.lock().unwrap().progress_counter() == 3,
                "liveness fabricated progress"
            );
            Ok(())
        })();
        drop(heartbeat);
        daemon.finish();
        outcome.expect("synchronous publication work starved the heartbeat executor");
    }

    #[test]
    fn heartbeat_service_survives_an_unpolled_caller_and_stops_on_drop() {
        let daemon = Daemon::start();
        let caller = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let heartbeat = caller.block_on(async { daemon.heartbeat(813, "paused-wrapper") });
        let abort = heartbeat.task.as_ref().unwrap().abort_handle();
        // The caller runtime exists but is no longer being driven at all.
        let outcome = (|| -> anyhow::Result<()> {
            let deadline = Instant::now() + Duration::from_secs(3);
            for _ in 0..4 {
                let observed = daemon.receive(deadline)?;
                anyhow::ensure!(observed.build_id == 813, "wrong build");
                anyhow::ensure!(
                    observed.local_wrapper_id.as_deref() == Some("paused-wrapper"),
                    "wrong wrapper"
                );
            }
            Ok(())
        })();
        drop(heartbeat);
        let deadline = Instant::now() + Duration::from_secs(3);
        while !abort.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        let stopped = abort.is_finished();
        daemon.finish();
        drop(caller);
        outcome.expect("heartbeat depended on polling the caller runtime");
        assert!(stopped, "dropping the build left a heartbeat task alive");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shared_executor_keeps_concurrent_build_identities_separate() {
        let daemon = Daemon::start();
        let first = daemon.heartbeat(814, "first-wrapper");
        let second = daemon.heartbeat(815, "second-wrapper");
        first.update_phase(
            BuildHeartbeatPhase::SyncDown,
            Some("first-publication".into()),
        );
        second.update_phase(
            BuildHeartbeatPhase::Execute,
            Some("second-execution".into()),
        );
        let outcome = (|| -> anyhow::Result<()> {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut counts = [0usize; 2];
            while counts.iter().any(|count| *count < 4) {
                let observed = daemon.receive(deadline)?;
                if observed.phase == BuildHeartbeatPhase::SyncUp {
                    continue;
                }
                match observed.build_id {
                    814 => {
                        anyhow::ensure!(
                            observed.local_wrapper_id.as_deref() == Some("first-wrapper"),
                            "mixed first identity"
                        );
                        anyhow::ensure!(
                            observed.phase == BuildHeartbeatPhase::SyncDown,
                            "mixed first phase"
                        );
                        anyhow::ensure!(
                            observed.detail.as_deref() == Some("first-publication"),
                            "mixed first detail"
                        );
                        counts[0] += 1;
                    }
                    815 => {
                        anyhow::ensure!(
                            observed.local_wrapper_id.as_deref() == Some("second-wrapper"),
                            "mixed second identity"
                        );
                        anyhow::ensure!(
                            observed.phase == BuildHeartbeatPhase::Execute,
                            "mixed second phase"
                        );
                        anyhow::ensure!(
                            observed.detail.as_deref() == Some("second-execution"),
                            "mixed second detail"
                        );
                        counts[1] += 1;
                    }
                    _ => anyhow::bail!("heartbeat belonged to an unrelated build"),
                }
                anyhow::ensure!(
                    observed.progress_counter == Some(1),
                    "progress must remain caller-owned"
                );
            }
            Ok(())
        })();
        drop(first);
        drop(second);
        daemon.finish();
        outcome.expect("shared service starved or mixed concurrent build heartbeats");
    }

    /// Use the production preparation, staging and publication APIs. The
    /// successful remote exit is an explicit fixture observation; no remote
    /// command, replacement copy implementation or ambient daemon is involved.
    struct Delivery {
        session: RecoverySession,
        writer: DurableLeaseWriter,
        local: PathBuf,
        stage: PathBuf,
        count: usize,
    }

    impl Delivery {
        fn prepare(root: &Path, count: usize) -> Self {
            let local = root.join("caller");
            std::fs::create_dir_all(&local).unwrap();
            std::fs::write(local.join("source-sentinel"), b"not an artifact").unwrap();
            let worker = WorkerConfig {
                id: WorkerId::new("independent-worker"),
                host: "unreachable.invalid".into(),
                user: "worker".into(),
                identity_file: "/unused/publication-key".into(),
                total_slots: 1,
                priority: 100,
                tags: Vec::new(),
                tools: Vec::new(),
            };
            let writer = DurableLeaseWriter {
                path: root.join("lease.json"),
                recovery_ownership: None,
                lease: Arc::new(Mutex::new(DurableJobLease::new(
                    JobIdentity::new_local(),
                    std::process::id(),
                    None,
                    None,
                    0,
                    false,
                    false,
                    "real-publication-liveness-fixture".into(),
                ))),
            };
            writer.admit(917, &worker.id).unwrap();
            let identity = uuid::Uuid::new_v4().simple().to_string();
            let transfer = TransferConfig {
                retrieval_staging_dir: Some(root.join("staging")),
                ..TransferConfig::default()
            };
            let sources = vec!["/data/projects/heartbeat-publication-fixture".into()];
            RecoverySession::begin(
                &writer,
                &worker,
                sources.clone(),
                None,
                None,
                None,
                transfer.clone(),
                local.clone(),
                identity.clone(),
            )
            .unwrap();
            let pipeline = crate::transfer::TransferPipeline::new(
                local.clone(),
                "heartbeat-publication".into(),
                identity.clone(),
                transfer.clone(),
            );
            let mut session = RecoverySession::prepare(
                &writer,
                &worker,
                &pipeline,
                sources,
                None,
                None,
                None,
                transfer,
                local.clone(),
                None,
                None,
                "make",
                &[PathBuf::from("doc")],
                identity.clone(),
            )
            .unwrap();
            session.starting_execution().unwrap();
            session.completed(0).unwrap();
            writer.heartbeat("sync_down").unwrap();
            session.staging_pipeline("result:doc", &pipeline).unwrap();
            let recovery = writer.snapshot().recovery.unwrap();
            let index = recovery["phases"]
                .as_array()
                .unwrap()
                .iter()
                .position(|phase| phase["name"] == "result:doc")
                .unwrap();
            // This is the configured, identity-bound stage layout. Requiring
            // its existence checks that the production API selected it too.
            let stage = root.join("staging").join(identity).join(index.to_string());
            assert!(stage.is_dir());
            std::fs::create_dir_all(stage.join("doc")).unwrap();
            for index in 0..count {
                std::fs::write(
                    stage.join(format!("doc/fn.{index:05}.html")),
                    Self::bytes(index),
                )
                .unwrap();
            }
            Self {
                session,
                writer,
                local,
                stage,
                count,
            }
        }

        fn bytes(index: usize) -> String {
            format!("<html>documentation for function {index}</html>\n")
        }

        fn assert_delivered(&self) {
            let disk: DurableJobLease =
                serde_json::from_slice(&std::fs::read(&self.writer.path).unwrap()).unwrap();
            let durable = disk.recovery.unwrap();
            let phase = durable["phases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|phase| phase["name"] == "result:doc")
                .unwrap();
            assert_eq!(phase["complete"], true);
            assert!(phase["pending"].is_null());
            assert_eq!(phase["published"].as_object().unwrap().len(), self.count);
            assert_eq!(durable["exit_code"], 0);
            assert_eq!(durable["returned"], 0);
            assert_eq!(self.writer.snapshot().recovery.as_ref(), Some(&durable));
            for index in 0..self.count {
                assert_eq!(
                    std::fs::read_to_string(self.local.join(format!("doc/fn.{index:05}.html")))
                        .unwrap(),
                    Self::bytes(index),
                );
            }
            assert_eq!(
                std::fs::read(self.local.join("source-sentinel")).unwrap(),
                b"not an artifact",
            );
            // Successful delivery is not permission to pretend the outstanding
            // source ownership was retired or the daemon acknowledged it.
            assert!(!disk.terminal_acknowledged);
            assert!(self.writer.acknowledge_terminal().is_err());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_publication_completes_while_journal_contention_and_heartbeats_overlap() {
        let _guard = rch_common::test_guard!();
        let daemon = Daemon::start();
        let mut delivery = Delivery::prepare(&daemon.root, 96);
        let heartbeat = daemon.heartbeat(917, &delivery.writer.wrapper_id());
        heartbeat.update_phase(
            BuildHeartbeatPhase::SyncDown,
            Some("real-publication".into()),
        );
        let lease = Arc::clone(&delivery.writer.lease);
        let beats = Arc::clone(&daemon.publication_beats);
        let (ready, locked) = oneshot::channel();
        let (arm, armed) = mpsc::channel::<usize>();
        let holder = thread::spawn(move || {
            let _held = lease.lock().unwrap();
            let _ = ready.send(());
            let initial = armed.recv_timeout(Duration::from_secs(3)).unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            while beats.load(Ordering::Acquire).saturating_sub(initial) < 4
                && Instant::now() < deadline
            {
                thread::sleep(Duration::from_millis(1));
            }
            beats.load(Ordering::Acquire).saturating_sub(initial)
        });
        locked.await.unwrap();
        arm.send(daemon.publication_beats.load(Ordering::Acquire))
            .unwrap();
        // On the old implementation this awaits a function that blocks the
        // sole caller thread on the real journal mutex. The holder's independent
        // watchdog releases it with zero heartbeats, so the test fails, not hangs.
        let publication = delivery.session.publish("result:doc").await;
        let during_contention = holder.join().unwrap();
        drop(heartbeat);
        daemon.finish();
        publication.unwrap();
        assert!(
            during_contention >= 4,
            "real publication starved wire heartbeats"
        );
        delivery.session.returned(0).unwrap();
        delivery.assert_delivered();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_stage_retains_journal_and_same_session_retry_delivers_outputs() {
        let _guard = rch_common::test_guard!();
        let root = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let mut delivery = Delivery::prepare(root.path(), 24);
        let retained = delivery.stage.with_extension("temporarily-unavailable");
        std::fs::rename(&delivery.stage, &retained).unwrap();
        let before = std::fs::read(&delivery.writer.path).unwrap();
        assert!(delivery.session.publish("result:doc").await.is_err());
        assert_eq!(std::fs::read(&delivery.writer.path).unwrap(), before);
        assert!(!delivery.local.join("doc").exists());
        assert!(delivery.writer.acknowledge_terminal().is_err());
        std::fs::rename(&retained, &delivery.stage).unwrap();
        delivery.session.publish("result:doc").await.unwrap();
        delivery.session.returned(0).unwrap();
        delivery.assert_delivered();
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "2048 real fsync-backed publications; run explicitly for large-artifact qualification"]
    async fn large_rustdoc_set_is_durably_delivered() {
        let _guard = rch_common::test_guard!();
        let root = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let mut delivery = Delivery::prepare(root.path(), 2048);
        delivery.session.publish("result:doc").await.unwrap();
        delivery.session.returned(0).unwrap();
        delivery.assert_delivered();
    }
}
