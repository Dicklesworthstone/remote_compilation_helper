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
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};
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
            let worker = thread::spawn(move || -> anyhow::Result<()> {
                let deadline = Instant::now() + Duration::from_secs(30);
                while !stopped.load(Ordering::Acquire) {
                    anyhow::ensure!(
                        Instant::now() < deadline,
                        "heartbeat peer watchdog expired"
                    );
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
                    if stream.write_all(reply.as_bytes()).is_ok()
                        && sender.send(heartbeat).is_err()
                    {
                        break;
                    }
                }
                Ok(())
            });
            Self {
                root,
                socket,
                received,
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
        first.update_phase(BuildHeartbeatPhase::SyncDown, Some("first-publication".into()));
        second.update_phase(BuildHeartbeatPhase::Execute, Some("second-execution".into()));
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
}
