//! Build-heartbeat progress reporting for the PreToolUse hook.
//!
//! While a compilation runs on a remote worker, the hook streams periodic
//! "heartbeat" updates to the daemon so it can detect a stuck or abandoned
//! build and reason about progress. This module owns that machinery: the
//! mutable snapshot of build phase/progress ([`BuildHeartbeatSnapshot`]), the
//! background loop that ticks every [`BUILD_HEARTBEAT_INTERVAL`] and on demand
//! ([`BuildHeartbeatLoop`]), the progress-counter bump used by output-streaming
//! callbacks ([`mark_heartbeat_progress`]), and the acknowledged
//! socket send ([`send_build_heartbeat`]).
//!
//! The loop is driven from the hook's `execute_remote_compilation` path; the
//! principal items it calls (`BuildHeartbeatLoop` and `mark_heartbeat_progress`)
//! are `pub(super)`, everything else is private to this module. The
//! `HookReporter` (human/agent-facing progress UI) is a separate concern that
//! stays in the parent module.

use super::*;

#[path = "heartbeat_executor.rs"]
mod heartbeat_executor;

const BUILD_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub(super) struct BuildHeartbeatSnapshot {
    phase: BuildHeartbeatPhase,
    detail: Option<String>,
    progress_counter: u64,
    progress_percent: Option<f64>,
    remote_pgid_file: Option<String>,
}

impl BuildHeartbeatSnapshot {
    /// Monotonic forward-progress counter carried by every heartbeat send.
    /// Exposed for tests asserting that streaming callbacks (sync upload,
    /// remote execution, artifact retrieval) actually mark progress.
    #[cfg(test)]
    pub(super) fn progress_counter(&self) -> u64 {
        self.progress_counter
    }

    pub(super) fn new() -> Self {
        Self {
            phase: BuildHeartbeatPhase::SyncUp,
            detail: Some("build_started".to_string()),
            progress_counter: 0,
            progress_percent: None,
            remote_pgid_file: None,
        }
    }

    fn update_phase(&mut self, phase: BuildHeartbeatPhase, detail: Option<String>) {
        self.phase = phase;
        self.detail = detail;
        self.progress_counter = self.progress_counter.saturating_add(1);
    }

    fn note_progress(&mut self) {
        self.progress_counter = self.progress_counter.saturating_add(1);
    }

    fn set_remote_pgid_file(&mut self, remote_pgid_file: Option<String>) {
        self.remote_pgid_file = remote_pgid_file;
    }
}

pub(super) struct BuildHeartbeatLoop {
    socket_path: String,
    build_id: u64,
    worker_id: WorkerId,
    hook_pid: u32,
    local_wrapper_id: Option<String>,
    durable_lease: Option<DurableLeaseWriter>,
    state: Arc<Mutex<BuildHeartbeatSnapshot>>,
    stop_tx: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    lease_stop_tx: Option<oneshot::Sender<()>>,
    lease_task: Option<tokio::task::JoinHandle<()>>,
}

impl BuildHeartbeatLoop {
    pub(super) fn start(
        socket_path: &str,
        build_id: u64,
        worker_id: &WorkerId,
        local_wrapper_id: Option<&str>,
        durable_lease: Option<&DurableLeaseWriter>,
    ) -> Self {
        Self::start_with_interval(
            socket_path,
            build_id,
            worker_id,
            local_wrapper_id,
            durable_lease,
            BUILD_HEARTBEAT_INTERVAL,
        )
    }

    fn start_with_interval(
        socket_path: &str,
        build_id: u64,
        worker_id: &WorkerId,
        local_wrapper_id: Option<&str>,
        durable_lease: Option<&DurableLeaseWriter>,
        interval: Duration,
    ) -> Self {
        let state = Arc::new(Mutex::new(BuildHeartbeatSnapshot::new()));
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

        let socket_path_owned = socket_path.to_string();
        let worker_id_owned = worker_id.clone();
        let state_for_task = Arc::clone(&state);
        let hook_pid = std::process::id();
        let local_wrapper_id = local_wrapper_id.map(str::to_string);
        let local_wrapper_id_for_task = local_wrapper_id.clone();
        let durable_lease = durable_lease.cloned();

        // The wire heartbeat must not await a durable journal writer. Even on
        // a blocking thread, a long fsync or publication-held journal mutex
        // would otherwise prevent this loop's next daemon heartbeat (#112).
        let task = heartbeat_executor::runtime().spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let snapshot = {
                            state_for_task
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone()
                        };
                        let heartbeat = BuildHeartbeatRequest {
                            build_id,
                            worker_id: worker_id_owned.clone(),
                            hook_pid: Some(hook_pid),
                            local_wrapper_id: local_wrapper_id_for_task.clone(),
                            remote_pgid_file: snapshot.remote_pgid_file.clone(),
                            phase: snapshot.phase,
                            detail: snapshot.detail,
                            progress_counter: Some(snapshot.progress_counter),
                            progress_percent: snapshot.progress_percent,
                        };
                        if let Err(e) = send_build_heartbeat(&socket_path_owned, &heartbeat).await {
                            debug!("build heartbeat send failed for build {}: {}", build_id, e);
                        }
                    }
                    _ = &mut stop_rx => break,
                }
            }
        });
        // Exactly one maintenance loop: do not enqueue one blocking journal
        // write per wire tick when storage is slow. It shares the existing
        // serialized writer and preserves identity-checked cancellation.
        let (lease_stop_tx, lease_task) = if let Some(lease) = durable_lease.clone() {
            let (stop, stopped) = oneshot::channel();
            let state = Arc::clone(&state);
            let task = heartbeat_executor::runtime().spawn(maintain_durable_lease(
                lease, state, build_id, interval, stopped,
            ));
            (Some(stop), Some(task))
        } else {
            (None, None)
        };

        Self {
            socket_path: socket_path.to_string(),
            build_id,
            worker_id: worker_id.clone(),
            hook_pid,
            local_wrapper_id,
            durable_lease,
            state,
            stop_tx: Some(stop_tx),
            task: Some(task),
            lease_stop_tx,
            lease_task,
        }
    }

    pub(super) fn shared_state(&self) -> Arc<Mutex<BuildHeartbeatSnapshot>> {
        Arc::clone(&self.state)
    }

    pub(super) fn update_phase(&self, phase: BuildHeartbeatPhase, detail: Option<String>) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .update_phase(phase, detail);
    }

    pub(super) fn set_remote_pgid_file(&self, remote_pgid_file: Option<String>) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_remote_pgid_file(remote_pgid_file);
    }

    pub(super) async fn flush(&self) {
        let snapshot = { self.state.lock().unwrap_or_else(|e| e.into_inner()).clone() };
        let phase_token = heartbeat_phase_token(&snapshot.phase);
        let heartbeat = BuildHeartbeatRequest {
            build_id: self.build_id,
            worker_id: self.worker_id.clone(),
            hook_pid: Some(self.hook_pid),
            local_wrapper_id: self.local_wrapper_id.clone(),
            remote_pgid_file: snapshot.remote_pgid_file.clone(),
            phase: snapshot.phase,
            detail: snapshot.detail,
            progress_counter: Some(snapshot.progress_counter),
            progress_percent: snapshot.progress_percent,
        };
        if let Err(e) = send_build_heartbeat(&self.socket_path, &heartbeat).await {
            debug!(
                "build heartbeat flush failed for build {}: {}",
                self.build_id, e
            );
        }
        if let Some(lease) = self.durable_lease.as_ref()
            && let Err(error) = write_durable_heartbeat(lease, phase_token).await
        {
            debug!(
                "durable lease flush write failed for build {}: {}",
                self.build_id, error
            );
        }
    }

    pub(super) async fn finish(mut self, phase: BuildHeartbeatPhase, detail: Option<String>) {
        self.update_phase(phase, detail);
        self.flush().await;
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(stop_tx) = self.lease_stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.lease_task.take() {
            let _ = task.await;
        }
    }
}

async fn write_durable_heartbeat(
    writer: &DurableLeaseWriter,
    phase: &'static str,
) -> anyhow::Result<()> {
    let writer = writer.clone();
    tokio::task::spawn_blocking(move || writer.heartbeat(phase))
        .await
        .context("durable heartbeat worker failed")?
}

fn cancellation_marker_matches(path: &Path, identity: &JobIdentity) -> bool {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<JobIdentity>(&bytes).ok())
        .as_ref()
        == Some(identity)
}

async fn maintain_durable_lease(
    lease: DurableLeaseWriter,
    heartbeat_state: Arc<Mutex<BuildHeartbeatSnapshot>>,
    build_id: u64,
    interval: Duration,
    mut stopped: oneshot::Receiver<()>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_warning = None;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = &mut stopped => break,
        }
        let writer = lease.clone();
        let evidence = tokio::task::spawn_blocking(move || {
            let evidence = writer.snapshot();
            let cancellation = default_job_lease_directory()
                .join(format!("{}.cancel", evidence.identity.local_wrapper_id));
            let cancelled = cancellation_marker_matches(&cancellation, &evidence.identity);
            (evidence, cancelled)
        })
        .await;
        let (evidence, cancelled) = match evidence {
            Ok(evidence) => evidence,
            Err(error) => {
                debug!(
                    "durable lease observation failed for build {}: {}",
                    build_id, error
                );
                continue;
            }
        };
        let observed = crate::commands::jobs::query(&evidence).await;
        if cancelled
            && let Ok(status) = &observed
            && let Ok(code) = crate::commands::jobs::validate_completion(&evidence, status)
        {
            let writer = lease.clone();
            let completion_evidence = evidence.clone();
            let acknowledged = tokio::task::spawn_blocking(move || {
                writer.acknowledge_observed_completion(&completion_evidence, code)
            })
            .await;
            if matches!(acknowledged, Ok(Ok(()))) {
                std::process::exit(code);
            }
        }
        let mut state = rch_common::job_recovery::WrapperState::waiting(evidence.state);
        if let Ok(status) = observed {
            if status["status"] == "not_found" {
                state.remote_absent = true;
            }
            if status["status"] == "completed" {
                state.job_state = rch_common::job_identity::JobLifecycleState::Finished;
                state.artifacts_pending = evidence.recovery.is_some();
            }
        }
        let warning = rch_common::job_recovery::diagnose_stuck_wrapper(&evidence.identity, &state);
        if warning.stuck && last_warning != Some(warning.class) {
            if let Ok(json) = serde_json::to_string(&warning) {
                eprintln!("{json}");
            }
            last_warning = Some(warning.class);
        }
        let phase = heartbeat_phase_token(
            &heartbeat_state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .phase,
        );
        if let Err(error) = write_durable_heartbeat(&lease, phase).await {
            debug!(
                "durable lease heartbeat write failed for build {}: {}",
                build_id, error
            );
        }
    }
}

fn heartbeat_phase_token(phase: &BuildHeartbeatPhase) -> &'static str {
    match phase {
        BuildHeartbeatPhase::SyncUp => "sync_up",
        BuildHeartbeatPhase::Execute => "execute",
        BuildHeartbeatPhase::SyncDown => "sync_down",
        BuildHeartbeatPhase::Finalize => "finalize",
    }
}

impl Drop for BuildHeartbeatLoop {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(stop_tx) = self.lease_stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some(task) = self.lease_task.take() {
            task.abort();
        }
    }
}

pub(super) fn mark_heartbeat_progress(state: &Arc<Mutex<BuildHeartbeatSnapshot>>) {
    state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .note_progress();
}

async fn send_build_heartbeat(
    socket_path: &str,
    heartbeat: &BuildHeartbeatRequest,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        Path::new(socket_path).exists(),
        "daemon socket disappeared during heartbeat"
    );

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => anyhow::bail!("daemon heartbeat connection timed out"),
    };
    let (reader, mut writer) = stream.into_split();

    let body = serde_json::to_string(heartbeat)?;
    let request = format!("POST /build-heartbeat\n{}\n", body);
    timeout(Duration::from_secs(5), async {
        writer.write_all(request.as_bytes()).await?;
        writer.flush().await?;
        writer.shutdown().await
    })
    .await
    .context("heartbeat write timed out")??;

    let body = super::daemon_ipc::read_daemon_body(reader, Duration::from_secs(5), false).await?;
    #[derive(serde::Deserialize)]
    struct Acknowledgement {
        status: String,
        build_id: u64,
        worker_id: String,
        phase: String,
    }
    let acknowledgement: Acknowledgement = serde_json::from_str(&body)?;
    anyhow::ensure!(
        acknowledgement.build_id == heartbeat.build_id
            && acknowledgement.worker_id == heartbeat.worker_id.as_str()
            && acknowledgement.phase == heartbeat_phase_token(&heartbeat.phase),
        "Daemon heartbeat acknowledgement does not match the submitted build, worker and phase"
    );
    if acknowledgement.status == "ignored" {
        warn!(
            build_id = heartbeat.build_id,
            worker_id = %heartbeat.worker_id,
            local_wrapper_id = ?heartbeat.local_wrapper_id,
            phase = heartbeat_phase_token(&heartbeat.phase),
            reason = "heartbeat_unknown_build",
            "Daemon no longer tracks this build; remote execution may still be active. Inspect rch status --jobs and rch queue before intervening; do not rerun the command"
        );
    }
    anyhow::ensure!(
        acknowledgement.status == "ok",
        "Daemon did not acknowledge heartbeat: {}",
        acknowledgement.status
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_build_heartbeat_is_not_acknowledged() {
        let root = tempfile::tempdir().unwrap().keep();
        let socket = root.join("heartbeat.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).await.unwrap();
            let (route, body) = request.split_once('\n').unwrap();
            assert_eq!(route, "POST /build-heartbeat");
            let heartbeat: BuildHeartbeatRequest = serde_json::from_str(body).unwrap();
            let response = serde_json::json!({
                "status": "ignored",
                "build_id": heartbeat.build_id,
                "worker_id": heartbeat.worker_id,
                "phase": "execute"
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
        });
        let heartbeat = BuildHeartbeatRequest {
            build_id: 71,
            worker_id: WorkerId::new("lost-worker"),
            hook_pid: Some(std::process::id()),
            local_wrapper_id: Some("lost-wrapper".to_string()),
            remote_pgid_file: None,
            phase: BuildHeartbeatPhase::Execute,
            detail: None,
            progress_counter: Some(1),
            progress_percent: None,
        };
        let result = send_build_heartbeat(socket.to_str().unwrap(), &heartbeat).await;
        server.await.unwrap();
        assert!(
            result.is_err(),
            "an ignored heartbeat is not an acknowledgement"
        );
    }

    #[tokio::test]
    async fn known_build_heartbeat_is_acknowledged() {
        let root = tempfile::tempdir().unwrap().keep();
        let socket = root.join("heartbeat.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).await.unwrap();
            let (_, body) = request.split_once('\n').unwrap();
            let heartbeat: BuildHeartbeatRequest = serde_json::from_str(body).unwrap();
            let response = serde_json::json!({
                "status": "ok",
                "build_id": heartbeat.build_id,
                "worker_id": heartbeat.worker_id,
                "phase": "execute"
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
        });
        let heartbeat = BuildHeartbeatRequest {
            build_id: 72,
            worker_id: WorkerId::new("tracked-worker"),
            hook_pid: Some(std::process::id()),
            local_wrapper_id: Some("tracked-wrapper".to_string()),
            remote_pgid_file: None,
            phase: BuildHeartbeatPhase::Execute,
            detail: None,
            progress_counter: Some(2),
            progress_percent: None,
        };
        let result = send_build_heartbeat(socket.to_str().unwrap(), &heartbeat).await;
        server.await.unwrap();
        assert!(
            result.is_ok(),
            "a matching ok acknowledgement must succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn mismatched_acknowledgement_is_rejected() {
        let root = tempfile::tempdir().unwrap().keep();
        let socket = root.join("heartbeat.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).await.unwrap();
            // Acknowledge a different build: correlation must fail closed.
            let response = serde_json::json!({
                "status": "ok",
                "build_id": 999,
                "worker_id": "tracked-worker",
                "phase": "execute"
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
        });
        let heartbeat = BuildHeartbeatRequest {
            build_id: 72,
            worker_id: WorkerId::new("tracked-worker"),
            hook_pid: Some(std::process::id()),
            local_wrapper_id: Some("tracked-wrapper".to_string()),
            remote_pgid_file: None,
            phase: BuildHeartbeatPhase::Execute,
            detail: None,
            progress_counter: Some(3),
            progress_percent: None,
        };
        let result = send_build_heartbeat(socket.to_str().unwrap(), &heartbeat).await;
        server.await.unwrap();
        let error = result.expect_err("mismatched acknowledgement must not pass");
        assert!(error.to_string().contains("does not match"), "{error}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn slow_durable_publication_does_not_stop_wire_heartbeats() {
        // Exercise the actual shared journal mutex and actual acknowledged
        // Unix-socket heartbeat protocol, without contacting an ambient daemon.
        let root = tempfile::tempdir().unwrap().keep();
        let socket = root.join("heartbeat.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let worker = WorkerId::new("publication-worker");
        let lease = DurableLeaseWriter {
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
                "heartbeat-publication-fixture".into(),
            ))),
        };
        lease.admit(72, &worker).unwrap();
        let wrapper = lease.wrapper_id();
        let blocked = lease.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            blocked.persist_snapshot(|path, bytes| {
                let _ = ready_tx.send(());
                // Independent watchdog makes reactor-blocking regressions
                // fail instead of hanging the process indefinitely.
                let _ = release_rx.recv_timeout(Duration::from_secs(3));
                atomic_write(path, bytes)
            })
        });
        ready_rx.await.unwrap();
        let server =
            tokio::spawn(async move {
                let mut publishing = 0;
                while publishing < 4 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = String::new();
                    stream.read_to_string(&mut request).await.unwrap();
                    let (route, body) = request.split_once('\n').unwrap();
                    assert_eq!(route, "POST /build-heartbeat");
                    let heartbeat: BuildHeartbeatRequest = serde_json::from_str(body).unwrap();
                    assert_eq!(heartbeat.build_id, 72);
                    // The service now runs concurrently with start()'s caller.
                    // An initial SyncUp can precede update_phase(); it does not
                    // count toward the four required publication heartbeats.
                    if heartbeat.phase == BuildHeartbeatPhase::SyncUp {
                        assert_eq!(heartbeat.detail.as_deref(), Some("build_started"));
                        assert_eq!(heartbeat.progress_counter, Some(0));
                    } else {
                        assert_eq!(heartbeat.phase, BuildHeartbeatPhase::SyncDown);
                        assert_eq!(heartbeat.detail.as_deref(), Some("publishing"));
                        publishing += 1;
                    }
                    let response = serde_json::json!({
                        "status": "ok", "build_id": heartbeat.build_id,
                        "worker_id": heartbeat.worker_id,
                        "phase": heartbeat_phase_token(&heartbeat.phase)
                    });
                    stream.write_all(format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{response}\n"
                ).as_bytes()).await.unwrap();
                }
            });
        let mut heartbeat = BuildHeartbeatLoop::start_with_interval(
            socket.to_str().unwrap(),
            72,
            &worker,
            Some(&wrapper),
            Some(&lease),
            Duration::from_millis(20),
        );
        heartbeat.update_phase(BuildHeartbeatPhase::SyncDown, Some("publishing".into()));
        let result = tokio::time::timeout(Duration::from_secs(1), server).await;
        // Abort maintenance before unlocking it: this fixture must never query
        // a real job service after the blocked snapshot becomes available.
        let maintenance = heartbeat.lease_task.take().unwrap();
        maintenance.abort();
        let _ = maintenance.await;
        drop(heartbeat);
        let _ = release_tx.send(());
        holder.join().unwrap().unwrap();
        result
            .expect("journal I/O stopped daemon heartbeats")
            .unwrap();
    }

    #[test]
    fn cancellation_marker_requires_the_exact_job_identity() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("owned.cancel");
        let identity = JobIdentity::new_local();
        assert!(!cancellation_marker_matches(&marker, &identity));
        std::fs::write(&marker, b"not an identity").unwrap();
        assert!(!cancellation_marker_matches(&marker, &identity));
        std::fs::write(
            &marker,
            serde_json::to_vec(&JobIdentity::new_local()).unwrap(),
        )
        .unwrap();
        assert!(!cancellation_marker_matches(&marker, &identity));
        std::fs::write(&marker, serde_json::to_vec(&identity).unwrap()).unwrap();
        assert!(cancellation_marker_matches(&marker, &identity));
    }
}
