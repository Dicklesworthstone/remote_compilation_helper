//! Build-heartbeat progress reporting for the PreToolUse hook.
//!
//! While a compilation runs on a remote worker, the hook streams periodic
//! "heartbeat" updates to the daemon so it can detect a stuck or abandoned
//! build and reason about progress. This module owns that machinery: the
//! mutable snapshot of build phase/progress ([`BuildHeartbeatSnapshot`]), the
//! background loop that ticks every [`BUILD_HEARTBEAT_INTERVAL`] and on demand
//! ([`BuildHeartbeatLoop`]), the progress-counter bump used by output-streaming
//! callbacks ([`mark_heartbeat_progress`]), and the single fire-and-forget
//! socket send ([`send_build_heartbeat`]).
//!
//! The loop is driven from the hook's `execute_remote_compilation` path; the
//! principal items it calls (`BuildHeartbeatLoop` and `mark_heartbeat_progress`)
//! are `pub(super)`, everything else is private to this module. The
//! `HookReporter` (human/agent-facing progress UI) is a separate concern that
//! stays in the parent module.

use super::*;

const BUILD_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_DETAIL_CARGO_GIT_FETCH: &str = "cargo_git_fetch";
const HEARTBEAT_DETAIL_REMOTE_EXEC_OUTPUT: &str = "remote_exec_output";

fn heartbeat_detail_for_remote_output(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    trimmed
        .starts_with("Updating git repository")
        .then_some(HEARTBEAT_DETAIL_CARGO_GIT_FETCH)
}

#[derive(Debug, Clone)]
pub(super) struct BuildHeartbeatSnapshot {
    phase: BuildHeartbeatPhase,
    detail: Option<String>,
    progress_counter: u64,
    progress_percent: Option<f64>,
    remote_pgid_file: Option<String>,
}

impl BuildHeartbeatSnapshot {
    fn new() -> Self {
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

    fn note_remote_output(&mut self, line: &str) {
        self.progress_counter = self.progress_counter.saturating_add(1);
        if let Some(detail) = heartbeat_detail_for_remote_output(line) {
            self.detail = Some(detail.to_string());
        } else if self.phase == BuildHeartbeatPhase::Execute
            && self.detail.as_deref() == Some(HEARTBEAT_DETAIL_CARGO_GIT_FETCH)
        {
            self.detail = Some(HEARTBEAT_DETAIL_REMOTE_EXEC_OUTPUT.to_string());
        }
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
    state: Arc<Mutex<BuildHeartbeatSnapshot>>,
    stop_tx: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl BuildHeartbeatLoop {
    pub(super) fn start(socket_path: &str, build_id: u64, worker_id: &WorkerId) -> Self {
        let state = Arc::new(Mutex::new(BuildHeartbeatSnapshot::new()));
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

        let socket_path_owned = socket_path.to_string();
        let worker_id_owned = worker_id.clone();
        let state_for_task = Arc::clone(&state);
        let hook_pid = std::process::id();

        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(BUILD_HEARTBEAT_INTERVAL);
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

        Self {
            socket_path: socket_path.to_string(),
            build_id,
            worker_id: worker_id.clone(),
            hook_pid,
            state,
            stop_tx: Some(stop_tx),
            task: Some(task),
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
        let heartbeat = BuildHeartbeatRequest {
            build_id: self.build_id,
            worker_id: self.worker_id.clone(),
            hook_pid: Some(self.hook_pid),
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
    }

    pub(super) async fn finish(mut self, phase: BuildHeartbeatPhase, detail: Option<String>) {
        self.update_phase(phase, detail);
        self.flush().await;
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for BuildHeartbeatLoop {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub(super) fn mark_heartbeat_progress(state: &Arc<Mutex<BuildHeartbeatSnapshot>>, line: &str) {
    state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .note_remote_output(line);
}

async fn send_build_heartbeat(
    socket_path: &str,
    heartbeat: &BuildHeartbeatRequest,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(());
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    let body = serde_json::to_string(heartbeat)?;
    let request = format!("POST /build-heartbeat\n{}\n", body);
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;
    writer.shutdown().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    #[test]
    fn heartbeat_detail_classifies_cargo_git_fetch_output() {
        let _guard = test_guard!();
        assert_eq!(
            heartbeat_detail_for_remote_output(
                "    Updating git repository `https://github.com/Dicklesworthstone/asupersync`"
            ),
            Some(HEARTBEAT_DETAIL_CARGO_GIT_FETCH)
        );
        assert_eq!(
            heartbeat_detail_for_remote_output("   Compiling rch-common v0.1.0"),
            None
        );
    }

    #[test]
    fn heartbeat_snapshot_clears_dependency_fetch_detail_after_other_output() {
        let _guard = test_guard!();
        let mut snapshot = BuildHeartbeatSnapshot::new();
        snapshot.update_phase(
            BuildHeartbeatPhase::Execute,
            Some("remote_exec_start".to_string()),
        );

        snapshot.note_remote_output("Updating git repository `https://example.invalid/repo`");
        assert_eq!(
            snapshot.detail.as_deref(),
            Some(HEARTBEAT_DETAIL_CARGO_GIT_FETCH)
        );

        snapshot.note_remote_output("   Compiling rch-common v0.1.0");
        assert_eq!(
            snapshot.detail.as_deref(),
            Some(HEARTBEAT_DETAIL_REMOTE_EXEC_OUTPUT)
        );
    }
}
