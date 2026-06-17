//! Transfer / remote-execution orchestration for the hook.
//!
//! This submodule owns the pieces that orchestrate a remote compilation: the
//! command-wrapping, telemetry-forwarding, and (eventually) the SSH / sync /
//! repo-updater machinery driven by `execute_remote_compilation`.
//!
//! It is being grown incrementally (see bead `remote_compilation_helper-zcecy.14`):
//! this first slice holds the leaf telemetry-forwarding helpers that
//! `execute_remote_compilation` calls — wrapping the remote command so it
//! piggybacks worker telemetry on stdout, and the two daemon-IPC POST helpers
//! that forward the collected `WorkerTelemetry` / `TestRunRecord` back to the
//! local daemon. All three are leaves: they reach their dependencies
//! (`PIGGYBACK_MARKER`, `TelemetrySource`, `TestRunRecord`, `WorkerTelemetry`,
//! `WorkerId`, `urlencoding_encode`, the async-IO primitives, …) through the
//! parent scope via `use super::*`, and are `pub(super)` because their only
//! callers are inside the `hook` module (`execute_remote_compilation` and the
//! hook test suite).

use super::*;

pub(super) fn wrap_command_with_telemetry(command: &str, worker_id: &WorkerId) -> String {
    let escaped_worker = shell_escape::escape(worker_id.as_str().into());
    // Use newline instead of semicolon to ensure trailing comments in command
    // don't comment out the status capture logic.
    format!(
        "{cmd}\nstatus=$?; if command -v rch-telemetry >/dev/null 2>&1; then \
         telemetry=$(rch-telemetry collect --format json --worker-id {worker} 2>/dev/null || true); \
         if [ -n \"$telemetry\" ]; then echo '{marker}'; echo \"$telemetry\"; fi; \
         fi; exit $status",
        cmd = command,
        worker = escaped_worker,
        marker = PIGGYBACK_MARKER
    )
}

pub(super) async fn send_telemetry(
    socket_path: &str,
    source: TelemetrySource,
    telemetry: &WorkerTelemetry,
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

    let body = telemetry.to_json()?;
    let request = format!(
        "POST /telemetry/ingest?source={}\n{}\n",
        urlencoding_encode(&source.to_string()),
        body
    );

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;
    writer.shutdown().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

pub(super) async fn send_test_run(socket_path: &str, record: &TestRunRecord) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(());
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    let body = record.to_json()?;
    let request = format!("POST /test-run\n{}\n", body);

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;
    writer.shutdown().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}
