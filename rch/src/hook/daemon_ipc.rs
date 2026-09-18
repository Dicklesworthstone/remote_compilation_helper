//! Daemon IPC client: the hook's worker-selection / release / build-record
//! requests over the `rchd` Unix socket, plus the request-timeout and
//! queue-when-busy policy helpers and the URL encoder for query strings.
//!
//! [`query_daemon`] / [`release_worker`] are `pub(crate)` because
//! `commands::status` and the daemon hot path both call them;
//! [`record_build`] is hook-internal. The selection response is parsed via
//! the parent's re-exported `parse_selection_response`; the timeout helpers
//! and `urlencoding_encode` stay `pub(super)` for the test suite.
use super::*;
use serde::Deserialize;

const MAX_DAEMON_HEADER_BYTES: usize = 16 * 1024;
const MAX_DAEMON_BODY_BYTES: usize = 64 * 1024;
const MAX_DAEMON_STATUS_BYTES: usize = 1024;

/// Bound the entire write, not each partial write. A listening daemon can
/// accept a connection and then stop reading; the response deadline has not
/// started yet, so an unbounded write would strand the dispatch indefinitely.
async fn write_daemon_request<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    request: &[u8],
    budget: Duration,
) -> anyhow::Result<()> {
    timeout(budget, async {
        writer.write_all(request).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "Daemon request write timed out after {}ms",
            budget.as_millis()
        )
    })??;
    Ok(())
}

/// This is the daemon's one-response-per-connection protocol, not a general
/// HTTP client. Limit bytes *before* reading them: read_line followed by a
/// length check cannot bound a peer that never sends a newline.
pub(super) async fn read_daemon_body<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    budget: Duration,
    allow_bare_json: bool,
) -> anyhow::Result<String> {
    const MAX_RESPONSE_BYTES: usize = MAX_DAEMON_HEADER_BYTES + MAX_DAEMON_BODY_BYTES + 4;
    let mut reader = reader.take((MAX_RESPONSE_BYTES + 1) as u64);
    let mut response = String::new();
    timeout(budget, reader.read_to_string(&mut response))
        .await
        .map_err(|_| {
            anyhow::anyhow!("Daemon response timed out after {}ms", budget.as_millis())
        })??;
    anyhow::ensure!(
        response.len() <= MAX_RESPONSE_BYTES,
        "Daemon response exceeded {} byte limit",
        MAX_RESPONSE_BYTES
    );
    let body = if let Some((headers, body)) = response
        .split_once("\r\n\r\n")
        .or_else(|| response.split_once("\n\n"))
    {
        anyhow::ensure!(
            headers.len() <= MAX_DAEMON_HEADER_BYTES,
            "Daemon response headers exceeded {} byte limit",
            MAX_DAEMON_HEADER_BYTES
        );
        validate_daemon_status(headers.lines().next().unwrap_or_default())?;
        body
    } else {
        anyhow::ensure!(
            allow_bare_json && !response.starts_with("HTTP/"),
            "Daemon response is missing complete HTTP headers"
        );
        response.as_str()
    };
    anyhow::ensure!(
        body.len() <= MAX_DAEMON_BODY_BYTES,
        "Daemon response body exceeded {}KB limit",
        MAX_DAEMON_BODY_BYTES / 1024
    );
    Ok(body.trim().to_string())
}

fn validate_daemon_status(line: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        line.len() <= MAX_DAEMON_STATUS_BYTES,
        "Daemon response status exceeded {} byte limit",
        MAX_DAEMON_STATUS_BYTES
    );
    let mut status = line.split_whitespace();
    anyhow::ensure!(
        matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) && status.next() == Some("200"),
        "Daemon returned non-success HTTP status: {}",
        line.trim()
    );
    Ok(())
}

pub(super) async fn read_daemon_ack<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    budget: Duration,
) -> anyhow::Result<()> {
    let mut reader = BufReader::new(reader).take((MAX_DAEMON_STATUS_BYTES + 1) as u64);
    let mut line = String::new();
    timeout(budget, reader.read_line(&mut line))
        .await
        .map_err(|_| {
            anyhow::anyhow!("daemon response timed out; release was not acknowledged")
        })??;
    anyhow::ensure!(
        line.len() <= MAX_DAEMON_STATUS_BYTES,
        "Daemon response status exceeded {} byte limit",
        MAX_DAEMON_STATUS_BYTES
    );
    anyhow::ensure!(
        line.ends_with('\n'),
        "daemon closed the connection without a complete acknowledgement"
    );
    validate_daemon_status(&line)
}

#[derive(Deserialize)]
struct RestartAdmissionStatus {
    admission_closed: bool,
}

/// Return whether a daemon restart remediator has closed new-worker admission.
/// This is intentionally a read-only preflight: the hook has already written
/// its durable lease, but must not change restart state itself.
pub(crate) async fn restart_admission_is_closed(socket_path: &str) -> anyhow::Result<bool> {
    if !Path::new(socket_path).exists() {
        return Err(DaemonError::SocketNotFound {
            socket_path: socket_path.to_string(),
        }
        .into());
    }
    let stream = timeout(daemon_io_timeout(), UnixStream::connect(socket_path))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Daemon connect timed out after {}ms",
                daemon_io_timeout().as_millis()
            )
        })??;
    let (reader, mut writer) = stream.into_split();
    write_daemon_request(
        &mut writer,
        b"GET /restart-admission\n",
        daemon_io_timeout(),
    )
    .await?;

    let body = read_daemon_body(reader, daemon_io_timeout(), true).await?;
    let status: RestartAdmissionStatus = serde_json::from_str(&body)
        .map_err(|error| anyhow::anyhow!("Malformed restart-admission response: {error}"))?;
    Ok(status.admission_closed)
}

/// Query the daemon for a worker.
#[allow(clippy::too_many_arguments)] // Command routing query wires many independent fields.
pub(crate) async fn query_daemon(
    socket_path: &str,
    project: &str,
    cores: u32,
    command: &str,
    toolchain: Option<&ToolchainInfo>,
    required_runtime: RequiredRuntime,
    command_priority: CommandPriority,
    classification_duration_us: u64,
    hook_pid: Option<u32>,
    local_wrapper_id: Option<&str>,
    wait_for_worker: bool,
    preferred_workers: &[WorkerId],
    job_mode: bool,
    required_tools: &[String],
) -> anyhow::Result<SelectionResponse> {
    // Mock support: RCH_MOCK_CIRCUIT_OPEN simulates all circuits open
    // This needs to be checked in the hook since the daemon may be started
    // before this environment variable is set for the test scenario.
    if std::env::var("RCH_MOCK_CIRCUIT_OPEN").is_ok() {
        debug!("RCH_MOCK_CIRCUIT_OPEN set, returning AllCircuitsOpen");
        return Ok(SelectionResponse {
            worker: None,
            reason: SelectionReason::AllCircuitsOpen,
            build_id: None,
            diagnostics: None,
        });
    }

    // Check if socket exists
    if !Path::new(socket_path).exists() {
        return Err(DaemonError::SocketNotFound {
            socket_path: socket_path.to_string(),
        }
        .into());
    }

    // Connect to daemon (with timeout to avoid hanging if socket is stuck)
    let stream = timeout(daemon_io_timeout(), UnixStream::connect(socket_path))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Daemon connect timed out after {}ms",
                daemon_io_timeout().as_millis()
            )
        })??;
    let (reader, mut writer) = stream.into_split();

    // Build query string
    let mut query = format!("project={}&cores={}", urlencoding_encode(project), cores);
    query.push_str(&format!("&command={}", urlencoding_encode(command)));

    if let Some(tc) = toolchain
        && let Ok(json) = serde_json::to_string(tc)
    {
        query.push_str(&format!("&toolchain={}", urlencoding_encode(&json)));
    }

    if required_runtime != RequiredRuntime::None {
        // Serialize to lowercase string (rust, bun, node)
        // Since it's an enum with lowercase serialization, serde_json::to_string gives "rust" (with quotes)
        // We want just the string.
        let json = serde_json::to_string(&required_runtime).unwrap_or_default();
        let raw = json.trim_matches('"');
        query.push_str(&format!("&runtime={}", urlencoding_encode(raw)));
    }

    query.push_str(&format!(
        "&priority={}",
        urlencoding_encode(&command_priority.to_string())
    ));

    // Add classification duration for AGENTS.md compliance tracking
    query.push_str(&format!(
        "&classification_us={}",
        classification_duration_us
    ));

    if let Some(pid) = hook_pid {
        query.push_str(&format!("&hook_pid={}", pid));
    }
    if let Some(local_wrapper_id) = local_wrapper_id {
        query.push_str(&format!(
            "&local_wrapper_id={}",
            urlencoding_encode(local_wrapper_id)
        ));
    }

    for worker in preferred_workers {
        query.push_str(&format!("&worker={}", urlencoding_encode(worker.as_str())));
    }
    if !preferred_workers.is_empty() {
        let legacy_preferred_workers = preferred_workers
            .iter()
            .map(|worker| worker.as_str())
            .collect::<Vec<_>>()
            .join(",");
        query.push_str(&format!(
            "&preferred_workers={}",
            urlencoding_encode(&legacy_preferred_workers)
        ));
    }

    // Job-mode admissions (bd-g7rpy) may queue on active-project exclusion.
    if job_mode {
        query.push_str("&job_mode=1");
    }

    // Verified named-tool requirements (bd-ceewf), repeatable. Job mode only —
    // the compilation classifier never produces them, so ordinary offloaded
    // builds send a byte-identical query.
    for tool in required_tools {
        query.push_str(&format!("&require_tool={}", urlencoding_encode(tool)));
    }

    // When all workers are at capacity, queue the build on the daemon instead of
    // falling back to a local compilation storm. Disable with RCH_QUEUE_WHEN_BUSY=0.
    if wait_for_worker {
        query.push_str("&wait=1");
        // Keep daemon queue timeout aligned with the client-side socket timeout
        // so queued requests return a structured SelectionReason instead of
        // triggering a client communication timeout.
        let wait_timeout_secs = daemon_response_timeout(wait_for_worker)
            .as_secs()
            .saturating_sub(1)
            .max(1);
        query.push_str(&format!("&wait_timeout_secs={}", wait_timeout_secs));
    }

    // Bound writes independently from the longer, queue-aware response wait.
    let request = format!("GET /select-worker?{}\n", query);
    write_daemon_request(&mut writer, request.as_bytes(), daemon_io_timeout()).await?;
    let body = read_daemon_body(reader, daemon_response_timeout(wait_for_worker), false).await?;
    let response = parse_selection_response(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse daemon response: {}", e))?;

    if let Some(worker) = response.worker.as_ref()
        && !selected_worker_is_requested(&worker.id, preferred_workers)
    {
        warn!(
            "Daemon selected unrequested worker {} for explicit request; releasing reservation and refusing remote execution",
            worker.id
        );
        let release_error = release_worker(
            socket_path,
            &worker.id,
            cores,
            response.build_id,
            Some(EXIT_BUILD_ERROR),
            None,
            None,
            None,
            local_wrapper_id,
        )
        .await
        .err();
        if let Some(error) = release_error.as_ref() {
            warn!(
                "Failed to release unrequested worker {} after selection refusal: {}",
                worker.id, error
            );
        }
        return Ok(SelectionResponse {
            worker: None,
            reason: release_error.map_or(SelectionReason::NoMatchingWorkers, |error| {
                SelectionReason::SelectionError(format!(
                    "[RCH-I001] unrequested worker reservation release was not acknowledged: {error}; restart rchd and verify capacity before retrying"
                ))
            }),
            build_id: None,
            diagnostics: response.diagnostics,
        });
    }

    Ok(response)
}

/// Release reserved slots on a worker.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn release_worker(
    socket_path: &str,
    worker_id: &WorkerId,
    slots: u32,
    build_id: Option<u64>,
    exit_code: Option<i32>,
    duration_ms: Option<u64>,
    bytes_transferred: Option<u64>,
    timing: Option<&CommandTimingBreakdown>,
    local_wrapper_id: Option<&str>,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        anyhow::bail!("daemon socket is missing; release was not acknowledged");
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => anyhow::bail!("daemon connection timed out; release was not acknowledged"),
    };
    let (reader, mut writer) = stream.into_split();

    // Send request
    let mut request = format!(
        "POST /release-worker?worker={}&slots={}",
        urlencoding_encode(worker_id.as_str()),
        slots
    );
    if let Some(build_id) = build_id {
        request.push_str(&format!("&build_id={}", build_id));
    }
    if let Some(wrapper_id) = local_wrapper_id {
        request.push_str(&format!(
            "&local_wrapper_id={}",
            urlencoding_encode(wrapper_id)
        ));
    }
    if let Some(exit_code) = exit_code {
        request.push_str(&format!("&exit_code={}", exit_code));
    }
    if let Some(duration_ms) = duration_ms {
        request.push_str(&format!("&duration_ms={}", duration_ms));
    }
    if let Some(bytes_transferred) = bytes_transferred {
        request.push_str(&format!("&bytes_transferred={}", bytes_transferred));
    }
    request.push('\n');

    // Add timing breakdown as JSON body if present
    if let Some(timing) = timing
        && let Ok(json) = serde_json::to_string(timing)
    {
        request.push_str(&json);
        request.push('\n');
    }

    write_daemon_request(&mut writer, request.as_bytes(), daemon_io_timeout())
        .await
        .context("release was not acknowledged")?;

    // The daemon writes its HTTP status only after processing the release.
    // A complete, bounded acknowledgement is required before publishing success.
    read_daemon_ack(reader, daemon_io_timeout())
        .await
        .context("release was not acknowledged")
}

/// Record a successful build on a worker (for cache affinity).
pub(crate) async fn record_build(
    socket_path: &str,
    worker_id: &WorkerId,
    project: &str,
    is_test: bool,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(()); // Ignore if daemon gone
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — daemon likely busy, don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    // Send request
    let mut request = format!(
        "POST /record-build?worker={}&project={}",
        urlencoding_encode(worker_id.as_str()),
        urlencoding_encode(project)
    );
    if is_test {
        request.push_str("&is_test=1");
    }
    request.push('\n');
    write_daemon_request(&mut writer, request.as_bytes(), daemon_io_timeout()).await?;

    // Best-effort reporting still must not allocate or wait without bounds.
    let _ = read_daemon_ack(reader, daemon_io_timeout()).await;
    Ok(())
}

/// Quarantine a worker by reporting a fault to the daemon (bd-68hon):
/// `POST /workers/{id}/disable?reason=…`. Fire-and-forget with the same
/// fail-open discipline as `record_build` — a missing/busy daemon never
/// blocks the hook, and the caller's retry logic proceeds either way.
pub(crate) async fn disable_worker_for_fault(
    socket_path: &str,
    worker_id: &WorkerId,
    reason: &str,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(()); // Ignore if daemon gone
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Daemon busy — don't block the hook
    };
    let (reader, mut writer) = stream.into_split();

    let request = format!(
        "POST /workers/{}/disable?reason={}\n",
        urlencoding_encode(worker_id.as_str()),
        urlencoding_encode(reason)
    );
    write_daemon_request(&mut writer, request.as_bytes(), daemon_io_timeout()).await?;
    let _ = read_daemon_ack(reader, daemon_io_timeout()).await;
    Ok(())
}

/// URL percent-encoding for query parameters.
///
/// Encodes characters that are not URL-safe (RFC 3986 unreserved characters).
/// Optimized to avoid allocations by using direct hex conversion.
pub(super) fn urlencoding_encode(s: &str) -> String {
    // Hex digits lookup table for zero-allocation encoding
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

    let mut result = String::with_capacity(s.len() * 3); // Worst case: all encoded

    for byte in s.as_bytes() {
        match *byte {
            // Unreserved characters (RFC 3986) - don't encode
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*byte as char);
            }
            // Everything else needs encoding
            _ => {
                result.push('%');
                result.push(HEX_DIGITS[(byte >> 4) as usize] as char);
                result.push(HEX_DIGITS[(byte & 0x0F) as usize] as char);
            }
        }
    }

    result
}

pub(super) const DEFAULT_DAEMON_RESPONSE_TIMEOUT_SECS: u64 = 30;
pub(super) const DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS: u64 = 330;

pub(super) fn queue_when_busy_enabled_from(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let value = value.trim().to_lowercase();
    !matches!(value.as_str(), "0" | "false" | "no" | "off")
}

pub(super) fn queue_when_busy_enabled() -> bool {
    let value = std::env::var("RCH_QUEUE_WHEN_BUSY").ok();
    queue_when_busy_enabled_from(value.as_deref())
}

/// Default connect/write/read timeout for one daemon IPC exchange, in milliseconds.
const DEFAULT_DAEMON_IO_TIMEOUT_MS: u64 = 5_000;
/// Bounds accepted for `RCH_DAEMON_TIMEOUT_MS`; anything outside is ignored
/// so a typo can neither make every hook call fail instantly nor hang it.
const DAEMON_IO_TIMEOUT_MS_RANGE: std::ops::RangeInclusive<u64> = 100..=600_000;

/// Resolve the daemon socket I/O timeout from an `RCH_DAEMON_TIMEOUT_MS`
/// value (issue #57). It bounds each connect, the entire request write, and
/// each response read. The select-worker response wait retains its separate
/// queue-aware policy because queued builds legitimately wait much longer.
pub(super) fn daemon_io_timeout_from(raw: Option<&str>) -> Duration {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|ms| DAEMON_IO_TIMEOUT_MS_RANGE.contains(ms))
        .map_or(
            Duration::from_millis(DEFAULT_DAEMON_IO_TIMEOUT_MS),
            Duration::from_millis,
        )
}

fn daemon_io_timeout() -> Duration {
    daemon_io_timeout_from(std::env::var("RCH_DAEMON_TIMEOUT_MS").ok().as_deref())
}

fn parse_timeout_secs(raw: &str) -> Option<u64> {
    raw.trim().parse::<u64>().ok().filter(|secs| *secs > 0)
}

pub(super) fn daemon_response_timeout_for(
    wait_for_worker: bool,
    global_override: Option<&str>,
    wait_override: Option<&str>,
) -> Duration {
    if let Some(secs) = global_override.and_then(parse_timeout_secs) {
        return Duration::from_secs(secs);
    }

    if wait_for_worker {
        let secs = wait_override
            .and_then(parse_timeout_secs)
            .unwrap_or(DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS);
        return Duration::from_secs(secs);
    }

    Duration::from_secs(DEFAULT_DAEMON_RESPONSE_TIMEOUT_SECS)
}

fn daemon_response_timeout(wait_for_worker: bool) -> Duration {
    let global_override = std::env::var("RCH_DAEMON_RESPONSE_TIMEOUT_SECS").ok();
    let wait_override = std::env::var("RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS").ok();
    daemon_response_timeout_for(
        wait_for_worker,
        global_override.as_deref(),
        wait_override.as_deref(),
    )
}

#[cfg(test)]
mod daemon_io_timeout_tests {
    use super::daemon_io_timeout_from;
    use std::time::Duration;

    #[test]
    fn unset_or_invalid_falls_back_to_default() {
        assert_eq!(daemon_io_timeout_from(None), Duration::from_millis(5_000));
        assert_eq!(
            daemon_io_timeout_from(Some("")),
            Duration::from_millis(5_000)
        );
        assert_eq!(
            daemon_io_timeout_from(Some("abc")),
            Duration::from_millis(5_000)
        );
        assert_eq!(
            daemon_io_timeout_from(Some("-5")),
            Duration::from_millis(5_000)
        );
    }

    #[test]
    fn out_of_range_values_are_ignored() {
        assert_eq!(
            daemon_io_timeout_from(Some("0")),
            Duration::from_millis(5_000)
        );
        assert_eq!(
            daemon_io_timeout_from(Some("99")),
            Duration::from_millis(5_000)
        );
        assert_eq!(
            daemon_io_timeout_from(Some("600001")),
            Duration::from_millis(5_000)
        );
    }

    #[test]
    fn in_range_values_apply() {
        assert_eq!(
            daemon_io_timeout_from(Some("100")),
            Duration::from_millis(100)
        );
        assert_eq!(
            daemon_io_timeout_from(Some(" 2500 ")),
            Duration::from_millis(2_500)
        );
        assert_eq!(
            daemon_io_timeout_from(Some("600000")),
            Duration::from_millis(600_000)
        );
    }
}

#[cfg(test)]
mod bounded_ipc_tests {
    use super::*;

    async fn caller_fixture(
        response: Vec<u8>,
        expected_request: &'static str,
        admission: bool,
    ) -> anyhow::Result<bool> {
        // Keep the fixture for diagnosis; do not mutate the test runner's env.
        let root = tempfile::tempdir().unwrap().keep();
        let path = root.join("ipc.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = async {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut request = String::new();
            reader.read_line(&mut request).await.unwrap();
            assert!(request.starts_with(expected_request), "{request}");
            // Oversized responses may be rejected before every byte is sent.
            let _ = writer.write_all(&response).await;
        };
        let client = async {
            if admission {
                restart_admission_is_closed(path.to_str().unwrap()).await
            } else {
                release_worker(
                    path.to_str().unwrap(),
                    &WorkerId::new("ipc-test"),
                    1,
                    Some(42),
                    Some(0),
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .map(|()| true)
            }
        };
        let (result, ()) = timeout(Duration::from_secs(2), async {
            tokio::join!(client, server)
        })
        .await
        .expect("real daemon IPC fixture must terminate");
        result
    }

    #[tokio::test]
    async fn restart_admission_rejects_http_errors_through_the_real_socket_caller() {
        for (status, success) in [("200 OK", true), ("500 Error", false), ("503 Busy", false)] {
            let response = format!("HTTP/1.1 {status}\r\n\r\n{{\"admission_closed\":false}}");
            let result =
                caller_fixture(response.into_bytes(), "GET /restart-admission", true).await;
            assert_eq!(result.is_ok(), success, "{status}: {result:?}");
        }
    }

    #[tokio::test]
    async fn release_requires_complete_bounded_success_acknowledgement() {
        for (response, success) in [
            ("HTTP/1.1 200 OK\r\n".to_string(), true),
            ("HTTP/1.1 200 OK".to_string(), false),
            ("HTTP/1.1 500 Error\r\n".to_string(), false),
            ("H".repeat(MAX_DAEMON_STATUS_BYTES + 1), false),
        ] {
            let result =
                caller_fixture(response.into_bytes(), "POST /release-worker?", false).await;
            assert_eq!(result.is_ok(), success, "{result:?}");
        }
    }

    #[tokio::test]
    async fn stalled_request_write_is_bounded_and_cancellation_stops_writing() {
        let (mut writer, mut peer) = tokio::io::duplex(16);
        let error = timeout(
            Duration::from_secs(1),
            write_daemon_request(&mut writer, &[b'x'; 4096], Duration::from_millis(20)),
        )
        .await
        .expect("write deadline must fire")
        .expect_err("an unread full pipe cannot finish the request");
        assert!(error.to_string().contains("request write timed out"));
        drop(writer);
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, vec![b'x'; 16], "no detached writer may continue");
    }

    #[tokio::test]
    async fn partial_write_progress_does_not_reset_the_deadline() {
        let (mut writer, mut peer) = tokio::io::duplex(1);
        let write = async {
            let result =
                write_daemon_request(&mut writer, &[b'x'; 4096], Duration::from_millis(30)).await;
            drop(writer);
            result
        };
        let drain = async {
            let mut count = 0;
            let mut byte = [0];
            while peer.read(&mut byte).await.unwrap() != 0 {
                count += 1;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            count
        };
        let (result, received) =
            timeout(Duration::from_secs(2), async { tokio::join!(write, drain) })
                .await
                .expect("partial progress must not prolong a stalled dispatch");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("request write timed out")
        );
        assert!(received < 4096);
    }

    #[tokio::test]
    async fn response_limits_apply_without_newlines_or_eof() {
        let error = read_daemon_body(tokio::io::repeat(b'x'), Duration::from_secs(1), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeded"), "{error}");
        let error = read_daemon_ack(tokio::io::repeat(b'H'), Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeded"), "{error}");
    }

    #[tokio::test]
    async fn body_and_header_limits_are_independent_and_checked_before_trimming() {
        let prefix = "HTTP/1.1 200 OK\r\n\r\n";
        let exact = format!("{prefix}{}", " ".repeat(MAX_DAEMON_BODY_BYTES));
        assert!(
            read_daemon_body(exact.as_bytes(), Duration::from_secs(1), false)
                .await
                .is_ok()
        );
        let oversized = format!("{exact} ");
        assert!(
            read_daemon_body(oversized.as_bytes(), Duration::from_secs(1), false)
                .await
                .is_err()
        );
        let headers = format!(
            "HTTP/1.1 200 OK\r\nX: {}\r\n\r\n{{}}",
            "x".repeat(MAX_DAEMON_HEADER_BYTES)
        );
        assert!(
            read_daemon_body(headers.as_bytes(), Duration::from_secs(1), false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn status_failures_cannot_authorize_admission_or_acknowledge_release() {
        for status in ["HTTP/1.1 500 Error", "HTTP/1.1 503 Busy", "garbage 200 OK"] {
            let reply = format!("{status}\r\n\r\n{{\"admission_closed\":false}}");
            assert!(
                read_daemon_body(reply.as_bytes(), Duration::from_secs(1), true)
                    .await
                    .is_err()
            );
            assert!(
                read_daemon_ack(reply.as_bytes(), Duration::from_secs(1))
                    .await
                    .is_err()
            );
        }
        assert!(
            read_daemon_ack(b"HTTP/1.1 200 OK".as_slice(), Duration::from_secs(1))
                .await
                .is_err()
        );
        for reply in [
            "HTTP/1.1 200 OK\r\n\r\n{\"admission_closed\":false}",
            "HTTP/1.0 200 OK\n\n{\"admission_closed\":false}",
            "{\"admission_closed\":false}",
        ] {
            assert_eq!(
                read_daemon_body(reply.as_bytes(), Duration::from_secs(1), true)
                    .await
                    .unwrap(),
                "{\"admission_closed\":false}"
            );
        }
        let (reader, mut peer) = tokio::io::duplex(64);
        peer.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
        read_daemon_ack(reader, Duration::from_secs(1))
            .await
            .expect("a complete acknowledgement must not wait for peer EOF");
    }

    #[tokio::test]
    async fn silent_response_is_bounded_without_shortening_the_queue_policy() {
        let (reader, _peer) = tokio::io::duplex(16);
        let error = read_daemon_body(reader, Duration::from_millis(20), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("response timed out"));
        assert_eq!(
            daemon_response_timeout_for(false, None, None),
            Duration::from_secs(30)
        );
        assert_eq!(
            daemon_response_timeout_for(true, None, None),
            Duration::from_secs(330)
        );
        assert_eq!(
            daemon_response_timeout_for(true, Some("90"), Some("450")),
            Duration::from_secs(90)
        );
    }
}
