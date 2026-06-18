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
    wait_for_worker: bool,
    preferred_workers: &[WorkerId],
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
    let stream = timeout(Duration::from_secs(5), UnixStream::connect(socket_path))
        .await
        .map_err(|_| anyhow::anyhow!("Daemon connect timed out after 5s"))??;
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

    // Send request
    let request = format!("GET /select-worker?{}\n", query);
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read response (skip HTTP headers) with timeout and body size limit.
    // Body is capped at 64KB to prevent unbounded memory growth.
    const MAX_RESPONSE_BODY: usize = 64 * 1024;
    let response_timeout = daemon_response_timeout(wait_for_worker);

    let read_response = async {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let mut body = String::new();
        let mut in_body = false;

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break;
            }
            if in_body {
                if body.len() + line.len() > MAX_RESPONSE_BODY {
                    return Err(anyhow::anyhow!(
                        "Daemon response body exceeded {}KB limit",
                        MAX_RESPONSE_BODY / 1024
                    ));
                }
                body.push_str(&line);
            } else if line.trim().is_empty() {
                in_body = true;
            }
        }

        parse_selection_response(body.trim())
            .map_err(|e| anyhow::anyhow!("Failed to parse daemon response: {}", e))
    };

    let response = timeout(response_timeout, read_response)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Daemon response timed out after {}s",
                response_timeout.as_secs()
            )
        })??;

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
        "POST /release-worker?worker={}&slots={}",
        urlencoding_encode(worker_id.as_str()),
        slots
    );
    if let Some(build_id) = build_id {
        request.push_str(&format!("&build_id={}", build_id));
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

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read response line (to ensure daemon processed it) with timeout
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
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
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read response line with timeout
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

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
