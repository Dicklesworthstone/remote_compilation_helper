//! Unix socket API for hook-daemon communication.
//!
//! Implements a simple HTTP-like protocol over Unix socket:
//! - Request: `GET /select-worker?project=X&cores=N\n`
//! - Response: JSON `SelectionResponse` or error

use crate::selection::{SelectionWeights, select_worker};
use crate::workers::WorkerPool;
use anyhow::{Result, anyhow};
use rch_common::{SelectionRequest, SelectionResponse};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{debug, warn};

/// Handle an incoming connection on the Unix socket.
pub async fn handle_connection(stream: UnixStream, pool: WorkerPool) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read the request line
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(()); // Connection closed
    }

    let line = line.trim();
    debug!("Received request: {}", line);

    // Parse and handle the request
    let response = match parse_request(line) {
        Ok(request) => handle_select_worker(&pool, request).await,
        Err(e) => Err(e),
    };

    // Send the response
    let response_bytes = match response {
        Ok(resp) => {
            let json = serde_json::to_string(&resp)?;
            format!(
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{}\n",
                json
            )
        }
        Err(e) => {
            let error_json = serde_json::json!({ "error": e.to_string() });
            format!(
                "HTTP/1.0 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{}\n",
                error_json
            )
        }
    };

    writer.write_all(response_bytes.as_bytes()).await?;
    writer.flush().await?;

    Ok(())
}

/// Parse a request line into a SelectionRequest.
fn parse_request(line: &str) -> Result<SelectionRequest> {
    // Expected format: GET /select-worker?project=X&cores=N
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid request format"));
    }

    let method = parts[0];
    let path = parts[1];

    if method != "GET" {
        return Err(anyhow!("Only GET method supported"));
    }

    if !path.starts_with("/select-worker") {
        return Err(anyhow!("Unknown endpoint: {}", path));
    }

    // Parse query parameters
    let query = path.strip_prefix("/select-worker").unwrap_or("");
    let query = query.strip_prefix('?').unwrap_or("");

    let mut project = None;
    let mut cores = None;

    for param in query.split('&') {
        if param.is_empty() {
            continue;
        }
        let mut kv = param.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let value = kv.next().unwrap_or("");

        match key {
            "project" => project = Some(urlencoding_decode(value)),
            "cores" => cores = value.parse().ok(),
            _ => {} // Ignore unknown parameters
        }
    }

    let project = project.ok_or_else(|| anyhow!("Missing 'project' parameter"))?;
    let estimated_cores = cores.unwrap_or(1);

    Ok(SelectionRequest {
        project,
        estimated_cores,
        preferred_workers: vec![],
    })
}

/// URL percent-decoding.
///
/// Decodes %XX hex sequences to their original characters.
fn urlencoding_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Try to read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            // Invalid encoding, keep original
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            // + is space in application/x-www-form-urlencoded
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

/// Handle a select-worker request.
async fn handle_select_worker(
    pool: &WorkerPool,
    request: SelectionRequest,
) -> Result<SelectionResponse> {
    debug!(
        "Selecting worker for project '{}' with {} cores",
        request.project, request.estimated_cores
    );

    let weights = SelectionWeights::default();
    let worker = select_worker(pool, &request, &weights)
        .await
        .ok_or_else(|| anyhow!("No available worker with {} slots", request.estimated_cores))?;

    // Reserve the slots
    if !worker.reserve_slots(request.estimated_cores) {
        warn!(
            "Failed to reserve {} slots on {}",
            request.estimated_cores, worker.config.id
        );
        return Err(anyhow!("Failed to reserve slots"));
    }

    Ok(SelectionResponse {
        worker: worker.config.id.clone(),
        host: worker.config.host.clone(),
        user: worker.config.user.clone(),
        identity_file: worker.config.identity_file.clone(),
        slots_available: worker.available_slots(),
        speed_score: worker.speed_score,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_basic() {
        let req = parse_request("GET /select-worker?project=myproject&cores=4").unwrap();
        assert_eq!(req.project, "myproject");
        assert_eq!(req.estimated_cores, 4);
    }

    #[test]
    fn test_parse_request_project_only() {
        let req = parse_request("GET /select-worker?project=test").unwrap();
        assert_eq!(req.project, "test");
        assert_eq!(req.estimated_cores, 1); // Default
    }

    #[test]
    fn test_parse_request_with_spaces() {
        let req = parse_request("GET /select-worker?project=my%20project&cores=2").unwrap();
        assert_eq!(req.project, "my project");
        assert_eq!(req.estimated_cores, 2);
    }

    #[test]
    fn test_parse_request_missing_project() {
        let result = parse_request("GET /select-worker?cores=4");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_invalid_method() {
        let result = parse_request("POST /select-worker?project=test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_unknown_endpoint() {
        let result = parse_request("GET /unknown?project=test");
        assert!(result.is_err());
    }

    #[test]
    fn test_urlencoding_decode_basic() {
        assert_eq!(urlencoding_decode("hello%20world"), "hello world");
        assert_eq!(urlencoding_decode("path%2Fto%2Ffile"), "path/to/file");
        assert_eq!(urlencoding_decode("foo%3Abar"), "foo:bar");
    }

    #[test]
    fn test_urlencoding_decode_special_chars() {
        assert_eq!(urlencoding_decode("a%26b%3Dc"), "a&b=c");
        assert_eq!(urlencoding_decode("100%25"), "100%");
        assert_eq!(urlencoding_decode("hello%2Bworld"), "hello+world");
    }

    #[test]
    fn test_urlencoding_decode_plus_as_space() {
        assert_eq!(urlencoding_decode("hello+world"), "hello world");
    }

    #[test]
    fn test_urlencoding_decode_no_encoding() {
        assert_eq!(urlencoding_decode("simple"), "simple");
        assert_eq!(
            urlencoding_decode("with-dash_underscore"),
            "with-dash_underscore"
        );
    }

    #[test]
    fn test_urlencoding_decode_invalid() {
        // Invalid hex should be preserved
        assert_eq!(urlencoding_decode("foo%GGbar"), "foo%GGbar");
        // Incomplete sequence at end
        assert_eq!(urlencoding_decode("foo%2"), "foo%2");
    }
}
