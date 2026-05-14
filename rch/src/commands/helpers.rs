//! Shared helper functions for RCH commands.

#[cfg(not(unix))]
use crate::error::PlatformError;
use crate::error::{DaemonError, SshError};
use anyhow::{Context, Result};
use rch_common::{RequiredRuntime, WorkerConfig, WorkerId};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;

#[cfg(unix)]
const DAEMON_COMMAND_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(unix)]
const DAEMON_COMMAND_IO_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(unix)]
const DAEMON_CAPABILITIES_REFRESH_RESPONSE_TIMEOUT: Duration = Duration::from_secs(90);

// ============================================================================
// Path helpers
// ============================================================================

/// Get the default socket path.
/// Uses XDG_RUNTIME_DIR if available, falls back to ~/.cache/rch/rch.sock, then /tmp/rch.sock.
#[cfg(test)]
pub fn default_socket_path() -> String {
    rch_common::default_socket_path()
}

/// Resolve the daemon socket path from the active RCH configuration.
///
/// Commands that talk to `rchd` must use this instead of the compiled-in
/// default; otherwise a custom `general.socket_path` can start the daemon on
/// one socket while hooks and status commands query another.
pub(crate) fn configured_socket_path() -> Result<String> {
    let config = crate::config::load_config()?;
    Ok(shellexpand::tilde(&config.general.socket_path).into_owned())
}

// ============================================================================
// Version extraction helpers
// ============================================================================

/// Extract all numeric components from a version string.
///
/// # Examples
/// ```
/// # use rch::commands::helpers::extract_version_numbers;
/// assert_eq!(extract_version_numbers("rustc 1.84.0-nightly"), vec![1, 84, 0]);
/// assert_eq!(extract_version_numbers("v22.3.1"), vec![22, 3, 1]);
/// ```
pub fn extract_version_numbers(version: &str) -> Vec<u64> {
    let mut numbers = Vec::new();
    let mut current: Option<u64> = None;
    for ch in version.chars() {
        if let Some(digit) = ch.to_digit(10) {
            let next = current
                .unwrap_or(0)
                .saturating_mul(10)
                .saturating_add(digit as u64);
            current = Some(next);
        } else if let Some(value) = current.take() {
            numbers.push(value);
        }
    }
    if let Some(value) = current {
        numbers.push(value);
    }
    numbers
}

/// Get the major version number from a version string.
pub fn major_version(version: &str) -> Option<u64> {
    extract_version_numbers(version).into_iter().next()
}

/// Get the major and minor version numbers from a version string.
pub fn major_minor_version(version: &str) -> Option<(u64, u64)> {
    let numbers = extract_version_numbers(version);
    if numbers.len() >= 2 {
        Some((numbers[0], numbers[1]))
    } else {
        None
    }
}

/// Check if two Rust version strings have mismatched major.minor versions.
pub fn rust_version_mismatch(local: &str, remote: &str) -> bool {
    match (major_minor_version(local), major_minor_version(remote)) {
        (Some((lmaj, lmin)), Some((rmaj, rmin))) => lmaj != rmaj || lmin != rmin,
        _ => false,
    }
}

/// Check if two version strings have mismatched major versions.
pub fn major_version_mismatch(local: &str, remote: &str) -> bool {
    match (major_version(local), major_version(remote)) {
        (Some(lmaj), Some(rmaj)) => lmaj != rmaj,
        _ => false,
    }
}

// ============================================================================
// Runtime helpers
// ============================================================================

/// Get a human-readable label for a required runtime.
pub fn runtime_label(runtime: &RequiredRuntime) -> &'static str {
    match runtime {
        RequiredRuntime::Rust => "rust",
        RequiredRuntime::Bun => "bun",
        RequiredRuntime::Node => "node",
        RequiredRuntime::None => "none",
    }
}

// ============================================================================
// SSH helpers
// ============================================================================

/// Get the expanded SSH key path for a worker configuration.
pub fn ssh_key_path(worker: &WorkerConfig) -> PathBuf {
    ssh_key_path_from_identity(Some(worker.identity_file.as_str()))
}

/// Get the expanded SSH key path from an optional identity file string.
///
/// Defaults to `~/.ssh/id_rsa` if no identity file is provided.
pub fn ssh_key_path_from_identity(identity_file: Option<&str>) -> PathBuf {
    let path = identity_file.unwrap_or("~/.ssh/id_rsa");
    PathBuf::from(shellexpand::tilde(path).to_string())
}

/// Classify an SSH error based on the error message and context.
pub fn classify_ssh_error(
    worker: &WorkerConfig,
    err: &anyhow::Error,
    timeout: Duration,
) -> SshError {
    let key_path = ssh_key_path(worker);
    classify_ssh_error_message(
        &worker.host,
        &worker.user,
        key_path,
        &err.to_string(),
        timeout,
    )
}

/// Classify an SSH error from its message and connection details.
pub fn classify_ssh_error_message(
    host: &str,
    user: &str,
    key_path: PathBuf,
    message: &str,
    timeout: Duration,
) -> SshError {
    let message_lower = message.to_lowercase();

    if message_lower.contains("permission denied") || message_lower.contains("publickey") {
        return SshError::PermissionDenied {
            host: host.to_string(),
            user: user.to_string(),
            key_path: key_path.clone(),
        };
    }

    if message_lower.contains("connection refused") {
        return SshError::ConnectionRefused {
            host: host.to_string(),
            user: user.to_string(),
            key_path: key_path.clone(),
        };
    }

    if message_lower.contains("timed out") || message_lower.contains("timeout") {
        return SshError::ConnectionTimeout {
            host: host.to_string(),
            user: user.to_string(),
            key_path: key_path.clone(),
            timeout_secs: timeout.as_secs().max(1),
        };
    }

    if message_lower.contains("host key verification failed")
        || message_lower.contains("known_hosts")
    {
        return SshError::HostKeyVerificationFailed {
            host: host.to_string(),
            user: user.to_string(),
            key_path: key_path.clone(),
        };
    }

    if message_lower.contains("authentication agent")
        || (message_lower.contains("agent") && message_lower.contains("no identities"))
    {
        return SshError::AgentUnavailable {
            host: host.to_string(),
            user: user.to_string(),
            key_path: key_path.clone(),
        };
    }

    SshError::ConnectionFailed {
        host: host.to_string(),
        user: user.to_string(),
        key_path,
        message: message.to_string(),
    }
}

/// Format an SSH error as a diagnostic report string.
pub fn format_ssh_report(error: SshError) -> String {
    format!("{:?}", miette::Report::new(error))
}

/// Map an SSH error to a stable `ErrorCode` from the shared catalog so callers
/// can surface `"RCH-Exxx"` in structured output.
///
/// The `SshError` enum carries its own diagnostic annotation codes for the
/// miette report, but those are display-only. The `ErrorCode` catalog is the
/// authoritative identifier that downstream automation branches on.
pub fn ssh_error_code(error: &SshError) -> rch_common::ErrorCode {
    use rch_common::ErrorCode;
    match error {
        SshError::AuthFailed { .. }
        | SshError::PermissionDenied { .. }
        | SshError::AgentUnavailable { .. } => ErrorCode::SshAuthFailed,
        SshError::KeyNotFound { .. } | SshError::KeyInsecurePermissions { .. } => {
            ErrorCode::SshKeyError
        }
        SshError::HostKeyVerificationFailed { .. } => ErrorCode::SshHostKeyError,
        SshError::ConnectionTimeout { .. } => ErrorCode::NetworkTimeout,
        SshError::ConnectionRefused { .. } => ErrorCode::NetworkConnectionRefused,
        SshError::ChannelError { .. } => ErrorCode::SshSessionDropped,
        SshError::ConnectionFailed { .. }
        | SshError::CommandFailed { .. }
        | SshError::BinaryNotFound { .. }
        | SshError::ToolchainInstallFailed { .. }
        | SshError::RemotePermissionDenied { .. } => ErrorCode::SshConnectionFailed,
    }
}

// ============================================================================
// Text formatting helpers
// ============================================================================

/// Indent each line of text with a given prefix.
pub fn indent_lines(text: &str, prefix: &str) -> String {
    let mut out = String::new();
    for (idx, line) in text.lines().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(prefix);
        out.push_str(line);
    }
    out
}

/// Format a duration in seconds as a human-readable string.
pub fn humanize_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

/// URL percent-encoding for query parameters.
/// Optimized to avoid allocations by using direct hex conversion.
pub fn urlencoding_encode(s: &str) -> String {
    // Hex digits lookup table for zero-allocation encoding
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*byte as char);
            }
            _ => {
                result.push('%');
                result.push(HEX_DIGITS[(byte >> 4) as usize] as char);
                result.push(HEX_DIGITS[(byte & 0x0F) as usize] as char);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Version extraction tests
    // ========================================================================

    #[test]
    fn test_extract_version_numbers() {
        assert_eq!(
            extract_version_numbers("rustc 1.84.0-nightly"),
            vec![1, 84, 0]
        );
        assert_eq!(extract_version_numbers("v22.3.1"), vec![22, 3, 1]);
        assert_eq!(extract_version_numbers("1.0"), vec![1, 0]);
        assert_eq!(extract_version_numbers("no numbers"), Vec::<u64>::new());
        assert_eq!(extract_version_numbers(""), Vec::<u64>::new());
    }

    #[test]
    fn test_major_version() {
        assert_eq!(major_version("rustc 1.84.0-nightly"), Some(1));
        assert_eq!(major_version("v22.3.1"), Some(22));
        assert_eq!(major_version("no numbers"), None);
    }

    #[test]
    fn test_major_minor_version() {
        assert_eq!(major_minor_version("rustc 1.84.0-nightly"), Some((1, 84)));
        assert_eq!(major_minor_version("v22.3.1"), Some((22, 3)));
        assert_eq!(major_minor_version("1"), None);
        assert_eq!(major_minor_version("no numbers"), None);
    }

    #[test]
    fn test_rust_version_mismatch() {
        assert!(!rust_version_mismatch("1.84.0", "1.84.1")); // Same major.minor
        assert!(rust_version_mismatch("1.84.0", "1.85.0")); // Different minor
        assert!(rust_version_mismatch("1.84.0", "2.0.0")); // Different major
        assert!(!rust_version_mismatch("", "")); // No valid versions
    }

    #[test]
    fn test_major_version_mismatch() {
        assert!(!major_version_mismatch("1.84.0", "1.85.0")); // Same major
        assert!(major_version_mismatch("1.84.0", "2.0.0")); // Different major
        assert!(!major_version_mismatch("", "")); // No valid versions
    }

    // ========================================================================
    // Runtime label tests
    // ========================================================================

    #[test]
    fn test_runtime_label() {
        assert_eq!(runtime_label(&RequiredRuntime::Rust), "rust");
        assert_eq!(runtime_label(&RequiredRuntime::Bun), "bun");
        assert_eq!(runtime_label(&RequiredRuntime::Node), "node");
        assert_eq!(runtime_label(&RequiredRuntime::None), "none");
    }

    // ========================================================================
    // SSH helper tests
    // ========================================================================

    #[test]
    fn test_ssh_key_path_from_identity() {
        let path = ssh_key_path_from_identity(Some("~/.ssh/my_key"));
        assert!(path.to_string_lossy().contains(".ssh/my_key"));

        let default_path = ssh_key_path_from_identity(None);
        assert!(default_path.to_string_lossy().contains(".ssh/id_rsa"));
    }

    #[test]
    fn test_classify_ssh_error_message_permission_denied() {
        let err = classify_ssh_error_message(
            "host.example.com",
            "testuser",
            PathBuf::from("/home/user/.ssh/id_rsa"),
            "Permission denied (publickey)",
            Duration::from_secs(30),
        );
        assert!(matches!(err, SshError::PermissionDenied { .. }));
    }

    #[test]
    fn test_classify_ssh_error_message_connection_refused() {
        let err = classify_ssh_error_message(
            "host.example.com",
            "testuser",
            PathBuf::from("/home/user/.ssh/id_rsa"),
            "Connection refused",
            Duration::from_secs(30),
        );
        assert!(matches!(err, SshError::ConnectionRefused { .. }));
    }

    #[test]
    fn test_classify_ssh_error_message_timeout() {
        let err = classify_ssh_error_message(
            "host.example.com",
            "testuser",
            PathBuf::from("/home/user/.ssh/id_rsa"),
            "Connection timed out",
            Duration::from_secs(30),
        );
        assert!(matches!(err, SshError::ConnectionTimeout { .. }));
    }

    #[test]
    fn test_classify_ssh_error_message_host_key() {
        let err = classify_ssh_error_message(
            "host.example.com",
            "testuser",
            PathBuf::from("/home/user/.ssh/id_rsa"),
            "Host key verification failed",
            Duration::from_secs(30),
        );
        assert!(matches!(err, SshError::HostKeyVerificationFailed { .. }));
    }

    #[test]
    fn test_classify_ssh_error_message_fallback() {
        let err = classify_ssh_error_message(
            "host.example.com",
            "testuser",
            PathBuf::from("/home/user/.ssh/id_rsa"),
            "Some unknown error",
            Duration::from_secs(30),
        );
        assert!(matches!(err, SshError::ConnectionFailed { .. }));
    }

    #[test]
    fn test_ssh_error_code_mapping() {
        use rch_common::ErrorCode;
        let host = "h".to_string();
        let user = "u".to_string();
        let key = PathBuf::from("/k");

        assert_eq!(
            ssh_error_code(&SshError::PermissionDenied {
                host: host.clone(),
                user: user.clone(),
                key_path: key.clone(),
            }),
            ErrorCode::SshAuthFailed
        );
        assert_eq!(
            ssh_error_code(&SshError::ConnectionRefused {
                host: host.clone(),
                user: user.clone(),
                key_path: key.clone(),
            }),
            ErrorCode::NetworkConnectionRefused
        );
        assert_eq!(
            ssh_error_code(&SshError::ConnectionTimeout {
                host: host.clone(),
                user: user.clone(),
                key_path: key.clone(),
                timeout_secs: 30,
            }),
            ErrorCode::NetworkTimeout
        );
        assert_eq!(
            ssh_error_code(&SshError::HostKeyVerificationFailed {
                host: host.clone(),
                user: user.clone(),
                key_path: key.clone(),
            }),
            ErrorCode::SshHostKeyError
        );
        assert_eq!(
            ssh_error_code(&SshError::KeyNotFound {
                key_path: key.clone(),
            }),
            ErrorCode::SshKeyError
        );
        assert_eq!(
            ssh_error_code(&SshError::KeyInsecurePermissions {
                key_path: key.clone(),
            }),
            ErrorCode::SshKeyError
        );
        assert_eq!(
            ssh_error_code(&SshError::ConnectionFailed {
                host,
                user,
                key_path: key,
                message: "generic".into(),
            }),
            ErrorCode::SshConnectionFailed
        );
    }

    // ========================================================================
    // Text formatting tests
    // ========================================================================

    #[test]
    fn test_indent_lines() {
        assert_eq!(indent_lines("hello\nworld", "  "), "  hello\n  world");
        assert_eq!(indent_lines("single", ">> "), ">> single");
        assert_eq!(indent_lines("", "  "), "");
    }

    #[test]
    fn test_humanize_duration() {
        assert_eq!(humanize_duration(0), "0s");
        assert_eq!(humanize_duration(45), "45s");
        assert_eq!(humanize_duration(65), "1m 5s");
        assert_eq!(humanize_duration(3661), "1h 1m");
        assert_eq!(humanize_duration(90000), "1d 1h");
    }

    #[test]
    fn test_urlencoding_encode() {
        assert_eq!(urlencoding_encode("hello"), "hello");
        assert_eq!(urlencoding_encode("hello world"), "hello%20world");
        assert_eq!(urlencoding_encode("a/b?c=d"), "a%2Fb%3Fc%3Dd");
    }

    #[test]
    fn configured_socket_path_uses_active_config() -> Result<()> {
        let _guard = rch_common::test_guard!();
        struct ResetConfigOverride;
        impl Drop for ResetConfigOverride {
            fn drop(&mut self) {
                crate::config::set_test_config_override(None);
            }
        }

        let mut config = rch_common::RchConfig::default();
        config.general.socket_path = "/tmp/rch-custom-test.sock".to_string();
        crate::config::set_test_config_override(Some(config));
        let _reset = ResetConfigOverride;

        let socket_path = configured_socket_path().context("configured socket path")?;

        assert_eq!(socket_path, "/tmp/rch-custom-test.sock");
        Ok(())
    }

    #[test]
    fn toml_u32_field_accepts_valid_unsigned_range() -> Result<()> {
        let entry: toml::Value =
            toml::from_str("total_slots = 12\npriority = 42\n").context("parse worker toml")?;

        assert_eq!(toml_u32_field_or(&entry, "total_slots", 8), 12);
        assert_eq!(toml_u32_field_or(&entry, "priority", 100), 42);
        Ok(())
    }

    #[test]
    fn toml_u32_field_rejects_negative_and_overflow_values() -> Result<()> {
        let entry: toml::Value = toml::from_str("total_slots = -1\npriority = 4294967296\n")
            .context("parse worker toml")?;

        assert_eq!(toml_u32_field_or(&entry, "total_slots", 8), 8);
        assert_eq!(toml_u32_field_or(&entry, "priority", 100), 100);
        Ok(())
    }
}

// ============================================================================
// Config directory helpers
// ============================================================================

/// Get the RCH configuration directory.
///
/// Uses XDG-compliant paths via the directories crate.
pub fn config_dir() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(dir) = test_config_dir_override() {
        return Some(dir);
    }
    crate::config::config_dir()
}

#[cfg(test)]
thread_local! {
    static TEST_CONFIG_DIR_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn test_config_dir_override() -> Option<PathBuf> {
    TEST_CONFIG_DIR_OVERRIDE.with(|override_path| override_path.borrow().clone())
}

#[cfg(test)]
pub(crate) fn set_test_config_dir_override(path: Option<PathBuf>) {
    TEST_CONFIG_DIR_OVERRIDE.with(|override_path| *override_path.borrow_mut() = path);
}

// ============================================================================
// Workers configuration helpers
// ============================================================================

/// Load workers from configuration file.
///
/// Returns an empty vector if no workers are configured. Does not print
/// any messages - callers should handle the empty case appropriately.
pub fn load_workers_from_config() -> Result<Vec<WorkerConfig>> {
    let config_path = config_dir()
        .map(|d| d.join("workers.toml"))
        .context("Could not determine config directory")?;

    if !config_path.exists() {
        return Ok(vec![]);
    }

    let contents = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read {:?}", config_path))?;

    // Parse the TOML - expect [[workers]] array
    let parsed: toml::Value =
        toml::from_str(&contents).with_context(|| format!("Failed to parse {:?}", config_path))?;

    let empty_array = vec![];
    let workers_array = parsed
        .get("workers")
        .and_then(|w| w.as_array())
        .unwrap_or(&empty_array);

    let mut workers = Vec::new();
    for entry in workers_array {
        let enabled = entry
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if !enabled {
            continue;
        }

        let id = entry
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let host = entry
            .get("host")
            .and_then(|v| v.as_str())
            .unwrap_or("localhost");
        let user = entry
            .get("user")
            .and_then(|v| v.as_str())
            .unwrap_or("ubuntu");
        let identity_file = entry
            .get("identity_file")
            .and_then(|v| v.as_str())
            .unwrap_or("~/.ssh/id_rsa");
        let total_slots = toml_u32_field_or(entry, "total_slots", 8);
        let priority = toml_u32_field_or(entry, "priority", 100);
        let tags: Vec<String> = entry
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        workers.push(WorkerConfig {
            id: WorkerId::new(id),
            host: host.to_string(),
            user: user.to_string(),
            identity_file: identity_file.to_string(),
            total_slots,
            priority,
            tags,
        });
    }

    Ok(workers)
}

fn toml_u32_field_or(entry: &toml::Value, key: &str, default: u32) -> u32 {
    entry
        .get(key)
        .and_then(|value| value.as_integer())
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(default)
}

// ============================================================================
// Daemon communication helpers
// ============================================================================

/// Helper to send command to daemon socket.
#[cfg(not(unix))]
pub async fn send_daemon_command(_command: &str) -> Result<String> {
    Err(PlatformError::UnixOnly {
        feature: "daemon commands".to_string(),
    })?
}

/// Helper to send command to daemon socket.
#[cfg(unix)]
pub async fn send_daemon_command(command: &str) -> Result<String> {
    let socket_path_str = configured_socket_path()?;
    let socket_path = Path::new(&socket_path_str);
    if !socket_path.exists() {
        return Err(DaemonError::SocketNotFound {
            socket_path: socket_path.display().to_string(),
        }
        .into());
    }

    send_daemon_command_to_socket(socket_path, command).await
}

#[cfg(unix)]
async fn send_daemon_command_to_socket(socket_path: &Path, command: &str) -> Result<String> {
    let stream = tokio::time::timeout(
        DAEMON_COMMAND_CONNECT_TIMEOUT,
        UnixStream::connect(socket_path),
    )
    .await
    .context("Timed out connecting to daemon socket")??;
    let (reader, mut writer) = stream.into_split();

    tokio::time::timeout(DAEMON_COMMAND_IO_TIMEOUT, async {
        writer.write_all(command.as_bytes()).await?;
        writer.flush().await?;
        writer.shutdown().await
    })
    .await
    .context("Timed out sending daemon command")??;

    let mut reader = BufReader::new(reader);
    let mut response = String::new();
    let response_timeout = daemon_command_response_timeout(command);
    tokio::time::timeout(response_timeout, reader.read_to_string(&mut response))
        .await
        .context("Timed out waiting for daemon response")??;

    Ok(response)
}

#[cfg(unix)]
fn daemon_command_response_timeout(command: &str) -> Duration {
    if daemon_command_is_capabilities_refresh(command) {
        DAEMON_CAPABILITIES_REFRESH_RESPONSE_TIMEOUT
    } else {
        DAEMON_COMMAND_IO_TIMEOUT
    }
}

#[cfg(unix)]
fn daemon_command_is_capabilities_refresh(command: &str) -> bool {
    let request_target = command
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("");
    let Some(query) = request_target.strip_prefix("/workers/capabilities?") else {
        return false;
    };

    query.split('&').any(|param| {
        let mut kv = param.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let value = kv.next().unwrap_or("");
        key == "refresh" && (value == "1" || value.eq_ignore_ascii_case("true"))
    })
}

#[cfg(all(test, unix))]
mod daemon_command_tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn send_daemon_command_half_closes_request_before_waiting_for_response() -> Result<()> {
        let temp_dir = tempfile::tempdir().context("create temp dir")?;
        let socket_path = temp_dir.path().join("rch-test.sock");
        let listener = UnixListener::bind(&socket_path).context("bind test socket")?;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.context("accept client")?;
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);

            let mut line = String::new();
            reader.read_line(&mut line).await.context("read request")?;
            assert_eq!(line, "GET /status\n");

            let mut eof_probe = String::new();
            let bytes = tokio::time::timeout(
                Duration::from_secs(1),
                reader.read_to_string(&mut eof_probe),
            )
            .await
            .context("client should half-close request")?
            .context("read client eof")?;
            assert_eq!(bytes, 0);

            writer
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}\n")
                .await
                .context("write response")?;
            Result::<()>::Ok(())
        });

        let response = send_daemon_command_to_socket(&socket_path, "GET /status\n")
            .await
            .context("daemon response")?;
        assert!(response.contains("\"ok\":true"));
        server.await.context("server task")??;
        Ok(())
    }

    #[test]
    fn capabilities_refresh_command_gets_extended_response_timeout() {
        assert_eq!(
            daemon_command_response_timeout("GET /workers/capabilities?refresh=true\n"),
            DAEMON_CAPABILITIES_REFRESH_RESPONSE_TIMEOUT
        );
        assert_eq!(
            daemon_command_response_timeout("GET /workers/capabilities?worker=all&refresh=1\n"),
            DAEMON_CAPABILITIES_REFRESH_RESPONSE_TIMEOUT
        );
    }

    #[test]
    fn ordinary_daemon_commands_keep_default_response_timeout() {
        assert_eq!(
            daemon_command_response_timeout("GET /workers/capabilities\n"),
            DAEMON_COMMAND_IO_TIMEOUT
        );
        assert_eq!(
            daemon_command_response_timeout("GET /workers/capabilities?refresh=false\n"),
            DAEMON_COMMAND_IO_TIMEOUT
        );
        assert_eq!(
            daemon_command_response_timeout("GET /status\n"),
            DAEMON_COMMAND_IO_TIMEOUT
        );
    }
}
