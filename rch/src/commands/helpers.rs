//! Shared helper functions for RCH commands.

#[cfg(not(unix))]
use crate::error::PlatformError;
use crate::error::{DaemonError, SshError};
use anyhow::{Context, Result};
use directories::ProjectDirs;
use rch_common::{RequiredRuntime, WorkerConfig, WorkerId};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;

// ============================================================================
// Path helpers
// ============================================================================

/// Get the default socket path.
/// Uses XDG_RUNTIME_DIR if available, falls back to ~/.cache/rch/rch.sock, then /tmp/rch.sock.
pub fn default_socket_path() -> String {
    rch_common::default_socket_path()
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
    ProjectDirs::from("com", "rch", "rch").map(|dirs| dirs.config_dir().to_path_buf())
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
        let total_slots = entry
            .get("total_slots")
            .and_then(|v| v.as_integer())
            .unwrap_or(8) as u32;
        let priority = entry
            .get("priority")
            .and_then(|v| v.as_integer())
            .unwrap_or(100) as u32;
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
    let config = crate::config::load_config()?;
    let expanded = shellexpand::tilde(&config.general.socket_path);
    let socket_path = Path::new(expanded.as_ref());
    if !socket_path.exists() {
        return Err(DaemonError::SocketNotFound {
            socket_path: socket_path.display().to_string(),
        }
        .into());
    }

    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    writer.write_all(command.as_bytes()).await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader);
    let mut response = String::new();
    reader.read_to_string(&mut response).await?;

    Ok(response)
}
