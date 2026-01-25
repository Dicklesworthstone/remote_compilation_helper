//! Unified API Error Types
//!
//! Provides [`ApiError`] which uses the [`ErrorCode`] enum for consistent
//! error codes across CLI and daemon.

use crate::errors::catalog::{ErrorCategory, ErrorCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Context information for an API error.
///
/// Contains key-value pairs providing additional context about the error,
/// such as worker IDs, file paths, or other relevant identifiers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ErrorContext {
    /// Key-value pairs of context information.
    #[serde(flatten)]
    pub fields: HashMap<String, String>,
}

impl ErrorContext {
    /// Create an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a context field.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    /// Check if context is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// Unified API error structure.
///
/// This type is used for all error responses in both CLI and daemon APIs.
/// It uses the [`ErrorCode`] enum for consistent error identification.
///
/// # Example
///
/// ```rust
/// use rch_common::api::ApiError;
/// use rch_common::ErrorCode;
///
/// let error = ApiError::from_code(ErrorCode::SshConnectionFailed)
///     .with_message("Connection refused")
///     .with_context("worker_id", "worker-1")
///     .with_context("host", "192.168.1.100");
///
/// assert_eq!(error.code, "RCH-E100");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiError {
    /// Error code in RCH-Exxx format (e.g., "RCH-E100").
    pub code: String,

    /// Error category for quick classification.
    pub category: ErrorCategory,

    /// Human-readable error message.
    pub message: String,

    /// Detailed description of what went wrong.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    /// Suggested remediation steps.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub remediation: Vec<String>,

    /// Additional context information.
    #[serde(skip_serializing_if = "ErrorContext::is_empty", default)]
    pub context: ErrorContext,

    /// Optional retry-after hint in seconds (for rate limiting).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
}

impl ApiError {
    /// Create an ApiError from an ErrorCode.
    ///
    /// Automatically populates the code string, category, message, and remediation
    /// from the error catalog.
    #[must_use]
    pub fn from_code(code: ErrorCode) -> Self {
        let entry = code.entry();
        Self {
            code: entry.code,
            category: entry.category,
            message: entry.message,
            details: None,
            remediation: entry.remediation,
            context: ErrorContext::new(),
            retry_after_secs: None,
        }
    }

    /// Create an ApiError with a custom message.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::from_code(code).with_message(message)
    }

    /// Add or replace the detailed message.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.details = Some(message.into());
        self
    }

    /// Alias for with_message for clarity.
    #[must_use]
    pub fn with_details(self, details: impl Into<String>) -> Self {
        self.with_message(details)
    }

    /// Add a context field.
    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context = self.context.with(key, value);
        self
    }

    /// Add multiple context fields.
    #[must_use]
    pub fn with_context_map(mut self, map: HashMap<String, String>) -> Self {
        for (k, v) in map {
            self.context = self.context.with(k, v);
        }
        self
    }

    /// Set retry-after hint for rate limiting errors.
    #[must_use]
    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after_secs = Some(seconds);
        self
    }

    /// Add additional remediation steps.
    #[must_use]
    pub fn with_remediation(mut self, steps: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.remediation.extend(steps.into_iter().map(Into::into));
        self
    }

    /// Create a generic internal error.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InternalStateError, message)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)?;
        if let Some(ref details) = self.details {
            write!(f, ": {}", details)?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

// =============================================================================
// Legacy Error Code Mapping
// =============================================================================

/// Legacy error codes used in older CLI versions.
///
/// This enum provides backward compatibility by mapping old string-based
/// error codes to the new [`ErrorCode`] enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyErrorCode {
    WorkerUnreachable,
    WorkerNotFound,
    ConfigInvalid,
    ConfigNotFound,
    DaemonNotRunning,
    DaemonConnectionFailed,
    SshConnectionFailed,
    BenchmarkFailed,
    HookInstallFailed,
    InternalError,
}

impl LegacyErrorCode {
    /// Parse a legacy error code string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "WORKER_UNREACHABLE" => Some(Self::WorkerUnreachable),
            "WORKER_NOT_FOUND" => Some(Self::WorkerNotFound),
            "CONFIG_INVALID" => Some(Self::ConfigInvalid),
            "CONFIG_NOT_FOUND" => Some(Self::ConfigNotFound),
            "DAEMON_NOT_RUNNING" => Some(Self::DaemonNotRunning),
            "DAEMON_CONNECTION_FAILED" => Some(Self::DaemonConnectionFailed),
            "SSH_CONNECTION_FAILED" => Some(Self::SshConnectionFailed),
            "BENCHMARK_FAILED" => Some(Self::BenchmarkFailed),
            "HOOK_INSTALL_FAILED" => Some(Self::HookInstallFailed),
            "INTERNAL_ERROR" => Some(Self::InternalError),
            _ => None,
        }
    }

    /// Convert to the modern ErrorCode enum.
    #[must_use]
    pub fn to_error_code(self) -> ErrorCode {
        match self {
            Self::WorkerUnreachable => ErrorCode::SshConnectionFailed,
            Self::WorkerNotFound => ErrorCode::ConfigInvalidWorker,
            Self::ConfigInvalid => ErrorCode::ConfigValidationError,
            Self::ConfigNotFound => ErrorCode::ConfigNotFound,
            Self::DaemonNotRunning => ErrorCode::InternalDaemonNotRunning,
            Self::DaemonConnectionFailed => ErrorCode::InternalDaemonSocket,
            Self::SshConnectionFailed => ErrorCode::SshConnectionFailed,
            Self::BenchmarkFailed => ErrorCode::WorkerSelfTestFailed,
            Self::HookInstallFailed => ErrorCode::InternalHookError,
            Self::InternalError => ErrorCode::InternalStateError,
        }
    }

    /// Get the legacy string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::WorkerUnreachable => "WORKER_UNREACHABLE",
            Self::WorkerNotFound => "WORKER_NOT_FOUND",
            Self::ConfigInvalid => "CONFIG_INVALID",
            Self::ConfigNotFound => "CONFIG_NOT_FOUND",
            Self::DaemonNotRunning => "DAEMON_NOT_RUNNING",
            Self::DaemonConnectionFailed => "DAEMON_CONNECTION_FAILED",
            Self::SshConnectionFailed => "SSH_CONNECTION_FAILED",
            Self::BenchmarkFailed => "BENCHMARK_FAILED",
            Self::HookInstallFailed => "HOOK_INSTALL_FAILED",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }
}

impl std::str::FromStr for LegacyErrorCode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

impl std::fmt::Display for LegacyErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Convert a legacy error code string to an ApiError.
///
/// # Arguments
///
/// * `legacy_code` - Legacy error code string (e.g., "WORKER_UNREACHABLE")
/// * `message` - Human-readable error message
///
/// # Returns
///
/// An [`ApiError`] using the modern [`ErrorCode`] equivalent.
#[must_use]
#[allow(dead_code)]
pub fn from_legacy_code(legacy_code: &str, message: impl Into<String>) -> ApiError {
    let error_code = LegacyErrorCode::parse(legacy_code)
        .map(|l| l.to_error_code())
        .unwrap_or(ErrorCode::InternalStateError);

    ApiError::new(error_code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_from_code() {
        let error = ApiError::from_code(ErrorCode::ConfigNotFound);
        assert_eq!(error.code, "RCH-E001");
        assert_eq!(error.category, ErrorCategory::Config);
        assert!(!error.remediation.is_empty());
    }

    #[test]
    fn test_api_error_with_context() {
        let error = ApiError::from_code(ErrorCode::SshConnectionFailed)
            .with_context("worker_id", "test-worker")
            .with_context("host", "192.168.1.100");

        assert_eq!(
            error.context.fields.get("worker_id"),
            Some(&"test-worker".to_string())
        );
        assert_eq!(
            error.context.fields.get("host"),
            Some(&"192.168.1.100".to_string())
        );
    }

    #[test]
    fn test_api_error_serialization() {
        let error = ApiError::from_code(ErrorCode::WorkerNoneAvailable)
            .with_message("All workers are busy");

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"code\":\"RCH-E200\""));
        assert!(json.contains("\"category\":\"worker\""));
        assert!(json.contains("\"details\":\"All workers are busy\""));
    }

    #[test]
    fn test_legacy_code_all_mappings() {
        // Verify all legacy codes map to valid modern codes
        let legacy_codes = [
            "WORKER_UNREACHABLE",
            "WORKER_NOT_FOUND",
            "CONFIG_INVALID",
            "CONFIG_NOT_FOUND",
            "DAEMON_NOT_RUNNING",
            "DAEMON_CONNECTION_FAILED",
            "SSH_CONNECTION_FAILED",
            "BENCHMARK_FAILED",
            "HOOK_INSTALL_FAILED",
            "INTERNAL_ERROR",
        ];

        for legacy in legacy_codes {
            let parsed = LegacyErrorCode::from_str(legacy);
            assert!(parsed.is_some(), "Failed to parse: {}", legacy);
            let modern = parsed.unwrap().to_error_code();
            // Verify it produces a valid RCH-E code
            assert!(modern.code_string().starts_with("RCH-E"));
        }
    }

    #[test]
    fn test_from_legacy_code() {
        let error = from_legacy_code("WORKER_UNREACHABLE", "Connection refused");
        assert_eq!(error.code, "RCH-E100");
        assert_eq!(error.details, Some("Connection refused".to_string()));
    }

    #[test]
    fn test_unknown_legacy_code_defaults_to_internal() {
        let error = from_legacy_code("UNKNOWN_CODE", "Something went wrong");
        assert_eq!(error.code, "RCH-E504"); // InternalStateError
    }

    #[test]
    fn test_error_context_serialization() {
        let mut ctx = ErrorContext::new();
        ctx = ctx.with("key1", "value1").with("key2", "value2");

        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("\"key1\":\"value1\""));
        assert!(json.contains("\"key2\":\"value2\""));
    }

    #[test]
    fn test_api_error_display() {
        let error = ApiError::from_code(ErrorCode::ConfigNotFound)
            .with_message("File ~/.config/rch/config.toml not found");

        let display = format!("{}", error);
        assert!(display.contains("RCH-E001"));
        assert!(display.contains("not found"));
    }

    #[test]
    fn test_retry_after() {
        let error = ApiError::from_code(ErrorCode::WorkerAtCapacity).with_retry_after(30);

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"retry_after_secs\":30"));
    }
}
