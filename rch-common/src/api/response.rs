//! Unified API Response Envelope
//!
//! Provides [`ApiResponse<T>`] which wraps all API responses in a consistent
//! envelope format.

use super::ApiError;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Current API version.
///
/// This is used for API compatibility detection. Clients can check this
/// value to determine if they're compatible with the response format.
pub const API_VERSION: &str = "1.0";

/// Unified API response envelope.
///
/// All CLI commands and daemon endpoints should return this structure
/// for consistent agent parsing.
///
/// # Example
///
/// ```rust
/// use rch_common::api::{ApiResponse, ApiError};
/// use rch_common::ErrorCode;
///
/// // Success response
/// #[derive(serde::Serialize)]
/// struct WorkerList {
///     workers: Vec<String>,
///     count: usize,
/// }
///
/// let data = WorkerList {
///     workers: vec!["worker-1".to_string(), "worker-2".to_string()],
///     count: 2,
/// };
/// let response = ApiResponse::ok("workers list", data);
///
/// // Error response
/// let error = ApiError::from_code(ErrorCode::ConfigNotFound);
/// let response: ApiResponse<()> = ApiResponse::err("config show", error);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T: Serialize> {
    /// API version for compatibility detection.
    pub api_version: &'static str,

    /// Unix timestamp when response was generated.
    pub timestamp: u64,

    /// Optional request ID for correlation/tracing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// Command that produced this response (e.g., "workers list").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// Whether the operation succeeded.
    pub success: bool,

    /// Response data on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,

    /// Error details on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

impl<T: Serialize> ApiResponse<T> {
    /// Create a successful response.
    ///
    /// # Arguments
    ///
    /// * `command` - Command name that produced this response
    /// * `data` - Response payload
    #[must_use]
    pub fn ok(command: impl Into<String>, data: T) -> Self {
        Self {
            api_version: API_VERSION,
            timestamp: current_timestamp(),
            request_id: None,
            command: Some(command.into()),
            success: true,
            data: Some(data),
            error: None,
        }
    }

    /// Create a successful response without command name.
    ///
    /// Useful for daemon endpoints where command context isn't applicable.
    #[must_use]
    pub fn ok_data(data: T) -> Self {
        Self {
            api_version: API_VERSION,
            timestamp: current_timestamp(),
            request_id: None,
            command: None,
            success: true,
            data: Some(data),
            error: None,
        }
    }

    /// Add a request ID for correlation.
    #[must_use]
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Add or override command name.
    #[must_use]
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }
}

impl<T: Serialize> ApiResponse<T> {
    /// Create an error response.
    ///
    /// # Arguments
    ///
    /// * `command` - Command name that failed
    /// * `error` - Error details
    #[must_use]
    pub fn err(command: impl Into<String>, error: ApiError) -> Self {
        Self {
            api_version: API_VERSION,
            timestamp: current_timestamp(),
            request_id: None,
            command: Some(command.into()),
            success: false,
            data: None,
            error: Some(error),
        }
    }

    /// Create an error response without command name.
    ///
    /// Useful for daemon endpoints.
    #[must_use]
    pub fn err_only(error: ApiError) -> Self {
        Self {
            api_version: API_VERSION,
            timestamp: current_timestamp(),
            request_id: None,
            command: None,
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

impl ApiResponse<()> {
    /// Create a simple success response with no data.
    #[must_use]
    pub fn ok_empty(command: impl Into<String>) -> Self {
        Self {
            api_version: API_VERSION,
            timestamp: current_timestamp(),
            request_id: None,
            command: Some(command.into()),
            success: true,
            data: None,
            error: None,
        }
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// =============================================================================
// Conversion Traits
// =============================================================================

impl<T: Serialize, E: Into<ApiError>> From<Result<T, E>> for ApiResponse<T> {
    fn from(result: Result<T, E>) -> Self {
        match result {
            Ok(data) => Self::ok_data(data),
            Err(e) => Self::err_only(e.into()),
        }
    }
}

// =============================================================================
// Builder Pattern for Complex Responses
// =============================================================================

/// Builder for constructing [`ApiResponse`] with full control.
#[allow(dead_code)]
pub struct ApiResponseBuilder<T: Serialize> {
    command: Option<String>,
    request_id: Option<String>,
    data: Option<T>,
    error: Option<ApiError>,
}

#[allow(dead_code)]
impl<T: Serialize> ApiResponseBuilder<T> {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            command: None,
            request_id: None,
            data: None,
            error: None,
        }
    }

    /// Set the command name.
    #[must_use]
    pub fn command(mut self, cmd: impl Into<String>) -> Self {
        self.command = Some(cmd.into());
        self
    }

    /// Set the request ID.
    #[must_use]
    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Set success data.
    #[must_use]
    pub fn data(mut self, data: T) -> Self {
        self.data = Some(data);
        self.error = None;
        self
    }

    /// Set error.
    #[must_use]
    pub fn error(mut self, error: ApiError) -> Self {
        self.error = Some(error);
        self.data = None;
        self
    }

    /// Build the response.
    #[must_use]
    pub fn build(self) -> ApiResponse<T> {
        let success = self.data.is_some();
        ApiResponse {
            api_version: API_VERSION,
            timestamp: current_timestamp(),
            request_id: self.request_id,
            command: self.command,
            success,
            data: self.data,
            error: self.error,
        }
    }
}

impl<T: Serialize> Default for ApiResponseBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    #[test]
    fn test_ok_response() {
        let response = ApiResponse::ok("test", "hello");
        assert!(response.success);
        assert_eq!(response.data, Some("hello"));
        assert!(response.error.is_none());
        assert_eq!(response.api_version, "1.0");
        assert!(response.timestamp > 0);
    }

    #[test]
    fn test_err_response() {
        let error = ApiError::from_code(ErrorCode::ConfigNotFound);
        let response: ApiResponse<()> = ApiResponse::err("config show", error);
        assert!(!response.success);
        assert!(response.data.is_none());
        assert!(response.error.is_some());
        assert_eq!(response.error.as_ref().unwrap().code, "RCH-E001");
    }

    #[test]
    fn test_ok_empty() {
        let response = ApiResponse::ok_empty("shutdown");
        assert!(response.success);
        assert!(response.data.is_none());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_with_request_id() {
        let response = ApiResponse::ok("test", "data").with_request_id("req-123");
        assert_eq!(response.request_id, Some("req-123".to_string()));
    }

    #[test]
    fn test_serialization_success() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Data {
            count: u32,
        }

        let response = ApiResponse::ok("count", Data { count: 42 });
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"api_version\":\"1.0\""));
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"count\":42"));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_serialization_error() {
        let error = ApiError::from_code(ErrorCode::SshConnectionFailed)
            .with_context("worker", "test-worker");
        let response: ApiResponse<()> = ApiResponse::err("probe", error);
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"success\":false"));
        assert!(json.contains("\"code\":\"RCH-E100\""));
        assert!(json.contains("\"worker\":\"test-worker\""));
        assert!(!json.contains("\"data\""));
    }

    #[test]
    fn test_builder() {
        let response: ApiResponse<String> = ApiResponseBuilder::new()
            .command("workers list")
            .request_id("req-456")
            .data("test data".to_string())
            .build();

        assert!(response.success);
        assert_eq!(response.command, Some("workers list".to_string()));
        assert_eq!(response.request_id, Some("req-456".to_string()));
        assert_eq!(response.data, Some("test data".to_string()));
    }

    #[test]
    fn test_from_result_ok() {
        let result: Result<String, ApiError> = Ok("success".to_string());
        let response: ApiResponse<String> = result.into();
        assert!(response.success);
        assert_eq!(response.data, Some("success".to_string()));
    }

    #[test]
    fn test_from_result_err() {
        let result: Result<String, ApiError> = Err(ApiError::from_code(ErrorCode::ConfigNotFound));
        let response: ApiResponse<String> = result.into();
        assert!(!response.success);
        assert!(response.error.is_some());
    }
}
