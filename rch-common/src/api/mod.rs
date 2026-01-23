//! Unified API Types for Remote Compilation Helper
//!
//! This module provides a consistent API interface for both CLI and daemon,
//! enabling agents and tools to parse responses uniformly.
//!
//! # Design Principles
//!
//! 1. **Unified Error Codes**: All errors use the `RCH-Exxx` format from [`ErrorCode`].
//! 2. **Consistent Envelope**: All responses wrapped in [`ApiResponse<T>`].
//! 3. **Machine-Readable**: Designed for programmatic parsing by AI agents.
//! 4. **Backward Compatible**: Supports legacy error codes via mapping.
//!
//! # Example
//!
//! ```rust
//! use rch_common::api::{ApiResponse, ApiError};
//! use rch_common::ErrorCode;
//!
//! // Success response
//! let response = ApiResponse::ok("workers list", vec!["worker1", "worker2"]);
//! println!("{}", serde_json::to_string_pretty(&response).unwrap());
//!
//! // Error response
//! let response: ApiResponse<()> = ApiResponse::err(
//!     "workers probe",
//!     ApiError::from_code(ErrorCode::SshConnectionFailed)
//!         .with_message("Connection refused to worker-1")
//!         .with_context("worker_id", "worker-1"),
//! );
//! println!("{}", serde_json::to_string_pretty(&response).unwrap());
//! ```
//!
//! # JSON Output Format
//!
//! Success:
//! ```json
//! {
//!   "api_version": "1.0",
//!   "timestamp": 1705936800,
//!   "success": true,
//!   "data": { ... }
//! }
//! ```
//!
//! Error:
//! ```json
//! {
//!   "api_version": "1.0",
//!   "timestamp": 1705936800,
//!   "success": false,
//!   "error": {
//!     "code": "RCH-E100",
//!     "category": "network",
//!     "message": "SSH connection to worker failed",
//!     "details": "Connection refused to worker-1",
//!     "remediation": ["Check worker is running", "Verify SSH key"],
//!     "context": { "worker_id": "worker-1" }
//!   }
//! }
//! ```

mod error;
mod response;

pub use error::{ApiError, ErrorContext, LegacyErrorCode};
pub use response::{API_VERSION, ApiResponse};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    #[test]
    fn test_success_response_serialization() {
        let response = ApiResponse::ok("test command", "test data");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"api_version\":\"1.0\""));
        assert!(json.contains("\"data\":\"test data\""));
    }

    #[test]
    fn test_error_response_serialization() {
        let error = ApiError::from_code(ErrorCode::ConfigNotFound);
        let response: ApiResponse<()> = ApiResponse::err("config show", error);
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("\"code\":\"RCH-E001\""));
        assert!(json.contains("\"category\":\"config\""));
    }

    #[test]
    fn test_legacy_code_mapping() {
        let legacy = LegacyErrorCode::WorkerUnreachable;
        let modern = legacy.to_error_code();
        assert_eq!(modern, ErrorCode::SshConnectionFailed);
    }

    #[test]
    fn test_error_with_context() {
        let error = ApiError::from_code(ErrorCode::WorkerNoneAvailable)
            .with_message("All workers are busy")
            .with_context("requested_slots", "8")
            .with_context("available_workers", "0");

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"requested_slots\":\"8\""));
        assert!(json.contains("\"available_workers\":\"0\""));
    }

    #[test]
    fn test_response_with_request_id() {
        let response = ApiResponse::ok("status", "healthy").with_request_id("req-12345");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"request_id\":\"req-12345\""));
    }
}
