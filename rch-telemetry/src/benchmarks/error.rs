//! Common benchmark error classification.
//!
//! Provides a single error type that captures common benchmark failures and
//! exposes retry/reschedule semantics for higher-level orchestration.

use crate::benchmarks::retry::RetryableError;

/// Errors that can occur while running benchmarks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BenchmarkError {
    #[error("SSH connection failed: {0}")]
    SshConnection(String),

    #[error("SSH timeout after {0}s")]
    SshTimeout(u64),

    #[error("Worker resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("Disk full on worker")]
    DiskFull,

    #[error("Compilation failed: {0}")]
    CompilationFailed(String),

    #[error("Network benchmark failed: {0}")]
    NetworkBenchmarkFailed(String),

    #[error("Invalid benchmark result: {0}")]
    InvalidResult(String),

    #[error("Worker unreachable")]
    WorkerUnreachable,

    #[error("Cancelled by user")]
    Cancelled,
}

impl BenchmarkError {
    /// Whether this error should be retried immediately.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::SshConnection(_)
                | Self::SshTimeout(_)
                | Self::NetworkBenchmarkFailed(_)
                | Self::WorkerUnreachable
        )
    }

    /// Whether this error should be rescheduled for a later attempt.
    pub fn should_reschedule(&self) -> bool {
        matches!(self, Self::ResourceExhausted(_) | Self::WorkerUnreachable)
    }
}

impl RetryableError for BenchmarkError {
    fn is_retryable(&self) -> bool {
        BenchmarkError::is_retryable(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retryable_classification() {
        assert!(BenchmarkError::SshConnection("oops".into()).is_retryable());
        assert!(BenchmarkError::SshTimeout(30).is_retryable());
        assert!(!BenchmarkError::DiskFull.is_retryable());
        assert!(!BenchmarkError::CompilationFailed("fail".into()).is_retryable());
    }

    #[test]
    fn test_should_reschedule() {
        assert!(BenchmarkError::ResourceExhausted("busy".into()).should_reschedule());
        assert!(BenchmarkError::WorkerUnreachable.should_reschedule());
        assert!(!BenchmarkError::SshTimeout(5).should_reschedule());
    }

    // -------------------------------------------------------------------------
    // Debug trait tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_debug_ssh_connection() {
        let err = BenchmarkError::SshConnection("connection refused".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("SshConnection"));
        assert!(debug_str.contains("connection refused"));
    }

    #[test]
    fn test_debug_ssh_timeout() {
        let err = BenchmarkError::SshTimeout(60);
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("SshTimeout"));
        assert!(debug_str.contains("60"));
    }

    #[test]
    fn test_debug_resource_exhausted() {
        let err = BenchmarkError::ResourceExhausted("out of memory".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("ResourceExhausted"));
        assert!(debug_str.contains("out of memory"));
    }

    #[test]
    fn test_debug_disk_full() {
        let err = BenchmarkError::DiskFull;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("DiskFull"));
    }

    #[test]
    fn test_debug_compilation_failed() {
        let err = BenchmarkError::CompilationFailed("type error".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("CompilationFailed"));
        assert!(debug_str.contains("type error"));
    }

    #[test]
    fn test_debug_network_benchmark_failed() {
        let err = BenchmarkError::NetworkBenchmarkFailed("iperf crashed".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("NetworkBenchmarkFailed"));
        assert!(debug_str.contains("iperf crashed"));
    }

    #[test]
    fn test_debug_invalid_result() {
        let err = BenchmarkError::InvalidResult("negative latency".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("InvalidResult"));
        assert!(debug_str.contains("negative latency"));
    }

    #[test]
    fn test_debug_worker_unreachable() {
        let err = BenchmarkError::WorkerUnreachable;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("WorkerUnreachable"));
    }

    #[test]
    fn test_debug_cancelled() {
        let err = BenchmarkError::Cancelled;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Cancelled"));
    }

    // -------------------------------------------------------------------------
    // Clone trait tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_clone_ssh_connection() {
        let err = BenchmarkError::SshConnection("test".to_string());
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_clone_ssh_timeout() {
        let err = BenchmarkError::SshTimeout(45);
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_clone_unit_variants() {
        let disk_full = BenchmarkError::DiskFull;
        assert_eq!(disk_full.clone(), BenchmarkError::DiskFull);

        let unreachable = BenchmarkError::WorkerUnreachable;
        assert_eq!(unreachable.clone(), BenchmarkError::WorkerUnreachable);

        let cancelled = BenchmarkError::Cancelled;
        assert_eq!(cancelled.clone(), BenchmarkError::Cancelled);
    }

    // -------------------------------------------------------------------------
    // PartialEq trait tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_partial_eq_same_variant_same_data() {
        let err1 = BenchmarkError::SshConnection("test".to_string());
        let err2 = BenchmarkError::SshConnection("test".to_string());
        assert_eq!(err1, err2);
    }

    #[test]
    fn test_partial_eq_same_variant_different_data() {
        let err1 = BenchmarkError::SshConnection("test1".to_string());
        let err2 = BenchmarkError::SshConnection("test2".to_string());
        assert_ne!(err1, err2);
    }

    #[test]
    fn test_partial_eq_different_variants() {
        let err1 = BenchmarkError::DiskFull;
        let err2 = BenchmarkError::WorkerUnreachable;
        assert_ne!(err1, err2);
    }

    #[test]
    fn test_partial_eq_timeout_values() {
        let err1 = BenchmarkError::SshTimeout(30);
        let err2 = BenchmarkError::SshTimeout(30);
        let err3 = BenchmarkError::SshTimeout(60);
        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }

    // -------------------------------------------------------------------------
    // Display trait tests (via thiserror)
    // -------------------------------------------------------------------------

    #[test]
    fn test_display_ssh_connection() {
        let err = BenchmarkError::SshConnection("port 22 refused".to_string());
        let display = err.to_string();
        assert!(display.contains("SSH connection failed"));
        assert!(display.contains("port 22 refused"));
    }

    #[test]
    fn test_display_ssh_timeout() {
        let err = BenchmarkError::SshTimeout(30);
        let display = err.to_string();
        assert!(display.contains("SSH timeout"));
        assert!(display.contains("30"));
    }

    #[test]
    fn test_display_resource_exhausted() {
        let err = BenchmarkError::ResourceExhausted("CPU at 100%".to_string());
        let display = err.to_string();
        assert!(display.contains("Worker resource exhausted"));
        assert!(display.contains("CPU at 100%"));
    }

    #[test]
    fn test_display_disk_full() {
        let err = BenchmarkError::DiskFull;
        let display = err.to_string();
        assert!(display.contains("Disk full"));
    }

    #[test]
    fn test_display_compilation_failed() {
        let err = BenchmarkError::CompilationFailed("missing crate".to_string());
        let display = err.to_string();
        assert!(display.contains("Compilation failed"));
        assert!(display.contains("missing crate"));
    }

    #[test]
    fn test_display_network_benchmark_failed() {
        let err = BenchmarkError::NetworkBenchmarkFailed("DNS timeout".to_string());
        let display = err.to_string();
        assert!(display.contains("Network benchmark failed"));
        assert!(display.contains("DNS timeout"));
    }

    #[test]
    fn test_display_invalid_result() {
        let err = BenchmarkError::InvalidResult("NaN throughput".to_string());
        let display = err.to_string();
        assert!(display.contains("Invalid benchmark result"));
        assert!(display.contains("NaN throughput"));
    }

    #[test]
    fn test_display_worker_unreachable() {
        let err = BenchmarkError::WorkerUnreachable;
        let display = err.to_string();
        assert!(display.contains("Worker unreachable"));
    }

    #[test]
    fn test_display_cancelled() {
        let err = BenchmarkError::Cancelled;
        let display = err.to_string();
        assert!(display.contains("Cancelled"));
    }

    // -------------------------------------------------------------------------
    // is_retryable() comprehensive tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_retryable_ssh_connection() {
        assert!(BenchmarkError::SshConnection("any".into()).is_retryable());
    }

    #[test]
    fn test_is_retryable_ssh_timeout() {
        assert!(BenchmarkError::SshTimeout(1).is_retryable());
        assert!(BenchmarkError::SshTimeout(999).is_retryable());
    }

    #[test]
    fn test_is_retryable_network_benchmark_failed() {
        assert!(BenchmarkError::NetworkBenchmarkFailed("err".into()).is_retryable());
    }

    #[test]
    fn test_is_retryable_worker_unreachable() {
        assert!(BenchmarkError::WorkerUnreachable.is_retryable());
    }

    #[test]
    fn test_is_not_retryable_resource_exhausted() {
        assert!(!BenchmarkError::ResourceExhausted("busy".into()).is_retryable());
    }

    #[test]
    fn test_is_not_retryable_disk_full() {
        assert!(!BenchmarkError::DiskFull.is_retryable());
    }

    #[test]
    fn test_is_not_retryable_compilation_failed() {
        assert!(!BenchmarkError::CompilationFailed("err".into()).is_retryable());
    }

    #[test]
    fn test_is_not_retryable_invalid_result() {
        assert!(!BenchmarkError::InvalidResult("bad".into()).is_retryable());
    }

    #[test]
    fn test_is_not_retryable_cancelled() {
        assert!(!BenchmarkError::Cancelled.is_retryable());
    }

    // -------------------------------------------------------------------------
    // should_reschedule() comprehensive tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_should_reschedule_resource_exhausted() {
        assert!(BenchmarkError::ResourceExhausted("mem".into()).should_reschedule());
    }

    #[test]
    fn test_should_reschedule_worker_unreachable() {
        assert!(BenchmarkError::WorkerUnreachable.should_reschedule());
    }

    #[test]
    fn test_should_not_reschedule_ssh_connection() {
        assert!(!BenchmarkError::SshConnection("err".into()).should_reschedule());
    }

    #[test]
    fn test_should_not_reschedule_ssh_timeout() {
        assert!(!BenchmarkError::SshTimeout(30).should_reschedule());
    }

    #[test]
    fn test_should_not_reschedule_disk_full() {
        assert!(!BenchmarkError::DiskFull.should_reschedule());
    }

    #[test]
    fn test_should_not_reschedule_compilation_failed() {
        assert!(!BenchmarkError::CompilationFailed("err".into()).should_reschedule());
    }

    #[test]
    fn test_should_not_reschedule_network_benchmark_failed() {
        assert!(!BenchmarkError::NetworkBenchmarkFailed("err".into()).should_reschedule());
    }

    #[test]
    fn test_should_not_reschedule_invalid_result() {
        assert!(!BenchmarkError::InvalidResult("bad".into()).should_reschedule());
    }

    #[test]
    fn test_should_not_reschedule_cancelled() {
        assert!(!BenchmarkError::Cancelled.should_reschedule());
    }

    // -------------------------------------------------------------------------
    // RetryableError trait implementation test
    // -------------------------------------------------------------------------

    #[test]
    fn test_retryable_error_trait() {
        let err: &dyn RetryableError = &BenchmarkError::SshTimeout(10);
        assert!(err.is_retryable());

        let err: &dyn RetryableError = &BenchmarkError::DiskFull;
        assert!(!err.is_retryable());
    }
}
