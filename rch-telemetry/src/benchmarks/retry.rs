//! Retry utilities for benchmark execution.
//!
//! Provides a generic retry policy with exponential backoff and jitter,
//! and a helper to run benchmark phases with retryable errors.

use std::future::Future;
use std::time::Duration;

use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Errors that can be retried.
pub trait RetryableError {
    /// Whether this error should be retried immediately.
    fn is_retryable(&self) -> bool;
}

/// Retry policy for benchmark execution.
#[derive(Debug, Clone)]
pub struct BenchmarkRetryPolicy {
    /// Maximum attempts including the first try (minimum 1).
    pub max_retries: u32,
    /// Base delay between retries (exponential backoff).
    pub base_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Jitter factor (0.0-1.0) applied to delay.
    pub jitter: f64,
}

impl Default for BenchmarkRetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(60),
            jitter: 0.2,
        }
    }
}

impl BenchmarkRetryPolicy {
    /// Calculate backoff delay for a given attempt (1-based).
    pub fn backoff_delay(&self, attempt: u32) -> Duration {
        let attempt = attempt.max(1);
        let base_secs = self.base_delay.as_secs_f64();
        let max_secs = self.max_delay.as_secs_f64().max(0.0);

        let multiplier = 2_u32.saturating_pow(attempt.saturating_sub(1)) as f64;
        let mut delay = (base_secs * multiplier).min(max_secs);

        if self.jitter > 0.0 && delay > 0.0 {
            let jitter = (fastrand::f64() * 2.0 - 1.0) * self.jitter;
            delay = (delay * (1.0 + jitter)).max(0.0);
        }

        Duration::from_secs_f64(delay)
    }

    fn max_attempts(&self) -> u32 {
        self.max_retries.max(1)
    }
}

/// Run an async operation with retries on retryable errors.
pub async fn run_with_retry<F, Fut, T, E>(
    phase: &str,
    policy: &BenchmarkRetryPolicy,
    mut op: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: RetryableError,
{
    let max_attempts = policy.max_attempts();
    let mut attempt = 1;

    loop {
        debug!(phase, attempt, max_attempts, "Starting benchmark attempt");

        match op().await {
            Ok(value) => {
                info!(phase, attempt, "Benchmark attempt succeeded");
                return Ok(value);
            }
            Err(err) if err.is_retryable() && attempt < max_attempts => {
                warn!(phase, attempt, "Benchmark attempt failed (retryable)");
                let delay = policy.backoff_delay(attempt);
                debug!(
                    phase,
                    attempt,
                    delay_secs = delay.as_secs_f64(),
                    "Retrying after backoff"
                );
                sleep(delay).await;
                attempt += 1;
            }
            Err(err) => {
                warn!(phase, attempt, "Benchmark attempt failed (non-retryable)");
                return Err(err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Debug)]
    enum TestError {
        Retryable,
        Fatal,
    }

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                TestError::Retryable => write!(f, "retryable"),
                TestError::Fatal => write!(f, "fatal"),
            }
        }
    }

    impl std::error::Error for TestError {}

    impl RetryableError for TestError {
        fn is_retryable(&self) -> bool {
            matches!(self, TestError::Retryable)
        }
    }

    #[tokio::test]
    async fn test_retry_succeeds_on_third_attempt() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let policy = BenchmarkRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            jitter: 0.0,
        };

        let result = run_with_retry("test", &policy, move || {
            let attempts_clone = attempts_clone.clone();
            async move {
                let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
                if count < 2 {
                    Err(TestError::Retryable)
                } else {
                    Ok(42u32)
                }
            }
        })
        .await;

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_non_retryable_error_fails_immediately() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let policy = BenchmarkRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            jitter: 0.0,
        };

        let result: Result<u32, TestError> = run_with_retry("test", &policy, move || {
            let attempts_clone = attempts_clone.clone();
            async move {
                attempts_clone.fetch_add(1, Ordering::SeqCst);
                Err(TestError::Fatal)
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    // -------------------------------------------------------------------------
    // BenchmarkRetryPolicy trait tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_policy_debug() {
        let policy = BenchmarkRetryPolicy::default();
        let debug_str = format!("{:?}", policy);
        assert!(debug_str.contains("BenchmarkRetryPolicy"));
        assert!(debug_str.contains("max_retries"));
        assert!(debug_str.contains("base_delay"));
    }

    #[test]
    fn test_policy_clone() {
        let policy = BenchmarkRetryPolicy {
            max_retries: 5,
            base_delay: Duration::from_secs(10),
            max_delay: Duration::from_secs(120),
            jitter: 0.3,
        };
        let cloned = policy.clone();
        assert_eq!(cloned.max_retries, 5);
        assert_eq!(cloned.base_delay, Duration::from_secs(10));
        assert_eq!(cloned.max_delay, Duration::from_secs(120));
        assert!((cloned.jitter - 0.3).abs() < 0.001);
    }

    #[test]
    fn test_policy_default_values() {
        let policy = BenchmarkRetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.base_delay, Duration::from_secs(5));
        assert_eq!(policy.max_delay, Duration::from_secs(60));
        assert!((policy.jitter - 0.2).abs() < 0.001);
    }

    // -------------------------------------------------------------------------
    // backoff_delay() tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_backoff_delay_first_attempt() {
        let policy = BenchmarkRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(60),
            jitter: 0.0,
        };

        // First attempt (attempt=1) should return base_delay
        let delay = policy.backoff_delay(1);
        assert_eq!(delay, Duration::from_secs(5));
    }

    #[test]
    fn test_backoff_delay_exponential() {
        let policy = BenchmarkRetryPolicy {
            max_retries: 5,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(120),
            jitter: 0.0,
        };

        // attempt 1: 1 * 2^0 = 1
        assert_eq!(policy.backoff_delay(1), Duration::from_secs(1));
        // attempt 2: 1 * 2^1 = 2
        assert_eq!(policy.backoff_delay(2), Duration::from_secs(2));
        // attempt 3: 1 * 2^2 = 4
        assert_eq!(policy.backoff_delay(3), Duration::from_secs(4));
        // attempt 4: 1 * 2^3 = 8
        assert_eq!(policy.backoff_delay(4), Duration::from_secs(8));
    }

    #[test]
    fn test_backoff_delay_capped_at_max() {
        let policy = BenchmarkRetryPolicy {
            max_retries: 10,
            base_delay: Duration::from_secs(10),
            max_delay: Duration::from_secs(30),
            jitter: 0.0,
        };

        // attempt 1: 10 * 1 = 10 (under max)
        assert_eq!(policy.backoff_delay(1), Duration::from_secs(10));
        // attempt 2: 10 * 2 = 20 (under max)
        assert_eq!(policy.backoff_delay(2), Duration::from_secs(20));
        // attempt 3: 10 * 4 = 40 -> capped at 30
        assert_eq!(policy.backoff_delay(3), Duration::from_secs(30));
        // attempt 4: 10 * 8 = 80 -> capped at 30
        assert_eq!(policy.backoff_delay(4), Duration::from_secs(30));
    }

    #[test]
    fn test_backoff_delay_with_jitter() {
        let policy = BenchmarkRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_secs(10),
            max_delay: Duration::from_secs(60),
            jitter: 0.5, // 50% jitter
        };

        // With jitter, the delay should vary but be within bounds
        let delay = policy.backoff_delay(1);
        // With 50% jitter: delay should be between 5 and 15 seconds
        let delay_secs = delay.as_secs_f64();
        assert!(
            (5.0..=15.0).contains(&delay_secs),
            "delay {} out of expected range",
            delay_secs
        );
    }

    #[test]
    fn test_backoff_delay_zero_attempt_treated_as_one() {
        let policy = BenchmarkRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(60),
            jitter: 0.0,
        };

        // attempt=0 should be treated as attempt=1
        let delay = policy.backoff_delay(0);
        assert_eq!(delay, Duration::from_secs(5));
    }

    #[test]
    fn test_backoff_delay_zero_jitter() {
        let policy = BenchmarkRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(60),
            jitter: 0.0,
        };

        // With zero jitter, delays should be deterministic
        let delay1 = policy.backoff_delay(1);
        let delay2 = policy.backoff_delay(1);
        assert_eq!(delay1, delay2);
    }

    #[test]
    fn test_backoff_delay_zero_base_delay() {
        let policy = BenchmarkRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_secs(0),
            max_delay: Duration::from_secs(60),
            jitter: 0.0,
        };

        // Zero base delay should result in zero delay
        let delay = policy.backoff_delay(1);
        assert_eq!(delay, Duration::from_secs(0));
    }

    // -------------------------------------------------------------------------
    // max_attempts() tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_max_attempts_normal() {
        let policy = BenchmarkRetryPolicy {
            max_retries: 5,
            ..Default::default()
        };
        assert_eq!(policy.max_attempts(), 5);
    }

    #[test]
    fn test_max_attempts_minimum_is_one() {
        let policy = BenchmarkRetryPolicy {
            max_retries: 0,
            ..Default::default()
        };
        // Should never be less than 1
        assert_eq!(policy.max_attempts(), 1);
    }

    // -------------------------------------------------------------------------
    // run_with_retry() additional tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_retry_succeeds_on_first_attempt() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let policy = BenchmarkRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            jitter: 0.0,
        };

        let result = run_with_retry("test", &policy, move || {
            let attempts_clone = attempts_clone.clone();
            async move {
                attempts_clone.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestError>(99u32)
            }
        })
        .await;

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(result.unwrap(), 99);
    }

    #[tokio::test]
    async fn test_retry_exhausts_all_attempts() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let policy = BenchmarkRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            jitter: 0.0,
        };

        let result: Result<u32, TestError> = run_with_retry("test", &policy, move || {
            let attempts_clone = attempts_clone.clone();
            async move {
                attempts_clone.fetch_add(1, Ordering::SeqCst);
                Err(TestError::Retryable)
            }
        })
        .await;

        // Should try all 3 attempts
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_retry_with_single_max_retry() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let policy = BenchmarkRetryPolicy {
            max_retries: 1,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            jitter: 0.0,
        };

        let result: Result<u32, TestError> = run_with_retry("test", &policy, move || {
            let attempts_clone = attempts_clone.clone();
            async move {
                attempts_clone.fetch_add(1, Ordering::SeqCst);
                Err(TestError::Retryable)
            }
        })
        .await;

        // With max_retries=1, only one attempt should be made
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // TestError tests (for completeness)
    // -------------------------------------------------------------------------

    #[test]
    fn test_error_debug() {
        let err = TestError::Retryable;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Retryable"));

        let err = TestError::Fatal;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Fatal"));
    }

    #[test]
    fn test_error_display() {
        let err = TestError::Retryable;
        assert_eq!(err.to_string(), "retryable");

        let err = TestError::Fatal;
        assert_eq!(err.to_string(), "fatal");
    }

    #[test]
    fn test_retryable_error_trait_impl() {
        assert!(TestError::Retryable.is_retryable());
        assert!(!TestError::Fatal.is_retryable());
    }
}
