//! True End-to-End Test Infrastructure
//!
//! This module provides infrastructure for running true E2E tests that
//! execute against real worker machines over SSH.
//!
//! # Features
//!
//! This module is gated behind the `true-e2e` feature flag:
//!
//! ```bash
//! cargo test --features true-e2e
//! ```
//!
//! # Configuration
//!
//! Tests use the configuration in `tests/true_e2e/workers_test.toml`.
//! Override with the `RCH_E2E_WORKERS_CONFIG` environment variable.
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use tests::true_e2e::config::TestWorkersConfig;
//!
//! #[test]
//! fn test_with_real_worker() {
//!     let config = TestWorkersConfig::load().expect("Failed to load config");
//!
//!     if !config.has_enabled_workers() {
//!         eprintln!("Skipping: no workers configured");
//!         return;
//!     }
//!
//!     // Run test against real worker...
//! }
//! ```

pub mod cargo_build_tests;
pub mod cargo_test_tests;
pub mod config;
pub mod exit_code_tests;
pub mod failopen_tests;
pub mod output;
pub mod ssh_command_tests;
pub mod ssh_tests;

// Re-export common types for convenience
pub use config::{ConfigError, ConfigResult, TestWorkersConfig, TestWorkerEntry, TestSettings};
pub use config::{expand_path, get_config_path, should_skip_worker_check};
pub use config::{ENV_WORKERS_CONFIG, ENV_SKIP_WORKER_CHECK, ENV_TIMEOUT_SECS};
pub use output::{
    BinaryComparison, CapturedOutput, ComparisonResult, NormalizationResult,
    NormalizationTransform, OutputComparison, OutputNormalizer,
};
