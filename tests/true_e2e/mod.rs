//! True End-to-End Test Infrastructure
//!
//! This module provides infrastructure for running true E2E tests that
//! execute against real worker machines over SSH.
//!
//! # Features
//!
//! This module is gated behind the `true-e2e` feature flag.
//!
//! ## Running All E2E Tests
//!
//! ```bash
//! # Full command with feature flag
//! cargo test --features true-e2e -p rch --test true_e2e
//! ```
//!
//! ## Filtering Tests
//!
//! ```bash
//! # Run only cargo_build tests
//! cargo test --features true-e2e -p rch --test true_e2e cargo_build
//!
//! # Run SSH tests
//! cargo test --features true-e2e -p rch --test true_e2e ssh_tests
//! ```
//!
//! ## CI Integration
//!
//! E2E tests run in a dedicated CI job (`e2e`) separate from regular unit tests.
//! Regular `cargo test --workspace` does NOT run E2E tests.
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

pub mod artifact_tests;
pub mod build_rs_fixture_tests;
pub mod c_cpp_compiler_tests;
pub mod cargo_bench_tests;
pub mod cargo_build_tests;
pub mod cargo_check_clippy_tests;
pub mod cargo_nextest_tests;
pub mod cargo_test_tests;
pub mod config;
pub mod error_recovery_tests;
pub mod exit_code_tests;
pub mod failopen_tests;
pub mod output;
pub mod performance_tests;
pub mod ssh_command_tests;
pub mod ssh_tests;

// Re-export common types for convenience
pub use config::{ConfigError, ConfigResult, TestSettings, TestWorkerEntry, TestWorkersConfig};
pub use config::{ENV_SKIP_WORKER_CHECK, ENV_TIMEOUT_SECS, ENV_WORKERS_CONFIG};
pub use config::{expand_path, get_config_path, should_skip_worker_check};
pub use output::{
    BinaryComparison, CapturedOutput, ComparisonResult, NormalizationResult,
    NormalizationTransform, OutputComparison, OutputNormalizer,
};
