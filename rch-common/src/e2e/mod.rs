//! E2E Test Infrastructure
//!
//! This module provides comprehensive infrastructure for end-to-end testing
//! of the Remote Compilation Helper system.
//!
//! # Components
//!
//! - **logging**: Structured logging system for capturing test execution details
//! - **harness**: Test harness for managing processes, files, and assertions
//! - **fixtures**: Pre-built configurations and sample data for tests
//! - **verification**: Remote compilation verification for self-testing
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use rch_common::e2e::{TestHarnessBuilder, TestLoggerBuilder, HookInputFixture};
//!
//! #[test]
//! fn test_daemon_startup() {
//!     // Create a test harness
//!     let harness = TestHarnessBuilder::new("test_daemon_startup")
//!         .cleanup_on_success(true)
//!         .build()
//!         .unwrap();
//!
//!     // Create daemon config
//!     let socket_path = harness.test_dir().join("rch.sock");
//!     let config = DaemonConfigFixture::minimal(&socket_path);
//!     harness.create_daemon_config(&config.to_toml()).unwrap();
//!
//!     // Start the daemon
//!     harness.start_daemon(&[]).unwrap();
//!
//!     // Wait for socket to be available
//!     harness.wait_for_socket(&socket_path, Duration::from_secs(5)).unwrap();
//!
//!     // Run test assertions
//!     let result = harness.exec_rch(["status"]).unwrap();
//!     harness.assert_success(&result, "rch status").unwrap();
//!
//!     harness.mark_passed();
//! }
//! ```
//!
//! # Test Categories
//!
//! The E2E test infrastructure supports several categories of tests:
//!
//! - **Daemon Lifecycle**: Start/stop, configuration, health checks
//! - **Worker Connectivity**: SSH connections, capability detection
//! - **Hook Integration**: Command classification, interception
//! - **Full Build Pipeline**: End-to-end compilation offloading
//! - **Fleet Deployment**: Multi-worker scenarios

pub mod fixtures;
pub mod harness;
pub mod logging;
pub mod process_triage;
pub mod test_workers;
pub mod verification;

// Re-export commonly used items
pub use fixtures::{
    DEFAULT_MULTI_REPO_ALIAS_ROOT, DEFAULT_MULTI_REPO_CANONICAL_ROOT,
    DEFAULT_MULTI_REPO_FIXTURE_NAMESPACE, DaemonConfigFixture, FixtureFailureMode, FixtureLayer,
    FixtureReadiness, HookInputFixture, MultiRepoFixtureConfig, MultiRepoFixtureError,
    MultiRepoFixtureMetadata, MultiRepoFixtureResult, MultiRepoFixtureSet, RustProjectFixture,
    TestCaseFixture, WorkerFixture, WorkersFixture, reset_default_multi_repo_fixtures,
    reset_multi_repo_fixtures,
};
pub use harness::{
    CommandResult, HarnessConfig, HarnessError, HarnessResult, ProcessInfo,
    ReliabilityCommandRecord, ReliabilityFailureHook, ReliabilityFailureHookFlags,
    ReliabilityLifecycleCommand, ReliabilityScenarioReport, ReliabilityScenarioSpec,
    ReliabilityWorkerLifecycleHooks, TestHarness, TestHarnessBuilder, cleanup_stale_test_artifacts,
};
pub use logging::{
    LogEntry, LogLevel, LogSource, LoggerConfig, RELIABILITY_EVENT_SCHEMA_VERSION,
    ReliabilityContext, ReliabilityEventInput, ReliabilityPhase, ReliabilityPhaseEvent,
    TestLogSummary, TestLogger, TestLoggerBuilder,
};
pub use process_triage::{
    PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION, ProcessTriageActionClass, ProcessTriageActionOutcome,
    ProcessTriageActionRequest, ProcessTriageActionResult, ProcessTriageAdapterCommand,
    ProcessTriageAuditRecord, ProcessTriageCommandBudget, ProcessTriageContract,
    ProcessTriageContractError, ProcessTriageEscalationLevel, ProcessTriageFailure,
    ProcessTriageFailureKind, ProcessTriagePolicyDecision, ProcessTriageRequest,
    ProcessTriageResponse, ProcessTriageResponseStatus, ProcessTriageRetryPolicy,
    ProcessTriageSafeActionPolicy, ProcessTriageTimeoutPolicy, ProcessTriageTrigger,
    evaluate_triage_action, process_triage_request_schema, process_triage_response_schema,
};
pub use test_workers::{
    ENV_SKIP_WORKER_CHECK, ENV_TIMEOUT_SECS, ENV_WORKERS_CONFIG, TestConfigError, TestConfigResult,
    TestSettings, TestWorkerEntry, TestWorkersConfig, expand_tilde_path, get_config_path,
    is_mock_ssh_mode, should_skip_worker_check,
};
pub use verification::{RemoteCompilationTest, VerificationConfig, VerificationResult};

/// Macro for creating E2E tests with automatic harness setup and cleanup
///
/// # Example
///
/// ```rust,ignore
/// e2e_test!(test_basic_hook, |harness| {
///     let result = harness.exec_rch(["--help"]).unwrap();
///     harness.assert_success(&result, "rch --help").unwrap();
/// });
/// ```
#[macro_export]
macro_rules! e2e_test {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            use $crate::e2e::{HarnessResult, TestHarnessBuilder};

            fn run_test() -> HarnessResult<()> {
                let harness = TestHarnessBuilder::new(stringify!($name))
                    .cleanup_on_success(true)
                    .cleanup_on_failure(false)
                    .build()?;

                let body: fn(&$crate::e2e::TestHarness) -> HarnessResult<()> = $body;
                let result = body(&harness);

                if result.is_ok() {
                    harness.mark_passed();
                }

                result
            }

            if let Err(e) = run_test() {
                panic!("E2E test failed: {}", e);
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_e2e_infrastructure_integration() {
        // Create a logger
        let logger = TestLoggerBuilder::new("integration_test")
            .print_realtime(false)
            .build();

        logger.info("Starting integration test");

        // Create a harness
        let harness = TestHarnessBuilder::new("integration_test")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        // Create some files using fixtures
        let project = RustProjectFixture::minimal("test-proj");
        let project_dir = harness.create_dir("project").unwrap();
        project.create_in(&project_dir).unwrap();

        // Verify the project was created
        assert!(project_dir.join("Cargo.toml").exists());
        assert!(project_dir.join("src/main.rs").exists());

        // Create worker config
        let workers = WorkersFixture::mock_local(1);
        let workers_toml = workers.to_toml();
        assert!(workers_toml.contains("worker1"));

        // Create daemon config
        let socket_path = harness.test_dir().join("rch.sock");
        let daemon_config = DaemonConfigFixture::minimal(&socket_path);
        let daemon_toml = daemon_config.to_toml();
        assert!(daemon_toml.contains("confidence_threshold"));

        // Test hook input fixture
        let hook_input = HookInputFixture::cargo_build();
        let json = hook_input.to_json();
        assert!(json.contains("cargo build"));

        // Test command execution
        let result = harness.exec("echo", ["hello"]).unwrap();
        harness.assert_success(&result, "echo").unwrap();
        harness
            .assert_stdout_contains(&result, "hello", "echo output")
            .unwrap();

        logger.info("Integration test completed");
        harness.mark_passed();
    }

    #[test]
    fn test_logger_standalone() {
        let logger = TestLoggerBuilder::new("logger_test")
            .print_realtime(false)
            .min_level(LogLevel::Debug)
            .max_entries(100)
            .build();

        logger.debug("Debug message");
        logger.info("Info message");
        logger.warn("Warning message");
        logger.error("Error message");

        let entries = logger.entries();
        assert_eq!(entries.len(), 4);

        let errors = logger.entries_by_level(LogLevel::Error);
        assert_eq!(errors.len(), 1);

        let summary = logger.summary();
        assert_eq!(summary.total_entries, 4);
        assert_eq!(*summary.counts_by_level.get(&LogLevel::Error).unwrap(), 1);
    }

    #[test]
    fn test_harness_wait_for() {
        let harness = TestHarnessBuilder::new("wait_test")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        // Create a file to wait for
        let test_file = harness.test_dir().join("marker.txt");

        // Spawn a thread to create the file after a delay
        let file_path = test_file.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            std::fs::write(&file_path, "created").unwrap();
        });

        // Wait for the file to exist
        harness
            .wait_for_file(&test_file, Duration::from_secs(2))
            .unwrap();

        assert!(test_file.exists());
        harness.mark_passed();
    }
}
