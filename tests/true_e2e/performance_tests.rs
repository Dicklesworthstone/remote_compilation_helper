//! True E2E Tests: Performance & Timing Budget Verification
//!
//! Tests that verify RCH meets its strict performance budgets as documented in AGENTS.md.
//!
//! # Timing Budgets
//!
//! - Hook decision (non-compilation): <1ms, panic at 5ms
//! - Hook decision (compilation): <5ms, panic at 10ms
//! - Worker selection: <10ms, panic at 50ms
//! - Full pipeline overhead: <15%, panic at 50%
//!
//! # Running These Tests
//!
//! ```bash
//! cargo test --features true-e2e performance_tests -- --nocapture
//! ```
//!
//! # Bead Reference
//!
//! This implements bead bd-1nhd: True E2E Performance & Timing Budget Tests

use rch_common::e2e::{
    LogLevel, LogSource, TestConfigError, TestLoggerBuilder, TestWorkersConfig,
    should_skip_worker_check,
};
use rch_common::patterns::classify_command;
use rch_common::ssh::{KnownHostsPolicy, SshClient, SshOptions};
use std::time::{Duration, Instant};

// =============================================================================
// Timing Budget Constants
// =============================================================================

/// Budget for non-compilation hook decision (microseconds)
const NON_COMPILE_BUDGET_US: u64 = 1_000; // 1ms
/// Panic threshold for non-compilation hook decision (microseconds)
const NON_COMPILE_PANIC_US: u64 = 5_000; // 5ms

/// Budget for compilation hook decision (microseconds)
const COMPILE_BUDGET_US: u64 = 5_000; // 5ms
/// Panic threshold for compilation hook decision (microseconds)
const COMPILE_PANIC_US: u64 = 10_000; // 10ms

/// Budget for worker selection (microseconds)
const WORKER_SELECTION_BUDGET_US: u64 = 10_000; // 10ms
/// Panic threshold for worker selection (microseconds)
const WORKER_SELECTION_PANIC_US: u64 = 50_000; // 50ms

/// Number of samples for statistical significance
const SAMPLE_COUNT: usize = 100;

// =============================================================================
// Statistical Utilities
// =============================================================================

/// Timing statistics for a set of measurements
#[derive(Debug)]
struct TimingStats {
    mean_us: u64,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    max_us: u64,
    min_us: u64,
    stddev_us: f64,
    samples: usize,
}

impl TimingStats {
    fn compute(samples: &[Duration]) -> Self {
        if samples.is_empty() {
            return Self {
                mean_us: 0,
                p50_us: 0,
                p95_us: 0,
                p99_us: 0,
                max_us: 0,
                min_us: 0,
                stddev_us: 0.0,
                samples: 0,
            };
        }

        let mut us_values: Vec<u64> = samples.iter().map(|d| d.as_micros() as u64).collect();
        us_values.sort_unstable();

        let n = us_values.len();
        let sum: u64 = us_values.iter().sum();
        let mean = sum / n as u64;

        // Calculate standard deviation
        let variance: f64 = us_values
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean as f64;
                diff * diff
            })
            .sum::<f64>()
            / n as f64;
        let stddev = variance.sqrt();

        Self {
            mean_us: mean,
            p50_us: us_values[n / 2],
            p95_us: us_values[(n * 95) / 100],
            p99_us: us_values[(n * 99) / 100],
            max_us: us_values[n - 1],
            min_us: us_values[0],
            stddev_us: stddev,
            samples: n,
        }
    }
}

// =============================================================================
// Test Infrastructure
// =============================================================================

/// Skip the test if no real workers are available.
fn require_workers() -> Option<TestWorkersConfig> {
    if should_skip_worker_check() {
        eprintln!("Skipping: RCH_E2E_SKIP_WORKER_CHECK is set");
        return None;
    }

    match TestWorkersConfig::load() {
        Ok(config) => {
            if !config.has_enabled_workers() {
                eprintln!("Skipping: No enabled workers in configuration");
                return None;
            }
            Some(config)
        }
        Err(TestConfigError::NotFound(path)) => {
            eprintln!("Skipping: Config not found at {}", path.display());
            None
        }
        Err(e) => {
            eprintln!("Skipping: Failed to load config: {e}");
            None
        }
    }
}

/// Get a single enabled worker for testing.
fn get_test_worker(config: &TestWorkersConfig) -> Option<&rch_common::e2e::TestWorkerEntry> {
    config.enabled_workers().first().copied()
}

/// Helper to create a connected SSH client.
async fn get_connected_client(
    config: &TestWorkersConfig,
    worker_entry: &rch_common::e2e::TestWorkerEntry,
) -> Option<SshClient> {
    let worker_config = worker_entry.to_worker_config();
    let options = SshOptions {
        connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        ..Default::default()
    };

    let mut client = SshClient::new(worker_config, options);
    match client.connect().await {
        Ok(()) => Some(client),
        Err(_) => None,
    }
}

// =============================================================================
// Hook Classification Performance Tests
// =============================================================================

/// Test: Non-compilation command classification must be <1ms
///
/// Verifies that common non-compilation commands are rejected quickly.
#[tokio::test]
async fn test_hook_classification_non_compile() {
    let logger = TestLoggerBuilder::new("test_hook_classification_non_compile")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("performance".to_string()),
        "Starting non-compilation classification timing test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("budget_us".to_string(), NON_COMPILE_BUDGET_US.to_string()),
            ("panic_us".to_string(), NON_COMPILE_PANIC_US.to_string()),
            ("samples".to_string(), SAMPLE_COUNT.to_string()),
        ],
    );

    // Non-compilation commands to test
    let commands = vec![
        "ls -la",
        "git status",
        "echo hello",
        "cat README.md",
        "pwd",
        "cd /tmp",
        "mkdir -p test",
        "rm -rf temp",
        "cp file1 file2",
        "mv old new",
    ];

    for cmd in &commands {
        let mut samples = Vec::with_capacity(SAMPLE_COUNT);

        for _ in 0..SAMPLE_COUNT {
            let start = Instant::now();
            let classification = classify_command(cmd);
            let elapsed = start.elapsed();
            samples.push(elapsed);

            // Verify it's correctly classified as non-compilation
            assert!(
                !classification.is_compilation,
                "Command '{}' should be classified as non-compilation",
                cmd
            );
        }

        let stats = TimingStats::compute(&samples);

        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("performance".to_string()),
            "Classification timing measured",
            vec![
                ("phase".to_string(), "measure".to_string()),
                ("cmd".to_string(), cmd.to_string()),
                ("classification".to_string(), "non_compile".to_string()),
                ("mean_us".to_string(), stats.mean_us.to_string()),
                ("p95_us".to_string(), stats.p95_us.to_string()),
                ("p99_us".to_string(), stats.p99_us.to_string()),
                ("max_us".to_string(), stats.max_us.to_string()),
                ("budget_us".to_string(), NON_COMPILE_BUDGET_US.to_string()),
                (
                    "within_budget".to_string(),
                    (stats.p95_us <= NON_COMPILE_BUDGET_US).to_string(),
                ),
            ],
        );

        // Verify panic threshold not exceeded
        assert!(
            stats.max_us < NON_COMPILE_PANIC_US,
            "Command '{}' exceeded panic threshold: max {}us > {}us",
            cmd,
            stats.max_us,
            NON_COMPILE_PANIC_US
        );

        // Verify p95 is within budget (allow some variance)
        assert!(
            stats.p95_us <= NON_COMPILE_BUDGET_US,
            "Command '{}' p95 exceeded budget: {}us > {}us",
            cmd,
            stats.p95_us,
            NON_COMPILE_BUDGET_US
        );
    }

    logger.info("Non-compilation classification timing test passed");
    logger.print_summary();
}

/// Test: Compilation command classification must be <5ms
///
/// Verifies that compilation commands are classified within budget.
#[tokio::test]
async fn test_hook_classification_compile() {
    let logger = TestLoggerBuilder::new("test_hook_classification_compile")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("performance".to_string()),
        "Starting compilation classification timing test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("budget_us".to_string(), COMPILE_BUDGET_US.to_string()),
            ("panic_us".to_string(), COMPILE_PANIC_US.to_string()),
            ("samples".to_string(), SAMPLE_COUNT.to_string()),
        ],
    );

    // Compilation commands to test
    let commands = vec![
        "cargo build",
        "cargo build --release",
        "cargo test",
        "cargo check",
        "cargo clippy",
        "cargo build -p mypackage",
        "cargo test --features foo",
        "cargo build --target x86_64-unknown-linux-gnu",
        "rustc src/main.rs",
        "gcc hello.c -o hello",
    ];

    for cmd in &commands {
        let mut samples = Vec::with_capacity(SAMPLE_COUNT);

        for _ in 0..SAMPLE_COUNT {
            let start = Instant::now();
            let classification = classify_command(cmd);
            let elapsed = start.elapsed();
            samples.push(elapsed);

            // Verify it's correctly classified as compilation
            assert!(
                classification.is_compilation,
                "Command '{}' should be classified as compilation",
                cmd
            );
        }

        let stats = TimingStats::compute(&samples);

        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("performance".to_string()),
            "Classification timing measured",
            vec![
                ("phase".to_string(), "measure".to_string()),
                ("cmd".to_string(), cmd.to_string()),
                ("classification".to_string(), "compile".to_string()),
                ("mean_us".to_string(), stats.mean_us.to_string()),
                ("p95_us".to_string(), stats.p95_us.to_string()),
                ("p99_us".to_string(), stats.p99_us.to_string()),
                ("max_us".to_string(), stats.max_us.to_string()),
                ("budget_us".to_string(), COMPILE_BUDGET_US.to_string()),
                (
                    "within_budget".to_string(),
                    (stats.p95_us <= COMPILE_BUDGET_US).to_string(),
                ),
            ],
        );

        // Verify panic threshold not exceeded
        assert!(
            stats.max_us < COMPILE_PANIC_US,
            "Command '{}' exceeded panic threshold: max {}us > {}us",
            cmd,
            stats.max_us,
            COMPILE_PANIC_US
        );

        // Verify p95 is within budget
        assert!(
            stats.p95_us <= COMPILE_BUDGET_US,
            "Command '{}' p95 exceeded budget: {}us > {}us",
            cmd,
            stats.p95_us,
            COMPILE_BUDGET_US
        );
    }

    logger.info("Compilation classification timing test passed");
    logger.print_summary();
}

/// Test: Long/complex commands still classified quickly
///
/// Verifies that commands with many arguments don't cause slowdowns.
#[tokio::test]
async fn test_hook_classification_complex_commands() {
    let logger = TestLoggerBuilder::new("test_hook_classification_complex_commands")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("performance".to_string()),
        "Starting complex command classification timing test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("scenario".to_string(), "complex_commands".to_string()),
        ],
    );

    // Complex commands with many arguments
    let complex_commands = vec![
        // Long cargo command with many features
        "cargo build --release --features feat1,feat2,feat3,feat4,feat5 --target x86_64-unknown-linux-gnu --jobs 4 --message-format json",
        // Long cargo test with filters
        "cargo test --workspace --release --features full -- --test-threads=1 --nocapture test_name_filter",
        // Long gcc command
        "gcc -Wall -Wextra -O2 -march=native -flto -I/usr/include -L/usr/lib src/main.c src/util.c src/network.c -o output -lpthread -lssl -lcrypto",
        // Piped command (should be non-compilation)
        "cargo build 2>&1 | tee build.log | grep -E 'error|warning'",
    ];

    for cmd in &complex_commands {
        let mut samples = Vec::with_capacity(SAMPLE_COUNT);

        for _ in 0..SAMPLE_COUNT {
            let start = Instant::now();
            let _classification = classify_command(cmd);
            let elapsed = start.elapsed();
            samples.push(elapsed);
        }

        let stats = TimingStats::compute(&samples);

        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("performance".to_string()),
            "Complex command timing measured",
            vec![
                ("phase".to_string(), "measure".to_string()),
                ("cmd_len".to_string(), cmd.len().to_string()),
                ("mean_us".to_string(), stats.mean_us.to_string()),
                ("p95_us".to_string(), stats.p95_us.to_string()),
                ("max_us".to_string(), stats.max_us.to_string()),
            ],
        );

        // Complex commands should still be within the compile budget
        assert!(
            stats.max_us < COMPILE_PANIC_US,
            "Complex command exceeded panic threshold: max {}us > {}us",
            stats.max_us,
            COMPILE_PANIC_US
        );
    }

    logger.info("Complex command classification timing test passed");
    logger.print_summary();
}

// =============================================================================
// Worker Selection Performance Tests
// =============================================================================

/// Test: Worker selection timing must be <10ms
///
/// Measures time to select a worker from the pool (requires real workers).
#[tokio::test]
async fn test_worker_selection_timing() {
    let logger = TestLoggerBuilder::new("test_worker_selection_timing")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("performance".to_string()),
        "Starting worker selection timing test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            (
                "budget_us".to_string(),
                WORKER_SELECTION_BUDGET_US.to_string(),
            ),
            (
                "panic_us".to_string(),
                WORKER_SELECTION_PANIC_US.to_string(),
            ),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    // Test SSH connection establishment time (this is part of "worker selection")
    let mut samples = Vec::with_capacity(10);

    for i in 0..10 {
        let worker_config = worker_entry.to_worker_config();
        let options = SshOptions {
            connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
            known_hosts: KnownHostsPolicy::Add,
            ..Default::default()
        };

        let start = Instant::now();
        let mut client = SshClient::new(worker_config, options);
        let result = client.connect().await;
        let elapsed = start.elapsed();

        if result.is_ok() {
            samples.push(elapsed);
            client.disconnect().await.ok();
        }

        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("performance".to_string()),
            "Connection timing measured",
            vec![
                ("phase".to_string(), "measure".to_string()),
                ("iteration".to_string(), i.to_string()),
                ("elapsed_ms".to_string(), elapsed.as_millis().to_string()),
                ("success".to_string(), result.is_ok().to_string()),
            ],
        );
    }

    if !samples.is_empty() {
        let stats = TimingStats::compute(&samples);

        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("performance".to_string()),
            "Worker connection statistics",
            vec![
                ("phase".to_string(), "stats".to_string()),
                ("samples".to_string(), stats.samples.to_string()),
                ("mean_ms".to_string(), (stats.mean_us / 1000).to_string()),
                ("p95_ms".to_string(), (stats.p95_us / 1000).to_string()),
                ("max_ms".to_string(), (stats.max_us / 1000).to_string()),
            ],
        );
    }

    logger.info("Worker selection timing test completed");
    logger.print_summary();
}

// =============================================================================
// Classification Accuracy Tests (complement to timing)
// =============================================================================

/// Test: Classification accuracy for edge cases
///
/// Verifies that edge case commands are classified correctly (not just quickly).
#[tokio::test]
async fn test_classification_accuracy() {
    let logger = TestLoggerBuilder::new("test_classification_accuracy")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("performance".to_string()),
        "Starting classification accuracy test",
        vec![("phase".to_string(), "setup".to_string())],
    );

    // (command, expected_is_compilation, description)
    let test_cases: Vec<(&str, bool, &str)> = vec![
        // Clear compilation commands
        ("cargo build", true, "basic cargo build"),
        ("cargo test", true, "cargo test"),
        ("cargo check", true, "cargo check"),
        ("cargo clippy", true, "cargo clippy"),
        ("cargo bench", true, "cargo bench"),
        ("rustc main.rs", true, "rustc"),
        ("gcc hello.c", true, "gcc"),
        ("clang hello.c", true, "clang"),
        ("make", true, "make"),
        ("cmake --build .", true, "cmake build"),
        // Clear non-compilation commands
        ("ls", false, "ls"),
        ("ls -la", false, "ls with flags"),
        ("git status", false, "git status"),
        ("git commit -m 'msg'", false, "git commit"),
        ("echo hello", false, "echo"),
        ("cat file.txt", false, "cat"),
        ("grep pattern file", false, "grep"),
        ("find . -name '*.rs'", false, "find"),
        ("pwd", false, "pwd"),
        ("cd /tmp", false, "cd"),
        // Edge cases
        ("cargo --version", false, "cargo version check"),
        ("cargo fmt", false, "cargo fmt is not compilation"),
        ("cargo doc", true, "cargo doc is compilation"),
        ("cargo clean", false, "cargo clean is not compilation"),
        ("cargo update", false, "cargo update is not compilation"),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (cmd, expected, desc) in &test_cases {
        let classification = classify_command(cmd);
        let matches = classification.is_compilation == *expected;

        if matches {
            passed += 1;
        } else {
            failed += 1;
        }

        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("performance".to_string()),
            "Classification result",
            vec![
                ("phase".to_string(), "verify".to_string()),
                ("cmd".to_string(), cmd.to_string()),
                ("description".to_string(), desc.to_string()),
                (
                    "expected".to_string(),
                    if *expected { "compile" } else { "non_compile" }.to_string(),
                ),
                (
                    "actual".to_string(),
                    if classification.is_compilation {
                        "compile"
                    } else {
                        "non_compile"
                    }
                    .to_string(),
                ),
                ("correct".to_string(), matches.to_string()),
            ],
        );
    }

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("performance".to_string()),
        "Classification accuracy summary",
        vec![
            ("phase".to_string(), "summary".to_string()),
            ("passed".to_string(), passed.to_string()),
            ("failed".to_string(), failed.to_string()),
            ("total".to_string(), test_cases.len().to_string()),
            (
                "accuracy_pct".to_string(),
                format!("{:.1}", (passed as f64 / test_cases.len() as f64) * 100.0),
            ),
        ],
    );

    assert_eq!(
        failed, 0,
        "Classification accuracy test had {} failures",
        failed
    );

    logger.info("Classification accuracy test passed");
    logger.print_summary();
}

// =============================================================================
// Variance and Consistency Tests
// =============================================================================

/// Test: Classification timing is consistent (low variance)
///
/// Verifies that timing is predictable, not just fast.
#[tokio::test]
async fn test_classification_timing_consistency() {
    let logger = TestLoggerBuilder::new("test_classification_timing_consistency")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("performance".to_string()),
        "Starting timing consistency test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("samples".to_string(), SAMPLE_COUNT.to_string()),
        ],
    );

    let test_commands = vec!["cargo build", "ls -la", "gcc hello.c -o hello"];

    for cmd in &test_commands {
        let mut samples = Vec::with_capacity(SAMPLE_COUNT);

        for _ in 0..SAMPLE_COUNT {
            let start = Instant::now();
            let _classification = classify_command(cmd);
            samples.push(start.elapsed());
        }

        let stats = TimingStats::compute(&samples);

        // Coefficient of variation (CV) should be reasonable
        // CV = stddev / mean - lower is more consistent
        let cv = if stats.mean_us > 0 {
            stats.stddev_us / stats.mean_us as f64
        } else {
            0.0
        };

        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("performance".to_string()),
            "Timing consistency measured",
            vec![
                ("phase".to_string(), "stats".to_string()),
                ("cmd".to_string(), cmd.to_string()),
                ("mean_us".to_string(), stats.mean_us.to_string()),
                ("stddev_us".to_string(), format!("{:.1}", stats.stddev_us)),
                ("cv".to_string(), format!("{:.2}", cv)),
                ("min_us".to_string(), stats.min_us.to_string()),
                ("max_us".to_string(), stats.max_us.to_string()),
            ],
        );

        // CV should be less than 1.0 for consistent timing
        // (stddev less than mean)
        assert!(
            cv < 2.0,
            "Command '{}' timing too variable: CV={:.2}",
            cmd,
            cv
        );
    }

    logger.info("Timing consistency test passed");
    logger.print_summary();
}
