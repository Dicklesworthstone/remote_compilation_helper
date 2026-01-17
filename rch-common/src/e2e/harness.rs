//! E2E Test Harness Framework
//!
//! Provides infrastructure for running end-to-end tests including:
//! - Process lifecycle management (start/stop daemon, workers)
//! - Temporary directory and file management
//! - Command execution with output capture
//! - Assertions and matchers for test validation

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::logging::{LogLevel, LogSource, TestLogger, TestLoggerBuilder};

/// Error type for test harness operations
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("Process failed to start: {0}")]
    ProcessStartFailed(String),

    #[error("Process exited with non-zero status: {0}")]
    ProcessFailed(i32),

    #[error("Process timed out after {0:?}")]
    Timeout(Duration),

    #[error("Process not found: {0}")]
    ProcessNotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Assertion failed: {0}")]
    AssertionFailed(String),

    #[error("Setup failed: {0}")]
    SetupFailed(String),

    #[error("Cleanup failed: {0}")]
    CleanupFailed(String),
}

/// Result type for harness operations
pub type HarnessResult<T> = Result<T, HarnessError>;

/// Information about a managed process
#[derive(Debug)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub started_at: Instant,
    child: Child,
}

impl ProcessInfo {
    /// Check if the process is still running
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Get the process exit status (non-blocking)
    pub fn try_exit_status(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    /// Kill the process
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }

    /// Wait for the process to exit
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.wait()
    }

    /// Take stdout for reading (can only be called once)
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }

    /// Take stderr for reading (can only be called once)
    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.stderr.take()
    }
}

/// Result of a command execution
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
}

impl CommandResult {
    /// Check if the command succeeded (exit code 0)
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    /// Check if stdout contains a pattern
    pub fn stdout_contains(&self, pattern: &str) -> bool {
        self.stdout.contains(pattern)
    }

    /// Check if stderr contains a pattern
    pub fn stderr_contains(&self, pattern: &str) -> bool {
        self.stderr.contains(pattern)
    }

    /// Get combined output (stdout + stderr)
    pub fn combined_output(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

/// Configuration for the test harness
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    /// Base temporary directory for test artifacts
    pub temp_dir: PathBuf,
    /// Default timeout for commands
    pub default_timeout: Duration,
    /// Whether to clean up temp files on success
    pub cleanup_on_success: bool,
    /// Whether to clean up temp files on failure
    pub cleanup_on_failure: bool,
    /// Path to the rch binary
    pub rch_binary: PathBuf,
    /// Path to the rchd binary
    pub rchd_binary: PathBuf,
    /// Path to the rch-wkr binary
    pub rch_wkr_binary: PathBuf,
    /// Environment variables to set for all processes
    pub env_vars: HashMap<String, String>,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        // Find binaries in target/debug or target/release
        let cargo_target = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("target"));

        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };

        let bin_dir = cargo_target.join(profile);

        Self {
            temp_dir: std::env::temp_dir().join("rch_e2e_tests"),
            default_timeout: Duration::from_secs(30),
            cleanup_on_success: true,
            cleanup_on_failure: false,
            rch_binary: bin_dir.join("rch"),
            rchd_binary: bin_dir.join("rchd"),
            rch_wkr_binary: bin_dir.join("rch-wkr"),
            env_vars: HashMap::new(),
        }
    }
}

/// E2E Test Harness for managing test execution
pub struct TestHarness {
    pub config: HarnessConfig,
    pub logger: TestLogger,
    test_dir: PathBuf,
    managed_processes: Arc<Mutex<HashMap<String, ProcessInfo>>>,
    created_files: Arc<Mutex<Vec<PathBuf>>>,
    created_dirs: Arc<Mutex<Vec<PathBuf>>>,
    test_passed: Arc<Mutex<bool>>,
}

impl TestHarness {
    /// Create a new test harness with the given configuration
    pub fn new(test_name: &str, config: HarnessConfig) -> HarnessResult<Self> {
        // Create unique test directory
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f");
        let test_dir =
            config
                .temp_dir
                .join(format!("{}_{}", test_name.replace("::", "_"), timestamp));

        std::fs::create_dir_all(&test_dir)?;

        // Create logger with log dir in test directory
        let logger = TestLoggerBuilder::new(test_name)
            .log_dir(test_dir.join("logs"))
            .build();

        logger.info(format!("Test harness initialized: {test_name}"));
        logger.debug(format!("Test directory: {}", test_dir.display()));

        Ok(Self {
            config,
            logger,
            test_dir,
            managed_processes: Arc::new(Mutex::new(HashMap::new())),
            created_files: Arc::new(Mutex::new(Vec::new())),
            created_dirs: Arc::new(Mutex::new(vec![])),
            test_passed: Arc::new(Mutex::new(false)),
        })
    }

    /// Create a harness with default configuration
    pub fn default_for_test(test_name: &str) -> HarnessResult<Self> {
        Self::new(test_name, HarnessConfig::default())
    }

    /// Get the test directory path
    pub fn test_dir(&self) -> &Path {
        &self.test_dir
    }

    /// Create a subdirectory in the test directory
    pub fn create_dir(&self, name: &str) -> HarnessResult<PathBuf> {
        let path = self.test_dir.join(name);
        std::fs::create_dir_all(&path)?;
        self.created_dirs.lock().unwrap().push(path.clone());
        self.logger
            .debug(format!("Created directory: {}", path.display()));
        Ok(path)
    }

    /// Create a file in the test directory
    pub fn create_file(&self, name: &str, content: &str) -> HarnessResult<PathBuf> {
        let path = self.test_dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content)?;
        self.created_files.lock().unwrap().push(path.clone());
        self.logger
            .debug(format!("Created file: {}", path.display()));
        Ok(path)
    }

    /// Create a config file for the daemon
    pub fn create_daemon_config(&self, config_content: &str) -> HarnessResult<PathBuf> {
        let config_dir = self.create_dir("config")?;
        let config_path = config_dir.join("daemon.toml");
        std::fs::write(&config_path, config_content)?;
        self.logger
            .info(format!("Created daemon config: {}", config_path.display()));
        Ok(config_path)
    }

    /// Create a workers config file
    pub fn create_workers_config(&self, config_content: &str) -> HarnessResult<PathBuf> {
        let config_dir = self.test_dir.join("config");
        std::fs::create_dir_all(&config_dir)?;
        let config_path = config_dir.join("workers.toml");
        std::fs::write(&config_path, config_content)?;
        self.logger
            .info(format!("Created workers config: {}", config_path.display()));
        Ok(config_path)
    }

    /// Spawn a managed process
    pub fn spawn_process<I, S>(
        &self,
        name: &str,
        program: &Path,
        args: I,
        env: Option<&HashMap<String, String>>,
    ) -> HarnessResult<u32>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .current_dir(&self.test_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set default environment variables
        for (k, v) in &self.config.env_vars {
            cmd.env(k, v);
        }

        // Set additional environment variables
        if let Some(env_vars) = env {
            for (k, v) in env_vars {
                cmd.env(k, v);
            }
        }

        self.logger.info(format!(
            "Spawning process: {} {:?}",
            name,
            program.display()
        ));

        let child = cmd.spawn().map_err(|e| {
            HarnessError::ProcessStartFailed(format!("{}: {}", program.display(), e))
        })?;

        let pid = child.id();
        let info = ProcessInfo {
            name: name.to_string(),
            pid,
            started_at: Instant::now(),
            child,
        };

        self.managed_processes
            .lock()
            .unwrap()
            .insert(name.to_string(), info);

        self.logger.log_with_context(
            LogLevel::Info,
            LogSource::Harness,
            format!("Process spawned: {name}"),
            vec![("pid".to_string(), pid.to_string())],
        );

        Ok(pid)
    }

    /// Start the daemon process
    pub fn start_daemon(&self, extra_args: &[&str]) -> HarnessResult<u32> {
        let config_dir = self.test_dir.join("config");
        let config_str: String = config_dir.to_string_lossy().into_owned();
        let mut args: Vec<&str> = vec!["--config", &config_str];
        args.extend(extra_args);

        self.spawn_process("daemon", &self.config.rchd_binary, &args, None)
    }

    /// Stop a managed process by name
    pub fn stop_process(&self, name: &str) -> HarnessResult<()> {
        let mut processes = self.managed_processes.lock().unwrap();
        if let Some(mut info) = processes.remove(name) {
            self.logger
                .info(format!("Stopping process: {} (pid={})", name, info.pid));
            info.kill()?;
            let status = info.wait()?;
            self.logger
                .debug(format!("Process {} exited with status: {:?}", name, status));
            Ok(())
        } else {
            Err(HarnessError::ProcessNotFound(name.to_string()))
        }
    }

    /// Stop all managed processes
    pub fn stop_all_processes(&self) {
        let mut processes = self.managed_processes.lock().unwrap();
        for (name, mut info) in processes.drain() {
            self.logger
                .info(format!("Stopping process: {} (pid={})", name, info.pid));
            if let Err(e) = info.kill() {
                self.logger.warn(format!("Failed to kill {}: {}", name, e));
            }
            match info.wait() {
                Ok(status) => {
                    self.logger
                        .debug(format!("Process {} exited: {:?}", name, status));
                }
                Err(e) => {
                    self.logger
                        .warn(format!("Failed to wait for {}: {}", name, e));
                }
            }
        }
    }

    /// Execute a command and capture output
    pub fn exec<I, S>(&self, program: &str, args: I) -> HarnessResult<CommandResult>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.exec_with_timeout(program, args, self.config.default_timeout)
    }

    /// Execute a command with a specific timeout
    ///
    /// Note: Timeout enforcement is not yet implemented; the parameter is reserved
    /// for future use when async process spawning with timeouts is added.
    pub fn exec_with_timeout<I, S>(
        &self,
        program: &str,
        args: I,
        _timeout: Duration,
    ) -> HarnessResult<CommandResult>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        // TODO: Implement actual timeout enforcement with async process spawning
        let args: Vec<_> = args.into_iter().collect();
        let args_display: Vec<_> = args.iter().map(|s| s.as_ref().to_string_lossy()).collect();

        self.logger
            .debug(format!("Executing: {} {}", program, args_display.join(" ")));

        let start = Instant::now();

        let mut cmd = Command::new(program);
        cmd.args(&args)
            .current_dir(&self.test_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set default environment variables
        for (k, v) in &self.config.env_vars {
            cmd.env(k, v);
        }

        let output = cmd.output()?;
        let duration = start.elapsed();

        let result = CommandResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration,
        };

        self.logger.log_with_context(
            if result.success() {
                LogLevel::Debug
            } else {
                LogLevel::Warn
            },
            LogSource::Harness,
            format!("Command completed: {program}"),
            vec![
                ("exit_code".to_string(), result.exit_code.to_string()),
                ("duration_ms".to_string(), duration.as_millis().to_string()),
            ],
        );

        if !result.stdout.is_empty() {
            for line in result.stdout.lines() {
                self.logger.log(
                    LogLevel::Trace,
                    LogSource::Custom(program.to_string()),
                    line,
                );
            }
        }

        if !result.stderr.is_empty() {
            for line in result.stderr.lines() {
                self.logger.log(
                    LogLevel::Trace,
                    LogSource::Custom(format!("{program}:stderr")),
                    line,
                );
            }
        }

        Ok(result)
    }

    /// Execute the rch binary
    pub fn exec_rch<I, S>(&self, args: I) -> HarnessResult<CommandResult>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let binary = self.config.rch_binary.to_string_lossy().to_string();
        self.exec(&binary, args)
    }

    /// Execute the rchd binary
    pub fn exec_rchd<I, S>(&self, args: I) -> HarnessResult<CommandResult>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let binary = self.config.rchd_binary.to_string_lossy().to_string();
        self.exec(&binary, args)
    }

    /// Execute the rch-wkr binary
    pub fn exec_rch_wkr<I, S>(&self, args: I) -> HarnessResult<CommandResult>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let binary = self.config.rch_wkr_binary.to_string_lossy().to_string();
        self.exec(&binary, args)
    }

    /// Wait for a condition to become true
    pub fn wait_for<F>(
        &self,
        description: &str,
        timeout: Duration,
        interval: Duration,
        condition: F,
    ) -> HarnessResult<()>
    where
        F: Fn() -> bool,
    {
        self.logger
            .debug(format!("Waiting for: {description} (timeout: {timeout:?})"));

        let start = Instant::now();
        while start.elapsed() < timeout {
            if condition() {
                self.logger.debug(format!(
                    "Condition satisfied: {description} after {:?}",
                    start.elapsed()
                ));
                return Ok(());
            }
            std::thread::sleep(interval);
        }

        self.logger.error(format!(
            "Timeout waiting for: {description} after {timeout:?}"
        ));
        Err(HarnessError::Timeout(timeout))
    }

    /// Wait for a file to exist
    pub fn wait_for_file(&self, path: &Path, timeout: Duration) -> HarnessResult<()> {
        let path_display = path.display().to_string();
        self.wait_for(
            &format!("file to exist: {path_display}"),
            timeout,
            Duration::from_millis(100),
            || path.exists(),
        )
    }

    /// Wait for a socket to be available
    pub fn wait_for_socket(&self, socket_path: &Path, timeout: Duration) -> HarnessResult<()> {
        let socket_display = socket_path.display().to_string();
        self.wait_for(
            &format!("socket to be available: {socket_display}"),
            timeout,
            Duration::from_millis(100),
            || socket_path.exists(),
        )
    }

    /// Mark the test as passed
    pub fn mark_passed(&self) {
        *self.test_passed.lock().unwrap() = true;
        self.logger.info("Test marked as PASSED");
    }

    /// Mark the test as failed with a reason
    pub fn mark_failed(&self, reason: &str) {
        *self.test_passed.lock().unwrap() = false;
        self.logger
            .error(format!("Test marked as FAILED: {reason}"));
    }

    /// Check if the test passed
    pub fn passed(&self) -> bool {
        *self.test_passed.lock().unwrap()
    }

    /// Assert that a condition is true
    pub fn assert(&self, condition: bool, message: &str) -> HarnessResult<()> {
        if condition {
            self.logger.debug(format!("Assertion passed: {message}"));
            Ok(())
        } else {
            self.logger.error(format!("Assertion failed: {message}"));
            Err(HarnessError::AssertionFailed(message.to_string()))
        }
    }

    /// Assert that two values are equal
    pub fn assert_eq<T: PartialEq + std::fmt::Debug>(
        &self,
        actual: T,
        expected: T,
        message: &str,
    ) -> HarnessResult<()> {
        if actual == expected {
            self.logger.debug(format!("Assertion passed: {message}"));
            Ok(())
        } else {
            let msg = format!("{}: expected {:?}, got {:?}", message, expected, actual);
            self.logger.error(format!("Assertion failed: {msg}"));
            Err(HarnessError::AssertionFailed(msg))
        }
    }

    /// Assert that a command result succeeded
    pub fn assert_success(&self, result: &CommandResult, context: &str) -> HarnessResult<()> {
        if result.success() {
            self.logger.debug(format!("Command succeeded: {context}"));
            Ok(())
        } else {
            let msg = format!(
                "{}: command failed with exit code {} - stdout: {}, stderr: {}",
                context,
                result.exit_code,
                result.stdout.trim(),
                result.stderr.trim()
            );
            self.logger.error(&msg);
            Err(HarnessError::AssertionFailed(msg))
        }
    }

    /// Assert that a command result contains expected output
    pub fn assert_stdout_contains(
        &self,
        result: &CommandResult,
        pattern: &str,
        context: &str,
    ) -> HarnessResult<()> {
        if result.stdout_contains(pattern) {
            self.logger.debug(format!(
                "Stdout contains expected pattern: {context} -> {pattern}"
            ));
            Ok(())
        } else {
            let msg = format!(
                "{}: stdout does not contain '{}'. Actual stdout: {}",
                context,
                pattern,
                result.stdout.trim()
            );
            self.logger.error(&msg);
            Err(HarnessError::AssertionFailed(msg))
        }
    }

    /// Perform cleanup
    pub fn cleanup(&self) {
        self.logger.info("Starting cleanup");

        // Stop all managed processes
        self.stop_all_processes();

        // Determine if we should clean up files
        let should_cleanup = if *self.test_passed.lock().unwrap() {
            self.config.cleanup_on_success
        } else {
            self.config.cleanup_on_failure
        };

        if should_cleanup {
            self.logger.debug(format!(
                "Removing test directory: {}",
                self.test_dir.display()
            ));
            if let Err(e) = std::fs::remove_dir_all(&self.test_dir) {
                self.logger
                    .warn(format!("Failed to remove test directory: {}", e));
            }
        } else {
            self.logger.info(format!(
                "Preserving test directory for inspection: {}",
                self.test_dir.display()
            ));
        }

        self.logger.print_summary();
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Builder for creating a TestHarness with custom configuration
pub struct TestHarnessBuilder {
    test_name: String,
    config: HarnessConfig,
}

impl TestHarnessBuilder {
    /// Create a new builder for the given test name
    pub fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            config: HarnessConfig::default(),
        }
    }

    /// Set the temp directory
    pub fn temp_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config.temp_dir = dir.into();
        self
    }

    /// Set the default command timeout
    pub fn default_timeout(mut self, timeout: Duration) -> Self {
        self.config.default_timeout = timeout;
        self
    }

    /// Set whether to cleanup on success
    pub fn cleanup_on_success(mut self, cleanup: bool) -> Self {
        self.config.cleanup_on_success = cleanup;
        self
    }

    /// Set whether to cleanup on failure
    pub fn cleanup_on_failure(mut self, cleanup: bool) -> Self {
        self.config.cleanup_on_failure = cleanup;
        self
    }

    /// Set the rch binary path
    pub fn rch_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.rch_binary = path.into();
        self
    }

    /// Set the rchd binary path
    pub fn rchd_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.rchd_binary = path.into();
        self
    }

    /// Set the rch-wkr binary path
    pub fn rch_wkr_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.rch_wkr_binary = path.into();
        self
    }

    /// Add an environment variable
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.config
            .env_vars
            .insert(key.to_string(), value.to_string());
        self
    }

    /// Build the TestHarness
    pub fn build(self) -> HarnessResult<TestHarness> {
        TestHarness::new(&self.test_name, self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harness_creation() {
        let harness = TestHarnessBuilder::new("test_creation")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        assert!(harness.test_dir().exists());
        // Will cleanup on drop
    }

    #[test]
    fn test_harness_file_creation() {
        let harness = TestHarnessBuilder::new("test_files")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        let file_path = harness.create_file("test.txt", "hello world").unwrap();
        assert!(file_path.exists());

        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_harness_exec() {
        let harness = TestHarnessBuilder::new("test_exec")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        let result = harness.exec("echo", ["hello"]).unwrap();
        assert!(result.success());
        assert!(result.stdout_contains("hello"));
    }

    #[test]
    fn test_command_result() {
        let result = CommandResult {
            exit_code: 0,
            stdout: "hello world\n".to_string(),
            stderr: "".to_string(),
            duration: Duration::from_millis(10),
        };

        assert!(result.success());
        assert!(result.stdout_contains("hello"));
        assert!(!result.stderr_contains("error"));
    }

    #[test]
    fn test_harness_assertions() {
        let harness = TestHarnessBuilder::new("test_assertions")
            .cleanup_on_success(true)
            .build()
            .unwrap();

        harness.assert(true, "should pass").unwrap();
        harness.assert_eq(1, 1, "numbers equal").unwrap();

        let result = CommandResult {
            exit_code: 0,
            stdout: "success".to_string(),
            stderr: "".to_string(),
            duration: Duration::from_millis(1),
        };
        harness.assert_success(&result, "echo command").unwrap();

        harness.mark_passed();
        assert!(harness.passed());
    }
}
