//! Test utilities for UI output verification.
//!
//! Provides helpers for capturing and asserting on CLI output in tests.

use super::context::{ColorChoice, OutputConfig, OutputContext, OutputFormat, OutputMode};
use super::writer::SharedOutputBuffer;
use regex::Regex;

/// Captured output from a test run.
#[derive(Debug, Clone)]
pub struct OutputCapture {
    stdout: SharedOutputBuffer,
    stderr: SharedOutputBuffer,
    context: std::sync::Arc<std::sync::Mutex<Option<OutputContext>>>,
}

impl Default for OutputCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputCapture {
    /// Create a new output capture with default configuration.
    pub fn new() -> Self {
        Self::with_config(OutputConfig::default())
    }

    /// Create an output capture with specific configuration.
    pub fn with_config(config: OutputConfig) -> Self {
        let stdout = SharedOutputBuffer::new();
        let stderr = SharedOutputBuffer::new();

        let stdout_writer = stdout.as_writer(true); // Simulate TTY for human output
        let stderr_writer = stderr.as_writer(true);

        let ctx = OutputContext::with_writers(config, stdout_writer, stderr_writer);

        Self {
            stdout,
            stderr,
            context: std::sync::Arc::new(std::sync::Mutex::new(Some(ctx))),
        }
    }

    /// Create a capture configured for JSON mode.
    pub fn json() -> Self {
        Self::with_config(OutputConfig {
            json: true,
            ..Default::default()
        })
    }

    /// Create a capture configured for plain mode.
    pub fn plain() -> Self {
        Self::with_config(OutputConfig {
            color: ColorChoice::Never,
            ..Default::default()
        })
    }

    /// Create a capture configured for quiet mode.
    pub fn quiet() -> Self {
        Self::with_config(OutputConfig {
            quiet: true,
            ..Default::default()
        })
    }

    /// Create a capture configured for verbose mode.
    pub fn verbose() -> Self {
        Self::with_config(OutputConfig {
            verbose: true,
            ..Default::default()
        })
    }

    /// Get the captured stdout content.
    pub fn stdout_string(&self) -> String {
        self.stdout.to_string_lossy()
    }

    /// Get the captured stderr content.
    pub fn stderr_string(&self) -> String {
        self.stderr.to_string_lossy()
    }

    /// Get stdout with ANSI escape codes stripped.
    pub fn stdout_without_ansi(&self) -> String {
        strip_ansi(&self.stdout.to_string_lossy())
    }

    /// Get stderr with ANSI escape codes stripped.
    pub fn stderr_without_ansi(&self) -> String {
        strip_ansi(&self.stderr.to_string_lossy())
    }

    /// Check if stdout is empty.
    pub fn stdout_is_empty(&self) -> bool {
        self.stdout.to_string_lossy().is_empty()
    }

    /// Check if stderr is empty.
    pub fn stderr_is_empty(&self) -> bool {
        self.stderr.to_string_lossy().is_empty()
    }

    /// Get a reference to the output context.
    pub fn context(&self) -> impl std::ops::Deref<Target = OutputContext> + '_ {
        struct ContextGuard<'a>(std::sync::MutexGuard<'a, Option<OutputContext>>);

        impl std::ops::Deref for ContextGuard<'_> {
            type Target = OutputContext;
            fn deref(&self) -> &Self::Target {
                self.0.as_ref().unwrap()
            }
        }

        ContextGuard(self.context.lock().unwrap())
    }

    /// Execute a closure with the output context.
    pub fn with_context<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&OutputContext) -> R,
    {
        let guard = self.context.lock().unwrap();
        f(guard.as_ref().unwrap())
    }
}

/// Strip ANSI escape codes from a string.
pub fn strip_ansi(s: &str) -> String {
    // Regex for ANSI escape sequences
    let ansi_re = Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").unwrap();
    ansi_re.replace_all(s, "").to_string()
}

/// Assert that a string contains no ANSI escape codes.
pub fn assert_no_ansi(s: &str) {
    let stripped = strip_ansi(s);
    assert_eq!(
        s, stripped,
        "String contains ANSI escape codes:\nOriginal: {:?}\nStripped: {:?}",
        s, stripped
    );
}

/// Assert that a string contains ANSI escape codes.
pub fn assert_has_ansi(s: &str) {
    let stripped = strip_ansi(s);
    assert_ne!(
        s, stripped,
        "String should contain ANSI escape codes but doesn't: {:?}",
        s
    );
}

/// Assert that a string is valid JSON and return the parsed value.
pub fn assert_valid_json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or_else(|e| {
        panic!("String is not valid JSON: {}\nString: {:?}", e, s);
    })
}

/// Assert that stdout contains a specific substring.
pub fn assert_stdout_contains(capture: &OutputCapture, expected: &str) {
    let stdout = capture.stdout_string();
    assert!(
        stdout.contains(expected),
        "stdout should contain {:?}, but was: {:?}",
        expected,
        stdout
    );
}

/// Assert that stderr contains a specific substring.
pub fn assert_stderr_contains(capture: &OutputCapture, expected: &str) {
    let stderr = capture.stderr_string();
    assert!(
        stderr.contains(expected),
        "stderr should contain {:?}, but was: {:?}",
        expected,
        stderr
    );
}

/// Assert that stdout does not contain a specific substring.
pub fn assert_stdout_not_contains(capture: &OutputCapture, unexpected: &str) {
    let stdout = capture.stdout_string();
    assert!(
        !stdout.contains(unexpected),
        "stdout should not contain {:?}, but was: {:?}",
        unexpected,
        stdout
    );
}

/// Assert that stderr does not contain a specific substring.
pub fn assert_stderr_not_contains(capture: &OutputCapture, unexpected: &str) {
    let stderr = capture.stderr_string();
    assert!(
        !stderr.contains(unexpected),
        "stderr should not contain {:?}, but was: {:?}",
        unexpected,
        stderr
    );
}

/// Builder for creating test output contexts with specific configurations.
#[derive(Debug, Default)]
pub struct OutputContextBuilder {
    config: OutputConfig,
    stdout_is_tty: bool,
    stderr_is_tty: bool,
}

impl OutputContextBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            config: OutputConfig::default(),
            stdout_is_tty: true,
            stderr_is_tty: true,
        }
    }

    /// Set the output mode.
    pub fn mode(mut self, mode: OutputMode) -> Self {
        self.config.force_mode = Some(mode);
        self
    }

    /// Set JSON mode.
    pub fn json(mut self) -> Self {
        self.config.json = true;
        self
    }

    /// Set machine output format.
    pub fn format(mut self, format: OutputFormat) -> Self {
        self.config.format = format;
        self
    }

    /// Set quiet mode.
    pub fn quiet(mut self) -> Self {
        self.config.quiet = true;
        self
    }

    /// Set verbose mode.
    pub fn verbose(mut self) -> Self {
        self.config.verbose = true;
        self
    }

    /// Set color choice.
    pub fn color(mut self, choice: ColorChoice) -> Self {
        self.config.color = choice;
        self
    }

    /// Set whether stdout is a TTY.
    pub fn stdout_tty(mut self, is_tty: bool) -> Self {
        self.stdout_is_tty = is_tty;
        self
    }

    /// Set whether stderr is a TTY.
    pub fn stderr_tty(mut self, is_tty: bool) -> Self {
        self.stderr_is_tty = is_tty;
        self
    }

    /// Build the output capture.
    pub fn build(self) -> OutputCapture {
        let stdout = SharedOutputBuffer::new();
        let stderr = SharedOutputBuffer::new();

        let stdout_writer = stdout.as_writer(self.stdout_is_tty);
        let stderr_writer = stderr.as_writer(self.stderr_is_tty);

        let ctx = OutputContext::with_writers(self.config, stdout_writer, stderr_writer);

        OutputCapture {
            stdout,
            stderr,
            context: std::sync::Arc::new(std::sync::Mutex::new(Some(ctx))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::info;

    fn log_test_start(name: &str) {
        info!("TEST START: {}", name);
    }

    #[test]
    fn test_strip_ansi() {
        log_test_start("test_strip_ansi");
        let with_codes = "\x1b[32mgreen\x1b[0m text";
        let stripped = strip_ansi(with_codes);
        assert_eq!(stripped, "green text");
    }

    #[test]
    fn test_assert_no_ansi_passes() {
        log_test_start("test_assert_no_ansi_passes");
        assert_no_ansi("plain text");
    }

    #[test]
    #[should_panic(expected = "contains ANSI")]
    fn test_assert_no_ansi_fails() {
        log_test_start("test_assert_no_ansi_fails");
        assert_no_ansi("\x1b[32mcolored\x1b[0m");
    }

    #[test]
    fn test_assert_has_ansi_passes() {
        log_test_start("test_assert_has_ansi_passes");
        assert_has_ansi("\x1b[32mcolored\x1b[0m");
    }

    #[test]
    #[should_panic(expected = "should contain ANSI")]
    fn test_assert_has_ansi_fails() {
        log_test_start("test_assert_has_ansi_fails");
        assert_has_ansi("plain text");
    }

    #[test]
    fn test_assert_valid_json() {
        log_test_start("test_assert_valid_json");
        let json = assert_valid_json(r#"{"key": "value"}"#);
        assert_eq!(json["key"], "value");
    }

    #[test]
    #[should_panic(expected = "not valid JSON")]
    fn test_assert_valid_json_fails() {
        log_test_start("test_assert_valid_json_fails");
        assert_valid_json("not json");
    }

    #[test]
    fn test_output_capture_json_mode() {
        log_test_start("test_output_capture_json_mode");
        let capture = OutputCapture::json();
        capture.with_context(|ctx| {
            assert!(ctx.is_json());
        });
    }

    #[test]
    fn test_output_capture_quiet_mode() {
        log_test_start("test_output_capture_quiet_mode");
        let capture = OutputCapture::quiet();
        capture.with_context(|ctx| {
            assert!(ctx.is_quiet());
        });
    }

    #[test]
    fn test_output_capture_verbose_mode() {
        log_test_start("test_output_capture_verbose_mode");
        let capture = OutputCapture::verbose();
        capture.with_context(|ctx| {
            assert!(ctx.is_verbose());
        });
    }

    #[test]
    fn test_builder_pattern() {
        log_test_start("test_builder_pattern");
        let capture = OutputContextBuilder::new()
            .verbose()
            .color(ColorChoice::Never)
            .build();

        capture.with_context(|ctx| {
            assert!(ctx.is_verbose());
        });
    }

    #[test]
    fn test_capture_stdout() {
        log_test_start("test_capture_stdout");
        let capture = OutputCapture::new();
        capture.with_context(|ctx| {
            ctx.print("test output");
        });

        assert!(capture.stdout_string().contains("test output"));
    }

    #[test]
    fn test_capture_stderr() {
        log_test_start("test_capture_stderr");
        let capture = OutputCapture::new();
        capture.with_context(|ctx| {
            ctx.error("error message");
        });

        assert!(capture.stderr_string().contains("error message"));
    }
}
