//! Output Comparison Utilities for True E2E Tests
//!
//! This module provides intelligent comparison of local vs remote execution output,
//! handling acceptable differences like paths, timestamps, and ordering.
//!
//! # Comparison Modes
//!
//! - **Exact**: Byte-for-byte identical (for binary artifacts)
//! - **Normalized**: Ignore paths, timestamps, ordering (for compilation output)
//! - **Semantic**: Exit code + key patterns only (for error checking)
//!
//! # Example
//!
//! ```rust,ignore
//! use tests::true_e2e::output::{CapturedOutput, OutputComparison, OutputNormalizer};
//!
//! let local = CapturedOutput::new(b"Compiling at /home/user/project", b"", 0, 100);
//! let remote = CapturedOutput::new(b"Compiling at /tmp/rch/work_abc", b"", 0, 95);
//!
//! let comparison = OutputComparison::new(local, remote)
//!     .with_normalizer(OutputNormalizer::default().with_path_normalization(true));
//!
//! match comparison.compare() {
//!     ComparisonResult::EquivalentAfterNormalization => println!("Outputs match!"),
//!     _ => panic!("Outputs differ unexpectedly"),
//! }
//! ```

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::Duration;

/// Captured output from a command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedOutput {
    /// Standard output bytes
    pub stdout: Vec<u8>,
    /// Standard error bytes
    pub stderr: Vec<u8>,
    /// Process exit code
    pub exit_code: i32,
    /// Execution duration
    #[serde(with = "duration_millis")]
    pub duration: Duration,
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

impl CapturedOutput {
    /// Create a new CapturedOutput
    pub fn new(stdout: &[u8], stderr: &[u8], exit_code: i32, duration_ms: u64) -> Self {
        Self {
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
            exit_code,
            duration: Duration::from_millis(duration_ms),
        }
    }

    /// Get stdout as a string (lossy UTF-8 conversion)
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Get stderr as a string (lossy UTF-8 conversion)
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Check if stdout is valid UTF-8
    pub fn is_stdout_utf8(&self) -> bool {
        std::str::from_utf8(&self.stdout).is_ok()
    }

    /// Check if stderr is valid UTF-8
    pub fn is_stderr_utf8(&self) -> bool {
        std::str::from_utf8(&self.stderr).is_ok()
    }
}

/// Configuration for output normalization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputNormalizer {
    /// Replace absolute paths with placeholders (<PROJECT_ROOT>, <HOME>, <RCH_WORK>)
    pub normalize_paths: bool,
    /// Strip timestamps like "2024-01-19 12:00:00" or "in 1.23s"
    pub strip_timestamps: bool,
    /// Sort lines for parallel output comparison
    pub sort_lines: bool,
    /// Strip ANSI escape codes
    pub strip_ansi: bool,
    /// Ignore whitespace differences (leading, trailing, multiple spaces)
    pub ignore_whitespace: bool,
    /// Only compare exit codes (semantic mode)
    pub semantic_only: bool,
    /// Custom path patterns to normalize (regex -> replacement)
    pub custom_path_patterns: Vec<(String, String)>,
}

impl Default for OutputNormalizer {
    fn default() -> Self {
        Self {
            normalize_paths: true,
            strip_timestamps: true,
            sort_lines: false,
            strip_ansi: true,
            ignore_whitespace: false,
            semantic_only: false,
            custom_path_patterns: Vec::new(),
        }
    }
}

impl OutputNormalizer {
    /// Create an exact comparison normalizer (no normalization)
    pub fn exact() -> Self {
        Self {
            normalize_paths: false,
            strip_timestamps: false,
            sort_lines: false,
            strip_ansi: false,
            ignore_whitespace: false,
            semantic_only: false,
            custom_path_patterns: Vec::new(),
        }
    }

    /// Create a semantic comparison normalizer (only checks exit code)
    pub fn semantic() -> Self {
        Self {
            normalize_paths: false,
            strip_timestamps: false,
            sort_lines: false,
            strip_ansi: false,
            ignore_whitespace: false,
            semantic_only: true,
            custom_path_patterns: Vec::new(),
        }
    }

    /// Enable/disable path normalization
    pub fn with_path_normalization(mut self, enabled: bool) -> Self {
        self.normalize_paths = enabled;
        self
    }

    /// Enable/disable timestamp stripping
    pub fn with_timestamp_stripping(mut self, enabled: bool) -> Self {
        self.strip_timestamps = enabled;
        self
    }

    /// Enable/disable line sorting
    pub fn with_line_sorting(mut self, enabled: bool) -> Self {
        self.sort_lines = enabled;
        self
    }

    /// Enable/disable ANSI code stripping
    pub fn with_ansi_stripping(mut self, enabled: bool) -> Self {
        self.strip_ansi = enabled;
        self
    }

    /// Enable/disable whitespace normalization
    pub fn with_whitespace_normalization(mut self, enabled: bool) -> Self {
        self.ignore_whitespace = enabled;
        self
    }

    /// Add a custom path pattern to normalize
    pub fn with_custom_path_pattern(mut self, pattern: &str, replacement: &str) -> Self {
        self.custom_path_patterns
            .push((pattern.to_string(), replacement.to_string()));
        self
    }

    /// Normalize a string according to the configured rules
    pub fn normalize(&self, input: &str) -> NormalizationResult {
        let mut result = input.to_string();
        let mut transformations = Vec::new();

        // Strip ANSI codes first (affects everything else)
        if self.strip_ansi {
            let (new_result, count) = strip_ansi_codes(&result);
            if count > 0 {
                transformations.push(NormalizationTransform::AnsiStripped { count });
            }
            result = new_result;
        }

        // Normalize paths
        if self.normalize_paths {
            let (new_result, count) = normalize_paths(&result);
            if count > 0 {
                transformations.push(NormalizationTransform::PathsNormalized { count });
            }
            result = new_result;

            // Apply custom patterns
            for (pattern, replacement) in &self.custom_path_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    let matches = re.find_iter(&result).count();
                    if matches > 0 {
                        result = re.replace_all(&result, replacement.as_str()).into_owned();
                        transformations.push(NormalizationTransform::CustomPattern {
                            pattern: pattern.clone(),
                            count: matches,
                        });
                    }
                }
            }
        }

        // Strip timestamps
        if self.strip_timestamps {
            let (new_result, count) = strip_timestamps(&result);
            if count > 0 {
                transformations.push(NormalizationTransform::TimestampsStripped { count });
            }
            result = new_result;
        }

        // Normalize whitespace
        if self.ignore_whitespace {
            result = normalize_whitespace(&result);
            transformations.push(NormalizationTransform::WhitespaceNormalized);
        }

        // Sort lines
        if self.sort_lines {
            let mut lines: Vec<&str> = result.lines().collect();
            lines.sort();
            result = lines.join("\n");
            transformations.push(NormalizationTransform::LinesSorted);
        }

        NormalizationResult {
            original: input.to_string(),
            normalized: result,
            transformations,
        }
    }
}

/// Record of transformations applied during normalization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NormalizationTransform {
    AnsiStripped { count: usize },
    PathsNormalized { count: usize },
    TimestampsStripped { count: usize },
    WhitespaceNormalized,
    LinesSorted,
    CustomPattern { pattern: String, count: usize },
}

/// Result of normalization with transformation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizationResult {
    pub original: String,
    pub normalized: String,
    pub transformations: Vec<NormalizationTransform>,
}

/// Result of comparing two outputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonResult {
    /// Outputs are byte-for-byte identical
    Identical,
    /// Outputs are equivalent after normalization
    EquivalentAfterNormalization,
    /// Outputs differ
    Different { diff: String },
}

impl ComparisonResult {
    /// Check if the outputs match (either identical or equivalent)
    pub fn matches(&self) -> bool {
        matches!(
            self,
            ComparisonResult::Identical | ComparisonResult::EquivalentAfterNormalization
        )
    }

    /// Check if the outputs are different
    pub fn is_different(&self) -> bool {
        matches!(self, ComparisonResult::Different { .. })
    }
}

/// Detailed comparison of local vs remote output
#[derive(Debug)]
pub struct OutputComparison {
    pub local: CapturedOutput,
    pub remote: CapturedOutput,
    pub normalizer: OutputNormalizer,
}

impl OutputComparison {
    /// Create a new comparison with default normalizer
    pub fn new(local: CapturedOutput, remote: CapturedOutput) -> Self {
        Self {
            local,
            remote,
            normalizer: OutputNormalizer::default(),
        }
    }

    /// Set the normalizer configuration
    pub fn with_normalizer(mut self, normalizer: OutputNormalizer) -> Self {
        self.normalizer = normalizer;
        self
    }

    /// Compare the outputs
    pub fn compare(&self) -> ComparisonResult {
        // Log comparison start
        log_comparison_start(self);

        // For semantic mode, only check exit code
        if self.normalizer.semantic_only {
            let result = if self.local.exit_code == self.remote.exit_code {
                ComparisonResult::EquivalentAfterNormalization
            } else {
                ComparisonResult::Different {
                    diff: format!(
                        "Exit code mismatch: local={}, remote={}",
                        self.local.exit_code, self.remote.exit_code
                    ),
                }
            };
            log_comparison_result(self, &result);
            return result;
        }

        // Check exit codes first
        if self.local.exit_code != self.remote.exit_code {
            let result = ComparisonResult::Different {
                diff: format!(
                    "Exit code mismatch: local={}, remote={}",
                    self.local.exit_code, self.remote.exit_code
                ),
            };
            log_comparison_result(self, &result);
            return result;
        }

        // Check for exact match first
        if self.local.stdout == self.remote.stdout && self.local.stderr == self.remote.stderr {
            log_comparison_result(self, &ComparisonResult::Identical);
            return ComparisonResult::Identical;
        }

        // Try normalized comparison
        let local_stdout = self.normalizer.normalize(&self.local.stdout_str());
        let remote_stdout = self.normalizer.normalize(&self.remote.stdout_str());
        let local_stderr = self.normalizer.normalize(&self.local.stderr_str());
        let remote_stderr = self.normalizer.normalize(&self.remote.stderr_str());

        log_normalization(&local_stdout, &remote_stdout, "stdout");
        log_normalization(&local_stderr, &remote_stderr, "stderr");

        if local_stdout.normalized == remote_stdout.normalized
            && local_stderr.normalized == remote_stderr.normalized
        {
            let result = ComparisonResult::EquivalentAfterNormalization;
            log_comparison_result(self, &result);
            return result;
        }

        // Generate diff for different outputs
        let diff = generate_diff(
            &local_stdout.normalized,
            &remote_stdout.normalized,
            &local_stderr.normalized,
            &remote_stderr.normalized,
        );

        let result = ComparisonResult::Different { diff };
        log_comparison_result(self, &result);
        result
    }

    /// Generate a human-readable diff report
    pub fn diff(&self) -> String {
        let local_stdout = self.local.stdout_str();
        let remote_stdout = self.remote.stdout_str();
        let local_stderr = self.local.stderr_str();
        let remote_stderr = self.remote.stderr_str();

        generate_diff(&local_stdout, &remote_stdout, &local_stderr, &remote_stderr)
    }

    /// Generate a diff after normalization
    pub fn normalized_diff(&self) -> String {
        let local_stdout = self.normalizer.normalize(&self.local.stdout_str());
        let remote_stdout = self.normalizer.normalize(&self.remote.stdout_str());
        let local_stderr = self.normalizer.normalize(&self.local.stderr_str());
        let remote_stderr = self.normalizer.normalize(&self.remote.stderr_str());

        generate_diff(
            &local_stdout.normalized,
            &remote_stdout.normalized,
            &local_stderr.normalized,
            &remote_stderr.normalized,
        )
    }
}

/// Compare binary artifacts by hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryComparison {
    pub file_name: String,
    pub local_size: u64,
    pub remote_size: u64,
    pub local_hash: String,
    pub remote_hash: String,
    pub matches: bool,
}

impl BinaryComparison {
    /// Create a new binary comparison
    pub fn new(file_name: &str, local: &[u8], remote: &[u8]) -> Self {
        let local_hash = format!("sha256:{}", blake3::hash(local).to_hex());
        let remote_hash = format!("sha256:{}", blake3::hash(remote).to_hex());

        Self {
            file_name: file_name.to_string(),
            local_size: local.len() as u64,
            remote_size: remote.len() as u64,
            local_hash: local_hash.clone(),
            remote_hash: remote_hash.clone(),
            matches: local_hash == remote_hash,
        }
    }

    /// Log the binary comparison result
    pub fn log(&self) {
        let json = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "level": if self.matches { "INFO" } else { "WARN" },
            "component": "output_comparison",
            "phase": "binary_compare",
            "msg": "Binary artifact comparison",
            "data": {
                "file": self.file_name,
                "local_size": self.local_size,
                "remote_size": self.remote_size,
                "local_hash": self.local_hash,
                "remote_hash": self.remote_hash,
                "match": self.matches
            }
        });
        eprintln!("{}", json);
    }
}

// ============================================================================
// Helper functions
// ============================================================================

// Regex patterns for path normalization
static HOME_PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/home/[^/\s]+").expect("valid regex"));
static USERS_PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/Users/[^/\s]+").expect("valid regex"));
static TMP_RCH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/tmp/rch/[a-zA-Z0-9_-]+").expect("valid regex"));
static CARGO_TARGET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"target/(debug|release)/[^\s]+").expect("valid regex"));

// Regex patterns for timestamp stripping
static ISO8601_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?")
        .expect("valid regex")
});
static BUILD_TIME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"in \d+(\.\d+)?(ms|s|m)").expect("valid regex"));
static TOOK_TIME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"took \d+(\.\d+)?(ms|s|m)").expect("valid regex"));
static DURATION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d+(\.\d+)?(ms|s|m)\b").expect("valid regex"));
static UNIX_TIMESTAMP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b1[0-9]{9}\b").expect("valid regex"));
static DATETIME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}").expect("valid regex"));

// ANSI escape code regex
static ANSI_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").expect("valid regex"));

/// Strip ANSI escape codes from a string
fn strip_ansi_codes(input: &str) -> (String, usize) {
    let count = ANSI_RE.find_iter(input).count();
    let result = ANSI_RE.replace_all(input, "").into_owned();
    (result, count)
}

/// Normalize paths in a string
fn normalize_paths(input: &str) -> (String, usize) {
    let mut result = input.to_string();
    let mut count = 0;

    // Track original lengths to count replacements
    count += HOME_PATH_RE.find_iter(&result).count();
    result = HOME_PATH_RE.replace_all(&result, "<HOME>").into_owned();

    count += USERS_PATH_RE.find_iter(&result).count();
    result = USERS_PATH_RE.replace_all(&result, "<HOME>").into_owned();

    count += TMP_RCH_RE.find_iter(&result).count();
    result = TMP_RCH_RE.replace_all(&result, "<RCH_WORK>").into_owned();

    (result, count)
}

/// Strip timestamps from a string
fn strip_timestamps(input: &str) -> (String, usize) {
    let mut result = input.to_string();
    let mut count = 0;

    // ISO 8601 timestamps
    count += ISO8601_RE.find_iter(&result).count();
    result = ISO8601_RE.replace_all(&result, "<TIMESTAMP>").into_owned();

    // Date time format
    count += DATETIME_RE.find_iter(&result).count();
    result = DATETIME_RE.replace_all(&result, "<DATETIME>").into_owned();

    // Build time patterns ("in 1.23s", "took 45ms")
    count += BUILD_TIME_RE.find_iter(&result).count();
    result = BUILD_TIME_RE.replace_all(&result, "in <TIME>").into_owned();

    count += TOOK_TIME_RE.find_iter(&result).count();
    result = TOOK_TIME_RE
        .replace_all(&result, "took <TIME>")
        .into_owned();

    // Unix timestamps (rough detection - 10 digit numbers starting with 1)
    count += UNIX_TIMESTAMP_RE.find_iter(&result).count();
    result = UNIX_TIMESTAMP_RE
        .replace_all(&result, "<UNIX_TS>")
        .into_owned();

    (result, count)
}

/// Normalize whitespace in a string
fn normalize_whitespace(input: &str) -> String {
    let lines: Vec<&str> = input
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect();

    let result: Vec<String> = lines
        .iter()
        .map(|line| {
            // Collapse multiple spaces into single space
            let mut prev_space = false;
            line.chars()
                .filter(|c| {
                    if c.is_whitespace() {
                        if prev_space {
                            false
                        } else {
                            prev_space = true;
                            true
                        }
                    } else {
                        prev_space = false;
                        true
                    }
                })
                .collect()
        })
        .collect();

    result.join("\n")
}

/// Generate a unified diff between outputs
fn generate_diff(
    local_stdout: &str,
    remote_stdout: &str,
    local_stderr: &str,
    remote_stderr: &str,
) -> String {
    let mut diff = String::new();

    if local_stdout != remote_stdout {
        diff.push_str("=== STDOUT Differences ===\n");
        diff.push_str(&line_diff(local_stdout, remote_stdout));
        diff.push('\n');
    }

    if local_stderr != remote_stderr {
        diff.push_str("=== STDERR Differences ===\n");
        diff.push_str(&line_diff(local_stderr, remote_stderr));
        diff.push('\n');
    }

    if diff.is_empty() {
        diff.push_str("(no differences)");
    }

    diff
}

/// Generate a simple line-by-line diff
fn line_diff(local: &str, remote: &str) -> String {
    let local_lines: Vec<&str> = local.lines().collect();
    let remote_lines: Vec<&str> = remote.lines().collect();

    let local_set: HashSet<&str> = local_lines.iter().copied().collect();
    let remote_set: HashSet<&str> = remote_lines.iter().copied().collect();

    let mut diff = String::new();

    // Lines only in local
    for line in &local_lines {
        if !remote_set.contains(line) {
            diff.push_str(&format!("- {line}\n"));
        }
    }

    // Lines only in remote
    for line in &remote_lines {
        if !local_set.contains(line) {
            diff.push_str(&format!("+ {line}\n"));
        }
    }

    if diff.is_empty() {
        // Same lines but different order
        diff.push_str("(lines present in both, but in different order)\n");
        diff.push_str("Local:\n");
        for (i, line) in local_lines.iter().enumerate().take(5) {
            diff.push_str(&format!("  {}: {line}\n", i + 1));
        }
        diff.push_str("Remote:\n");
        for (i, line) in remote_lines.iter().enumerate().take(5) {
            diff.push_str(&format!("  {}: {line}\n", i + 1));
        }
    }

    diff
}

// ============================================================================
// Structured JSON Logging Functions
// ============================================================================

fn log_comparison_start(comparison: &OutputComparison) {
    let json = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "level": "INFO",
        "component": "output_comparison",
        "phase": "start",
        "msg": "Starting output comparison",
        "data": {
            "mode": if comparison.normalizer.semantic_only {
                "semantic"
            } else if comparison.normalizer.normalize_paths || comparison.normalizer.strip_timestamps {
                "normalized"
            } else {
                "exact"
            },
            "local_stdout_len": comparison.local.stdout.len(),
            "local_stderr_len": comparison.local.stderr.len(),
            "remote_stdout_len": comparison.remote.stdout.len(),
            "remote_stderr_len": comparison.remote.stderr.len(),
            "local_exit": comparison.local.exit_code,
            "remote_exit": comparison.remote.exit_code
        }
    });
    eprintln!("{}", json);
}

fn log_normalization(local: &NormalizationResult, remote: &NormalizationResult, stream: &str) {
    let local_transforms: Vec<String> = local
        .transformations
        .iter()
        .map(|t| format!("{:?}", t))
        .collect();
    let remote_transforms: Vec<String> = remote
        .transformations
        .iter()
        .map(|t| format!("{:?}", t))
        .collect();

    let json = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "level": "DEBUG",
        "component": "output_comparison",
        "phase": "normalize",
        "msg": format!("Normalization applied to {}", stream),
        "data": {
            "stream": stream,
            "local_original_len": local.original.len(),
            "local_normalized_len": local.normalized.len(),
            "local_transforms": local_transforms,
            "remote_original_len": remote.original.len(),
            "remote_normalized_len": remote.normalized.len(),
            "remote_transforms": remote_transforms
        }
    });
    eprintln!("{}", json);
}

fn log_comparison_result(comparison: &OutputComparison, result: &ComparisonResult) {
    let (level, result_str) = match result {
        ComparisonResult::Identical => ("INFO", "identical"),
        ComparisonResult::EquivalentAfterNormalization => {
            ("INFO", "equivalent_after_normalization")
        }
        ComparisonResult::Different { .. } => ("WARN", "different"),
    };

    let diff_preview = if let ComparisonResult::Different { diff } = result {
        Some(diff.chars().take(200).collect::<String>())
    } else {
        None
    };

    let json = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "level": level,
        "component": "output_comparison",
        "phase": "complete",
        "msg": "Comparison complete",
        "data": {
            "result": result_str,
            "stdout_match": comparison.local.stdout == comparison.remote.stdout,
            "stderr_match": comparison.local.stderr == comparison.remote.stderr,
            "exit_code_match": comparison.local.exit_code == comparison.remote.exit_code,
            "diff_preview": diff_preview
        }
    });
    eprintln!("{}", json);
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match_identical_output() {
        let output = CapturedOutput::new(b"Hello, World!\n", b"", 0, 100);

        let comparison = OutputComparison::new(output.clone(), output)
            .with_normalizer(OutputNormalizer::exact());

        assert!(matches!(comparison.compare(), ComparisonResult::Identical));
    }

    #[test]
    fn test_path_normalization_makes_equal() {
        let local = CapturedOutput::new(b"Compiling at /home/ubuntu/myproject\n", b"", 0, 100);

        let remote = CapturedOutput::new(b"Compiling at /tmp/rch/work_abc123\n", b"", 0, 95);

        let comparison = OutputComparison::new(local, remote)
            .with_normalizer(OutputNormalizer::default().with_path_normalization(true));

        assert!(matches!(
            comparison.compare(),
            ComparisonResult::EquivalentAfterNormalization
        ));
    }

    #[test]
    fn test_timestamp_stripping() {
        let local = CapturedOutput::new(b"Built in 1.23s at 2024-01-19T12:00:00Z\n", b"", 0, 1230);

        let remote = CapturedOutput::new(b"Built in 0.98s at 2024-01-19T12:05:30Z\n", b"", 0, 980);

        let comparison = OutputComparison::new(local, remote)
            .with_normalizer(OutputNormalizer::default().with_timestamp_stripping(true));

        assert!(matches!(
            comparison.compare(),
            ComparisonResult::EquivalentAfterNormalization
        ));
    }

    #[test]
    fn test_diff_generation_shows_actual_difference() {
        let local = CapturedOutput::new(b"line1\nline2\nline3\n", b"", 0, 100);

        let remote = CapturedOutput::new(b"line1\nmodified_line2\nline3\n", b"", 0, 100);

        let comparison =
            OutputComparison::new(local, remote).with_normalizer(OutputNormalizer::exact());

        let result = comparison.compare();
        assert!(matches!(result, ComparisonResult::Different { .. }));

        let diff = comparison.diff();
        assert!(diff.contains("line2"));
        assert!(diff.contains("modified_line2"));
    }

    #[test]
    fn test_binary_comparison_detects_corruption() {
        let local = CapturedOutput::new(&[0x7f, 0x45, 0x4c, 0x46, 0x01, 0x02], b"", 0, 100);

        let remote = CapturedOutput::new(&[0x7f, 0x45, 0x4c, 0x46, 0x01, 0x03], b"", 0, 100);

        let comparison =
            OutputComparison::new(local, remote).with_normalizer(OutputNormalizer::exact());

        assert!(matches!(
            comparison.compare(),
            ComparisonResult::Different { .. }
        ));
    }

    #[test]
    fn test_ansi_stripping_preserves_content() {
        let local = CapturedOutput::new(b"\x1b[32mSuccess\x1b[0m: compiled\n", b"", 0, 100);

        let remote = CapturedOutput::new(b"Success: compiled\n", b"", 0, 100);

        let comparison = OutputComparison::new(local, remote)
            .with_normalizer(OutputNormalizer::default().with_ansi_stripping(true));

        assert!(matches!(
            comparison.compare(),
            ComparisonResult::EquivalentAfterNormalization
        ));
    }

    #[test]
    fn test_parallel_output_sorting() {
        let local = CapturedOutput::new(b"Compiling a\nCompiling b\nCompiling c\n", b"", 0, 100);

        let remote = CapturedOutput::new(b"Compiling b\nCompiling c\nCompiling a\n", b"", 0, 100);

        let comparison = OutputComparison::new(local, remote)
            .with_normalizer(OutputNormalizer::default().with_line_sorting(true));

        assert!(matches!(
            comparison.compare(),
            ComparisonResult::EquivalentAfterNormalization
        ));
    }

    #[test]
    fn test_exit_code_mismatch_fails_comparison() {
        let local = CapturedOutput::new(b"output\n", b"", 0, 100);

        let remote = CapturedOutput::new(b"output\n", b"", 1, 100);

        let comparison =
            OutputComparison::new(local, remote).with_normalizer(OutputNormalizer::default());

        let result = comparison.compare();
        assert!(matches!(result, ComparisonResult::Different { .. }));
    }

    #[test]
    fn test_stderr_comparison() {
        let local = CapturedOutput::new(b"", b"warning: unused variable\n", 0, 100);

        let remote = CapturedOutput::new(b"", b"warning: unused variable\n", 0, 100);

        let comparison =
            OutputComparison::new(local, remote).with_normalizer(OutputNormalizer::exact());

        assert!(matches!(comparison.compare(), ComparisonResult::Identical));
    }

    #[test]
    fn test_semantic_comparison_ignores_output_checks_exit() {
        let local = CapturedOutput::new(
            b"lots of different output here\n",
            b"various warnings\n",
            0,
            100,
        );

        let remote = CapturedOutput::new(b"completely different text\n", b"other stuff\n", 0, 100);

        let comparison =
            OutputComparison::new(local, remote).with_normalizer(OutputNormalizer::semantic());

        assert!(matches!(
            comparison.compare(),
            ComparisonResult::EquivalentAfterNormalization
        ));
    }

    #[test]
    fn test_macos_path_normalization() {
        let local = CapturedOutput::new(b"Path: /Users/john/project\n", b"", 0, 100);

        let remote = CapturedOutput::new(b"Path: /home/ubuntu/project\n", b"", 0, 100);

        let comparison = OutputComparison::new(local, remote)
            .with_normalizer(OutputNormalizer::default().with_path_normalization(true));

        assert!(matches!(
            comparison.compare(),
            ComparisonResult::EquivalentAfterNormalization
        ));
    }

    #[test]
    fn test_binary_artifact_comparison() {
        let local_data = b"ELF binary content here";
        let remote_data = b"ELF binary content here";

        let comparison = BinaryComparison::new("test_binary", local_data, remote_data);
        assert!(comparison.matches);
        assert_eq!(comparison.local_size, comparison.remote_size);
        assert_eq!(comparison.local_hash, comparison.remote_hash);
    }

    #[test]
    fn test_binary_artifact_mismatch() {
        let local_data = b"ELF binary content v1";
        let remote_data = b"ELF binary content v2";

        let comparison = BinaryComparison::new("test_binary", local_data, remote_data);
        assert!(!comparison.matches);
        assert_ne!(comparison.local_hash, comparison.remote_hash);
    }

    #[test]
    fn test_normalizer_builder_pattern() {
        let normalizer = OutputNormalizer::default()
            .with_path_normalization(true)
            .with_timestamp_stripping(true)
            .with_ansi_stripping(true)
            .with_line_sorting(false)
            .with_whitespace_normalization(false);

        assert!(normalizer.normalize_paths);
        assert!(normalizer.strip_timestamps);
        assert!(normalizer.strip_ansi);
        assert!(!normalizer.sort_lines);
        assert!(!normalizer.ignore_whitespace);
    }

    #[test]
    fn test_normalization_result_tracking() {
        let normalizer = OutputNormalizer::default()
            .with_path_normalization(true)
            .with_timestamp_stripping(true);

        let input = "Built /home/user/project in 1.23s";
        let result = normalizer.normalize(input);

        assert!(result.normalized.contains("<HOME>"));
        assert!(result.normalized.contains("<TIME>"));
        assert!(!result.transformations.is_empty());
    }

    #[test]
    fn test_custom_path_pattern() {
        let normalizer = OutputNormalizer::default()
            .with_path_normalization(false)
            .with_custom_path_pattern(r"/custom/path/\d+", "<CUSTOM>");

        let input = "File at /custom/path/12345";
        let result = normalizer.normalize(input);

        assert!(result.normalized.contains("<CUSTOM>"));
    }

    #[test]
    fn test_whitespace_normalization() {
        let input = "  line1  \n   line2   with    spaces  \n\n  line3  ";
        let result = normalize_whitespace(input);

        assert_eq!(result, "line1\nline2 with spaces\nline3");
    }

    #[test]
    fn test_captured_output_helpers() {
        let output = CapturedOutput::new(b"stdout content", b"stderr content", 0, 100);

        assert_eq!(output.stdout_str(), "stdout content");
        assert_eq!(output.stderr_str(), "stderr content");
        assert!(output.is_stdout_utf8());
        assert!(output.is_stderr_utf8());
    }

    #[test]
    fn test_comparison_result_helpers() {
        let identical = ComparisonResult::Identical;
        let equivalent = ComparisonResult::EquivalentAfterNormalization;
        let different = ComparisonResult::Different {
            diff: "some diff".to_string(),
        };

        assert!(identical.matches());
        assert!(equivalent.matches());
        assert!(!different.matches());

        assert!(!identical.is_different());
        assert!(!equivalent.is_different());
        assert!(different.is_different());
    }
}
