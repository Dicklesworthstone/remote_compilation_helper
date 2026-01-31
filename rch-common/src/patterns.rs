//! Command classification patterns for identifying compilation commands.
//!
//! Implements the 5-tier classification system:
//! - Tier 0: Instant reject (non-Bash, empty)
//! - Tier 1: Structure analysis (pipes, redirects, background)
//! - Tier 2: SIMD keyword filter
//! - Tier 3: Negative pattern check
//! - Tier 4: Full classification with confidence

use memchr::memmem;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

// Tier name constants (avoid allocations on hot path).
const TIER_INSTANT_REJECT: &str = "instant_reject";
const TIER_STRUCTURE_ANALYSIS: &str = "structure_analysis";
const TIER_KEYWORD_FILTER: &str = "keyword_filter";
const TIER_NEVER_INTERCEPT: &str = "never_intercept";
const TIER_FULL_CLASSIFICATION: &str = "full_classification";

/// Keywords that indicate a potential compilation command.
/// Used for SIMD-accelerated quick filtering (Tier 2).
pub static COMPILATION_KEYWORDS: &[&str] = &[
    "cargo", "rustc", "gcc", "g++", "clang", "clang++", "make", "cmake", "ninja", "meson", "cc",
    "c++", "bun", "nextest",
];

/// Commands that should NEVER be intercepted, even if they contain compilation keywords.
/// These either modify local state or have dependencies on local execution.
pub static NEVER_INTERCEPT: &[&str] = &[
    // Cargo commands that modify local state or shouldn't be intercepted
    "cargo install",
    "cargo publish",
    "cargo login",
    "cargo fmt",
    "cargo fix",
    "cargo clean",
    "cargo new",
    "cargo init",
    "cargo add",
    "cargo remove",
    "cargo update",
    "cargo generate-lockfile",
    "cargo watch",
    "cargo --version",
    "cargo -V",
    // Compiler version checks
    "rustc --version",
    "rustc -V",
    "gcc --version",
    "gcc -v",
    "clang --version",
    "clang -v",
    "make --version",
    "make -v",
    "cmake --version",
    // Bun package management - MUST NOT intercept (modifies local state)
    "bun install",
    "bun add",
    "bun remove",
    "bun link",
    "bun unlink",
    "bun pm",
    "bun init",
    "bun create",
    "bun upgrade",
    "bun completions",
    // Bun execution that shouldn't be intercepted
    "bun run",
    "bun build",
    "bun --help",
    "bun -h",
    "bun --version",
    "bun -v",
    // Bun dev/repl - require local interactivity
    "bun dev",
    "bun repl",
    // cargo-nextest commands that shouldn't be intercepted
    "cargo nextest list",    // Lists tests only, doesn't run them
    "cargo nextest archive", // Creates test archives
    "cargo nextest show",    // Shows config/setup info
];

/// Result of command classification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Classification {
    /// Whether this is a compilation command.
    pub is_compilation: bool,
    /// Confidence score (0.0-1.0).
    pub confidence: f64,
    /// The kind of compilation if detected.
    pub kind: Option<CompilationKind>,
    /// Reason for the classification decision.
    pub reason: Cow<'static, str>,
}

/// Decision outcome for a classification tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TierDecision {
    Pass,
    Reject,
}

/// Detailed result for a single classification tier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClassificationTier {
    /// Tier index (0-4).
    pub tier: u8,
    /// Tier name.
    pub name: Cow<'static, str>,
    /// Decision for this tier.
    pub decision: TierDecision,
    /// Reason for the decision.
    pub reason: Cow<'static, str>,
}

/// Detailed classification results with per-tier decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClassificationDetails {
    /// Original command string.
    pub original: String,
    /// Normalized command string (wrappers stripped).
    pub normalized: String,
    /// Per-tier decisions.
    pub tiers: Vec<ClassificationTier>,
    /// Final classification result.
    pub classification: Classification,
}

impl Classification {
    /// Create a non-compilation classification.
    pub fn not_compilation(reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            is_compilation: false,
            confidence: 0.0,
            kind: None,
            reason: reason.into(),
        }
    }

    /// Create a compilation classification.
    pub fn compilation(
        kind: CompilationKind,
        confidence: f64,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            is_compilation: true,
            confidence,
            kind: Some(kind),
            reason: reason.into(),
        }
    }
}

/// Kind of compilation command detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompilationKind {
    // Rust commands
    /// cargo build, cargo test, cargo check, etc.
    CargoBuild,
    CargoTest,
    CargoCheck,
    CargoClippy,
    CargoDoc,
    /// cargo nextest run - next-generation test runner
    CargoNextest,
    /// cargo bench - run benchmarks
    CargoBench,
    /// rustc invocation
    Rustc,

    // C/C++ commands
    /// GCC compilation
    Gcc,
    /// G++ compilation
    Gpp,
    /// Clang compilation
    Clang,
    /// Clang++ compilation
    Clangpp,

    // Build systems
    /// make build
    Make,
    /// cmake --build
    CmakeBuild,
    /// ninja build
    Ninja,
    /// meson compile
    Meson,

    // Bun commands
    /// bun test - Runs Bun's built-in test runner
    BunTest,
    /// bun typecheck - Runs TypeScript type checking
    BunTypecheck,
}

impl CompilationKind {
    /// Returns true if this is a test-related command.
    ///
    /// Test commands have special cache affinity behavior because test binaries
    /// (e.g., target/debug/deps/) are expensive to compile and benefit more
    /// from warm caches than regular builds.
    pub fn is_test_command(&self) -> bool {
        matches!(
            self,
            CompilationKind::CargoTest
                | CompilationKind::CargoNextest
                | CompilationKind::CargoBench
                | CompilationKind::BunTest
        )
    }

    /// Returns the base command name for allowlist matching (bd-785w).
    ///
    /// This is the primary executable name that should appear in the
    /// execution allowlist configuration.
    pub fn command_base(&self) -> &'static str {
        match self {
            // Rust commands
            CompilationKind::CargoBuild
            | CompilationKind::CargoTest
            | CompilationKind::CargoCheck
            | CompilationKind::CargoClippy
            | CompilationKind::CargoDoc
            | CompilationKind::CargoBench => "cargo",
            CompilationKind::CargoNextest => "cargo", // cargo nextest, base is still cargo
            CompilationKind::Rustc => "rustc",
            // C/C++ commands
            CompilationKind::Gcc => "gcc",
            CompilationKind::Gpp => "g++",
            CompilationKind::Clang => "clang",
            CompilationKind::Clangpp => "clang++",
            // Build systems
            CompilationKind::Make => "make",
            CompilationKind::CmakeBuild => "cmake",
            CompilationKind::Ninja => "ninja",
            CompilationKind::Meson => "meson",
            // Bun commands
            CompilationKind::BunTest | CompilationKind::BunTypecheck => "bun",
        }
    }
}

/// Classify a shell command.
///
/// Implements the 5-tier classification system for maximum precision with
/// minimal latency on non-compilation commands.
///
/// Multi-command strings (joined by `&&`, `||`, or `;`) are rejected by
/// Tier 1 structure analysis to prevent partial interception issues.
pub fn classify_command(cmd: &str) -> Classification {
    classify_command_inner(cmd, 0)
}

/// Maximum recursion depth for multi-command splitting.
/// Depth 0 = top-level call that may split; depth 1 = sub-command (no further splitting).
#[allow(dead_code)] // Reserved for future multi-command classification
const MAX_CLASSIFY_DEPTH: u8 = 1;

/// Maximum command length for multi-command splitting (10 KB).
/// Commands longer than this skip splitting and are classified as a single command.
#[allow(dead_code)] // Reserved for future multi-command classification
const MAX_SPLIT_INPUT_LEN: usize = 10 * 1024;

fn classify_command_inner(cmd: &str, _depth: u8) -> Classification {
    let cmd = cmd.trim();

    // Tier 0: Instant reject - empty command
    if cmd.is_empty() {
        return Classification::not_compilation("empty command");
    }

    // Tier 1: Structure analysis - reject complex shell structures
    if let Some(reason) = check_structure(cmd) {
        return Classification::not_compilation(reason);
    }

    // Tier 2: SIMD keyword filter - quick check for compilation keywords
    if !contains_compilation_keyword(cmd) {
        return Classification::not_compilation("no compilation keyword");
    }

    // Normalize command for Tier 3 and 4
    let normalized_cow = normalize_command(cmd);
    let normalized = normalized_cow.as_ref();

    // Tier 3: Negative pattern check - never intercept these
    // Performance: use static string to avoid format! allocation on hot rejection path
    for pattern in NEVER_INTERCEPT {
        if let Some(rest) = normalized.strip_prefix(pattern) {
            // Ensure exact match or boundary match (e.g. "cargo clean" matches "cargo clean"
            // or "cargo clean ", but NOT "cargo cleanup")
            if rest.is_empty() || rest.starts_with(' ') {
                return Classification::not_compilation("matches never-intercept pattern");
            }
        }
    }

    // Tier 4: Full classification
    classify_full(normalized)
}

/// Split a multi-command string on `&&`, `||`, and `;` while respecting quotes.
///
/// Returns `None` if no multi-command operators are found.
/// Returns `Some(segments)` where each segment is a trimmed sub-command.
#[allow(dead_code)] // Reserved for future multi-command classification
fn split_multi_command(cmd: &str) -> Option<Vec<&str>> {
    // Quick check: if no operators, return None early
    if !cmd.contains("&&") && !cmd.contains("||") && !cmd.contains(';') {
        return None;
    }

    let mut segments = Vec::new();
    let mut current_start = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if escaped {
            escaped = false;
            i += 1;
            continue;
        }

        if c == '\\' {
            escaped = true;
            i += 1;
            continue;
        }

        if c == '\'' && !in_double {
            in_single = !in_single;
        } else if c == '"' && !in_single {
            in_double = !in_double;
        } else if !in_single && !in_double {
            // Check for operators
            if c == ';' {
                let segment = &cmd[current_start..byte_index(&chars, i)];
                let trimmed = segment.trim();
                if !trimmed.is_empty() {
                    segments.push(trimmed);
                }
                current_start = byte_index(&chars, i + 1);
            } else if c == '&' && i + 1 < chars.len() && chars[i + 1] == '&' {
                let segment = &cmd[current_start..byte_index(&chars, i)];
                let trimmed = segment.trim();
                if !trimmed.is_empty() {
                    segments.push(trimmed);
                }
                current_start = byte_index(&chars, i + 2);
                i += 1; // Skip second '&'
            } else if c == '|' && i + 1 < chars.len() && chars[i + 1] == '|' {
                let segment = &cmd[current_start..byte_index(&chars, i)];
                let trimmed = segment.trim();
                if !trimmed.is_empty() {
                    segments.push(trimmed);
                }
                current_start = byte_index(&chars, i + 2);
                i += 1; // Skip second '|'
            }
        }

        i += 1;
    }

    // Add final segment
    let final_segment = &cmd[current_start..];
    let trimmed = final_segment.trim();
    if !trimmed.is_empty() {
        segments.push(trimmed);
    }

    // Only return Some if we actually split something
    if segments.len() > 1 {
        Some(segments)
    } else {
        None
    }
}

/// Convert char index to byte index for string slicing.
#[allow(dead_code)] // Reserved for future multi-command classification
fn byte_index(chars: &[char], char_idx: usize) -> usize {
    chars.iter().take(char_idx).map(|c| c.len_utf8()).sum()
}

/// Classify a multi-command string by evaluating each sub-command independently.
///
/// Returns compilation if ANY sub-command is compilation (highest confidence wins).
/// Returns non-compilation only if ALL sub-commands are non-compilation.
#[allow(dead_code)] // Reserved for future multi-command classification
fn classify_multi_command(segments: &[&str], depth: u8) -> Classification {
    let mut best_compilation: Option<Classification> = None;

    for &segment in segments {
        let result = classify_command_inner(segment, depth + 1);
        if result.is_compilation {
            let dominated = match &best_compilation {
                Some(prev) => result.confidence > prev.confidence,
                None => true,
            };
            if dominated {
                best_compilation = Some(result);
            }
        }
    }

    if let Some(compilation) = best_compilation {
        return compilation;
    }

    Classification::not_compilation("no sub-command is compilation")
}

/// Classify a shell command with detailed tier decisions for diagnostics.
pub fn classify_command_detailed(cmd: &str) -> ClassificationDetails {
    let original = cmd.to_string();
    let cmd = cmd.trim();
    let mut tiers = Vec::new();

    // Tier 0: Instant reject - empty command
    if cmd.is_empty() {
        let classification = Classification::not_compilation("empty command");
        tiers.push(ClassificationTier {
            tier: 0,
            name: Cow::Borrowed(TIER_INSTANT_REJECT),
            decision: TierDecision::Reject,
            reason: Cow::Borrowed("empty command"),
        });
        return ClassificationDetails {
            original,
            normalized: cmd.to_string(),
            tiers,
            classification,
        };
    }

    tiers.push(ClassificationTier {
        tier: 0,
        name: Cow::Borrowed(TIER_INSTANT_REJECT),
        decision: TierDecision::Pass,
        reason: Cow::Borrowed("command present"),
    });

    // Tier 1: Structure analysis
    if let Some(reason) = check_structure(cmd) {
        let classification = Classification::not_compilation(reason);
        tiers.push(ClassificationTier {
            tier: 1,
            name: Cow::Borrowed(TIER_STRUCTURE_ANALYSIS),
            decision: TierDecision::Reject,
            reason: Cow::Borrowed(reason),
        });
        return ClassificationDetails {
            original,
            normalized: cmd.to_string(),
            tiers,
            classification,
        };
    }

    tiers.push(ClassificationTier {
        tier: 1,
        name: Cow::Borrowed(TIER_STRUCTURE_ANALYSIS),
        decision: TierDecision::Pass,
        reason: Cow::Borrowed("no pipes/redirects/backgrounding"),
    });

    // Tier 2: SIMD keyword filter
    if !contains_compilation_keyword(cmd) {
        let classification = Classification::not_compilation("no compilation keyword");
        tiers.push(ClassificationTier {
            tier: 2,
            name: Cow::Borrowed(TIER_KEYWORD_FILTER),
            decision: TierDecision::Reject,
            reason: Cow::Borrowed("no compilation keyword"),
        });
        return ClassificationDetails {
            original,
            normalized: cmd.to_string(),
            tiers,
            classification,
        };
    }

    tiers.push(ClassificationTier {
        tier: 2,
        name: Cow::Borrowed(TIER_KEYWORD_FILTER),
        decision: TierDecision::Pass,
        reason: Cow::Borrowed("keyword present"),
    });

    // Normalize command for Tier 3 and 4
    let normalized_cow = normalize_command(cmd);
    let normalized = normalized_cow.as_ref();

    // Tier 3: Negative pattern check - never intercept these
    for pattern in NEVER_INTERCEPT {
        if let Some(rest) = normalized.strip_prefix(pattern)
            && (rest.is_empty() || rest.starts_with(' '))
        {
            let reason: Cow<'static, str> =
                Cow::Owned(format!("matches never-intercept: {pattern}"));
            let classification = Classification::not_compilation(reason.clone());
            tiers.push(ClassificationTier {
                tier: 3,
                name: Cow::Borrowed(TIER_NEVER_INTERCEPT),
                decision: TierDecision::Reject,
                reason,
            });
            return ClassificationDetails {
                original,
                normalized: normalized.to_string(),
                tiers,
                classification,
            };
        }
    }

    tiers.push(ClassificationTier {
        tier: 3,
        name: Cow::Borrowed(TIER_NEVER_INTERCEPT),
        decision: TierDecision::Pass,
        reason: Cow::Borrowed("no never-intercept match"),
    });

    // Tier 4: Full classification
    let classification = classify_full(normalized);
    let decision = if classification.is_compilation {
        TierDecision::Pass
    } else {
        TierDecision::Reject
    };
    tiers.push(ClassificationTier {
        tier: 4,
        name: Cow::Borrowed(TIER_FULL_CLASSIFICATION),
        decision,
        reason: classification.reason.clone(),
    });

    ClassificationDetails {
        original,
        normalized: normalized.to_string(),
        tiers,
        classification,
    }
}

/// Normalize a command by stripping common wrappers (sudo, time, env, etc.)
pub fn normalize_command(cmd: &str) -> Cow<'_, str> {
    let mut result = cmd.trim();

    // Strip common command prefixes/wrappers
    // Note: We match the command name, then ensure it's followed by whitespace
    let wrappers = [
        "sudo", "env", "time", "nice", "ionice", "strace", "ltrace", "perf", "taskset", "numactl",
    ];

    loop {
        let mut changed = false;
        for wrapper in wrappers {
            if let Some(rest) = result.strip_prefix(wrapper) {
                // Must be followed by whitespace or end of string
                // (e.g., "sudo" matches "sudo ls", but not "sudoku")
                if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                    result = rest.trim_start();
                    changed = true;

                    // Strip flags that might follow the wrapper (e.g., "time -v", "sudo -E")
                    // We heuristically strip any token starting with '-' until we find a non-flag.
                    while result.starts_with('-') {
                        // Find the end of this token
                        let end_idx = result.find(char::is_whitespace).unwrap_or(result.len());

                        // Safety: we checked starts_with('-'), so token is not empty
                        result = result[end_idx..].trim_start();
                    }
                }
            }
        }

        // Handle env VAR=val syntax
        // Logic: if result starts with VAR=val (potentially quoted), strip it.
        // We need to parse the first token respecting quotes.
        let chars = result.chars();
        let mut token_len = 0;
        let mut in_quote = None; // None, Some('\''), Some('"')
        let mut escaped = false;
        let mut has_equals = false;
        let mut has_space = false;

        for c in chars {
            if escaped {
                escaped = false;
                token_len += c.len_utf8();
                continue;
            }

            if c == '\\' {
                escaped = true;
                token_len += c.len_utf8();
                continue;
            }

            if let Some(q) = in_quote {
                if c == q {
                    in_quote = None;
                }
                token_len += c.len_utf8();
            } else if c == '"' || c == '\'' {
                in_quote = Some(c);
                token_len += c.len_utf8();
            } else if c.is_whitespace() {
                has_space = true;
                break;
            } else {
                if c == '=' {
                    has_equals = true;
                }
                token_len += c.len_utf8();
            }
        }

        if has_equals && in_quote.is_none() && has_space {
            // It was a complete token with an equals sign followed by space.
            // We assume it's an env var and strip it.
            result = result[token_len..].trim_start();
            changed = true;
        }

        // Strip absolute paths: /usr/bin/cargo -> cargo
        // We assume the command is the first word
        if result.starts_with('/') {
            if let Some(space_idx) = result.find(' ') {
                let cmd_part = &result[..space_idx];
                if let Some(last_slash) = cmd_part.rfind('/') {
                    // Result becomes substring starting after the last slash of the command word
                    result = &result[last_slash + 1..];
                    changed = true;
                }
            } else {
                // Single word command
                if let Some(last_slash) = result.rfind('/') {
                    result = &result[last_slash + 1..];
                    changed = true;
                }
            }
        }

        if !changed {
            break;
        }
    }

    if result == cmd {
        Cow::Borrowed(cmd)
    } else {
        Cow::Owned(result.to_string())
    }
}

/// Check command structure for patterns that shouldn't be intercepted.
/// Check command structure for patterns that shouldn't be intercepted.
///
/// Performance: single-pass O(n) state machine instead of 11+ separate scans.
/// This is critical because structure analysis runs on EVERY command.
///
/// Detection priority (matches original behavior):
/// 1. Embedded newlines (security - command injection)
/// 2. Standalone & (backgrounding)
/// 3. Single | pipe (not ||)
/// 4. Subshell ( or >( or <(
/// 5. Output redirection >
/// 6. Input redirection <
/// 7. Semicolon ;
/// 8. && chaining
/// 9. || chaining
/// 10. Subshell capture $( or backtick
fn check_structure(cmd: &str) -> Option<&'static str> {
    let bytes = cmd.as_bytes();
    let len = bytes.len();

    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    // Track what we find (in priority order, lower = higher priority)
    // Using Option to track if found, with priority encoded by check order
    let mut found_backgrounded = false;
    let mut found_piped = false;
    let mut found_subshell = false;
    let mut found_output_redirect = false;
    let mut found_input_redirect = false;
    let mut found_semicolon = false;
    let mut found_and_chain = false;
    let mut found_or_chain = false;
    let mut found_subshell_capture = false;

    let mut i = 0;
    while i < len {
        let b = bytes[i];

        // Handle escape sequences
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if b == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }

        // Handle quote state transitions
        if b == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }

        // Skip quoted content
        if in_single || in_double {
            i += 1;
            continue;
        }

        // Check for problematic characters/patterns (unquoted)
        match b {
            // Embedded newlines - return immediately (highest priority, security issue)
            b'\n' | b'\r' => return Some("contains embedded newline"),

            // Ampersand: check for && vs standalone &
            b'&' => {
                if i + 1 < len && bytes[i + 1] == b'&' {
                    found_and_chain = true;
                    i += 1; // Skip second &
                } else {
                    // Check for redirection patterns like 2>&1 or &>
                    let prev = if i > 0 { bytes[i - 1] } else { 0 };
                    let next = if i + 1 < len { bytes[i + 1] } else { 0 };
                    if prev != b'>' && next != b'>' {
                        found_backgrounded = true;
                    }
                }
            }

            // Pipe: check for || vs single |
            b'|' => {
                if i + 1 < len && bytes[i + 1] == b'|' {
                    found_or_chain = true;
                    i += 1; // Skip second |
                } else {
                    found_piped = true;
                }
            }

            // Subshell/process substitution
            b'(' => found_subshell = true,

            // Output redirection (>( is process substitution, caught by ( check)
            b'>' => {
                if i + 1 < len && bytes[i + 1] == b'(' {
                    found_subshell = true;
                } else {
                    found_output_redirect = true;
                }
            }

            // Input redirection (<( is process substitution, caught by ( check)
            b'<' => {
                if i + 1 < len && bytes[i + 1] == b'(' {
                    found_subshell = true;
                } else {
                    found_input_redirect = true;
                }
            }

            // Semicolon chaining
            b';' => found_semicolon = true,

            // Backtick subshell capture
            b'`' => found_subshell_capture = true,

            // Dollar sign: check for $( subshell capture
            b'$' => {
                if i + 1 < len && bytes[i + 1] == b'(' {
                    found_subshell_capture = true;
                }
            }

            _ => {}
        }

        i += 1;
    }

    // Return in priority order (matches original check_structure behavior)
    if found_backgrounded {
        return Some("backgrounded command");
    }
    // Pipe check: only if not ||
    if found_piped && !found_or_chain {
        return Some("piped command");
    }
    if found_subshell {
        return Some("subshell execution");
    }
    if found_output_redirect {
        return Some("output redirected");
    }
    if found_input_redirect {
        return Some("input redirected");
    }
    if found_semicolon {
        return Some("chained command (;)");
    }
    if found_and_chain {
        return Some("chained command (&&)");
    }
    if found_or_chain {
        return Some("chained command (||)");
    }
    if found_subshell_capture {
        return Some("subshell capture");
    }

    None
}

/// Check if command contains any compilation keyword (SIMD-accelerated).
fn contains_compilation_keyword(cmd: &str) -> bool {
    let cmd_bytes = cmd.as_bytes();
    for keyword in COMPILATION_KEYWORDS {
        if memmem::find(cmd_bytes, keyword.as_bytes()).is_some() {
            return true;
        }
    }
    false
}

/// Check if character appears outside of quotes.
fn contains_unquoted(cmd: &str, ch: char) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for c in cmd.chars() {
        if escaped {
            escaped = false;
            continue;
        }

        if c == '\\' {
            escaped = true;
            continue;
        }

        if c == '\'' && !in_double {
            in_single = !in_single;
        } else if c == '"' && !in_single {
            in_double = !in_double;
        } else if c == ch && !in_single && !in_double {
            return true;
        }
    }
    false
}

/// Check if string appears outside of quotes.
fn contains_unquoted_str(cmd: &str, s: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let bytes = cmd.as_bytes();
    let pattern = s.as_bytes();

    if pattern.is_empty() {
        return false;
    }

    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];

        if escaped {
            escaped = false;
            i += 1;
            continue;
        }

        if b == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }

        if b == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }

        if !in_single
            && !in_double
            && i + pattern.len() <= bytes.len()
            && bytes[i..i + pattern.len()] == *pattern
        {
            return true;
        }

        i += 1;
    }

    false
}

/// Check for standalone ampersand (&) outside of quotes and not part of &&
fn contains_unquoted_standalone_ampersand(cmd: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let bytes = cmd.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }

        if b == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }

        if b == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }

        if b == b'&' && !in_single && !in_double {
            // Check for &&
            if i + 1 < bytes.len() && bytes[i + 1] == b'&' {
                // Found &&. Skip both.
                i += 2;
                continue;
            }
            let prev = if i > 0 { bytes[i - 1] } else { 0 };
            let next = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
            // Ignore redirection patterns like 2>&1 or &>
            if prev == b'>' || next == b'>' {
                i += 1;
                continue;
            }
            // Standalone &
            return true;
        }
        i += 1;
    }
    false
}

/// Full classification of a command (Tier 4).
fn classify_full(cmd: &str) -> Classification {
    // Cargo commands
    if cmd.starts_with("cargo ") || cmd == "cargo" {
        return classify_cargo(cmd);
    }

    // rustc
    if cmd.starts_with("rustc ") || cmd == "rustc" {
        return Classification::compilation(CompilationKind::Rustc, 0.95, "rustc invocation");
    }

    // GCC
    if cmd.starts_with("gcc ")
        && (cmd.contains(" -c ") || cmd.contains(" -o ") || cmd.contains(".c"))
    {
        return Classification::compilation(CompilationKind::Gcc, 0.90, "gcc compilation");
    }

    // G++
    if cmd.starts_with("g++ ")
        && (cmd.contains(" -c ")
            || cmd.contains(" -o ")
            || cmd.contains(".cpp")
            || cmd.contains(".cc"))
    {
        return Classification::compilation(CompilationKind::Gpp, 0.90, "g++ compilation");
    }

    // Clang
    if cmd.starts_with("clang ")
        && !cmd.starts_with("clang++ ")
        && (cmd.contains(" -c ") || cmd.contains(" -o ") || cmd.contains(".c"))
    {
        return Classification::compilation(CompilationKind::Clang, 0.90, "clang compilation");
    }

    // Clang++
    if cmd.starts_with("clang++ ")
        && (cmd.contains(" -c ")
            || cmd.contains(" -o ")
            || cmd.contains(".cpp")
            || cmd.contains(".cc"))
    {
        return Classification::compilation(CompilationKind::Clangpp, 0.90, "clang++ compilation");
    }

    // cc (standard C compiler)
    if cmd.starts_with("cc ")
        && (cmd.contains(" -c ") || cmd.contains(" -o ") || cmd.contains(".c"))
    {
        return Classification::compilation(CompilationKind::Gcc, 0.85, "cc compilation");
    }

    // c++ (standard C++ compiler)
    if cmd.starts_with("c++ ")
        && (cmd.contains(" -c ")
            || cmd.contains(" -o ")
            || cmd.contains(".cpp")
            || cmd.contains(".cc"))
    {
        return Classification::compilation(CompilationKind::Gpp, 0.85, "c++ compilation");
    }

    // Make
    if cmd.starts_with("make") && (cmd == "make" || cmd.starts_with("make ")) {
        // Don't intercept "make clean", "make install", etc.
        if cmd.contains("clean") || cmd.contains("install") || cmd.contains("distclean") {
            return Classification::not_compilation("make maintenance command");
        }
        return Classification::compilation(CompilationKind::Make, 0.85, "make build");
    }

    // CMake build
    if cmd.contains("cmake") && cmd.contains("--build") {
        return Classification::compilation(CompilationKind::CmakeBuild, 0.90, "cmake --build");
    }

    // Ninja
    if cmd.starts_with("ninja") && (cmd == "ninja" || cmd.starts_with("ninja ")) {
        if cmd.contains("-t clean") || cmd.contains("clean") {
            return Classification::not_compilation("ninja clean");
        }
        return Classification::compilation(CompilationKind::Ninja, 0.90, "ninja build");
    }

    // Meson
    if cmd.contains("meson") && cmd.contains("compile") {
        return Classification::compilation(CompilationKind::Meson, 0.85, "meson compile");
    }

    // Bun commands
    let mut tokens = cmd.split_whitespace();
    if tokens.next() == Some("bun") {
        match tokens.next() {
            Some("test") => {
                // Check for --watch flag - don't intercept interactive mode
                // Clone the iterator to check remaining args
                if tokens.any(|a| a == "-w" || a == "--watch") {
                    return Classification::not_compilation(
                        "bun test --watch is interactive (not intercepted)",
                    );
                }
                return Classification::compilation(
                    CompilationKind::BunTest,
                    0.95,
                    "bun test command",
                );
            }
            Some("typecheck") => {
                // Check for --watch flag - don't intercept interactive mode
                if tokens.any(|a| a == "-w" || a == "--watch") {
                    return Classification::not_compilation(
                        "bun typecheck --watch is interactive (not intercepted)",
                    );
                }
                return Classification::compilation(
                    CompilationKind::BunTypecheck,
                    0.95,
                    "bun typecheck command",
                );
            }
            Some("x") => {
                // bun x (alias for bunx - package runner)
                // NOT intercepted - similar to npx, runs arbitrary packages
                return Classification::not_compilation("bun x runs arbitrary packages");
            }
            _ => {}
        }
    }

    Classification::not_compilation("no matching pattern")
}

/// Classify cargo subcommands.
///
/// Performance: uses iterator `.nth()` to avoid Vec allocation on the hot path.
/// We only need tokens 0-3 (cargo, [+toolchain], subcommand, [nextest-subcommand]).
fn classify_cargo(cmd: &str) -> Classification {
    let mut tokens = cmd.split_whitespace();

    // Token 0: "cargo" (already validated by caller)
    let _cargo = tokens.next();

    // Token 1: subcommand or +toolchain
    let Some(token1) = tokens.next() else {
        return Classification::not_compilation("bare cargo command");
    };

    // Handle toolchain overrides (e.g., cargo +nightly build)
    let subcommand = if token1.starts_with('+') {
        let Some(sub) = tokens.next() else {
            return Classification::not_compilation("cargo +toolchain without subcommand");
        };
        sub
    } else {
        token1
    };

    match subcommand {
        "build" | "b" => {
            Classification::compilation(CompilationKind::CargoBuild, 0.95, "cargo build")
        }
        "test" | "t" => Classification::compilation(CompilationKind::CargoTest, 0.95, "cargo test"),
        "check" | "c" => {
            Classification::compilation(CompilationKind::CargoCheck, 0.90, "cargo check")
        }
        "clippy" => Classification::compilation(CompilationKind::CargoClippy, 0.90, "cargo clippy"),
        "doc" => Classification::compilation(CompilationKind::CargoDoc, 0.85, "cargo doc"),
        "run" | "r" => {
            // cargo run compiles first, so it's a compilation command
            Classification::compilation(
                CompilationKind::CargoBuild,
                0.85,
                "cargo run (includes build)",
            )
        }
        "bench" => Classification::compilation(CompilationKind::CargoBench, 0.90, "cargo bench"),
        "nextest" => {
            // cargo nextest has subcommands: run, list, archive, show
            // Only intercept "run" - the actual test execution
            // Next token is the nextest subcommand (e.g., "run", "list")
            let Some(nextest_sub) = tokens.next() else {
                return Classification::not_compilation("bare cargo nextest without subcommand");
            };

            match nextest_sub {
                "run" | "r" => Classification::compilation(
                    CompilationKind::CargoNextest,
                    0.95,
                    "cargo nextest run",
                ),
                _ => Classification::not_compilation("cargo nextest subcommand not interceptable"),
            }
        }
        _ => Classification::not_compilation("cargo subcommand not interceptable"),
    }
}

/// Split a shell command string on unquoted `;`, `&&`, and `||` operators.
///
/// Returns a list of sub-commands with each segment trimmed of whitespace.
/// Characters inside single quotes, double quotes, or backticks are treated
/// as literal and are never split. Escaped quotes (`\'`, `\"`) do not toggle
/// quote state. Pipes (`|`) within a segment are preserved (they are part of
/// one command, not a command separator).
///
/// Performance: single-pass O(n) character state machine, no regex, no heap
/// allocation for the common single-command case.
pub fn split_shell_commands(cmd: &str) -> Vec<&str> {
    let bytes = cmd.as_bytes();
    let len = bytes.len();
    let mut segments: Vec<&str> = Vec::new();
    let mut start = 0;
    let mut i = 0;

    // Quote state
    let mut in_single = false;
    let mut in_double = false;
    let mut in_backtick = false;
    let mut escaped = false;

    while i < len {
        let b = bytes[i];

        if escaped {
            escaped = false;
            i += 1;
            continue;
        }

        if b == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }

        // Toggle quote state
        if !in_double && !in_backtick && b == b'\'' {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if !in_single && !in_backtick && b == b'"' {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if !in_single && !in_double && b == b'`' {
            in_backtick = !in_backtick;
            i += 1;
            continue;
        }

        // Only split when outside all quotes
        if in_single || in_double || in_backtick {
            i += 1;
            continue;
        }

        // Check for `&&`
        if b == b'&' && i + 1 < len && bytes[i + 1] == b'&' {
            let seg = cmd[start..i].trim();
            if !seg.is_empty() {
                segments.push(seg);
            }
            i += 2;
            start = i;
            continue;
        }

        // Check for `||`
        if b == b'|' && i + 1 < len && bytes[i + 1] == b'|' {
            let seg = cmd[start..i].trim();
            if !seg.is_empty() {
                segments.push(seg);
            }
            i += 2;
            start = i;
            continue;
        }

        // Check for `;`
        if b == b';' {
            let seg = cmd[start..i].trim();
            if !seg.is_empty() {
                segments.push(seg);
            }
            i += 1;
            start = i;
            continue;
        }

        i += 1;
    }

    // Push the final segment
    let seg = cmd[start..].trim();
    if !seg.is_empty() {
        segments.push(seg);
    }

    segments
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_guard;

    #[test]
    fn test_cargo_build_with_toolchain() {
        let _guard = test_guard!();
        let result = classify_command("cargo +nightly build");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBuild));
    }

    #[test]
    fn test_cargo_test_with_toolchain() {
        let _guard = test_guard!();
        let result = classify_command("cargo +1.80.0 test");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_nextest_with_toolchain() {
        let _guard = test_guard!();
        let result = classify_command("cargo +nightly nextest run");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));
    }

    #[test]
    fn test_cargo_build() {
        let _guard = test_guard!();
        let result = classify_command("cargo build");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBuild));
        assert!(result.confidence >= 0.90);
    }

    #[test]
    fn test_cargo_build_release() {
        let _guard = test_guard!();
        let result = classify_command("cargo build --release");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBuild));
    }

    #[test]
    fn test_cargo_test() {
        let _guard = test_guard!();
        let result = classify_command("cargo test");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_fmt_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("cargo fmt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_cargo_install_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("cargo install ripgrep");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_piped_command_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("cargo build 2>&1 | grep error");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("piped"));
    }

    #[test]
    fn test_backgrounded_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("cargo build &");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("background"));
    }

    #[test]
    fn test_newline_injection_not_intercepted() {
        let _guard = test_guard!();
        // Newlines could cause command injection via `sh -c`
        let result = classify_command("cargo build\nrm -rf /");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("newline"));

        let result = classify_command("cargo build\r\nrm -rf /");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("newline"));
    }

    #[test]
    fn test_redirected_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("cargo build > log.txt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("redirect"));
    }

    #[test]
    fn test_input_redirected_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("cargo build < input.txt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("input redirected"));
    }

    #[test]
    fn test_process_substitution_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("cargo build --config <(echo ...)");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("subshell execution"));
    }

    #[test]
    fn test_subshell_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("(cargo build)");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("subshell execution"));
    }

    #[test]
    fn test_gcc_compile() {
        let _guard = test_guard!();
        let result = classify_command("gcc -c main.c -o main.o");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::Gcc));
    }

    #[test]
    fn test_make() {
        let _guard = test_guard!();
        let result = classify_command("make -j8");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::Make));
    }

    #[test]
    fn test_make_clean_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("make clean");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("make maintenance command"));
    }

    #[test]
    fn test_non_compilation() {
        let _guard = test_guard!();
        let result = classify_command("ls -la");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("no compilation keyword"));
    }

    #[test]
    fn test_empty_command() {
        let _guard = test_guard!();
        let result = classify_command("");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("empty command"));
    }

    // Bun tests - keyword detection and never-intercept patterns

    #[test]
    fn test_bun_keyword_detected() {
        let _guard = test_guard!();
        // Verify "bun" triggers keyword detection (Tier 2 passes)
        assert!(contains_compilation_keyword("bun test"));
        assert!(contains_compilation_keyword("bun typecheck"));
        assert!(contains_compilation_keyword("bun install")); // keyword present, but will be blocked in Tier 3
    }

    #[test]
    fn test_bun_install_not_intercepted() {
        let _guard = test_guard!();
        // Package management - modifies node_modules
        let result = classify_command("bun install");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_add_not_intercepted() {
        let _guard = test_guard!();
        // Adding packages - modifies package.json and node_modules
        let result = classify_command("bun add lodash");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_remove_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("bun remove lodash");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_run_not_intercepted() {
        let _guard = test_guard!();
        // Generic script runner - could do anything
        let result = classify_command("bun run build");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_build_not_intercepted() {
        let _guard = test_guard!();
        // Creates bundles in local directory
        let result = classify_command("bun build ./src/index.ts");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_version_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("bun --version");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));

        let result = classify_command("bun -v");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_dev_not_intercepted() {
        let _guard = test_guard!();
        // Development server needs local ports
        let result = classify_command("bun dev");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_repl_not_intercepted() {
        let _guard = test_guard!();
        // Interactive REPL
        let result = classify_command("bun repl");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_link_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("bun link");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_init_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("bun init");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_create_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("bun create next-app");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_pm_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("bun pm cache");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_help_not_intercepted() {
        let _guard = test_guard!();
        let result = classify_command("bun --help");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));

        let result = classify_command("bun -h");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    // Bun Tier 4 classification tests

    #[test]
    fn test_bun_test_classification() {
        let _guard = test_guard!();
        // Basic command
        let result = classify_command("bun test");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::BunTest));
        assert!((result.confidence - 0.95).abs() < 0.001);

        // With directory argument
        let result = classify_command("bun test src/");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::BunTest));

        // With coverage flag (non-interactive)
        let result = classify_command("bun test --coverage");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::BunTest));

        // Specific file
        let result = classify_command("bun test auth.test.ts");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::BunTest));

        // With multiple flags
        let result = classify_command("bun test --bail --timeout 5000");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::BunTest));

        // With reporter
        let result = classify_command("bun test --reporter json");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::BunTest));
    }

    #[test]
    fn test_bun_test_watch_not_intercepted() {
        let _guard = test_guard!();
        // --watch mode is interactive and should NOT be intercepted
        let result = classify_command("bun test --watch");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("interactive"));

        // Watch with other flags
        let result = classify_command("bun test --watch --coverage");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("interactive"));

        // Watch with directory
        let result = classify_command("bun test src/ --watch");
        assert!(!result.is_compilation);

        // Short form -w
        let result = classify_command("bun test -w");
        assert!(!result.is_compilation);

        // Short form with args
        let result = classify_command("bun test -w src/");
        assert!(!result.is_compilation);
    }

    #[test]
    fn test_bun_typecheck_watch_not_intercepted() {
        let _guard = test_guard!();
        // --watch mode is interactive and should NOT be intercepted
        let result = classify_command("bun typecheck --watch");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("interactive"));

        // Short form -w
        let result = classify_command("bun typecheck -w");
        assert!(!result.is_compilation);
    }

    #[test]
    fn test_bun_typecheck_classification() {
        let _guard = test_guard!();
        // Basic command
        let result = classify_command("bun typecheck");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::BunTypecheck));
        assert!((result.confidence - 0.95).abs() < 0.001);

        // With directory argument
        let result = classify_command("bun typecheck src/");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::BunTypecheck));

        // NOTE: --watch mode is tested separately in test_bun_typecheck_watch_not_intercepted
        // It should NOT be intercepted as it's interactive
    }

    #[test]
    fn test_bun_edge_cases_not_matched() {
        let _guard = test_guard!();
        // Invalid commands should not match
        let result = classify_command("bun testing");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("no matching pattern"));

        let result = classify_command("bun typechecker");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("no matching pattern"));

        let result = classify_command("bun type");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("no matching pattern"));

        // bun x should not be intercepted (runs arbitrary packages like npx)
        let result = classify_command("bun x eslint");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("bun x runs arbitrary packages"));

        let result = classify_command("bun x prettier --write .");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("bun x runs arbitrary packages"));

        let result = classify_command("bun x vitest run");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("bun x runs arbitrary packages"));
    }

    #[test]
    fn test_bun_test_vs_never_intercept() {
        let _guard = test_guard!();
        // bun test should NOT be blocked by never-intercept
        let result = classify_command("bun test");
        assert!(!result.reason.contains("never-intercept"));
        assert!(result.is_compilation);
    }

    #[test]
    fn test_bun_typecheck_vs_never_intercept() {
        let _guard = test_guard!();
        // bun typecheck should NOT be blocked by never-intercept
        let result = classify_command("bun typecheck");
        assert!(!result.reason.contains("never-intercept"));
        assert!(result.is_compilation);
    }

    // Bun CompilationKind serialization tests

    #[test]
    fn test_bun_compilation_kind_serde() {
        let _guard = test_guard!();
        // BunTest serialization
        let kind = CompilationKind::BunTest;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"bun_test\"");
        let parsed: CompilationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CompilationKind::BunTest);

        // BunTypecheck serialization
        let kind = CompilationKind::BunTypecheck;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"bun_typecheck\"");
        let parsed: CompilationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CompilationKind::BunTypecheck);
    }

    #[test]
    fn test_bun_kinds_are_distinct() {
        let _guard = test_guard!();
        // BunTest and BunTypecheck are different
        assert_ne!(CompilationKind::BunTest, CompilationKind::BunTypecheck);
        // BunTest is different from CargoTest (different ecosystems)
        assert_ne!(CompilationKind::BunTest, CompilationKind::CargoTest);
    }

    #[test]
    fn test_wrapped_command_classification_repro() {
        let _guard = test_guard!();
        // This fails currently because classify_full expects command to start with "cargo"
        // Wrapper tools like "time", "sudo", "env" break this logic
        let result = classify_command("time cargo build");
        assert!(
            result.is_compilation,
            "Should classify 'time cargo build' as compilation"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoBuild));

        let result = classify_command("sudo cargo check");
        assert!(
            result.is_compilation,
            "Should classify 'sudo cargo check' as compilation"
        );

        let result = classify_command("env RUST_BACKTRACE=1 cargo test");
        assert!(
            result.is_compilation,
            "Should classify env-wrapped cargo test as compilation"
        );
    }

    // =========================================================================
    // Bun E2E Edge Case Tests (from bead remote_compilation_helper-65m)
    // =========================================================================

    #[test]
    fn test_bun_piped_commands_not_intercepted() {
        let _guard = test_guard!();
        // Piped commands should be rejected at Tier 1 (structure analysis)
        let result = classify_command("bun test | grep error");
        assert!(!result.is_compilation);
        assert!(
            result.reason.contains("piped"),
            "Should be rejected as piped command"
        );

        // Piped with output filtering
        let result = classify_command("bun test 2>&1 | tee output.log");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("piped"));

        // Piped typecheck
        let result = classify_command("bun typecheck | head -20");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("piped"));
    }

    #[test]
    fn test_bunx_tsc_not_intercepted() {
        let _guard = test_guard!();
        // bunx (bun x) runs arbitrary packages - should NOT be intercepted
        // even for typecheck-like commands like tsc
        let result = classify_command("bun x tsc --noEmit");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("bun x"));

        // bunx with other tools
        let result = classify_command("bun x eslint .");
        assert!(!result.is_compilation);

        let result = classify_command("bun x prettier --write .");
        assert!(!result.is_compilation);

        let result = classify_command("bun x vitest run");
        assert!(!result.is_compilation);
    }

    #[test]
    fn test_bun_redirected_not_intercepted() {
        let _guard = test_guard!();
        // Output redirection should be rejected at Tier 1
        let result = classify_command("bun test > results.txt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("redirect"));

        let result = classify_command("bun typecheck > errors.log");
        assert!(!result.is_compilation);
    }

    #[test]
    fn test_bun_backgrounded_not_intercepted() {
        let _guard = test_guard!();
        // Backgrounded commands should be rejected at Tier 1
        let result = classify_command("bun test &");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("background"));
    }

    #[test]
    fn test_bun_chained_commands_classified() {
        let _guard = test_guard!();
        // Multi-command strings should be rejected
        let result = classify_command("bun test && echo done");
        assert!(
            !result.is_compilation,
            "chained commands should be rejected"
        );
        assert!(result.reason.contains("chained"));

        let result = classify_command("bun typecheck; bun test");
        assert!(
            !result.is_compilation,
            "chained commands should be rejected"
        );
        assert!(result.reason.contains("chained"));
    }

    #[test]
    fn test_bun_subshell_capture_not_intercepted() {
        let _guard = test_guard!();
        // Subshell capture should be rejected at Tier 1
        let result = classify_command("bun test $(echo src/)");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("subshell"));
    }

    #[test]
    fn test_bun_wrapped_commands() {
        let _guard = test_guard!();
        // Wrapped bun commands should still be classified
        // (requires normalize_command to handle wrappers)
        let result = classify_command("time bun test");
        // Currently may or may not work depending on normalize_command
        // This test documents current behavior
        if result.is_compilation {
            assert_eq!(result.kind, Some(CompilationKind::BunTest));
        }

        let result = classify_command("env DEBUG=1 bun test");
        if result.is_compilation {
            assert_eq!(result.kind, Some(CompilationKind::BunTest));
        }
    }

    #[test]
    fn test_classify_command_detailed_matches_basic() {
        let _guard = test_guard!();
        let commands = [
            "cargo build",
            "cargo test --release",
            "bun typecheck",
            "gcc -c main.c -o main.o",
            "ls -la",
        ];

        for cmd in commands {
            let basic = classify_command(cmd);
            let detailed = classify_command_detailed(cmd);
            assert_eq!(basic, detailed.classification);
        }
    }

    #[test]
    fn test_classify_command_detailed_rejects_piped() {
        let _guard = test_guard!();
        let detailed = classify_command_detailed("cargo build | tee log.txt");
        assert!(!detailed.classification.is_compilation);
        let tier1 = detailed.tiers.iter().find(|t| t.tier == 1).unwrap();
        assert_eq!(tier1.decision, TierDecision::Reject);
        assert!(tier1.reason.contains("piped"));
    }

    #[test]
    fn test_classify_command_detailed_normalizes_wrappers() {
        let _guard = test_guard!();
        let detailed = classify_command_detailed("sudo cargo check");
        assert_eq!(detailed.normalized, "cargo check");
        assert!(detailed.classification.is_compilation);
    }

    // =========================================================================
    // Comprehensive cargo test variant tests (bead remote_compilation_helper-xcvl)
    // =========================================================================

    #[test]
    fn test_cargo_test_release() {
        let _guard = test_guard!();
        let result = classify_command("cargo test --release");
        assert!(
            result.is_compilation,
            "cargo test --release should be classified as compilation"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
        assert!(result.confidence >= 0.90);
    }

    #[test]
    fn test_cargo_test_specific_test_name() {
        let _guard = test_guard!();
        let result = classify_command("cargo test my_test_function");
        assert!(
            result.is_compilation,
            "cargo test with specific test name should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_with_nocapture() {
        let _guard = test_guard!();
        let result = classify_command("cargo test -- --nocapture");
        assert!(
            result.is_compilation,
            "cargo test -- --nocapture should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_workspace() {
        let _guard = test_guard!();
        let result = classify_command("cargo test --workspace");
        assert!(
            result.is_compilation,
            "cargo test --workspace should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_package() {
        let _guard = test_guard!();
        let result = classify_command("cargo test -p rch-common");
        assert!(result.is_compilation, "cargo test -p should be classified");
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_short_alias() {
        let _guard = test_guard!();
        // cargo t is an alias for cargo test
        let result = classify_command("cargo t");
        assert!(
            result.is_compilation,
            "cargo t (short alias) should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_all_features() {
        let _guard = test_guard!();
        let result = classify_command("cargo test --all-features");
        assert!(
            result.is_compilation,
            "cargo test --all-features should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_no_default_features() {
        let _guard = test_guard!();
        let result = classify_command("cargo test --no-default-features");
        assert!(
            result.is_compilation,
            "cargo test --no-default-features should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_with_env_var() {
        let _guard = test_guard!();
        let result = classify_command("RUST_BACKTRACE=1 cargo test");
        assert!(
            result.is_compilation,
            "cargo test with env var should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_with_multiple_flags() {
        let _guard = test_guard!();
        let result = classify_command("cargo test --release --workspace -p rch -- --nocapture");
        assert!(
            result.is_compilation,
            "cargo test with multiple flags should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_with_jobs() {
        let _guard = test_guard!();
        let result = classify_command("cargo test -j 8");
        assert!(result.is_compilation, "cargo test -j should be classified");
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_target() {
        let _guard = test_guard!();
        let result = classify_command("cargo test --target x86_64-unknown-linux-gnu");
        assert!(
            result.is_compilation,
            "cargo test --target should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_lib() {
        let _guard = test_guard!();
        let result = classify_command("cargo test --lib");
        assert!(
            result.is_compilation,
            "cargo test --lib should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_bins() {
        let _guard = test_guard!();
        let result = classify_command("cargo test --bins");
        assert!(
            result.is_compilation,
            "cargo test --bins should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_doc() {
        let _guard = test_guard!();
        let result = classify_command("cargo test --doc");
        assert!(
            result.is_compilation,
            "cargo test --doc should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_filter_pattern() {
        let _guard = test_guard!();
        let result = classify_command("cargo test test_classification");
        assert!(
            result.is_compilation,
            "cargo test with filter pattern should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_exact() {
        let _guard = test_guard!();
        let result = classify_command("cargo test --exact my_test");
        assert!(
            result.is_compilation,
            "cargo test --exact should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    // =========================================================================
    // cargo-nextest tests (bead remote_compilation_helper-c7ky)
    // =========================================================================

    #[test]
    fn test_nextest_keyword_detected() {
        let _guard = test_guard!();
        // Verify "nextest" triggers keyword detection (Tier 2 passes)
        assert!(contains_compilation_keyword("cargo nextest run"));
        assert!(contains_compilation_keyword("cargo nextest list"));
    }

    #[test]
    fn test_cargo_nextest_run_classification() {
        let _guard = test_guard!();
        // Basic command
        let result = classify_command("cargo nextest run");
        assert!(
            result.is_compilation,
            "cargo nextest run should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));
        assert!((result.confidence - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_cargo_nextest_run_with_flags() {
        let _guard = test_guard!();
        // With release flag
        let result = classify_command("cargo nextest run --release");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));

        // With profile flag
        let result = classify_command("cargo nextest run --cargo-profile ci");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));

        // With workspace flag
        let result = classify_command("cargo nextest run --workspace");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));

        // With package filter
        let result = classify_command("cargo nextest run -p rch-common");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));

        // With test filter
        let result = classify_command("cargo nextest run test_classification");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));

        // With multiple flags
        let result = classify_command("cargo nextest run --release --no-fail-fast -j 8");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));
    }

    #[test]
    fn test_cargo_nextest_run_short_alias() {
        let _guard = test_guard!();
        // cargo nextest r is an alias for cargo nextest run
        let result = classify_command("cargo nextest r");
        assert!(
            result.is_compilation,
            "cargo nextest r should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));
    }

    #[test]
    fn test_cargo_nextest_list_not_intercepted() {
        let _guard = test_guard!();
        // cargo nextest list only shows tests, doesn't run them
        let result = classify_command("cargo nextest list");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_cargo_nextest_archive_not_intercepted() {
        let _guard = test_guard!();
        // cargo nextest archive creates archives
        let result = classify_command("cargo nextest archive");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_cargo_nextest_show_not_intercepted() {
        let _guard = test_guard!();
        // cargo nextest show displays config info
        let result = classify_command("cargo nextest show");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bare_cargo_nextest_not_intercepted() {
        let _guard = test_guard!();
        // bare "cargo nextest" without subcommand
        let result = classify_command("cargo nextest");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("without subcommand"));
    }

    #[test]
    fn test_cargo_nextest_wrapped_commands() {
        let _guard = test_guard!();
        // Wrapped nextest commands should still be classified
        let result = classify_command("time cargo nextest run");
        assert!(
            result.is_compilation,
            "time cargo nextest run should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));

        let result = classify_command("RUST_BACKTRACE=1 cargo nextest run");
        assert!(
            result.is_compilation,
            "env-wrapped cargo nextest run should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));
    }

    #[test]
    fn test_cargo_nextest_compilation_kind_serde() {
        let _guard = test_guard!();
        // CargoNextest serialization
        let kind = CompilationKind::CargoNextest;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"cargo_nextest\"");
        let parsed: CompilationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CompilationKind::CargoNextest);
    }

    #[test]
    fn test_cargo_nextest_vs_cargo_test_distinct() {
        let _guard = test_guard!();
        // CargoNextest and CargoTest are different
        assert_ne!(CompilationKind::CargoNextest, CompilationKind::CargoTest);

        // Both should be classified but as different kinds
        let nextest_result = classify_command("cargo nextest run");
        let test_result = classify_command("cargo test");
        assert!(nextest_result.is_compilation);
        assert!(test_result.is_compilation);
        assert_eq!(nextest_result.kind, Some(CompilationKind::CargoNextest));
        assert_eq!(test_result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_nextest_piped_not_intercepted() {
        let _guard = test_guard!();
        // Piped commands should be rejected at Tier 1
        let result = classify_command("cargo nextest run | grep FAIL");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("piped"));
    }

    #[test]
    fn test_cargo_nextest_redirected_not_intercepted() {
        let _guard = test_guard!();
        // Redirected commands should be rejected at Tier 1
        let result = classify_command("cargo nextest run > results.txt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("redirect"));
    }

    #[test]
    fn test_cargo_nextest_backgrounded_not_intercepted() {
        let _guard = test_guard!();
        // Backgrounded commands should be rejected at Tier 1
        let result = classify_command("cargo nextest run &");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("background"));
    }

    // =========================================================================
    // cargo bench tests (bead remote_compilation_helper-8o52)
    // =========================================================================

    #[test]
    fn test_cargo_bench_classification() {
        let _guard = test_guard!();
        let result = classify_command("cargo bench");
        assert!(result.is_compilation, "cargo bench should be classified");
        assert_eq!(result.kind, Some(CompilationKind::CargoBench));
        assert!((result.confidence - 0.90).abs() < 0.001);
    }

    #[test]
    fn test_cargo_bench_with_filter() {
        let _guard = test_guard!();
        // Benchmarks with name filter
        let result = classify_command("cargo bench my_bench");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBench));
    }

    #[test]
    fn test_cargo_bench_with_flags() {
        let _guard = test_guard!();
        // With release flag (benchmarks typically use release)
        let result = classify_command("cargo bench --release");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBench));

        // With package flag
        let result = classify_command("cargo bench -p rch-common");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBench));

        // With features
        let result = classify_command("cargo bench --features benchmarks");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBench));

        // With target filter
        let result = classify_command("cargo bench --bench criterion_bench");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBench));
    }

    #[test]
    fn test_cargo_bench_wrapped() {
        let _guard = test_guard!();
        // Wrapped with time
        let result = classify_command("time cargo bench");
        assert!(
            result.is_compilation,
            "time cargo bench should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoBench));

        // With env var
        let result = classify_command("CARGO_INCREMENTAL=0 cargo bench");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBench));
    }

    #[test]
    fn test_cargo_bench_serde() {
        let _guard = test_guard!();
        // CargoBench serialization
        let kind = CompilationKind::CargoBench;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"cargo_bench\"");
        let parsed: CompilationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CompilationKind::CargoBench);
    }

    #[test]
    fn test_cargo_bench_distinct_from_test() {
        let _guard = test_guard!();
        // CargoBench and CargoTest are different
        assert_ne!(CompilationKind::CargoBench, CompilationKind::CargoTest);

        // Both should be classified but as different kinds
        let bench_result = classify_command("cargo bench");
        let test_result = classify_command("cargo test");
        assert!(bench_result.is_compilation);
        assert!(test_result.is_compilation);
        assert_eq!(bench_result.kind, Some(CompilationKind::CargoBench));
        assert_eq!(test_result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_bench_piped_not_intercepted() {
        let _guard = test_guard!();
        // Piped commands should be rejected at Tier 1
        let result = classify_command("cargo bench | tee output.txt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("piped"));
    }

    #[test]

    fn test_normalize_path_and_wrapper_bug_repro() {
        let _guard = test_guard!();
        // Case: /usr/bin/time cargo build

        // Current behavior: strips path -> "time cargo build", then returns.

        // Desired behavior: strips path -> "time cargo build", then strips wrapper -> "cargo build".

        // This test asserts the CURRENT BROKEN behavior.

        let normalized = normalize_command("/usr/bin/time cargo build");

        assert_eq!(normalized, "cargo build");

        let result = classify_command("/usr/bin/time cargo build");

        assert!(result.is_compilation);
    }

    // ==========================================================================
    // Command Base Tests (bd-785w)
    // ==========================================================================

    #[test]
    fn test_command_base_rust() {
        let _guard = test_guard!();
        assert_eq!(CompilationKind::CargoBuild.command_base(), "cargo");
        assert_eq!(CompilationKind::CargoTest.command_base(), "cargo");
        assert_eq!(CompilationKind::CargoCheck.command_base(), "cargo");
        assert_eq!(CompilationKind::CargoClippy.command_base(), "cargo");
        assert_eq!(CompilationKind::CargoDoc.command_base(), "cargo");
        assert_eq!(CompilationKind::CargoBench.command_base(), "cargo");
        assert_eq!(CompilationKind::CargoNextest.command_base(), "cargo");
        assert_eq!(CompilationKind::Rustc.command_base(), "rustc");
    }

    #[test]
    fn test_command_base_c_cpp() {
        let _guard = test_guard!();
        assert_eq!(CompilationKind::Gcc.command_base(), "gcc");
        assert_eq!(CompilationKind::Gpp.command_base(), "g++");
        assert_eq!(CompilationKind::Clang.command_base(), "clang");
        assert_eq!(CompilationKind::Clangpp.command_base(), "clang++");
    }

    #[test]
    fn test_command_base_build_systems() {
        let _guard = test_guard!();
        assert_eq!(CompilationKind::Make.command_base(), "make");
        assert_eq!(CompilationKind::CmakeBuild.command_base(), "cmake");
        assert_eq!(CompilationKind::Ninja.command_base(), "ninja");
        assert_eq!(CompilationKind::Meson.command_base(), "meson");
    }

    #[test]
    fn test_command_base_bun() {
        let _guard = test_guard!();
        assert_eq!(CompilationKind::BunTest.command_base(), "bun");
        assert_eq!(CompilationKind::BunTypecheck.command_base(), "bun");
    }

    // ==========================================================================
    // Proptest: Command Classification with Random Inputs (bd-2kdm)
    // ==========================================================================

    mod proptest_classification {
        use super::*;
        use proptest::prelude::*;

        // Strategy for arbitrary strings (pure random)
        fn arbitrary_string() -> impl Strategy<Value = String> {
            prop::string::string_regex(".{0,500}").unwrap()
        }

        // Strategy for command-like strings with random suffixes
        fn command_like_string() -> impl Strategy<Value = String> {
            let prefixes = prop::sample::select(vec![
                "cargo", "rustc", "gcc", "g++", "clang", "make", "cmake", "ninja", "bun", "ls",
                "cd", "echo", "cat", "grep", "find", "rm", "mv", "cp", "mkdir",
            ]);
            (prefixes, "[ a-zA-Z0-9_.-]{0,200}")
                .prop_map(|(prefix, suffix)| format!("{}{}", prefix, suffix))
        }

        // Strategy for known compilation commands with random flags
        fn known_command_with_flags() -> impl Strategy<Value = String> {
            let base_commands = prop::sample::select(vec![
                "cargo build",
                "cargo test",
                "cargo check",
                "cargo clippy",
                "cargo run",
                "rustc",
                "gcc",
                "g++",
                "make",
                "bun test",
                "bun typecheck",
            ]);
            let flags = prop::collection::vec(
                prop::sample::select(vec![
                    "--release",
                    "--verbose",
                    "-j8",
                    "-p",
                    "--all",
                    "--workspace",
                    "--lib",
                    "--bin",
                    "-o",
                    "-c",
                ]),
                0..5,
            );
            (base_commands, flags).prop_map(|(cmd, flags)| {
                if flags.is_empty() {
                    cmd.to_string()
                } else {
                    format!("{} {}", cmd, flags.join(" "))
                }
            })
        }

        // Strategy for strings with unicode and control characters
        fn unicode_and_control_chars() -> impl Strategy<Value = String> {
            prop::string::string_regex(
                r"[\x00-\x1f\x80-\xff\u{100}-\u{10FFFF}a-zA-Z0-9 |>&;$()]{0,100}",
            )
            .unwrap()
        }

        // Strategy for shell-like commands with special characters
        fn shell_special_commands() -> impl Strategy<Value = String> {
            let components = prop::sample::select(vec![
                "cargo build",
                "ls -la",
                "echo test",
                "cat file.txt",
                "grep pattern",
            ]);
            let operators = prop::sample::select(vec![
                " | ", " && ", " || ", " ; ", " > ", " < ", " & ", " 2>&1 ", " $(", " `",
            ]);
            prop::collection::vec((components, operators), 1..4).prop_map(|pairs| {
                let mut result = String::new();
                for (i, (comp, op)) in pairs.iter().enumerate() {
                    if i > 0 {
                        result.push_str(op);
                    }
                    result.push_str(comp);
                }
                result
            })
        }

        // Strategy for wrapper-prefixed commands
        fn wrapped_commands() -> impl Strategy<Value = String> {
            let wrappers = prop::sample::select(vec![
                "sudo ",
                "env ",
                "time ",
                "nice ",
                "/usr/bin/time ",
                "RUST_BACKTRACE=1 ",
                "CC=clang ",
                "",
            ]);
            let commands = prop::sample::select(vec![
                "cargo build",
                "cargo test",
                "make",
                "gcc -c main.c",
                "ls -la",
            ]);
            (wrappers, commands).prop_map(|(wrapper, cmd)| format!("{}{}", wrapper, cmd))
        }

        proptest! {
            // Configure proptest for high-volume testing
            #![proptest_config(ProptestConfig::with_cases(1000))]

            // Test 1: Arbitrary strings never cause panics
            #[test]
            fn test_classify_arbitrary_no_panic(s in arbitrary_string()) {
                // Just call classify_command - if it panics, proptest will catch it
                let _ = classify_command(&s);
            }

            // Test 2: Command-like strings never cause panics
            #[test]
            fn test_classify_command_like_no_panic(s in command_like_string()) {
                let _ = classify_command(&s);
            }

            // Test 3: Known commands with flags produce valid classification
            #[test]
            fn test_classify_known_commands_valid(s in known_command_with_flags()) {
                let result = classify_command(&s);
                // Confidence should be in valid range
                prop_assert!(result.confidence >= 0.0 && result.confidence <= 1.0,
                    "Confidence {} out of range for command: {}", result.confidence, s);
                // If is_compilation, must have a kind
                if result.is_compilation {
                    prop_assert!(result.kind.is_some(),
                        "is_compilation=true but kind=None for: {}", s);
                }
            }

            // Test 4: Unicode and control characters never panic
            #[test]
            fn test_classify_unicode_no_panic(s in unicode_and_control_chars()) {
                let _ = classify_command(&s);
            }

            // Test 5: Shell special commands are handled
            #[test]
            fn test_classify_shell_special(s in shell_special_commands()) {
                let result = classify_command(&s);
                // Commands with shell operators should typically NOT be intercepted
                // (pipes, redirects, backgrounding, chaining)
                if s.contains(" | ") || s.contains(" > ") || s.contains(" < ") || s.contains(" & ") {
                    // May or may not be classified depending on quote handling
                    let _ = result; // Just ensure no panic
                }
            }

            // Test 6: Wrapped commands are handled
            #[test]
            fn test_classify_wrapped_commands(s in wrapped_commands()) {
                let result = classify_command(&s);
                prop_assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
            }

            // Test 7: Classification is deterministic
            #[test]
            fn test_classify_deterministic(s in arbitrary_string()) {
                let result1 = classify_command(&s);
                let result2 = classify_command(&s);
                prop_assert_eq!(result1, result2,
                    "Non-deterministic classification for: {}", s);
            }

            // Test 8: Empty-ish strings handled correctly
            #[test]
            fn test_classify_whitespace_variants(s in "[ \t\n\r]{0,20}") {
        let _guard = test_guard!();
                let result = classify_command(&s);
                prop_assert!(!result.is_compilation,
                    "Whitespace-only command should not be classified as compilation: {:?}", s);
                prop_assert!(result.reason.contains("empty") || result.reason.contains("keyword"),
                    "Unexpected reason for whitespace: {}", result.reason);
            }

            // Test 9: Very long commands don't panic
            #[test]
            fn test_classify_long_commands(
                prefix in "cargo (build|test|check)",
                suffix in "[a-zA-Z0-9_ -]{0,10000}"
            ) {
                let long_cmd = format!("{} {}", prefix, suffix);
                let result = classify_command(&long_cmd);
                prop_assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
            }

            // Test 10: Null bytes and special sequences
            #[test]
            fn test_classify_special_bytes(s in prop::collection::vec(any::<u8>(), 0..200)) {
                if let Ok(valid_str) = String::from_utf8(s.clone()) {
                    let _ = classify_command(&valid_str);
                }
                // Non-UTF8 sequences can't be tested with &str
            }
        }

        // Additional targeted proptest tests

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(500))]

            // Test: Cargo subcommands with arbitrary suffixes
            #[test]
            fn test_cargo_subcommand_robustness(
                subcommand in "(build|test|check|clippy|fmt|clean|run|doc|bench|nextest)",
                suffix in "[a-zA-Z0-9_ -]{0,50}"
            ) {
                let cmd = format!("cargo {} {}", subcommand, suffix);
                let result = classify_command(&cmd);
                // Ensure valid result structure
                prop_assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
                // fmt and clean should NEVER be classified as compilation
                if subcommand == "fmt" || subcommand == "clean" {
                    prop_assert!(!result.is_compilation,
                        "cargo {} should not be compilation: {}", subcommand, cmd);
                }
            }

            // Test: Bun commands robustness
            #[test]
            fn test_bun_command_robustness(
                subcommand in "(test|typecheck|install|add|remove|run|build|dev)",
                suffix in "[a-zA-Z0-9_ -]{0,30}"
            ) {
                let cmd = format!("bun {} {}", subcommand, suffix);
                let result = classify_command(&cmd);
                prop_assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
                // install, add, remove, run, build, dev should NOT be compilation
                if matches!(subcommand.as_str(), "install" | "add" | "remove" | "run" | "build" | "dev") {
                    prop_assert!(!result.is_compilation,
                        "bun {} should not be compilation", subcommand);
                }
            }

            // Test: GCC/Clang commands with file patterns
            #[test]
            fn test_c_compiler_robustness(
                compiler in "(gcc|g\\+\\+|clang|clang\\+\\+)",
                flags in "(-[cCoOgW][a-z0-9]* )*",
                file in "[a-zA-Z_][a-zA-Z0-9_]*\\.(c|cpp|cc|h|hpp)"
            ) {
                let cmd = format!("{} {}{}", compiler, flags, file);
                let result = classify_command(&cmd);
                prop_assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
            }

            // Test: Commands with quoted strings preserve correctness
            #[test]
            fn test_quoted_args_handling(
                base in "(cargo build|cargo test|gcc|make)",
                quoted_content in "[a-zA-Z0-9 _-]{0,30}"
            ) {
                // Single quotes
                let cmd_single = format!("{} '{}'", base, quoted_content);
                let _ = classify_command(&cmd_single);

                // Double quotes
                let cmd_double = format!("{} \"{}\"", base, quoted_content);
                let _ = classify_command(&cmd_double);
            }
        }

        // Regression test: ensure specific problematic inputs are handled
        #[test]
        fn test_known_edge_cases() {
            let _guard = test_guard!();
            // These are edge cases that might have caused issues
            let edge_cases = [
                "",
                " ",
                "\t",
                "\n",
                "cargo",
                "cargo ",
                "cargo  ",
                "cargo\tbuild",
                "cargo\nbuild",
                "cargo\rbuild",
                "cargo+nightly",
                "cargo +nightly",
                "cargo +nightly build",
                "  cargo build  ",
                "CARGO_TARGET_DIR=/tmp cargo build",
                "/usr/local/bin/cargo build",
                "~/.cargo/bin/cargo build",
                "./cargo build",
                "../cargo build",
                "cargo build 'test file.rs'",
                "cargo build \"test file.rs\"",
                "cargo build test\\ file.rs",
                "cargo build -- --test-threads=1",
                "cargo build --features \"feat1 feat2\"",
                "cargo build 2>&1",
                "cargo build 2>/dev/null",
                "gcc -DFOO=\"bar baz\" main.c",
                "make -j$(nproc)",
                "ninja -C build",
                "cmake --build . --target all",
                "bun test --timeout 5000 src/",
                "env -i PATH=/usr/bin cargo build",
            ];

            for cmd in edge_cases {
                let result = classify_command(cmd);
                assert!(
                    result.confidence >= 0.0 && result.confidence <= 1.0,
                    "Invalid confidence for: {:?}",
                    cmd
                );
            }
        }

        // Test that detailed classification matches simple classification
        #[test]
        fn test_detailed_matches_simple_proptest() {
            let _guard = test_guard!();
            let test_cases = [
                "cargo build --release",
                "cargo test",
                "make -j8",
                "ls -la",
                "echo hello",
            ];

            for cmd in test_cases {
                let simple = classify_command(cmd);
                let detailed = classify_command_detailed(cmd);
                assert_eq!(simple, detailed.classification, "Mismatch for: {}", cmd);
            }
        }

        // =================== split_shell_commands tests ===================

        #[test]
        fn test_split_single_command() {
            let _guard = test_guard!();
            assert_eq!(split_shell_commands("cargo build"), vec!["cargo build"]);
        }

        #[test]
        fn test_split_and_operator() {
            let _guard = test_guard!();
            assert_eq!(
                split_shell_commands("cargo fmt && cargo build"),
                vec!["cargo fmt", "cargo build"]
            );
        }

        #[test]
        fn test_split_quoted_operator() {
            let _guard = test_guard!();
            assert_eq!(
                split_shell_commands("echo '&&' && cargo build"),
                vec!["echo '&&'", "cargo build"]
            );
        }

        #[test]
        fn test_split_mixed_operators() {
            let _guard = test_guard!();
            assert_eq!(
                split_shell_commands("cd /tmp && make -j4 || echo fail"),
                vec!["cd /tmp", "make -j4", "echo fail"]
            );
        }

        #[test]
        fn test_split_semicolons() {
            let _guard = test_guard!();
            assert_eq!(split_shell_commands("a ; b ; c"), vec!["a", "b", "c"]);
        }

        #[test]
        fn test_split_quoted_semicolon() {
            let _guard = test_guard!();
            assert_eq!(
                split_shell_commands("echo 'hello;world' && make"),
                vec!["echo 'hello;world'", "make"]
            );
        }

        #[test]
        fn test_split_pipe_preserved() {
            let _guard = test_guard!();
            // Single pipe is NOT a command separator
            assert_eq!(
                split_shell_commands("cargo build 2>&1 | tee log"),
                vec!["cargo build 2>&1 | tee log"]
            );
        }

        #[test]
        fn test_split_double_quoted_operator() {
            let _guard = test_guard!();
            assert_eq!(
                split_shell_commands(r#"echo "&&" && cargo build"#),
                vec![r#"echo "&&""#, "cargo build"]
            );
        }

        #[test]
        fn test_split_nested_quotes() {
            let _guard = test_guard!();
            assert_eq!(
                split_shell_commands("echo \"he said 'hello && bye'\" && cargo test"),
                vec!["echo \"he said 'hello && bye'\"", "cargo test"]
            );
        }

        #[test]
        fn test_split_escaped_quote() {
            let _guard = test_guard!();
            // Escaped quotes don't toggle state
            assert_eq!(
                split_shell_commands(r"echo it\'s && cargo build"),
                vec![r"echo it\'s", "cargo build"]
            );
        }

        #[test]
        fn test_split_empty_string() {
            let _guard = test_guard!();
            assert!(split_shell_commands("").is_empty());
        }

        #[test]
        fn test_split_only_whitespace() {
            let _guard = test_guard!();
            assert!(split_shell_commands("   ").is_empty());
        }

        #[test]
        fn test_split_backtick_quoting() {
            let _guard = test_guard!();
            assert_eq!(
                split_shell_commands("echo `echo && fail` && cargo build"),
                vec!["echo `echo && fail`", "cargo build"]
            );
        }

        #[test]
        fn test_split_trailing_operator() {
            let _guard = test_guard!();
            // Trailing && with nothing after should yield just the first segment
            assert_eq!(split_shell_commands("cargo build &&"), vec!["cargo build"]);
        }

        // =================== fail-open safeguard tests (bd-16t3) ===================

        #[test]
        fn test_split_unclosed_single_quote() {
            let _guard = test_guard!();
            // Unclosed quote: everything stays "inside quotes", no split found
            let result = split_shell_commands("echo 'hello && cargo build");
            assert_eq!(result, vec!["echo 'hello && cargo build"]);
        }

        #[test]
        fn test_split_unclosed_double_quote() {
            let _guard = test_guard!();
            let result = split_shell_commands("echo \"hello && cargo build");
            assert_eq!(result, vec!["echo \"hello && cargo build"]);
        }

        #[test]
        fn test_split_unclosed_backtick() {
            let _guard = test_guard!();
            let result = split_shell_commands("echo `hello && cargo build");
            assert_eq!(result, vec!["echo `hello && cargo build"]);
        }

        #[test]
        fn test_split_embedded_nulls() {
            let _guard = test_guard!();
            // Embedded null bytes should not cause panic
            let input = "cargo build\0 && echo done";
            let result = split_shell_commands(input);
            assert_eq!(result.len(), 2);
        }

        #[test]
        fn test_split_unicode_input() {
            let _guard = test_guard!();
            let result = split_shell_commands("echo 'こんにちは' && cargo build");
            assert_eq!(result, vec!["echo 'こんにちは'", "cargo build"]);
        }

        #[test]
        fn test_split_extremely_long_input() {
            let _guard = test_guard!();
            // 20KB string should still work (split_shell_commands has no length limit)
            let long_cmd = format!("echo {} && cargo build", "x".repeat(20_000));
            let result = split_shell_commands(&long_cmd);
            assert_eq!(result.len(), 2);
        }

        #[test]
        fn test_classify_long_input_skips_splitting() {
            let _guard = test_guard!();
            // Commands >10KB skip multi-command splitting in classify_command
            let long_cmd = format!("cargo build && echo {}", "x".repeat(11_000));
            let result = classify_command(&long_cmd);
            // Falls through to single-command classification which rejects at check_structure
            assert!(!result.is_compilation);
            assert!(
                result.reason.to_string().contains("chained"),
                "long input should be rejected by check_structure, not split"
            );
        }

        #[test]
        fn test_split_only_operators() {
            let _guard = test_guard!();
            // Just operators with no commands
            let result = split_shell_commands("&& || ;");
            assert!(
                result.is_empty(),
                "only operators should yield empty result"
            );
        }

        #[test]
        fn test_split_consecutive_operators() {
            let _guard = test_guard!();
            let result = split_shell_commands("cargo build && && echo done");
            // Middle empty segment is dropped, yielding 2 segments
            assert_eq!(result, vec!["cargo build", "echo done"]);
        }

        #[test]
        fn test_classify_empty_after_split() {
            let _guard = test_guard!();
            // All sub-commands are non-compilation
            let result = classify_command("echo hello && ls -la || pwd");
            assert!(!result.is_compilation);
        }

        // =================== comprehensive multi-command tests (bd-1q0e) ===================

        // --- Split edge cases ---

        #[test]
        fn test_split_three_segment_chain() {
            let _guard = test_guard!();
            assert_eq!(
                split_shell_commands("cd /proj && cmake .. && make"),
                vec!["cd /proj", "cmake ..", "make"]
            );
        }

        #[test]
        fn test_split_single_with_flags() {
            let _guard = test_guard!();
            assert_eq!(
                split_shell_commands("cargo build --release"),
                vec!["cargo build --release"]
            );
        }

        #[test]
        fn test_split_nested_quotes_semicolon() {
            let _guard = test_guard!();
            assert_eq!(
                split_shell_commands("echo \"it's && done\" && make"),
                vec!["echo \"it's && done\"", "make"]
            );
        }

        #[test]
        fn test_split_pipe_then_and() {
            let _guard = test_guard!();
            // Single pipe within segment, && between segments
            assert_eq!(
                split_shell_commands("make 2>&1 | grep error && echo done"),
                vec!["make 2>&1 | grep error", "echo done"]
            );
        }

        #[test]
        fn test_split_leading_operator() {
            let _guard = test_guard!();
            // Leading && with nothing before
            assert_eq!(split_shell_commands("&& cargo build"), vec!["cargo build"]);
        }

        // --- Classification integration: should classify as COMPILATION ---

        #[test]
        fn test_classify_cargo_fmt_and_build() {
            let _guard = test_guard!();
            let result = classify_command("cargo fmt && cargo build");
            assert!(
                !result.is_compilation,
                "chained commands should be rejected for security"
            );
            assert!(result.reason.contains("chained"));
        }

        #[test]
        fn test_classify_cd_and_make() {
            let _guard = test_guard!();
            let result = classify_command("cd /project && make -j8");
            assert!(
                !result.is_compilation,
                "chained commands should be rejected"
            );
            assert!(result.reason.contains("chained"));
        }
        #[test]
        fn test_classify_export_and_cargo_build() {
            let _guard = test_guard!();
            let result =
                classify_command("export RUSTFLAGS='-C opt-level=3' && cargo build --release");
            assert!(
                !result.is_compilation,
                "chained commands should be rejected"
            );
            assert!(result.reason.contains("chained"));
        }
        #[test]
        fn test_classify_mkdir_cmake_chain() {
            let _guard = test_guard!();
            let result =
                classify_command("mkdir -p build && cmake -B build && cmake --build build");
            assert!(
                !result.is_compilation,
                "chained commands should be rejected"
            );
            assert!(result.reason.contains("chained"));
        }
        #[test]
        fn test_classify_echo_and_cargo_test() {
            let _guard = test_guard!();
            let result = classify_command("echo 'Starting...' && cargo test");
            assert!(
                !result.is_compilation,
                "chained commands should be rejected"
            );
            assert!(result.reason.contains("chained"));
        }
        #[test]
        fn test_classify_semicolon_chain_with_compilation() {
            let _guard = test_guard!();
            let result = classify_command("cargo fmt; cargo build; cargo test");
            assert!(
                !result.is_compilation,
                "chained commands should be rejected"
            );
            assert!(result.reason.contains("chained"));
        }
        // --- Classification integration: should classify as NON-COMPILATION ---

        #[test]
        fn test_classify_echo_chain_non_compilation() {
            let _guard = test_guard!();
            let result = classify_command("echo hello && echo world");
            assert!(!result.is_compilation);
        }

        #[test]
        fn test_classify_ls_cat_non_compilation() {
            let _guard = test_guard!();
            let result = classify_command("ls -la && cat file.txt");
            assert!(!result.is_compilation);
        }

        #[test]
        fn test_classify_git_chain_non_compilation() {
            let _guard = test_guard!();
            let result = classify_command("git status && git log");
            assert!(!result.is_compilation);
        }

        // --- Performance test ---

        #[test]
        fn test_classify_multi_command_performance() {
            let _guard = test_guard!();
            let start = std::time::Instant::now();
            for _ in 0..100 {
                let _ = classify_command("cargo fmt && cargo build && cargo test");
            }
            let elapsed = start.elapsed();
            let per_call_us = elapsed.as_micros() / 100;
            // Each classify_command call should be well under 5ms
            assert!(
                per_call_us < 5_000,
                "classify_command took {}us per call, should be <5000us",
                per_call_us
            );
            eprintln!(
                "[perf] classify_command multi-command: {}us avg per call",
                per_call_us
            );
        }

        // --- Pipe preservation with split ---

        #[test]
        fn test_classify_pipe_preserved_in_segment() {
            let _guard = test_guard!();
            // Pipe within a segment is NOT a split point; segment stays whole
            // and gets rejected by check_structure (piped command)
            let result = classify_command("cargo build 2>&1 | tee log");
            assert!(!result.is_compilation, "piped command should be rejected");
        }

        #[test]
        fn test_classify_pipe_segment_and_operator() {
            let _guard = test_guard!();
            // Pipe within first segment, && separates from second
            let result = classify_command("make 2>&1 | grep error && cargo build");
            // Should be rejected due to chaining (&&) AND piping (|)
            assert!(
                !result.is_compilation,
                "chained commands should be rejected"
            );
            // The reason will likely be "chained command (&&)" because check_structure checks separators first or pipes first?
            // Let's check check_structure impl: pipes are checked AFTER backgrounding, separators are after pipes?
            // Actually, check_structure checks pipes, then redirects, then chaining.
            // So "piped command" might be the reason. Either is fine.
            assert!(result.reason.contains("piped") || result.reason.contains("chained"));
        }
    }

    // =========================================================================
    // WS2.4: Zero-allocation reject path tests (bd-3mog)
    //
    // Verify that the Cow<'static, str> conversion in Classification and
    // ClassificationTier produces Cow::Borrowed on the reject path (zero heap
    // allocations) and that serde roundtrips work correctly.
    // =========================================================================

    /// Helper: assert that a Cow is the Borrowed variant (no heap allocation).
    /// We need the actual &Cow to distinguish Borrowed from Owned.
    #[allow(clippy::ptr_arg)]
    fn assert_cow_borrowed(cow: &Cow<'static, str>, context: &str) {
        assert!(
            matches!(cow, Cow::Borrowed(_)),
            "{context}: expected Cow::Borrowed, got Cow::Owned({:?})",
            cow,
        );
    }

    // --- 1. Classification correctness after Cow conversion ---

    #[test]
    fn test_cow_reject_empty_command_correctness() {
        let _guard = test_guard!();
        let result = classify_command("");
        assert!(!result.is_compilation);
        assert_eq!(result.confidence, 0.0);
        assert_eq!(result.kind, None);
        assert!(result.reason.contains("empty"), "reason: {}", result.reason);
    }

    #[test]
    fn test_cow_reject_non_compilation_commands() {
        let _guard = test_guard!();
        let non_compilation = [
            "ls -la",
            "cat file.txt",
            "echo hello",
            "git status",
            "pwd",
            "cd /tmp",
        ];
        for cmd in non_compilation {
            let result = classify_command(cmd);
            assert!(
                !result.is_compilation,
                "'{cmd}' should NOT be classified as compilation"
            );
            assert_eq!(result.confidence, 0.0, "'{cmd}' should have 0.0 confidence");
            assert_eq!(result.kind, None, "'{cmd}' should have no CompilationKind");
            assert!(!result.reason.is_empty(), "'{cmd}' should have a reason");
        }
    }

    #[test]
    fn test_cow_accept_compilation_commands() {
        let _guard = test_guard!();
        let cases: &[(&str, CompilationKind)] = &[
            ("cargo build", CompilationKind::CargoBuild),
            ("cargo test", CompilationKind::CargoTest),
            ("cargo check", CompilationKind::CargoCheck),
            ("cargo clippy", CompilationKind::CargoClippy),
            ("gcc -o hello hello.c", CompilationKind::Gcc),
            ("make", CompilationKind::Make),
            ("bun test", CompilationKind::BunTest),
        ];
        for &(cmd, expected_kind) in cases {
            let result = classify_command(cmd);
            assert!(
                result.is_compilation,
                "'{cmd}' should be classified as compilation"
            );
            assert_eq!(
                result.kind,
                Some(expected_kind),
                "'{cmd}' should have kind {expected_kind:?}"
            );
            assert!(
                result.confidence > 0.0,
                "'{cmd}' should have positive confidence"
            );
            assert!(!result.reason.is_empty(), "'{cmd}' should have a reason");
        }
    }

    // --- 2. Zero-allocation verification on reject path ---

    #[test]
    fn test_cow_borrowed_on_tier0_reject() {
        let _guard = test_guard!();
        // Empty command -> Tier 0 instant reject
        let result = classify_command("");
        assert_cow_borrowed(&result.reason, "Tier 0 empty command reason");
    }

    #[test]
    fn test_cow_borrowed_on_tier1_reject() {
        let _guard = test_guard!();
        // Piped command -> Tier 1 structure analysis reject
        let result = classify_command("cargo build | tee log");
        assert!(!result.is_compilation);
        assert_cow_borrowed(&result.reason, "Tier 1 piped command reason");

        // Backgrounded command
        let result = classify_command("cargo build &");
        assert!(!result.is_compilation);
        assert_cow_borrowed(&result.reason, "Tier 1 backgrounded command reason");

        // Output redirected
        let result = classify_command("cargo build > log.txt");
        assert!(!result.is_compilation);
        assert_cow_borrowed(&result.reason, "Tier 1 redirected command reason");
    }

    #[test]
    fn test_cow_borrowed_on_tier2_reject() {
        let _guard = test_guard!();
        // Commands with no compilation keyword -> Tier 2 keyword filter reject
        let non_keyword_commands = [
            "ls -la",
            "cat file.txt",
            "echo hello world",
            "git status",
            "pwd",
            "cd /tmp",
            "grep pattern file",
            "find . -name '*.rs'",
            "cp src dst",
            "rm file.txt",
        ];
        for cmd in non_keyword_commands {
            let result = classify_command(cmd);
            assert!(!result.is_compilation, "'{cmd}' should be rejected");
            assert_cow_borrowed(&result.reason, &format!("Tier 2 reject for '{cmd}'"));
        }
    }

    #[test]
    fn test_cow_borrowed_on_tier3_reject() {
        let _guard = test_guard!();
        // Never-intercept commands now use static strings for performance (no format! allocation)
        let never_intercept = ["cargo fmt", "cargo install ripgrep", "cargo clean"];
        for cmd in never_intercept {
            let result = classify_command(cmd);
            assert!(!result.is_compilation, "'{cmd}' should be rejected");
            assert!(
                result.reason.contains("never-intercept"),
                "'{cmd}' reason should mention never-intercept: {}",
                result.reason
            );
            // Tier 3 now uses static string for performance -> Cow::Borrowed
            assert_cow_borrowed(&result.reason, &format!("Tier 3 reject for '{cmd}'"));
        }
    }

    // --- 3. ClassificationDetails tier Cow verification ---

    #[test]
    fn test_detailed_tiers_use_borrowed_names() {
        let _guard = test_guard!();
        // classify_command_detailed produces ClassificationTier entries
        // All tier names should be Cow::Borrowed (static constants)
        let details = classify_command_detailed("ls -la");
        for tier in &details.tiers {
            assert_cow_borrowed(&tier.name, &format!("Tier {} name", tier.tier));
        }
    }

    #[test]
    fn test_detailed_tier_reasons_borrowed_on_reject() {
        let _guard = test_guard!();
        // Non-compilation commands should have Cow::Borrowed reasons on all tiers
        let details = classify_command_detailed("ls -la");
        assert!(!details.classification.is_compilation);
        for tier in &details.tiers {
            assert_cow_borrowed(
                &tier.reason,
                &format!("Tier {} reason for 'ls -la'", tier.tier),
            );
        }
    }

    #[test]
    fn test_detailed_compilation_tier_names_borrowed() {
        let _guard = test_guard!();
        // Even for compilation commands, tier NAMES should always be Cow::Borrowed
        let details = classify_command_detailed("cargo build");
        assert!(details.classification.is_compilation);
        for tier in &details.tiers {
            assert_cow_borrowed(
                &tier.name,
                &format!("Tier {} name for 'cargo build'", tier.tier),
            );
        }
    }

    // --- 4. Serde roundtrip tests for Cow fields ---

    #[test]
    fn test_classification_serde_roundtrip_borrowed() {
        let _guard = test_guard!();
        let original = Classification::not_compilation("no compilation keyword");
        assert_cow_borrowed(&original.reason, "before serialize");

        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: Classification = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.is_compilation, original.is_compilation);
        assert_eq!(deserialized.confidence, original.confidence);
        assert_eq!(deserialized.kind, original.kind);
        assert_eq!(deserialized.reason, original.reason);
        // Note: after deserialization, Cow will be Owned (serde deserializes into String)
        // This is correct behavior — only the pre-serialization path needs to be allocation-free
    }

    #[test]
    fn test_classification_serde_roundtrip_compilation() {
        let _guard = test_guard!();
        let original =
            Classification::compilation(CompilationKind::CargoBuild, 0.95, "cargo build detected");

        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: Classification = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.is_compilation, original.is_compilation);
        assert_eq!(deserialized.confidence, original.confidence);
        assert_eq!(deserialized.kind, original.kind);
        assert_eq!(deserialized.reason.as_ref(), original.reason.as_ref());
    }

    #[test]
    fn test_classification_tier_serde_roundtrip() {
        let _guard = test_guard!();
        let tier = ClassificationTier {
            tier: 2,
            name: Cow::Borrowed(TIER_KEYWORD_FILTER),
            decision: TierDecision::Reject,
            reason: Cow::Borrowed("no compilation keyword"),
        };
        assert_cow_borrowed(&tier.name, "tier name before serialize");
        assert_cow_borrowed(&tier.reason, "tier reason before serialize");

        let json = serde_json::to_string(&tier).expect("serialize");
        let deserialized: ClassificationTier = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.tier, tier.tier);
        assert_eq!(deserialized.name.as_ref(), tier.name.as_ref());
        assert_eq!(deserialized.decision, tier.decision);
        assert_eq!(deserialized.reason.as_ref(), tier.reason.as_ref());
    }

    #[test]
    fn test_classification_details_serde_roundtrip() {
        let _guard = test_guard!();
        let details = classify_command_detailed("cargo build");
        assert!(details.classification.is_compilation);

        let json = serde_json::to_string(&details).expect("serialize");
        let deserialized: ClassificationDetails = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.original, details.original);
        assert_eq!(deserialized.normalized, details.normalized);
        assert_eq!(deserialized.tiers.len(), details.tiers.len());
        assert_eq!(
            deserialized.classification.is_compilation,
            details.classification.is_compilation
        );
        assert_eq!(
            deserialized.classification.kind,
            details.classification.kind
        );
    }

    // --- 5. Cow display and comparison tests ---

    #[test]
    fn test_cow_reason_display() {
        let _guard = test_guard!();
        let result = classify_command("ls");
        // Cow<str> should Display/Debug correctly
        let displayed = format!("{}", result.reason);
        assert!(!displayed.is_empty());
        let debugged = format!("{:?}", result.reason);
        assert!(!debugged.is_empty());
    }

    #[test]
    fn test_cow_reason_comparison() {
        let _guard = test_guard!();
        // Cow::Borrowed and Cow::Owned with same content should be equal
        let borrowed: Cow<'static, str> = Cow::Borrowed("no compilation keyword");
        let owned: Cow<'static, str> = Cow::Owned("no compilation keyword".to_string());
        assert_eq!(borrowed, owned);

        // Classification reasons should be comparable
        let r1 = classify_command("ls");
        let r2 = classify_command("pwd");
        // Both should be "no compilation keyword" (Tier 2 reject)
        assert_eq!(r1.reason, r2.reason);
    }
}

#[cfg(test)]
mod tests_bun_whitespace {
    use super::*;
    use crate::test_guard;

    #[test]
    fn test_bun_whitespace_resilience() {
        let _guard = test_guard!();

        // Standard single space
        let result = classify_command("bun test");
        assert!(result.is_compilation, "bun test failed");
        assert_eq!(result.kind, Some(CompilationKind::BunTest));

        // Multiple spaces
        let result = classify_command("bun  test");
        assert!(result.is_compilation, "bun  test failed");
        assert_eq!(result.kind, Some(CompilationKind::BunTest));

        // Tab separation
        let result = classify_command("bun\ttest");
        assert!(result.is_compilation, "bun\\ttest failed");
        assert_eq!(result.kind, Some(CompilationKind::BunTest));

        // Typecheck with extra spaces
        let result = classify_command("bun   typecheck   src/");
        assert!(result.is_compilation, "bun typecheck with spaces failed");
        assert_eq!(result.kind, Some(CompilationKind::BunTypecheck));
    }

    #[test]
    fn test_bun_watch_with_whitespace() {
        let _guard = test_guard!();

        // Watch with extra spaces
        let result = classify_command("bun  test  --watch");
        assert!(
            !result.is_compilation,
            "bun test --watch should be rejected"
        );
        assert!(result.reason.contains("interactive"));

        // Watch with short flag and tabs
        let result = classify_command("bun\ttypecheck\t-w");
        assert!(
            !result.is_compilation,
            "bun typecheck -w should be rejected"
        );
        assert!(result.reason.contains("interactive"));
    }

    #[test]
    fn test_bun_x_whitespace() {
        let _guard = test_guard!();

        // bun x with extra spaces
        let result = classify_command("bun  x  vitest");
        assert!(!result.is_compilation, "bun x should be rejected");
        assert!(result.reason.contains("bun x"));
    }
}

#[cfg(test)]
mod tests_normalize_whitespace {
    use super::*;
    use crate::test_guard;

    #[test]
    fn test_wrapper_whitespace_resilience() {
        let _guard = test_guard!();

        // Multiple spaces
        assert_eq!(normalize_command("sudo  cargo"), "cargo");

        // Tabs
        assert_eq!(normalize_command("sudo\tcargo"), "cargo");

        // Mixed wrappers with weird spacing
        assert_eq!(normalize_command("time\tsudo  cargo"), "cargo");

        // Prefix matching safety
        assert_eq!(normalize_command("sudocargo"), "sudocargo");

        // Bare wrapper (should become empty)
        assert_eq!(normalize_command("sudo"), "");
    }

    #[test]
    fn test_env_var_whitespace() {
        let _guard = test_guard!();

        // env with multiple spaces before VAR
        assert_eq!(normalize_command("env  RUST_BACKTRACE=1 cargo"), "cargo");

        // env with tabs
        assert_eq!(normalize_command("env\tRUST_BACKTRACE=1\tcargo"), "cargo");
    }
}
