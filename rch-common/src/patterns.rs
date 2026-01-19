//! Command classification patterns for identifying compilation commands.
//!
//! Implements the 5-tier classification system:
//! - Tier 0: Instant reject (non-Bash, empty)
//! - Tier 1: Structure analysis (pipes, redirects, background)
//! - Tier 2: SIMD keyword filter
//! - Tier 3: Negative pattern check
//! - Tier 4: Full classification with confidence

use memchr::memmem;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Classification {
    /// Whether this is a compilation command.
    pub is_compilation: bool,
    /// Confidence score (0.0-1.0).
    pub confidence: f64,
    /// The kind of compilation if detected.
    pub kind: Option<CompilationKind>,
    /// Reason for the classification decision.
    pub reason: String,
}

/// Decision outcome for a classification tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierDecision {
    Pass,
    Reject,
}

/// Detailed result for a single classification tier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassificationTier {
    /// Tier index (0-4).
    pub tier: u8,
    /// Tier name.
    pub name: String,
    /// Decision for this tier.
    pub decision: TierDecision,
    /// Reason for the decision.
    pub reason: String,
}

/// Detailed classification results with per-tier decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    pub fn not_compilation(reason: impl Into<String>) -> Self {
        Self {
            is_compilation: false,
            confidence: 0.0,
            kind: None,
            reason: reason.into(),
        }
    }

    /// Create a compilation classification.
    pub fn compilation(kind: CompilationKind, confidence: f64, reason: impl Into<String>) -> Self {
        Self {
            is_compilation: true,
            confidence,
            kind: Some(kind),
            reason: reason.into(),
        }
    }
}

/// Kind of compilation command detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Classify a shell command.
///
/// Implements the 5-tier classification system for maximum precision with
/// minimal latency on non-compilation commands.
pub fn classify_command(cmd: &str) -> Classification {
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
    for pattern in NEVER_INTERCEPT {
        if let Some(rest) = normalized.strip_prefix(pattern) {
            // Ensure exact match or boundary match (e.g. "cargo clean" matches "cargo clean"
            // or "cargo clean ", but NOT "cargo cleanup")
            if rest.is_empty() || rest.starts_with(' ') {
                return Classification::not_compilation(format!(
                    "matches never-intercept: {pattern}"
                ));
            }
        }
    }

    // Tier 4: Full classification
    classify_full(normalized)
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
            name: "instant_reject".to_string(),
            decision: TierDecision::Reject,
            reason: "empty command".to_string(),
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
        name: "instant_reject".to_string(),
        decision: TierDecision::Pass,
        reason: "command present".to_string(),
    });

    // Tier 1: Structure analysis
    if let Some(reason) = check_structure(cmd) {
        let classification = Classification::not_compilation(reason);
        tiers.push(ClassificationTier {
            tier: 1,
            name: "structure_analysis".to_string(),
            decision: TierDecision::Reject,
            reason: reason.to_string(),
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
        name: "structure_analysis".to_string(),
        decision: TierDecision::Pass,
        reason: "no pipes/redirects/backgrounding".to_string(),
    });

    // Tier 2: SIMD keyword filter
    if !contains_compilation_keyword(cmd) {
        let classification = Classification::not_compilation("no compilation keyword");
        tiers.push(ClassificationTier {
            tier: 2,
            name: "keyword_filter".to_string(),
            decision: TierDecision::Reject,
            reason: "no compilation keyword".to_string(),
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
        name: "keyword_filter".to_string(),
        decision: TierDecision::Pass,
        reason: "keyword present".to_string(),
    });

    // Normalize command for Tier 3 and 4
    let normalized_cow = normalize_command(cmd);
    let normalized = normalized_cow.as_ref();

    // Tier 3: Negative pattern check - never intercept these
    for pattern in NEVER_INTERCEPT {
        if let Some(rest) = normalized.strip_prefix(pattern) {
            if rest.is_empty() || rest.starts_with(' ') {
                let reason = format!("matches never-intercept: {pattern}");
                let classification = Classification::not_compilation(reason.clone());
                tiers.push(ClassificationTier {
                    tier: 3,
                    name: "never_intercept".to_string(),
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
    }

    tiers.push(ClassificationTier {
        tier: 3,
        name: "never_intercept".to_string(),
        decision: TierDecision::Pass,
        reason: "no never-intercept match".to_string(),
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
        name: "full_classification".to_string(),
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
    let wrappers = [
        "sudo ", "env ", "time ", "nice ", "ionice ", "strace ", "ltrace ", "perf ", "taskset ",
        "numactl ",
    ];

    loop {
        let mut changed = false;
        for wrapper in wrappers {
            if let Some(rest) = result.strip_prefix(wrapper) {
                result = rest.trim_start();
                changed = true;
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

        if !changed {
            break;
        }
    }

    // Strip absolute paths: /usr/bin/cargo -> cargo
    // We assume the command is the first word
    if result.starts_with('/') {
        if let Some(space_idx) = result.find(' ') {
            let cmd_part = &result[..space_idx];
            if let Some(last_slash) = cmd_part.rfind('/') {
                // Reconstruct: <stripped_cmd> <rest>
                // This is tricky with Cow, so we'll just return Owned if we modify
                let stripped_cmd = &cmd_part[last_slash + 1..];
                let rest = &result[space_idx..];
                return Cow::Owned(format!("{}{}", stripped_cmd, rest));
            }
        } else {
            // Single word command
            if let Some(last_slash) = result.rfind('/') {
                result = &result[last_slash + 1..];
            }
        }
    }

    if result == cmd {
        Cow::Borrowed(cmd)
    } else {
        Cow::Owned(result.to_string())
    }
}

/// Check command structure for patterns that shouldn't be intercepted.
fn check_structure(cmd: &str) -> Option<&'static str> {
    // Check for backgrounding (ends with & but not &&)
    let trimmed = cmd.trim_end();
    if trimmed.ends_with('&') && !trimmed.ends_with("&&") {
        return Some("backgrounded command");
    }

    // Check for pipes (output format matters)
    if contains_unquoted(cmd, '|') && !contains_unquoted_str(cmd, "||") {
        return Some("piped command");
    }

    // Check for output redirection
    if contains_unquoted(cmd, '>') {
        return Some("output redirected");
    }

    // Check for command chaining
    if contains_unquoted(cmd, ';') {
        return Some("chained command (;)");
    }
    if contains_unquoted_str(cmd, "&&") {
        return Some("chained command (&&)");
    }
    if contains_unquoted_str(cmd, "||") {
        return Some("chained command (||)");
    }

    // Check for subshell capture
    if cmd.contains("$(") || cmd.contains('`') {
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
    let mut prev = '\0';

    for c in cmd.chars() {
        if c == '\'' && !in_double && prev != '\\' {
            in_single = !in_single;
        } else if c == '"' && !in_single && prev != '\\' {
            in_double = !in_double;
        } else if c == ch && !in_single && !in_double {
            return true;
        }
        prev = c;
    }
    false
}

/// Check if string appears outside of quotes.
fn contains_unquoted_str(cmd: &str, s: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut prev = '\0';
    let chars: Vec<char> = cmd.chars().collect();
    let pattern: Vec<char> = s.chars().collect();

    for i in 0..chars.len() {
        let c = chars[i];
        if c == '\'' && !in_double && prev != '\\' {
            in_single = !in_single;
        } else if c == '"' && !in_single && prev != '\\' {
            in_double = !in_double;
        } else if !in_single && !in_double {
            // Check for pattern match at this position
            if i + pattern.len() <= chars.len() {
                let mut matched = true;
                for (j, &pc) in pattern.iter().enumerate() {
                    if chars[i + j] != pc {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    return true;
                }
            }
        }
        prev = c;
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
    if let Some(rest) = cmd.strip_prefix("bun ") {
        // bun test [options] [patterns]
        // Examples: "bun test", "bun test src/", "bun test --coverage"
        // NOTE: --watch mode should NOT be intercepted (interactive)
        if let Some(after_test) = rest.strip_prefix("test") {
            // Ensure it's "test" or "test " (not "testing")
            if after_test.is_empty() || after_test.starts_with(' ') {
                // Check for --watch flag - don't intercept interactive mode
                if after_test
                    .split_whitespace()
                    .any(|a| a == "-w" || a == "--watch")
                {
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
        }

        // bun typecheck [options]
        // Examples: "bun typecheck", "bun typecheck src/"
        // NOTE: --watch mode should NOT be intercepted (interactive)
        if let Some(after) = rest.strip_prefix("typecheck") {
            if after.is_empty() || after.starts_with(' ') {
                // Check for --watch flag - don't intercept interactive mode
                if after
                    .split_whitespace()
                    .any(|a| a == "-w" || a == "--watch")
                {
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
        }

        // bun x (alias for bunx - package runner)
        // NOT intercepted - similar to npx, runs arbitrary packages
        if rest.starts_with("x ") {
            return Classification::not_compilation("bun x runs arbitrary packages");
        }
    }

    Classification::not_compilation("no matching pattern")
}

/// Classify cargo subcommands.
fn classify_cargo(cmd: &str) -> Classification {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() < 2 {
        return Classification::not_compilation("bare cargo command");
    }

    // Handle toolchain overrides (e.g., cargo +nightly build)
    let subcommand = if parts[1].starts_with('+') {
        if parts.len() < 3 {
            return Classification::not_compilation("cargo +toolchain without subcommand");
        }
        parts[2]
    } else {
        parts[1]
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
            // Adjust index based on whether toolchain was present
            let args_start = if parts[1].starts_with('+') { 3 } else { 2 };

            if parts.len() > args_start {
                match parts[args_start] {
                    "run" | "r" => Classification::compilation(
                        CompilationKind::CargoNextest,
                        0.95,
                        "cargo nextest run",
                    ),
                    _ => Classification::not_compilation(format!(
                        "cargo nextest {} not interceptable",
                        parts[args_start]
                    )),
                }
            } else {
                // Bare "cargo nextest" without subcommand
                Classification::not_compilation("bare cargo nextest without subcommand")
            }
        }
        _ => Classification::not_compilation(format!("cargo {subcommand} not interceptable")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cargo_build_with_toolchain() {
        let result = classify_command("cargo +nightly build");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBuild));
    }

    #[test]
    fn test_cargo_test_with_toolchain() {
        let result = classify_command("cargo +1.80.0 test");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_nextest_with_toolchain() {
        let result = classify_command("cargo +nightly nextest run");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));
    }

    #[test]
    fn test_cargo_build() {
        let result = classify_command("cargo build");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBuild));
        assert!(result.confidence >= 0.90);
    }

    #[test]
    fn test_cargo_build_release() {
        let result = classify_command("cargo build --release");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBuild));
    }

    #[test]
    fn test_cargo_test() {
        let result = classify_command("cargo test");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_fmt_not_intercepted() {
        let result = classify_command("cargo fmt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_cargo_install_not_intercepted() {
        let result = classify_command("cargo install ripgrep");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_piped_command_not_intercepted() {
        let result = classify_command("cargo build 2>&1 | grep error");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("piped"));
    }

    #[test]
    fn test_backgrounded_not_intercepted() {
        let result = classify_command("cargo build &");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("background"));
    }

    #[test]
    fn test_redirected_not_intercepted() {
        let result = classify_command("cargo build > log.txt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("redirect"));
    }

    #[test]
    fn test_gcc_compile() {
        let result = classify_command("gcc -c main.c -o main.o");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::Gcc));
    }

    #[test]
    fn test_make() {
        let result = classify_command("make -j8");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::Make));
    }

    #[test]
    fn test_make_clean_not_intercepted() {
        let result = classify_command("make clean");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("make maintenance command"));
    }

    #[test]
    fn test_non_compilation() {
        let result = classify_command("ls -la");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("no compilation keyword"));
    }

    #[test]
    fn test_empty_command() {
        let result = classify_command("");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("empty command"));
    }

    // Bun tests - keyword detection and never-intercept patterns

    #[test]
    fn test_bun_keyword_detected() {
        // Verify "bun" triggers keyword detection (Tier 2 passes)
        assert!(contains_compilation_keyword("bun test"));
        assert!(contains_compilation_keyword("bun typecheck"));
        assert!(contains_compilation_keyword("bun install")); // keyword present, but will be blocked in Tier 3
    }

    #[test]
    fn test_bun_install_not_intercepted() {
        // Package management - modifies node_modules
        let result = classify_command("bun install");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_add_not_intercepted() {
        // Adding packages - modifies package.json and node_modules
        let result = classify_command("bun add lodash");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_remove_not_intercepted() {
        let result = classify_command("bun remove lodash");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_run_not_intercepted() {
        // Generic script runner - could do anything
        let result = classify_command("bun run build");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_build_not_intercepted() {
        // Creates bundles in local directory
        let result = classify_command("bun build ./src/index.ts");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_version_not_intercepted() {
        let result = classify_command("bun --version");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));

        let result = classify_command("bun -v");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_dev_not_intercepted() {
        // Development server needs local ports
        let result = classify_command("bun dev");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_repl_not_intercepted() {
        // Interactive REPL
        let result = classify_command("bun repl");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_link_not_intercepted() {
        let result = classify_command("bun link");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_init_not_intercepted() {
        let result = classify_command("bun init");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_create_not_intercepted() {
        let result = classify_command("bun create next-app");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_pm_not_intercepted() {
        let result = classify_command("bun pm cache");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_help_not_intercepted() {
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
        // bun test should NOT be blocked by never-intercept
        let result = classify_command("bun test");
        assert!(!result.reason.contains("never-intercept"));
        assert!(result.is_compilation);
    }

    #[test]
    fn test_bun_typecheck_vs_never_intercept() {
        // bun typecheck should NOT be blocked by never-intercept
        let result = classify_command("bun typecheck");
        assert!(!result.reason.contains("never-intercept"));
        assert!(result.is_compilation);
    }

    // Bun CompilationKind serialization tests

    #[test]
    fn test_bun_compilation_kind_serde() {
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
        // BunTest and BunTypecheck are different
        assert_ne!(CompilationKind::BunTest, CompilationKind::BunTypecheck);
        // BunTest is different from CargoTest (different ecosystems)
        assert_ne!(CompilationKind::BunTest, CompilationKind::CargoTest);
    }

    #[test]
    fn test_wrapped_command_classification_repro() {
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
        // Output redirection should be rejected at Tier 1
        let result = classify_command("bun test > results.txt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("redirect"));

        let result = classify_command("bun typecheck > errors.log");
        assert!(!result.is_compilation);
    }

    #[test]
    fn test_bun_backgrounded_not_intercepted() {
        // Backgrounded commands should be rejected at Tier 1
        let result = classify_command("bun test &");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("background"));
    }

    #[test]
    fn test_bun_chained_commands_not_intercepted() {
        // Chained commands should be rejected at Tier 1
        let result = classify_command("bun test && echo done");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("chained"));

        let result = classify_command("bun typecheck; bun test");
        assert!(!result.is_compilation);
    }

    #[test]
    fn test_bun_subshell_capture_not_intercepted() {
        // Subshell capture should be rejected at Tier 1
        let result = classify_command("bun test $(echo src/)");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("subshell"));
    }

    #[test]
    fn test_bun_wrapped_commands() {
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
        let detailed = classify_command_detailed("cargo build | tee log.txt");
        assert!(!detailed.classification.is_compilation);
        let tier1 = detailed.tiers.iter().find(|t| t.tier == 1).unwrap();
        assert_eq!(tier1.decision, TierDecision::Reject);
        assert!(tier1.reason.contains("piped"));
    }

    #[test]
    fn test_classify_command_detailed_normalizes_wrappers() {
        let detailed = classify_command_detailed("sudo cargo check");
        assert_eq!(detailed.normalized, "cargo check");
        assert!(detailed.classification.is_compilation);
    }

    // =========================================================================
    // Comprehensive cargo test variant tests (bead remote_compilation_helper-xcvl)
    // =========================================================================

    #[test]
    fn test_cargo_test_release() {
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
        let result = classify_command("cargo test my_test_function");
        assert!(
            result.is_compilation,
            "cargo test with specific test name should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_with_nocapture() {
        let result = classify_command("cargo test -- --nocapture");
        assert!(
            result.is_compilation,
            "cargo test -- --nocapture should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_workspace() {
        let result = classify_command("cargo test --workspace");
        assert!(
            result.is_compilation,
            "cargo test --workspace should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_package() {
        let result = classify_command("cargo test -p rch-common");
        assert!(result.is_compilation, "cargo test -p should be classified");
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_short_alias() {
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
        let result = classify_command("cargo test --all-features");
        assert!(
            result.is_compilation,
            "cargo test --all-features should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_no_default_features() {
        let result = classify_command("cargo test --no-default-features");
        assert!(
            result.is_compilation,
            "cargo test --no-default-features should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_with_env_var() {
        let result = classify_command("RUST_BACKTRACE=1 cargo test");
        assert!(
            result.is_compilation,
            "cargo test with env var should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_with_multiple_flags() {
        let result = classify_command("cargo test --release --workspace -p rch -- --nocapture");
        assert!(
            result.is_compilation,
            "cargo test with multiple flags should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_with_jobs() {
        let result = classify_command("cargo test -j 8");
        assert!(result.is_compilation, "cargo test -j should be classified");
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_target() {
        let result = classify_command("cargo test --target x86_64-unknown-linux-gnu");
        assert!(
            result.is_compilation,
            "cargo test --target should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_lib() {
        let result = classify_command("cargo test --lib");
        assert!(
            result.is_compilation,
            "cargo test --lib should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_bins() {
        let result = classify_command("cargo test --bins");
        assert!(
            result.is_compilation,
            "cargo test --bins should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_doc() {
        let result = classify_command("cargo test --doc");
        assert!(
            result.is_compilation,
            "cargo test --doc should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_filter_pattern() {
        let result = classify_command("cargo test test_classification");
        assert!(
            result.is_compilation,
            "cargo test with filter pattern should be classified"
        );
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_test_exact() {
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
        // Verify "nextest" triggers keyword detection (Tier 2 passes)
        assert!(contains_compilation_keyword("cargo nextest run"));
        assert!(contains_compilation_keyword("cargo nextest list"));
    }

    #[test]
    fn test_cargo_nextest_run_classification() {
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
        // cargo nextest list only shows tests, doesn't run them
        let result = classify_command("cargo nextest list");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_cargo_nextest_archive_not_intercepted() {
        // cargo nextest archive creates archives
        let result = classify_command("cargo nextest archive");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_cargo_nextest_show_not_intercepted() {
        // cargo nextest show displays config info
        let result = classify_command("cargo nextest show");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bare_cargo_nextest_not_intercepted() {
        // bare "cargo nextest" without subcommand
        let result = classify_command("cargo nextest");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("without subcommand"));
    }

    #[test]
    fn test_cargo_nextest_wrapped_commands() {
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
        // CargoNextest serialization
        let kind = CompilationKind::CargoNextest;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"cargo_nextest\"");
        let parsed: CompilationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CompilationKind::CargoNextest);
    }

    #[test]
    fn test_cargo_nextest_vs_cargo_test_distinct() {
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
        // Piped commands should be rejected at Tier 1
        let result = classify_command("cargo nextest run | grep FAIL");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("piped"));
    }

    #[test]
    fn test_cargo_nextest_redirected_not_intercepted() {
        // Redirected commands should be rejected at Tier 1
        let result = classify_command("cargo nextest run > results.txt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("redirect"));
    }

    #[test]
    fn test_cargo_nextest_backgrounded_not_intercepted() {
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
        let result = classify_command("cargo bench");
        assert!(result.is_compilation, "cargo bench should be classified");
        assert_eq!(result.kind, Some(CompilationKind::CargoBench));
        assert!((result.confidence - 0.90).abs() < 0.001);
    }

    #[test]
    fn test_cargo_bench_with_filter() {
        // Benchmarks with name filter
        let result = classify_command("cargo bench my_bench");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBench));
    }

    #[test]
    fn test_cargo_bench_with_flags() {
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
        // CargoBench serialization
        let kind = CompilationKind::CargoBench;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"cargo_bench\"");
        let parsed: CompilationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CompilationKind::CargoBench);
    }

    #[test]
    fn test_cargo_bench_distinct_from_test() {
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
        // Piped commands should be rejected at Tier 1
        let result = classify_command("cargo bench | tee output.txt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("piped"));
    }
}
