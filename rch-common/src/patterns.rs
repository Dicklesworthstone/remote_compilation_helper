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

/// Keywords that indicate a potential compilation command.
/// Used for SIMD-accelerated quick filtering (Tier 2).
pub static COMPILATION_KEYWORDS: &[&str] = &[
    "cargo", "rustc", "gcc", "g++", "clang", "clang++", "make", "cmake", "ninja", "meson", "cc",
    "c++", "bun",
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

    // Tier 3: Negative pattern check - never intercept these
    for pattern in NEVER_INTERCEPT {
        if let Some(rest) = cmd.strip_prefix(pattern) {
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
    classify_full(cmd)
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
    if cmd.starts_with("bun ") {
        let rest = &cmd[4..]; // Skip "bun "

        // bun test [options] [patterns]
        // Examples: "bun test", "bun test --watch", "bun test src/"
        if rest.starts_with("test") {
            let after_test = &rest[4..];
            // Ensure it's "test" or "test " (not "testing")
            if after_test.is_empty() || after_test.starts_with(' ') {
                return Classification::compilation(
                    CompilationKind::BunTest,
                    0.95,
                    "bun test command",
                );
            }
        }

        // bun typecheck [options]
        // Examples: "bun typecheck", "bun typecheck --watch"
        if rest.starts_with("typecheck") {
            let after = &rest[9..];
            if after.is_empty() || after.starts_with(' ') {
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

    let subcommand = parts[1];
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
        "bench" => Classification::compilation(CompilationKind::CargoBuild, 0.90, "cargo bench"),
        _ => Classification::not_compilation(format!("cargo {subcommand} not interceptable")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn test_cargo_install_not_intercepted() {
        let result = classify_command("cargo install ripgrep");
        assert!(!result.is_compilation);
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
    }

    #[test]
    fn test_non_compilation() {
        let result = classify_command("ls -la");
        assert!(!result.is_compilation);
    }

    #[test]
    fn test_empty_command() {
        let result = classify_command("");
        assert!(!result.is_compilation);
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

    #[test]
    fn test_bun_test_passes_tier3() {
        // bun test should NOT be blocked by never-intercept
        // It will reach Tier 4 and fail with "no matching pattern" for now
        // (until BunTest classification is added in a subsequent bead)
        let result = classify_command("bun test");
        // Currently fails Tier 4 because BunTest isn't implemented yet
        // But it should NOT have been blocked by Tier 3
        assert!(!result.reason.contains("never-intercept"));
    }

    #[test]
    fn test_bun_typecheck_passes_tier3() {
        // bun typecheck should NOT be blocked by never-intercept
        let result = classify_command("bun typecheck");
        // Should reach Tier 4 (not blocked by Tier 3)
        assert!(!result.reason.contains("never-intercept"));
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
}
