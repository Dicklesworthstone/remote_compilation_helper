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
    "cargo", "rustc", "gcc", "g++", "clang", "clang++", "make", "cmake", "ninja", "meson",
];

/// Commands that should NEVER be intercepted, even if they contain compilation keywords.
/// These either modify local state or have dependencies on local execution.
pub static NEVER_INTERCEPT: &[&str] = &[
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
    "rustc --version",
    "rustc -V",
    "gcc --version",
    "gcc -v",
    "clang --version",
    "clang -v",
    "make --version",
    "make -v",
    "cmake --version",
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
    /// cargo build, cargo test, cargo check, etc.
    CargoBuild,
    CargoTest,
    CargoCheck,
    CargoClippy,
    CargoDoc,
    /// rustc invocation
    Rustc,
    /// GCC compilation
    Gcc,
    /// G++ compilation
    Gpp,
    /// Clang compilation
    Clang,
    /// Clang++ compilation
    Clangpp,
    /// make build
    Make,
    /// cmake --build
    CmakeBuild,
    /// ninja build
    Ninja,
    /// meson compile
    Meson,
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
        if cmd.starts_with(pattern) {
            return Classification::not_compilation(format!("matches never-intercept: {pattern}"));
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
}
