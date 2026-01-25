//! Output context detection for RCH.
//!
//! Determines when rich terminal output is safe to use vs when plain/JSON output is required.
//! This is critical for agent compatibility - hook mode must output pure JSON.

use std::io::IsTerminal;

/// Output context determines what level of rich formatting to use.
///
/// RCH operates in multiple contexts with vastly different output requirements:
///
/// | Context | Rich OK? | Why |
/// |---------|----------|-----|
/// | Hook mode | NO | Agent reads JSON from stdout |
/// | Interactive | YES | Human at terminal |
/// | Piped output | MAYBE | Depends on FORCE_COLOR |
/// | Daemon service | NO | No terminal, logs only |
/// | Worker execute | NO | Output goes to agent |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputContext {
    /// Hook mode - JSON protocol only, ZERO decoration.
    /// Detected when: JSON on stdin, or called as hook subprocess.
    Hook,

    /// Machine-readable output explicitly requested.
    /// Detected when: --json flag, RCH_JSON=1, --format=json.
    Machine,

    /// Interactive terminal session.
    /// Detected when: stderr is TTY, not hook mode.
    Interactive,

    /// Colored output but no full rich (no tables/panels).
    /// Detected when: FORCE_COLOR set but no TTY.
    Colored,

    /// Plain text only, no ANSI codes.
    /// Detected when: NO_COLOR set, or no TTY and no FORCE_COLOR.
    Plain,
}

impl OutputContext {
    /// Detect the current output context automatically.
    ///
    /// Detection order (first match wins):
    /// 1. RCH_JSON=1 -> Machine
    /// 2. Hook invocation detection -> Hook
    /// 3. NO_COLOR set -> Plain
    /// 4. FORCE_COLOR=0 -> Plain
    /// 5. stderr is TTY -> Interactive
    /// 6. FORCE_COLOR set -> Colored
    /// 7. Default -> Plain
    #[must_use]
    pub fn detect() -> Self {
        let first_arg = std::env::args().nth(1);
        Self::detect_with(
            |key| std::env::var(key).ok(),
            std::io::stdin().is_terminal(),
            std::io::stderr().is_terminal(),
            first_arg.as_deref(),
        )
    }

    fn detect_with<F>(
        get_env: F,
        stdin_is_tty: bool,
        stderr_is_tty: bool,
        first_arg: Option<&str>,
    ) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        // 1. Check for explicit machine output request
        if get_env("RCH_JSON").is_some() {
            return Self::Machine;
        }

        // 2. Check for hook mode (CRITICAL - must detect first)
        if Self::is_hook_invocation_with(&get_env, stdin_is_tty, first_arg) {
            return Self::Hook;
        }

        // 3. Check NO_COLOR (https://no-color.org/ standard)
        if get_env("NO_COLOR").is_some() {
            return Self::Plain;
        }

        // 4. FORCE_COLOR=0 disables colors even in TTY
        let force_color = get_env("FORCE_COLOR");
        let force_color_on = force_color.as_deref().map(|value| value.trim() != "0");
        if force_color_on == Some(false) {
            return Self::Plain;
        }

        // 5. Check if stderr is a terminal (we output rich to stderr!)
        // Note: NOT stdout! stdout is for machine data
        if stderr_is_tty {
            return Self::Interactive;
        }

        // 6. Check FORCE_COLOR for piped scenarios
        if force_color_on == Some(true) {
            return Self::Colored;
        }

        // 7. Default: plain text
        Self::Plain
    }

    /// Create a context that explicitly uses plain text (no colors/formatting).
    #[must_use]
    pub const fn plain() -> Self {
        Self::Plain
    }

    /// Create a context that explicitly uses interactive mode.
    #[must_use]
    pub const fn interactive() -> Self {
        Self::Interactive
    }

    /// Create a context for hook/machine output.
    #[must_use]
    pub const fn machine() -> Self {
        Self::Machine
    }

    /// Detect if this is a hook invocation.
    ///
    /// Hook mode is detected when:
    /// 1. RCH_HOOK_MODE environment variable is set
    /// 2. Stdin is not a terminal AND no known subcommand is provided
    #[allow(dead_code)]
    fn is_hook_invocation() -> bool {
        let first_arg = std::env::args().nth(1);
        let get_env = |key: &str| std::env::var(key).ok();
        Self::is_hook_invocation_with(
            &get_env,
            std::io::stdin().is_terminal(),
            first_arg.as_deref(),
        )
    }

    fn is_hook_invocation_with<F>(get_env: &F, stdin_is_tty: bool, first_arg: Option<&str>) -> bool
    where
        F: Fn(&str) -> Option<String>,
    {
        // Explicit hook mode flag
        if get_env("RCH_HOOK_MODE").is_some() {
            return true;
        }

        // If stdin is not a terminal and we have no subcommand args,
        // we're likely being called as a hook
        if !stdin_is_tty {
            // Check if first arg looks like a subcommand
            match first_arg {
                None => return true, // No args = hook mode
                Some(arg) => {
                    // If it doesn't start with - and isn't a known subcommand,
                    // could be hook JSON on stdin
                    if !arg.starts_with('-') && !Self::is_known_subcommand(arg) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if an argument is a known RCH subcommand.
    fn is_known_subcommand(arg: &str) -> bool {
        matches!(
            arg,
            "status"
                | "workers"
                | "daemon"
                | "config"
                | "hook"
                | "install"
                | "doctor"
                | "version"
                | "help"
                | "completions"
                | "benchmark"
                | "release"
                | "drain"
                | "undrain"
                | "enable"
                | "disable"
                | "speedscores"
        )
    }

    /// Can we use full rich output (tables, panels, etc)?
    #[must_use]
    pub const fn supports_rich(&self) -> bool {
        matches!(self, Self::Interactive)
    }

    /// Can we use ANSI color codes?
    #[must_use]
    pub const fn supports_color(&self) -> bool {
        matches!(self, Self::Interactive | Self::Colored)
    }

    /// Is this machine-readable output mode?
    #[must_use]
    pub const fn is_machine(&self) -> bool {
        matches!(self, Self::Hook | Self::Machine)
    }

    /// Should we output ANYTHING decorative?
    #[must_use]
    pub const fn is_decorated(&self) -> bool {
        !matches!(self, Self::Plain | Self::Hook | Self::Machine)
    }

    /// Can we use Unicode characters (box drawing, etc)?
    ///
    /// Checks locale environment variables for UTF-8 support.
    #[must_use]
    pub fn supports_unicode(&self) -> bool {
        if !self.supports_rich() {
            return false;
        }

        // Check LANG/LC_ALL for UTF-8
        for var in ["LC_ALL", "LC_CTYPE", "LANG"] {
            if let Ok(val) = std::env::var(var) {
                let val_lower = val.to_lowercase();
                if val_lower.contains("utf-8") || val_lower.contains("utf8") {
                    return true;
                }
            }
        }

        // Check TERM for known Unicode-capable terminals
        if let Ok(term) = std::env::var("TERM") {
            // Most modern terminals support Unicode, except dumb
            return !term.contains("dumb");
        }

        false
    }
}

impl Default for OutputContext {
    fn default() -> Self {
        Self::detect()
    }
}

impl std::fmt::Display for OutputContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hook => write!(f, "hook"),
            Self::Machine => write!(f, "machine"),
            Self::Interactive => write!(f, "interactive"),
            Self::Colored => write!(f, "colored"),
            Self::Plain => write!(f, "plain"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct TestEnv {
        vars: HashMap<&'static str, &'static str>,
    }

    impl TestEnv {
        fn new(pairs: &[(&'static str, &'static str)]) -> Self {
            let vars = pairs.iter().copied().collect();
            Self { vars }
        }

        fn get(&self, key: &str) -> Option<String> {
            self.vars.get(key).map(|value| (*value).to_string())
        }
    }

    fn detect_with(
        env: &TestEnv,
        stdin_is_tty: bool,
        stderr_is_tty: bool,
        first_arg: Option<&str>,
    ) -> OutputContext {
        OutputContext::detect_with(|key| env.get(key), stdin_is_tty, stderr_is_tty, first_arg)
    }

    #[test]
    fn test_supports_rich_only_interactive() {
        assert!(OutputContext::Interactive.supports_rich());
        assert!(!OutputContext::Plain.supports_rich());
        assert!(!OutputContext::Hook.supports_rich());
        assert!(!OutputContext::Machine.supports_rich());
        assert!(!OutputContext::Colored.supports_rich());
    }

    #[test]
    fn test_supports_color() {
        assert!(OutputContext::Interactive.supports_color());
        assert!(OutputContext::Colored.supports_color());
        assert!(!OutputContext::Plain.supports_color());
        assert!(!OutputContext::Hook.supports_color());
        assert!(!OutputContext::Machine.supports_color());
    }

    #[test]
    fn test_is_machine() {
        assert!(OutputContext::Hook.is_machine());
        assert!(OutputContext::Machine.is_machine());
        assert!(!OutputContext::Interactive.is_machine());
        assert!(!OutputContext::Colored.is_machine());
        assert!(!OutputContext::Plain.is_machine());
    }

    #[test]
    fn test_is_decorated() {
        assert!(OutputContext::Interactive.is_decorated());
        assert!(OutputContext::Colored.is_decorated());
        assert!(!OutputContext::Plain.is_decorated());
        assert!(!OutputContext::Hook.is_decorated());
        assert!(!OutputContext::Machine.is_decorated());
    }

    #[test]
    fn test_display() {
        assert_eq!(OutputContext::Hook.to_string(), "hook");
        assert_eq!(OutputContext::Machine.to_string(), "machine");
        assert_eq!(OutputContext::Interactive.to_string(), "interactive");
        assert_eq!(OutputContext::Colored.to_string(), "colored");
        assert_eq!(OutputContext::Plain.to_string(), "plain");
    }

    #[test]
    fn test_constructors() {
        assert_eq!(OutputContext::plain(), OutputContext::Plain);
        assert_eq!(OutputContext::interactive(), OutputContext::Interactive);
        assert_eq!(OutputContext::machine(), OutputContext::Machine);
    }

    #[test]
    fn test_known_subcommands() {
        assert!(OutputContext::is_known_subcommand("status"));
        assert!(OutputContext::is_known_subcommand("workers"));
        assert!(OutputContext::is_known_subcommand("daemon"));
        assert!(OutputContext::is_known_subcommand("help"));
        assert!(!OutputContext::is_known_subcommand("unknown"));
        assert!(!OutputContext::is_known_subcommand(""));
    }

    // Environment-dependent tests - these may behave differently in CI
    // They're kept simple to avoid flakiness

    #[test]
    fn test_default_is_detect() {
        // Just verify default() doesn't panic
        let _ = OutputContext::default();
    }

    #[test]
    fn test_detect_rch_json() {
        let env = TestEnv::new(&[("RCH_JSON", "1")]);
        let ctx = detect_with(&env, true, true, Some("status"));
        assert_eq!(ctx, OutputContext::Machine);
        assert!(ctx.is_machine());
    }

    #[test]
    fn test_detect_hook_mode_env() {
        let env = TestEnv::new(&[("RCH_HOOK_MODE", "1")]);
        let ctx = detect_with(&env, true, true, Some("status"));
        assert_eq!(ctx, OutputContext::Hook);
        assert!(ctx.is_machine());
    }

    #[test]
    fn test_detect_hook_mode_stdin_no_args() {
        let env = TestEnv::new(&[]);
        let ctx = detect_with(&env, false, false, None);
        assert_eq!(ctx, OutputContext::Hook);
    }

    #[test]
    fn test_no_color_disables_colors() {
        let env = TestEnv::new(&[("NO_COLOR", "1")]);
        let ctx = detect_with(&env, true, true, Some("status"));
        assert_eq!(ctx, OutputContext::Plain);
        assert!(!ctx.supports_color());
    }

    #[test]
    fn test_no_color_empty_string() {
        let env = TestEnv::new(&[("NO_COLOR", "")]);
        let ctx = detect_with(&env, true, true, Some("status"));
        assert_eq!(ctx, OutputContext::Plain);
    }

    #[test]
    fn test_force_color_zero_disables_colors() {
        let env = TestEnv::new(&[("FORCE_COLOR", "0")]);
        let ctx = detect_with(&env, true, true, Some("status"));
        assert_eq!(ctx, OutputContext::Plain);
    }

    #[test]
    fn test_force_color_on_without_tty() {
        let env = TestEnv::new(&[("FORCE_COLOR", "1")]);
        let ctx = detect_with(&env, true, false, Some("status"));
        assert_eq!(ctx, OutputContext::Colored);
    }

    #[test]
    fn test_force_color_on_with_tty() {
        let env = TestEnv::new(&[("FORCE_COLOR", "1")]);
        let ctx = detect_with(&env, true, true, Some("status"));
        assert_eq!(ctx, OutputContext::Interactive);
    }

    #[test]
    fn test_force_color_empty_string_enables() {
        let env = TestEnv::new(&[("FORCE_COLOR", "")]);
        let ctx = detect_with(&env, true, false, Some("status"));
        assert_eq!(ctx, OutputContext::Colored);
    }

    #[test]
    fn test_force_color_invalid_value_enables() {
        let env = TestEnv::new(&[("FORCE_COLOR", "yes")]);
        let ctx = detect_with(&env, true, false, Some("status"));
        assert_eq!(ctx, OutputContext::Colored);
    }

    #[test]
    fn test_rch_json_takes_priority_over_force_color() {
        let env = TestEnv::new(&[("RCH_JSON", "1"), ("FORCE_COLOR", "3")]);
        let ctx = detect_with(&env, true, false, Some("status"));
        assert_eq!(ctx, OutputContext::Machine);
    }

    #[test]
    fn test_hook_mode_takes_priority_over_force_color() {
        let env = TestEnv::new(&[("RCH_HOOK_MODE", "1"), ("FORCE_COLOR", "3")]);
        let ctx = detect_with(&env, true, false, Some("status"));
        assert_eq!(ctx, OutputContext::Hook);
    }

    #[test]
    fn test_no_color_takes_priority_over_force_color() {
        let env = TestEnv::new(&[("NO_COLOR", "1"), ("FORCE_COLOR", "3")]);
        let ctx = detect_with(&env, true, true, Some("status"));
        assert_eq!(ctx, OutputContext::Plain);
    }

    #[test]
    fn test_interactive_when_tty_and_no_overrides() {
        let env = TestEnv::new(&[]);
        let ctx = detect_with(&env, true, true, Some("status"));
        assert_eq!(ctx, OutputContext::Interactive);
    }

    #[test]
    fn test_plain_when_no_tty_and_no_overrides() {
        let env = TestEnv::new(&[]);
        let ctx = detect_with(&env, true, false, Some("status"));
        assert_eq!(ctx, OutputContext::Plain);
    }

    #[test]
    fn test_hook_detection_unknown_arg_no_tty() {
        let env = TestEnv::new(&[]);
        let ctx = detect_with(&env, false, false, Some("unknown"));
        assert_eq!(ctx, OutputContext::Hook);
    }
}
